"""Test offline toan bo pipeline ma KHONG can chay server.
Chay: python3 test_offline.py
  1. Security pipeline -> incident_type dung cho SSH, network, web, FIM/auditd
  2. Web/Nginx pipeline -> sensitive path va traversal attempt
  3. Correlation: Web + host -> Suspected Web Compromise; Network + Web + host
     with matching IP -> Possible Server Compromise
  4. Local ML -> anomaly_score/risk_delta tu baseline cuc bo
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.classifier import classify
from app.scoring import mitre_for_result, score_envelope, severity_of
from app.normalizer import from_soc_flat
from app.correlation import correlate, remember, reset
from app.explainer import ai_explain
from app.ml_anomaly import evaluate_anomaly, feature_vector, load_training_baseline

WL = json.load(open("data/whitelist.json"))
passed = 0
failed = 0


def check(cond, label):
    global passed, failed
    if cond:
        passed += 1
        print("[PASS] " + label)
    else:
        failed += 1
        print("[FAIL] " + label)


def run_soc(payload):
    ev = from_soc_flat(payload)
    incident = classify(ev["description"], ev["raw"].get("full_log", ""))
    corr = correlate(
        ev["source"],
        ev["server"],
        current_ip=ev.get("related_ip"),
        current_incident=incident,
    )
    remember(ev["source"], ev["server"], incident, ev.get("related_ip"))
    if corr:
        incident = corr["incident_type"]
    s = score_envelope(ev, incident, corr, WL)
    return incident, s, severity_of(s)


print("=== 1) SOC pipeline ===")
EXPECT = {
    "brute_force.json": "SSH Brute Force",
    "valid_login_after_bruteforce.json": "Valid Login After Brute Force",
    "nginx_sensitive_path.json": "Web Sensitive Path Scan",
    "nginx_traversal_attempt.json": "Web Traversal Attempt",
    "passwd_modified.json": "Account File Modified",
    "authorized_keys_modified.json": "SSH Key Backdoor",
    "sudo_abuse.json": "Privilege Escalation",
    "network_port_scan.json": "Network Port Scan",
    "webroot_modified.json": "Web Root Modified",
}
for fname in sorted(os.listdir("data/samples")):
    if not fname.endswith(".json"):
        continue
    reset()
    payload = json.load(open(os.path.join("data/samples", fname)))
    incident, s, sev = run_soc(payload)
    check(incident == EXPECT[fname], fname + ": " + incident + " (risk " + str(s) + "/" + sev + ")")

print("")
print("=== 2) Web/Application log pipeline ===")
reset()
web_ev = from_soc_flat(json.load(open("data/samples/nginx_sensitive_path.json")))
check(web_ev["source"] == "web", "normalize Nginx access log -> source=web")
web_inc = classify(web_ev["description"], web_ev["raw"].get("full_log", ""))
check(web_inc == "Web Sensitive Path Scan", "classify sensitive web path scan")
s = score_envelope(web_ev, web_inc, None, WL)
check(s >= 60, "web security incident co risk High de tao canh bao")
print("    Web incident=" + web_inc + " risk=" + str(s) + " (" + severity_of(s) + ")")

print("")
print("=== 3) Correlation Network -> Web -> Host (cung server, <10') ===")
reset()
network_ev = from_soc_flat(json.load(open("data/samples/network_port_scan.json")))
network_inc = classify(network_ev["description"], network_ev["raw"].get("full_log", ""))
remember(network_ev["source"], network_ev["server"], network_inc, network_ev.get("related_ip"))
web_ev = from_soc_flat(json.load(open("data/samples/nginx_traversal_attempt.json")))
web_inc = classify(web_ev["description"], web_ev["raw"].get("full_log", ""))
corr_web = correlate(
    web_ev["source"],
    web_ev["server"],
    current_ip=web_ev.get("related_ip"),
    current_incident=web_inc,
)
remember(web_ev["source"], web_ev["server"], web_inc, web_ev.get("related_ip"))
check(corr_web is None,
      "web alert chua bi nang cap khi chuoi chua co su kien OS/host")
host_ev = from_soc_flat(json.load(open("data/samples/webroot_modified.json")))
host_inc = classify(host_ev["description"], host_ev["raw"].get("full_log", ""))
corr_host = correlate(
    host_ev["source"],
    host_ev["server"],
    current_ip=host_ev.get("related_ip"),
    current_incident=host_inc,
)
incident_b = corr_host["incident_type"] if corr_host else host_inc
s_b = score_envelope(host_ev, incident_b, corr_host, WL)
check(corr_host is not None and corr_host.get("sources") == ["network", "web", "os"],
      "host event thay du ngu canh network + web truoc do")
check(incident_b == "Possible Server Compromise" and corr_host.get("confidence") == "high"
      and corr_host.get("src_ip_match") == "true",
      "incident nang cap high khi IP Network/Web khop = " + incident_b)
check(s_b >= 90 and severity_of(s_b) == "Critical", "risk = " + str(s_b) + " (" + severity_of(s_b) + ")")
check("T1046" in mitre_for_result(incident_b, corr_host)
      and "T1505.003" not in mitre_for_result(incident_b, corr_host),
      "MITRE full chain bam Network/Web/OS evidence thuc te")
analysis = ai_explain({"srcip": host_ev.get("related_ip"), "agent_name": host_ev["server"], "full_log": ""}, incident_b, s_b, correlation=corr_host)
print("    analysis = " + analysis[:100] + "...")

print("")
print("=== 4) Correlation Web -> Host khong can Network precursor ===")
reset()
web_ev = from_soc_flat(json.load(open("data/samples/nginx_traversal_attempt.json")))
web_inc = classify(web_ev["description"], web_ev["raw"].get("full_log", ""))
remember(web_ev["source"], web_ev["server"], web_inc, web_ev.get("related_ip"))
corr_medium = correlate(
    host_ev["source"],
    host_ev["server"],
    current_ip=host_ev.get("related_ip"),
    current_incident=host_inc,
)
incident_medium = corr_medium["incident_type"] if corr_medium else host_inc
s_medium = score_envelope(host_ev, incident_medium, corr_medium, WL)
check(corr_medium is not None and corr_medium.get("confidence") == "medium"
      and corr_medium.get("src_ip_match") == "unknown",
      "Web -> Host tao chuoi medium khi khong co Network precursor")
check(incident_medium == "Suspected Web Compromise" and s_medium < 100,
      "medium chain khong bi ep thanh full-chain score = " + str(s_medium))
check("T1505.003" not in mitre_for_result(incident_medium, corr_medium),
      "medium generic Web/OS khong tu gan MITRE web shell")

print("")
print("=== 5) Network-aware correlation ===")
reset()
network_payload = json.load(open("data/samples/network_port_scan.json"))
network_ev = from_soc_flat(network_payload)
check(network_ev["source"] == "network", "Suricata/Wazuh alert duoc tach source=network")
network_inc = classify(network_ev["description"], network_ev["raw"].get("full_log", ""))
remember(network_ev["source"], network_ev["server"], network_inc, network_ev.get("related_ip"))
web_ev = from_soc_flat(json.load(open("data/samples/nginx_sensitive_path.json")))
web_inc = classify(web_ev["description"], web_ev["raw"].get("full_log", ""))
corr_web = correlate(
    web_ev["source"],
    web_ev["server"],
    current_ip=web_ev.get("related_ip"),
    current_incident=web_inc,
)
remember(web_ev["source"], web_ev["server"], web_inc, web_ev.get("related_ip"))
check(corr_web is None,
      "web alert chua bi nang cap khi chuoi chua co su kien OS/host")
corr_3 = correlate(
    host_ev["source"],
    host_ev["server"],
    current_ip=host_ev.get("related_ip"),
    current_incident=host_inc,
)
check(corr_3 is not None and corr_3.get("sources") == ["network", "web", "os"]
      and corr_3.get("src_ip_match") == "true",
      "host event thay du ngu canh network + web truoc do")

print("")
print("=== 6) Local ML anomaly scoring ===")
ml = evaluate_anomaly(host_ev, incident_b, s_b, corr_host)
check("model" in ml, "ML tra ve ten model: " + str(ml.get("model")))
check(0 <= ml.get("anomaly_score", -1) <= 100, "anomaly_score nam trong 0..100")
check(isinstance(ml.get("is_anomaly"), bool), "is_anomaly la boolean")
fv = feature_vector(host_ev, "Possible Server Compromise", 100, corr_3)
check(len(fv) == 9, "feature vector co 9 dac trung security-log")
check(fv[0] == 0 and fv[1] == 0 and fv[2] == 1 and fv[6] == 1 and fv[7] == 1,
      "feature vector bat co OS/host + correlated + network precursor")
baseline, baseline_source = load_training_baseline("data/baseline.json")
check(baseline_source.endswith("data/baseline.json"), "ML load baseline tu data/baseline.json")
check(len(baseline) >= 12 and all(len(row) == 9 for row in baseline), "baseline co du vector 9 dac trung")
check(os.path.exists("collect_baseline.py"), "co script collect_baseline.py de tao baseline tu sample/alert")

print("")
print("=== KET QUA: " + str(passed) + " pass, " + str(failed) + " fail ===")
sys.exit(1 if failed else 0)
