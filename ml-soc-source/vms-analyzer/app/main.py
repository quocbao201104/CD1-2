"""Local ML Security Log Analyzer - FastAPI app.

Endpoints:
- GET /health          : kiem tra trang thai VM3
- POST /analyze-alert  : nhan alert bao mat tu Wazuh Integrator

Luong chung sau khi chuan hoa ve envelope:
  normalize -> correlate(network/web/host) -> rule score -> local ML score -> notify -> policy
Phan quyet dinh cot loi la deterministic. ML local chi bo sung anomaly_score.
"""
import json
import os

from fastapi import FastAPI

from app.classifier import classify
from app.scoring import score_envelope, severity_of, MITRE
from app.playbook import playbook_for
from app.explainer import ai_explain
from app.notifier import notify
from app.policy import policy_engine
from app.normalizer import from_soc_flat
from app.correlation import remember, correlate
from app.ml_anomaly import evaluate_anomaly

app = FastAPI(title="Local ML Security Log Analyzer", version="2.0")

_WL_PATH = os.getenv("WHITELIST_PATH", "data/whitelist.json")
try:
    with open(_WL_PATH) as f:
        WL = json.load(f)
except Exception:
    WL = {"ips": []}

DRY_RUN = os.getenv("DRY_RUN", "true").lower() != "false"


def _pipeline(ev):
    """Xu ly chung cho mot envelope bao mat da chuan hoa."""
    incident = classify(ev.get("description", ""), ev.get("raw", {}).get("full_log", ""))

    corr = correlate(ev["source"], ev.get("server", ""))
    remember(ev["source"], ev.get("server", ""), incident, ev.get("related_ip"))
    if corr:
        incident = "Possible Server Compromise"
        if not ev.get("related_ip") and corr.get("other_ip"):
            ev = {**ev, "related_ip": corr["other_ip"]}

    base_score = score_envelope(ev, incident, corr, WL)
    ml_result = evaluate_anomaly(ev, incident, base_score, corr)
    s = min(100, base_score + ml_result.get("risk_delta", 0))
    sev = severity_of(s)
    explain_ctx = {
        "srcip": ev.get("related_ip"),
        "agent_name": ev.get("server"),
        "full_log": ev.get("raw", {}).get("full_log", ""),
    }
    analysis = ai_explain(explain_ctx, incident, s, ml_result)

    result = {
        "source": ev["source"],
        "incident_type": incident,
        "severity": sev,
        "risk_score": s,
        "base_risk_score": base_score,
        "ml": ml_result,
        "mitre": MITRE.get(incident),
        "server": ev.get("server"),
        "srcip": ev.get("related_ip"),
        "correlated": bool(corr),
        "correlation": corr,
        "analysis": analysis,
        "playbook": playbook_for(incident),
        "agent": ev.get("server"),
    }
    notify(result)
    result["actions"] = policy_engine(result, "", dry_run=DRY_RUN)
    return result


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze-alert")
def analyze_alert(payload: dict):
    """Nhan schema phang tu Wazuh Integrator."""
    ev = from_soc_flat(payload)
    return _pipeline(ev)
