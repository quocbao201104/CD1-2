"""Risk scoring + nguong + MITRE mapping. Deterministic, khong phu thuoc AI."""
from datetime import datetime
import re

BASE = {
    "SSH Brute Force": 30,
    "Valid Login After Brute Force": 70,
    "Account File Modified": 40,
    "SSH Key Backdoor": 50,
    "Privilege Escalation": 60,
    "Suspicious User Creation": 40,
    "Network Port Scan": 30,
    "Web Sensitive Path Scan": 35,
    "Web Traversal Attempt": 50,
    "Web Root Modified": 60,
    "Suspicious Web File": 70,
    "Possible Server Compromise": 90,
    "Unknown": 10,
}

MITRE = {
    "SSH Brute Force": "T1110 - Brute Force",
    "Valid Login After Brute Force": "T1078 - Valid Accounts",
    "Account File Modified": "T1136 - Create Account",
    "SSH Key Backdoor": "T1098 - Account Manipulation",
    "Privilege Escalation": "T1548 - Abuse Elevation Control Mechanism",
    "Suspicious User Creation": "T1136 - Create Account",
    "Network Port Scan": "T1046 - Network Service Discovery",
    "Web Sensitive Path Scan": "T1595 - Active Scanning",
    "Web Traversal Attempt": "T1190 - Exploit Public-Facing Application",
    "Web Root Modified": "T1491 - Defacement",
    "Suspicious Web File": "T1505.003 - Web Shell",
    "Possible Server Compromise": "T1190/T1505.003/T1548 - Web Exploit / Web Shell / Privilege Escalation",
    "Unknown": "N/A",
}


def is_off_hours(ts):
    try:
        normalized = ts.replace("Z", "+00:00")
        normalized = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", normalized)
        h = datetime.fromisoformat(normalized).hour
        return h < 7 or h >= 19
    except Exception:
        return False


def score(incident, srcip, ts, whitelist):
    """Scoring co ban cho 1 alert bao mat truyen thong."""
    s = BASE.get(incident, 10)
    if srcip and srcip not in whitelist.get("ips", []):
        s += 20
    if is_off_hours(ts):
        s += 20
    return min(s, 100)


def score_envelope(ev, incident, corr, whitelist):
    """Scoring cho envelope da chuan hoa, cong diem tuong quan neu co."""
    s = BASE.get(incident, 10)
    ip = ev.get("related_ip")
    if ip and ip not in whitelist.get("ips", []):
        s += 20
    if is_off_hours(ev.get("timestamp", "")):
        s += 20
    if corr:
        s = max(s, BASE["Possible Server Compromise"])
        s += 10
    return min(s, 100)


def severity_of(s):
    if s >= 80:
        return "Critical"
    if s >= 60:
        return "High"
    if s >= 40:
        return "Medium"
    return "Low"
