"""Chuan hoa alert bao mat tu Wazuh/Suricata/Nginx ve envelope thong nhat.

Envelope:
{
  source, timestamp, server, alert_type, severity,
  description, related_ip, raw
}
"""
import json
import os

_HOST_MAP_PATH = os.getenv("HOST_MAP_PATH", "data/host_map.json")
try:
    with open(_HOST_MAP_PATH) as f:
        HOST_MAP = json.load(f)   # {"192.168.245.10": "vms-production", ...}
except Exception:
    HOST_MAP = {}


def _sev(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"

def _is_network_alert(description: str, full_log: str, location: str = "") -> bool:
    text = f"{description} {full_log} {location}".lower()
    return (
        "suricata" in text
        or "eve.json" in text
        or "event_type\":\"alert" in text
        or "et scan" in text
        or "nmap" in text
    )


def _is_web_alert(description: str, full_log: str, location: str = "") -> bool:
    text = f"{description} {full_log} {location}".lower()
    return (
        "nginx" in text
        or "access.log" in text
        or "http/1." in text
        or "web:" in text
        or "/.env" in text
        or "/.git" in text
        or "phpmyadmin" in text
    )


def _is_auth_alert(description: str, full_log: str, location: str = "") -> bool:
    text = f"{description} {full_log} {location}".lower()
    return "ssh" in text or "sshd" in text or "auth.log" in text or "authentication" in text


def _source_for(description: str, full_log: str, location: str = "") -> str:
    if _is_network_alert(description, full_log, location):
        return "network"
    if _is_web_alert(description, full_log, location):
        return "web"
    if _is_auth_alert(description, full_log, location):
        return "auth"
    return "os"


def _srcip_from_json_log(full_log: str):
    try:
        data = json.loads(full_log)
    except Exception:
        return None
    return data.get("src_ip") or data.get("srcip")


def from_soc_flat(p: dict) -> dict:
    """Nhan schema phang ma Wazuh Integrator gui (giu tuong thich code da test)."""
    description = p.get("rule_description", "")
    full_log = p.get("full_log", "")
    location = p.get("location", "")
    return {
        "source": _source_for(description, full_log, location),
        "timestamp": p.get("timestamp", ""),
        "server": p.get("agent_name") or HOST_MAP.get(p.get("agent_ip", ""), p.get("agent_ip", "")),
        "alert_type": description,
        "severity": _sev(p.get("rule_level", 0)),
        "description": description,
        "related_ip": p.get("srcip") or _srcip_from_json_log(full_log),
        "raw": {
            "rule_id": str(p.get("rule_id", "")),
            "rule_level": p.get("rule_level", 0),
            "mitre_id": p.get("mitre_id", []),
            "full_log": full_log,
            "srcuser": p.get("srcuser", ""),
            "location": location,
        },
    }


def from_wazuh(p: dict) -> dict:
    """Nhan alert JSON day du tu /var/ossec/logs/alerts/alerts.json (neu dung cach do)."""
    rule = p.get("rule", {})
    data = p.get("data", {})
    agent = p.get("agent", {})
    description = rule.get("description", "")
    full_log = p.get("full_log", "")
    location = p.get("location", "")
    return {
        "source": _source_for(description, full_log, location),
        "timestamp": p.get("timestamp", ""),
        "server": agent.get("name") or HOST_MAP.get(agent.get("ip", ""), agent.get("ip", "")),
        "alert_type": description,
        "severity": _sev(rule.get("level", 0)),
        "description": description,
        "related_ip": data.get("srcip") or data.get("src_ip") or _srcip_from_json_log(full_log),
        "raw": {
            "rule_id": str(rule.get("id", "")),
            "rule_level": rule.get("level", 0),
            "mitre_id": rule.get("mitre", {}).get("id", []),
            "full_log": full_log,
            "location": location,
        },
    }
