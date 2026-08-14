"""Policy Engine de xuat hanh dong an toan.

Nguyen tac:
- < 40 (Low): chi ghi log (notifier da lo).
- 40-79: gui canh bao (notifier da lo), khong tu dong hanh dong.
- >= 80 (Critical) VA IP ngoai whitelist: de xuat block IP tam thoi.
- Hanh dong manh (xoa user, sua config, restart) KHONG BAO GIO tu dong.
"""
import os
import json
import ipaddress
import subprocess

_WL_PATH = os.getenv("WHITELIST_PATH", "data/whitelist.json")


def _load_wl():
    try:
        with open(_WL_PATH) as f:
            return json.load(f)
    except Exception:
        return {"ips": []}


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _ssh_action(script: str, arg: str, dry_run: bool = True):
    """De xuat lenh co dinh tren VM1 qua SSH. Validate arg truoc."""
    if not _valid_ip(arg):
        return {"action": script, "status": "rejected", "reason": "invalid ip"}

    key = os.getenv("VM1_KEY", "~/.ssh/soc_action_key")
    host = os.getenv("VM1_HOST", "soc-responder@192.168.245.10")
    cmd = [
        "ssh", "-i", os.path.expanduser(key),
        "-o", "StrictHostKeyChecking=accept-new",
        host, "sudo", f"/usr/local/bin/{script}", arg,
    ]
    if dry_run:
        return {"action": script, "status": "proposed", "cmd": " ".join(cmd)}
    try:
        subprocess.run(cmd, timeout=10, check=False)
        return {"action": script, "status": "executed", "target": arg}
    except Exception as e:
        return {"action": script, "status": "error", "error": str(e)}


def policy_engine(result: dict, agent_ip: str = "", dry_run: bool = True):
    """Tra ve danh sach hanh dong da/duoc de xuat. dry_run=True de demo an toan."""
    s = result["risk_score"]
    ip = result.get("srcip")
    wl = _load_wl()
    actions = []

    if s < 40:
        actions.append({"action": "log_only", "status": "done"})
        return actions

    # Medium/High: chi canh bao + (High) tao incident
    if s >= 60:
        actions.append({"action": "create_incident_report", "status": "done"})

    # Critical + IP ngoai whitelist: block tam thoi
    if s >= 80 and ip and ip not in wl.get("ips", []):
        actions.append(_ssh_action("block_ip_temp.sh", ip, dry_run=dry_run))
        actions.append({"action": "require_admin_confirmation",
                        "note": "Hanh dong manh can admin xac nhan"})
    return actions
