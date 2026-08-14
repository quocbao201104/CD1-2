#!/bin/bash
# CD1 - Cai dat VM1 endpoint can bao ve (chi SOC/Wazuh)
# Chay tren VM1: sudo bash install_vm1_cd1.sh <IP_VM2> [SURICATA_IFACE] [HOME_NET]
set -e

VM2_IP="${1:?Usage: install_vm1_cd1.sh <IP_VM2> [SURICATA_IFACE] [HOME_NET]}"
SURICATA_IFACE="${2:-}"
HOME_NET="${3:-192.168.245.0/24}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

ensure_wazuh_agent_config() {
  local ossec_conf="/var/ossec/etc/ossec.conf"
  [ -f "$ossec_conf" ] || return 0

  python3 - "$ossec_conf" "$VM2_IP" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
vm2_ip = sys.argv[2]
src = path.read_text(encoding="utf-8", errors="replace")

src = re.sub(
    r"(<client>\s*<server>\s*<address>)(.*?)(</address>)",
    rf"\g<1>{vm2_ip}\3",
    src,
    count=1,
    flags=re.S,
)

fim_entries = [
    '<directories check_all="yes" realtime="yes" whodata="yes">/etc/passwd,/etc/shadow,/etc/sudoers</directories>',
    '<directories check_all="yes" realtime="yes" whodata="yes">/root/.ssh</directories>',
    '<directories check_all="yes" realtime="yes" whodata="yes">/etc/nginx</directories>',
    '<directories check_all="yes" realtime="yes" whodata="yes">/var/www/html</directories>',
    '<directories check_all="yes" realtime="yes" whodata="yes">/home</directories>',
]

if "<syscheck>" in src:
    for entry in fim_entries:
        marker = entry.split(">")[1].split("<")[0]
        if marker not in src:
            src = src.replace("    <ignore>/etc/mtab</ignore>", f"    {entry}\n\n    <ignore>/etc/mtab</ignore>", 1)

localfiles = [
    ("json", "/var/log/suricata/eve.json"),
    ("apache", "/var/log/nginx/access.log"),
    ("syslog", "/var/log/nginx/error.log"),
    ("audit", "/var/log/audit/audit.log"),
]

insert_blocks = []
for log_format, location in localfiles:
    if location not in src:
        insert_blocks.append(
            "  <localfile>\n"
            f"    <log_format>{log_format}</log_format>\n"
            f"    <location>{location}</location>\n"
            "  </localfile>\n"
        )

if insert_blocks:
    src = src.replace("</ossec_config>", "\n" + "\n".join(insert_blocks) + "\n</ossec_config>", 1)

path.write_text(src, encoding="utf-8")
PY
}

configure_nginx_demo() {
  cat > /var/www/html/index.html <<'HTML'
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <title>vms-production - CD1 SOC Lab</title>
</head>
<body>
  <h1>vms-production</h1>
  <p>Nginx demo service for CD1 SOC/Wazuh/Suricata lab.</p>
</body>
</html>
HTML
  chown root:root /var/www/html/index.html
  chmod 0644 /var/www/html/index.html
}

timedatectl set-timezone Asia/Ho_Chi_Minh
hostnamectl set-hostname vms-production

apt update
apt upgrade -y -o Dpkg::Options::="--force-confold"
apt install -y -o Dpkg::Options::="--force-confold" auditd audispd-plugins openssh-server nginx suricata suricata-update curl gnupg apt-transport-https vim htop

systemctl enable --now ssh
systemctl enable --now nginx
systemctl enable --now auditd
configure_nginx_demo

# Suricata IDS cho tang network. Mac dinh HOME_NET theo dai lab VMware Host-only.
if [ -z "$SURICATA_IFACE" ]; then
  SURICATA_IFACE="$(ip -o -4 addr show scope global | awk '{print $2; exit}')"
fi
if [ -n "$SURICATA_IFACE" ]; then
  sed -i "s|^ *HOME_NET:.*|    HOME_NET: \"[$HOME_NET]\"|" /etc/suricata/suricata.yaml
  sed -i "s/interface: eth0/interface: $SURICATA_IFACE/g" /etc/suricata/suricata.yaml
  sed -i "0,/interface: default/s/interface: default/interface: $SURICATA_IFACE/" /etc/suricata/suricata.yaml
  python3 "$SCRIPT_DIR/suricata_eve_config.py" /etc/suricata/suricata.yaml
  if [ -f /etc/default/suricata ]; then
    sed -i "s/^IFACE=.*/IFACE=$SURICATA_IFACE/" /etc/default/suricata || true
    sed -i "s/^RUN=.*/RUN=yes/" /etc/default/suricata || true
  fi
  mkdir -p /etc/suricata/rules
  suricata-update -o /etc/suricata/rules || true
  suricata -T -c /etc/suricata/suricata.yaml -i "$SURICATA_IFACE"
  systemctl enable --now suricata
else
  echo "[WARN] Khong tu detect duoc interface cho Suricata. Chay lai voi tham so [SURICATA_IFACE]."
fi

# Wazuh Agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt update
WAZUH_MANAGER="$VM2_IP" WAZUH_AGENT_NAME="vms-production" apt install -y -o Dpkg::Options::="--force-confold" wazuh-agent
systemctl daemon-reload
systemctl enable --now wazuh-agent
ensure_wazuh_agent_config
systemctl restart wazuh-agent

# Audit rules cho cac kich ban CD1
cp "$SCRIPT_DIR/soc.rules" /etc/audit/rules.d/soc.rules
augenrules --load
systemctl restart auditd

# Khoa version agent de tranh lech version ngoai y muon trong lab
echo "wazuh-agent hold" | dpkg --set-selections

echo "[OK] VM1 CD1 da cai xong."
echo "[OK] Nginx demo page, FIM, Suricata log va Nginx log da duoc them vao Wazuh Agent."
echo "[NEXT] Kiem tra: systemctl status wazuh-agent && tail -f /var/ossec/logs/ossec.log"
