#!/usr/bin/env bash
# CD2 - Cai dat VM3 Local ML Analyzer, WireGuard va Gotify tu host.
# Chay tren VM3:
#   sudo bash install_vm3_cd2.sh <IP_VM2> <HOST_ONLY_IFACE> <NAT_IFACE> <BRIDGED_IFACE>
# Vi du lab:
#   sudo bash install_vm3_cd2.sh 192.168.245.20 ens33 ens34 ens35

set -euo pipefail

INSTALL_MODE="${1:-install}"
if [ "$INSTALL_MODE" = "--resume-gotify" ]; then
  RESUME_GOTIFY=true
else
  RESUME_GOTIFY=false
  VM2_IP="${1:?Usage: install_vm3_cd2.sh <IP_VM2> <HOST_ONLY_IFACE> <NAT_IFACE> <BRIDGED_IFACE>}"
  HOST_ONLY_IFACE="${2:?Thieu HOST_ONLY_IFACE, vi du ens33}"
  NAT_IFACE="${3:?Thieu NAT_IFACE, vi du ens34}"
  BRIDGED_IFACE="${4:?Thieu BRIDGED_IFACE, vi du ens35}"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_USER="${SUDO_USER:-ubuntu}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
PROJECT_DIR="$SCRIPT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"
ENV_FILE="$PROJECT_DIR/.env"
GOTIFY_VERSION="${GOTIFY_VERSION:-3.0.0}"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

if [ "${EUID}" -ne 0 ]; then
  echo "[ERROR] Hay chay script bang sudo."
  exit 1
fi

if ! getent passwd "$TARGET_USER" >/dev/null; then
  echo "[ERROR] Khong tim thay user muc tieu: $TARGET_USER"
  exit 1
fi

if [ "$RESUME_GOTIFY" = false ]; then
  for iface in "$HOST_ONLY_IFACE" "$NAT_IFACE" "$BRIDGED_IFACE"; do
    if ! ip link show dev "$iface" >/dev/null 2>&1; then
      echo "[ERROR] NIC khong ton tai: $iface"
      exit 1
    fi
  done
fi

for required in requirements.txt .env.example train_model.py evaluate_model.py \
  test_offline.py verify_deployment.py data/baseline_vm2_20260722.json app/main.py; do
  if [ ! -f "$PROJECT_DIR/$required" ]; then
    echo "[ERROR] Thieu source bat buoc: $PROJECT_DIR/$required"
    exit 1
  fi
done

is_ipv4() {
  local candidate="$1"
  local -a octets
  IFS='.' read -r -a octets <<< "$candidate"
  [ "${#octets[@]}" -eq 4 ] || return 1
  local octet
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    [ "$octet" -le 255 ] || return 1
  done
}

iface_ipv4() {
  ip -o -4 addr show dev "$1" scope global | awk '{split($4, value, "/"); print value[1]; exit}'
}

write_env_value() {
  local key="$1"
  local value="$2"
  ENV_KEY="$key" ENV_VALUE="$value" python3 - "$ENV_FILE" <<'PY'
import os
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = os.environ["ENV_KEY"]
value = os.environ["ENV_VALUE"]
text = path.read_text(encoding="utf-8")
pattern = rf"^{re.escape(key)}=.*$"
replacement = f"{key}={value}"
if re.search(pattern, text, flags=re.MULTILINE):
    text = re.sub(pattern, replacement, text, count=1, flags=re.MULTILINE)
else:
    text = text.rstrip("\n") + "\n" + replacement + "\n"
path.write_text(text, encoding="utf-8")
PY
}

configure_bridged_netplan() {
  local netplan_file="/etc/netplan/60-bridged.yaml"
  if [ -f "$netplan_file" ]; then
    cp -a "$netplan_file" "$netplan_file.before-cd2-$(date +%Y%m%d-%H%M%S)"
  fi

  cat > "$netplan_file" <<EOF
network:
  version: 2
  ethernets:
    $BRIDGED_IFACE:
      dhcp4: true
      dhcp4-overrides:
        route-metric: 200
EOF
  chmod 0600 "$netplan_file"
  netplan generate
  netplan apply
  networkctl renew "$BRIDGED_IFACE" 2>/dev/null || true
}

configure_analyzer_service() {
  cat > /etc/systemd/system/vms-analyzer.service <<EOF
[Unit]
Description=VM3 Local ML Security Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$TARGET_USER
Group=$TARGET_USER
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false
ReadWritePaths=$PROJECT_DIR

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vms-analyzer
}

wait_for_analyzer_health() {
  local attempt
  # Uvicorn starts asynchronously after systemd reports the unit started.
  # Poll the real HTTP readiness condition for at most 30 seconds.
  for attempt in $(seq 1 30); do
    if curl -fsS -o /dev/null http://127.0.0.1:8000/health; then
      return 0
    fi
    sleep 1
  done
  echo "[ERROR] Analyzer chua san sang sau 30 giay."
  systemctl status vms-analyzer --no-pager -l || true
  return 1
}

configure_wireguard() {
  local client_public_key
  local admin_wifi_ip
  local bridged_ip
  local server_private_key

  read -r -p "Nhap WireGuard client public key cua may Admin: " client_public_key
  if ! [[ "$client_public_key" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "[ERROR] WireGuard public key khong dung dinh dang."
    exit 1
  fi

  read -r -p "Nhap IPv4 Wi-Fi/LAN cua may Admin (de gioi han UFW UDP 51820): " admin_wifi_ip
  if ! is_ipv4 "$admin_wifi_ip"; then
    echo "[ERROR] IPv4 may Admin khong hop le."
    exit 1
  fi

  bridged_ip="$(iface_ipv4 "$BRIDGED_IFACE")"
  if [ -z "$bridged_ip" ]; then
    echo "[ERROR] $BRIDGED_IFACE chua co IPv4 DHCP. Kiem tra VMnet0/Wi-Fi roi chay lai."
    exit 1
  fi

  if [ -e /etc/wireguard/wg0.conf ]; then
    echo "[ERROR] /etc/wireguard/wg0.conf da ton tai. Khong ghi de cau hinh WireGuard cu."
    exit 1
  fi

  install -d -m 0700 /etc/wireguard
  if [ ! -f /etc/wireguard/server.key ]; then
    umask 077
    wg genkey > /etc/wireguard/server.key
    wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
  fi
  chmod 0600 /etc/wireguard/server.key
  chmod 0644 /etc/wireguard/server.pub
  server_private_key="$(cat /etc/wireguard/server.key)"

  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = $server_private_key

[Peer]
PublicKey = $client_public_key
AllowedIPs = 10.66.0.2/32
EOF
  unset server_private_key
  chmod 0600 /etc/wireguard/wg0.conf
  systemctl enable --now wg-quick@wg0

  echo
  echo "[MANUAL] Server public key (dien vao WireGuard client):"
  cat /etc/wireguard/server.pub
  echo "[MANUAL] Endpoint cua may Admin: $bridged_ip:51820"
  echo "[MANUAL] Client Address: 10.66.0.2/24 ; AllowedIPs: 10.66.0.1/32 ; PersistentKeepalive: 25"

  UFW_SSH_SOURCE="$(iface_ipv4 "$HOST_ONLY_IFACE")"
  UFW_SSH_SOURCE="${UFW_SSH_SOURCE%.*}.1"
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow from "$UFW_SSH_SOURCE" to "$(iface_ipv4 "$HOST_ONLY_IFACE")" port 22 proto tcp
  ufw allow from "$VM2_IP" to "$(iface_ipv4 "$HOST_ONLY_IFACE")" port 8000 proto tcp
  ufw allow from "$admin_wifi_ip" to "$bridged_ip" port 51820 proto udp
  ufw allow in on wg0 to 10.66.0.1 port 8080 proto tcp
  ufw --force enable
}

wait_for_wireguard_handshake() {
  local attempt
  echo
  echo "[MANUAL] Cap nhat WireGuard client theo server public key va Endpoint vua in, roi bat tunnel."
  read -r -p "Nhan Enter sau khi da bat tunnel de kiem tra handshake: "
  for attempt in $(seq 1 30); do
    if wg show wg0 latest-handshakes | awk '$2 > 0 {found=1} END {exit !found}'; then
      echo "[OK] WireGuard da co handshake."
      return 0
    fi
    sleep 1
  done
  echo "[ERROR] Khong co WireGuard handshake sau 30 giay."
  echo "[HINT] Kiem tra lai Public Key cua Interface Windows, Endpoint va UFW UDP 51820."
  wg show wg0
  return 1
}

install_gotify() {
  local normalized_version="${GOTIFY_VERSION#v}"
  local archive="/tmp/gotify-linux-amd64.zip"
  local unpack_dir

  unpack_dir="$(mktemp -d /tmp/gotify-unpack.XXXXXX)"
  curl -fsSLo "$archive" "https://github.com/gotify/server/releases/download/v${normalized_version}/gotify-linux-amd64.zip"
  unzip -q -o "$archive" -d "$unpack_dir"
  id -u gotify >/dev/null 2>&1 || useradd --system --home-dir /opt/gotify --shell /usr/sbin/nologin gotify
  install -d -o gotify -g gotify -m 0750 /opt/gotify /opt/gotify/data /etc/gotify
  install -o root -g root -m 0755 "$unpack_dir/gotify-linux-amd64" /opt/gotify/gotify

  cat > /etc/gotify/server.env <<'EOF'
GOTIFY_SERVER_LISTENADDR=10.66.0.1
GOTIFY_SERVER_PORT=8080
EOF
  chown root:gotify /etc/gotify/server.env
  chmod 0640 /etc/gotify/server.env

  cat > /etc/systemd/system/gotify.service <<'EOF'
[Unit]
Description=Gotify notification server
After=network-online.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
User=gotify
Group=gotify
WorkingDirectory=/opt/gotify
EnvironmentFile=/etc/gotify/server.env
ExecStart=/opt/gotify/gotify
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/opt/gotify

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now gotify
}

configure_gotify_token() {
  local gotify_app_token

  echo
  echo "[MANUAL] Bat tunnel tren may Admin, mo http://10.66.0.1:8080, tao application 'SOC Analyzer'."
  echo "[MANUAL] Khong nhap client token; chi nhap application token o prompt tiep theo."
  read -r -s -p "Nhap Gotify application token (an): " gotify_app_token
  echo
  if [ -z "$gotify_app_token" ]; then
    echo "[ERROR] Gotify application token khong duoc de trong."
    exit 1
  fi
  write_env_value "GOTIFY_APP_TOKEN" "$gotify_app_token"
  unset gotify_app_token
  chmod 0600 "$ENV_FILE"
  chown "$TARGET_USER:$TARGET_USER" "$ENV_FILE"
  systemctl restart vms-analyzer
}

final_checks() {
  systemctl is-active vms-analyzer wg-quick@wg0 gotify
  wait_for_analyzer_health
  curl -fsS http://127.0.0.1:8000/health
  ss -ltn '( sport = :8080 )'
  wg show
}

resume_gotify_installation() {
  if ! systemctl is-active --quiet wg-quick@wg0; then
    echo "[ERROR] WireGuard wg0 chua active. Hay bat lai tunnel server truoc khi tiep tuc Gotify."
    exit 1
  fi
  if ! wg show wg0 latest-handshakes | awk '$2 > 0 {found=1} END {exit !found}'; then
    echo "[ERROR] Chua co WireGuard handshake. Khong cai Gotify khi tunnel chua san sang."
    exit 1
  fi

  echo "[RESUME] Cai Gotify, giu nguyen Analyzer va cau hinh WireGuard hien tai..."
  install_gotify
  configure_gotify_token
  echo "[RESUME] Kiem tra cuoi..."
  final_checks
  echo "[OK] Gotify da san sang qua http://10.66.0.1:8080"
}

if [ "$RESUME_GOTIFY" = true ]; then
  resume_gotify_installation
  exit 0
fi

echo "[1/7] Cau hinh hostname va NIC Bridged..."
hostnamectl set-hostname vms-analyzer
configure_bridged_netplan

echo "[2/7] Cai dependency he thong..."
apt update
apt install -y ca-certificates curl unzip ufw wireguard python3 python3-venv python3-pip python3-dev build-essential

echo "[3/7] Tao Python environment va artifact ML..."
install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 0750 "$PROJECT_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$PROJECT_DIR/requirements.txt"
install -o "$TARGET_USER" -g "$TARGET_USER" -m 0600 "$PROJECT_DIR/.env.example" "$ENV_FILE"
install -o "$TARGET_USER" -g "$TARGET_USER" -m 0644 "$PROJECT_DIR/data/baseline_vm2_20260722.json" "$PROJECT_DIR/data/baseline.json"
chown -R "$TARGET_USER:$TARGET_USER" "$VENV_DIR" "$PROJECT_DIR/data"
runuser -u "$TARGET_USER" -- "$VENV_DIR/bin/python" "$PROJECT_DIR/train_model.py"
runuser -u "$TARGET_USER" -- "$VENV_DIR/bin/python" "$PROJECT_DIR/evaluate_model.py"
runuser -u "$TARGET_USER" -- "$VENV_DIR/bin/python" -m unittest discover -s "$PROJECT_DIR/tests" -v
runuser -u "$TARGET_USER" -- "$VENV_DIR/bin/python" "$PROJECT_DIR/test_offline.py"
runuser -u "$TARGET_USER" -- sh -c "cd '$PROJECT_DIR' && '$VENV_DIR/bin/python' verify_deployment.py"

echo "[4/7] Tao Analyzer systemd service..."
configure_analyzer_service
wait_for_analyzer_health
curl -fsS http://127.0.0.1:8000/health

echo "[5/7] Tao WireGuard server va UFW rules..."
configure_wireguard
wait_for_wireguard_handshake

echo "[6/7] Cai Gotify (chi bind trong WireGuard)..."
install_gotify
configure_gotify_token

echo "[7/7] Kiem tra cuoi..."
final_checks
echo "[OK] VM3 CD2 da cai xong. VM2 kiem tra: curl -fsS http://$(iface_ipv4 "$HOST_ONLY_IFACE"):8000/health"
