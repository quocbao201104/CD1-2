#!/usr/bin/env bash
set -Eeuo pipefail

VM1_IP="192.168.245.10"
VM2_IP="192.168.245.20"
VM3_IP="192.168.245.30"
KALI_IP="192.168.245.157"
FIM_MARKER="/var/www/html/shell.php"
FIM_BACKUP="/tmp/index.html.before-soc-demo"
FIM_PATH_FILE="/tmp/cd1-demo-index.path"
ACCOUNT_USER="socdemo_user"
ACCOUNT_KEY_PRIV="/tmp/soc_demo_key"
ACCOUNT_KEY_PUB="/tmp/soc_demo_key.pub"
ACCOUNT_AUTH_KEYS="/root/.ssh/authorized_keys"
ACCOUNT_AUTH_BACKUP="/tmp/authorized_keys.before-soc-demo"
ACCOUNT_AUTH_CREATED="/tmp/authorized_keys.created-by-soc-demo"

title() {
  printf '\n============================================================\n%s\n============================================================\n' "$1"
}

detect_role() {
  case "$(hostname 2>/dev/null || true)" in
    vms-production) printf 'vm1\n' ;;
    vms-soc) printf 'vm2\n' ;;
    vms-analyzer) printf 'vm3\n' ;;
    *)
      if grep -qi '^ID=kali' /etc/os-release 2>/dev/null; then
        printf 'kali\n'
      else
        printf 'unknown\n'
      fi
      ;;
  esac
}

require_role() {
  local current="$1"
  shift
  local allowed
  for allowed in "$@"; do
    [[ "$current" == "$allowed" ]] && return 0
  done
  printf '[ERROR] Stage này không dành cho vai trò %s. Vai trò hợp lệ: %s\n' "$current" "$*" >&2
  exit 2
}

usage() {
  cat <<'EOF'
Sử dụng: ./ThucThi_Demo_CD1.sh <stage>

Chạy đúng stage trên đúng máy:
  preflight  Kali/VM1/VM2  - IP, ping và dịch vụ chính
  config     Kali/VM1/VM2  - gói và cấu hình quan trọng
  benign     Kali          - truy cập Web hợp lệ
  network    Kali          - quét cổng trong lab
  web        Kali          - sensitive path và traversal attempt
  auth       Kali          - 8 lần SSH thất bại có kiểm soát
  account    VM1           - tạo tài khoản mẫu
  sshkey     VM1           - thay đổi authorized_keys mẫu
  sudo       VM1           - lệnh quyền cao/auditd
  fim        VM1           - thay đổi Web root và tạo marker an toàn
  evidence   VM1/VM2       - đối chiếu raw log và Wazuh alert
  cleanup    VM1           - phục hồi Web root sau demo

Mục tiêu cố định của thao tác kiểm thử: 192.168.245.10 trong VMnet1 lab.
EOF
}

show_service() {
  local service="$1"
  printf '%-14s: ' "$service"
  systemctl is-active "$service" 2>/dev/null || true
}

stage_preflight() {
  local role="$1"
  require_role "$role" kali vm1 vm2
  title "CD1 PREFLIGHT - role=$role"
  hostname
  ip -br -4 addr

  case "$role" in
    kali)
      printf '\n[Kết nối VMnet1 từ Kali %s]\n' "$KALI_IP"
      ping -c 2 -W 2 "$VM1_IP"
      ping -c 2 -W 2 "$VM2_IP"
      ;;
    vm1)
      printf '\n[Dịch vụ bảo vệ VM1]\n'
      for service in nginx suricata wazuh-agent auditd ssh; do show_service "$service"; done
      curl -fsSI --max-time 5 http://127.0.0.1/ | head -n 1
      ping -c 2 -W 2 "$VM2_IP"
      ;;
    vm2)
      printf '\n[Wazuh trên VM2]\n'
      for service in wazuh-manager wazuh-indexer wazuh-dashboard ssh; do show_service "$service"; done
      sudo /var/ossec/bin/agent_control -l
      ping -c 2 -W 2 "$VM1_IP"
      ;;
  esac
}

stage_config() {
  local role="$1"
  require_role "$role" kali vm1 vm2
  title "CD1 CẤU HÌNH QUAN TRỌNG - role=$role"

  case "$role" in
    kali)
      printf '[Công cụ kiểm thử đã cài]\n'
      for tool in nmap curl hydra nc sshpass jq; do
        if command -v "$tool" >/dev/null 2>&1; then
          printf '%-10s %s\n' "$tool" "$(command -v "$tool")"
        else
          printf '%-10s MISSING\n' "$tool"
        fi
      done
      nmap --version | head -n 1
      hydra -h 2>&1 | head -n 1 || true
      ;;
    vm1)
      printf '[Suricata HOME_NET và interface]\n'
      sudo grep -nE 'HOME_NET|af-packet:|interface:' /etc/suricata/suricata.yaml | head -n 12
      printf '\n[Wazuh Agent: Manager, Nginx, Suricata và FIM]\n'
      sudo grep -nE '<address>|access\.log|error\.log|eve\.json|authorized_keys|/root/\.ssh|/etc/passwd|/etc/sudoers|/var/www/html|<directories' /var/ossec/etc/ossec.conf | head -n 20
      printf '\n[Audit rule phục vụ demo]\n'
      sudo grep -RInE 'root_cmd|/var/www/html' /etc/audit/rules.d 2>/dev/null | head -n 10 || true
      ;;
    vm2)
      printf '[Agent đang được Manager quản lý]\n'
      sudo /var/ossec/bin/agent_control -l
      printf '\n[Local rules trọng tâm]\n'
      sudo grep -nE 'rule id="100100"|rule id="100102"|rule id="100103"|rule id="100104"|rule id="100105"|rule id="100106"|rule id="100200"|rule id="100201"|rule id="100202"|rule id="100203"|<description>|<mitre>' /var/ossec/etc/rules/local_rules.xml
      ;;
  esac
}

stage_benign() {
  local role="$1"
  require_role "$role" kali
  title 'CD1 HOẠT ĐỘNG HỢP LỆ - KALI TRUY CẬP TRANG CHỦ'
  curl -sS -D - -o /dev/null -A 'soc-lab-benign/1.0' "http://${VM1_IP}/"
  printf '\n[PASS] Web hợp lệ đã trả phản hồi. Chuyển sang PC2 để quay SSH quản trị hợp lệ.\n'
}

stage_network() {
  local role="$1"
  require_role "$role" kali
  title 'CD1 NETWORK - NMAP TRONG LAB ĐƯỢC PHÉP'
  printf 'Nguồn dự kiến: %s | Đích cố định: %s\n' "$KALI_IP" "$VM1_IP"
  sudo nmap -sS -sV -T4 -p 1-1000 "$VM1_IP"
  sudo nmap -sS -T4 --script http-title,http-headers,ssh-hostkey -p 22,80 "$VM1_IP"
  printf '[NOTE] Trên VM2, chỉ alert chứa ET SCAN/Nmap mới được rule 100106 nâng lên level 10 để forward sang VM3.\n'
}

stage_web() {
  local role="$1"
  require_role "$role" kali
  title 'CD1 WEB - PROBING VÀ TRAVERSAL ATTEMPT'
  for path in '/.env' '/.git/config' '/admin' '/phpmyadmin' '/wp-login.php'; do
    curl -sS -o /dev/null -w "${path} -> HTTP %{http_code}\n" "http://${VM1_IP}${path}"
  done
  curl --path-as-is -sS -o /dev/null -w 'traversal encoded -> HTTP %{http_code}\n' \
    "http://${VM1_IP}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  printf '[NOTE] Mã 400/404 vẫn là bằng chứng nỗ lực; không kết luận khai thác thành công.\n'
}

stage_auth() {
  local role="$1"
  require_role "$role" kali
  title 'CD1 AUTH - 8 LẦN SSH THẤT BẠI CÓ KIỂM SOÁT'
  command -v sshpass >/dev/null 2>&1 || { printf '[ERROR] Cần cài sshpass trên Kali.\n' >&2; exit 3; }
  set +e
  for attempt in $(seq 1 8); do
    printf 'Attempt %s/8\n' "$attempt"
    sshpass -p 'wrongpass-demo-only' ssh \
      -o StrictHostKeyChecking=no \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=4 \
      wronguser@"$VM1_IP" 'whoami' >/dev/null 2>&1
  done
  set -e
  printf '[PASS] Đã tạo 8 sự kiện đăng nhập thất bại; không thử tài khoản/mật khẩu thật.\n'
}

stage_account() {
  local role="$1"
  require_role "$role" vm1
  title 'CD1 ACCOUNT - TẠO TÀI KHOẢN MẪU'
  if id "$ACCOUNT_USER" >/dev/null 2>&1; then
    sudo userdel -r "$ACCOUNT_USER" >/dev/null 2>&1 || true
  fi
  sudo useradd -m -s /bin/bash "$ACCOUNT_USER"
  getent passwd "$ACCOUNT_USER"
  sudo tail -n 40 /var/log/auth.log | grep -E "useradd|new user|adduser|${ACCOUNT_USER}" || true
  printf '[WAIT] Chờ 20 giây để Wazuh ghi nhận sự kiện tài khoản...\n'
  sleep 20
}

stage_sshkey() {
  local role="$1"
  require_role "$role" vm1
  title 'CD1 SSH AUTHORIZED_KEYS - THAY ĐỔI KHÓA MẪU'
  sudo mkdir -p /root/.ssh
  sudo chmod 700 /root/.ssh
  if [[ ! -e "$ACCOUNT_AUTH_BACKUP" && -f "$ACCOUNT_AUTH_KEYS" ]]; then
    sudo cp -a "$ACCOUNT_AUTH_KEYS" "$ACCOUNT_AUTH_BACKUP"
  elif [[ ! -f "$ACCOUNT_AUTH_KEYS" ]]; then
    sudo rm -f "$ACCOUNT_AUTH_CREATED"
    sudo touch "$ACCOUNT_AUTH_CREATED"
  fi
  sudo rm -f "$ACCOUNT_KEY_PRIV" "$ACCOUNT_KEY_PUB"
  sudo ssh-keygen -q -t ed25519 -N '' -C 'soc-demo-key' -f "$ACCOUNT_KEY_PRIV"
  sudo sh -c "cat '$ACCOUNT_KEY_PUB' >> '$ACCOUNT_AUTH_KEYS'"
  sudo chmod 600 "$ACCOUNT_AUTH_KEYS"
  sudo stat "$ACCOUNT_AUTH_KEYS"
  sudo tail -n 3 "$ACCOUNT_AUTH_KEYS"
  printf '[WAIT] Chờ 25 giây để Wazuh FIM ghi nhận authorized_keys...\n'
  sleep 25
}

stage_sudo() {
  local role="$1"
  require_role "$role" vm1
  title 'CD1 PRIVILEGED COMMANDS - SUDO/LỆNH QUYỀN CAO'
  sudo id
  sudo stat /etc/shadow
  sudo ausearch -k root_cmd -ts recent | tail -n 40 || true
  printf '[WAIT] Chờ 20 giây để auditd/Wazuh xử lý lệnh quyền cao...\n'
  sleep 20
}

stage_fim() {
  local role="$1"
  require_role "$role" vm1
  title 'CD1 FIM - THAY ĐỔI WEB ROOT ĐƯỢC PHÉP'
  local web_index
  web_index="$(find /var/www/html -maxdepth 1 -type f -name 'index*.html' -print | head -n 1)"
  [[ -n "$web_index" ]] || { printf '[ERROR] Không tìm thấy index*.html trong /var/www/html.\n' >&2; exit 4; }

  if [[ ! -e "$FIM_BACKUP" ]]; then
    sudo cp -a "$web_index" "$FIM_BACKUP"
    printf '%s\n' "$web_index" | sudo tee "$FIM_PATH_FILE" >/dev/null
  fi
  printf '%s\n' '<h1>SOC LAB - FIM CHANGE MARKER</h1>' | sudo tee "$web_index" >/dev/null
  printf '%s\n' 'SOC-LAB-SUSPICIOUS-FILE-MARKER' | sudo tee "$FIM_MARKER" >/dev/null
  sudo stat "$web_index" "$FIM_MARKER"
  printf '[WAIT] Chờ 25 giây để Wazuh FIM xử lý sự kiện...\n'
  sleep 25
}

stage_evidence() {
  local role="$1"
  require_role "$role" vm1 vm2
  title "CD1 BẰNG CHỨNG - role=$role"
  case "$role" in
    vm1)
      printf '[Nginx requests mới nhất]\n'
      sudo tail -n 15 /var/log/nginx/access.log
      printf '\n[Suricata alert mới nhất]\n'
      sudo grep '"event_type":"alert"' /var/log/suricata/eve.json | tail -n 8 || true
      printf '\n[Tài khoản mới / authorized_keys / sudo]\n'
      sudo stat /root/.ssh/authorized_keys /etc/shadow 2>/dev/null || true
      sudo grep -Ei 'useradd|adduser|socdemo_user|authorized_keys|sudo|root_cmd' /var/log/auth.log | tail -n 20 || true
      sudo ausearch -k root_cmd -ts recent | tail -n 20 || true
      printf '\n[SSH thất bại mới nhất]\n'
      sudo grep -Ei 'Failed password|Invalid user' /var/log/auth.log | tail -n 10 || true
      ;;
    vm2)
      printf '[Wazuh alert theo rule demo]\n'
      sudo grep -E '"id":"(100100|100102|100103|100104|100105|100106|100200|100201|100202|100203)"' \
        /var/ossec/logs/alerts/alerts.json | tail -n 20 || true
      printf '\nDashboard filter:\n'
      printf 'agent.name:vms-production AND rule.id:(100100 OR 100102 OR 100103 OR 100104 OR 100105 OR 100106 OR 100200 OR 100201 OR 100202 OR 100203)\n'
      ;;
  esac
}

stage_cleanup() {
  local role="$1"
  require_role "$role" vm1
  title 'CD1 CLEANUP - PHỤC HỒI WEB ROOT'
  if id "$ACCOUNT_USER" >/dev/null 2>&1; then
    sudo userdel -r "$ACCOUNT_USER" || true
  fi
  if [[ -f "$ACCOUNT_AUTH_BACKUP" ]]; then
    sudo cp -a "$ACCOUNT_AUTH_BACKUP" "$ACCOUNT_AUTH_KEYS"
    sudo rm -f "$ACCOUNT_AUTH_BACKUP"
  elif [[ -f "$ACCOUNT_AUTH_CREATED" ]]; then
    sudo rm -f "$ACCOUNT_AUTH_KEYS"
  fi
  sudo rm -f "$ACCOUNT_AUTH_CREATED" "$ACCOUNT_KEY_PRIV" "$ACCOUNT_KEY_PUB"
  if [[ -f "$FIM_BACKUP" && -f "$FIM_PATH_FILE" ]]; then
    local web_index
    web_index="$(sudo cat "$FIM_PATH_FILE")"
    sudo cp -a "$FIM_BACKUP" "$web_index"
    sudo rm -f "$FIM_BACKUP" "$FIM_PATH_FILE"
    printf '[OK] Đã phục hồi %s\n' "$web_index"
  else
    printf '[INFO] Không có backup FIM cần phục hồi.\n'
  fi
  sudo rm -f "$FIM_MARKER"
  curl -fsSI --max-time 5 http://127.0.0.1/ | head -n 1
}

main() {
  local stage="${1:-help}"
  local role
  role="$(detect_role)"
  case "$stage" in
    preflight) stage_preflight "$role" ;;
    config) stage_config "$role" ;;
    benign) stage_benign "$role" ;;
    network) stage_network "$role" ;;
    web) stage_web "$role" ;;
    auth) stage_auth "$role" ;;
    account) stage_account "$role" ;;
    sshkey) stage_sshkey "$role" ;;
    sudo) stage_sudo "$role" ;;
    fim) stage_fim "$role" ;;
    evidence) stage_evidence "$role" ;;
    cleanup) stage_cleanup "$role" ;;
    help|-h|--help) usage ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
