#!/usr/bin/env bash
set -Eeuo pipefail

VM1_IP="192.168.245.10"
VM2_IP="192.168.245.20"
VM3_IP="192.168.245.30"
KALI_IP="192.168.245.157"
GOTIFY_URL="http://10.66.0.1:8080"
PROJECT_DIR="/home/ubuntu/vms-analyzer"

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
Sử dụng: ./ThucThi_Demo_CD2.sh <stage>

Chạy đúng stage trên đúng máy:
  preflight   Kali/VM1/VM2/VM3 - IP, kết nối và dịch vụ chính
  config      VM2/VM3          - integration, whitelist, DRY_RUN, Gotify/WireGuard
  model       VM3              - metadata model và baseline
  reset       VM3              - restart Analyzer để xóa correlation buffer
  benign      VM3              - phân tích mẫu SSH hợp lệ từ IP whitelist
  watch       VM3              - theo dõi POST realtime; Ctrl+C để dừng
  live-attack Kali             - traversal thật qua chuỗi CD1 -> CD2
  evidence    VM2/VM3          - alert Wazuh, incident và ML
  tests       VM3              - kiểm tra deployment ngắn gọn

Gotify trên PC2: bật WireGuard rồi mở http://10.66.0.1:8080.
EOF
}

show_service() {
  local service="$1"
  printf '%-18s: ' "$service"
  systemctl is-active "$service" 2>/dev/null || true
}

print_result_summary() {
  python3 -c '
import json
import sys

data = json.load(sys.stdin)
ml = data.get("ml") or {}
correlation = data.get("correlation") or {}
summary = {
    "source": data.get("source"),
    "incident_type": data.get("incident_type"),
    "severity": data.get("severity"),
    "risk_score": data.get("risk_score"),
    "base_risk_score": data.get("base_risk_score"),
    "ml": {
        "model": ml.get("model"),
        "is_anomaly": ml.get("is_anomaly"),
        "anomaly_score": ml.get("anomaly_score"),
        "risk_delta": ml.get("risk_delta"),
    },
    "correlated": data.get("correlated"),
    "correlation_sources": correlation.get("sources"),
    "has_network_precursor": correlation.get("has_network_precursor"),
    "correlation_confidence": correlation.get("confidence"),
    "src_ip_match": correlation.get("src_ip_match"),
    "observed_ips": correlation.get("observed_ips"),
    "actions": data.get("actions"),
}
print(json.dumps(summary, ensure_ascii=False, indent=2))
'
}

stage_preflight() {
  local role="$1"
  require_role "$role" kali vm1 vm2 vm3
  title "CD2 PREFLIGHT - role=$role"
  hostname
  ip -br -4 addr

  case "$role" in
    kali)
      printf '\n[Kali %s đến ba VM]\n' "$KALI_IP"
      for ip in "$VM1_IP" "$VM2_IP" "$VM3_IP"; do ping -c 1 -W 2 "$ip"; done
      curl -fsS --max-time 5 "http://${VM3_IP}:8000/health"
      printf '\n'
      ;;
    vm1)
      for service in nginx suricata wazuh-agent auditd; do show_service "$service"; done
      ping -c 1 -W 2 "$VM2_IP"
      ;;
    vm2)
      for service in wazuh-manager wazuh-indexer wazuh-dashboard; do show_service "$service"; done
      sudo /var/ossec/bin/agent_control -l
      curl -fsS --max-time 5 "http://${VM3_IP}:8000/health"
      printf '\n'
      ;;
    vm3)
      for service in vms-analyzer gotify wg-quick@wg0; do show_service "$service"; done
      curl -fsS --max-time 5 http://127.0.0.1:8000/health
      printf '\n'
      printf '[NIC Host-only/NAT/Bridged/WireGuard]\n'
      ip -br -4 addr show ens33
      ip -br -4 addr show ens34
      ip -br -4 addr show ens38
      ip -br -4 addr show wg0
      ;;
  esac
}

stage_config() {
  local role="$1"
  require_role "$role" vm2 vm3
  title "CD2 CẤU HÌNH QUAN TRỌNG - role=$role"

  case "$role" in
    vm2)
      printf '[Wazuh integration level >= 8 sang VM3]\n'
      sudo grep -nA8 -B2 '<integration>' /var/ossec/etc/ossec.conf
      printf '\n[Integration executable]\n'
      sudo stat -c '%A %U:%G %n' /var/ossec/integrations/custom-ai-soc
      sudo grep -nE 'analyze-alert|hook_url|requests\.post|curl' /var/ossec/integrations/custom-ai-soc | head -n 10 || true
      ;;
    vm3)
      cd "$PROJECT_DIR"
      printf '[Biến môi trường an toàn]\n'
      awk -F= '
        /^DRY_RUN=/{print}
        /^GOTIFY_URL=/{print}
        /^GOTIFY_MIN_RISK=/{print}
        /^GOTIFY_APP_TOKEN=/{print "GOTIFY_APP_TOKEN_SET=" (length($2)>0 ? "yes":"no")}
      ' .env
      printf '\n[Whitelist quản trị hợp lệ]\n'
      python3 -m json.tool data/whitelist.json
      printf '\n[Port chỉ lắng nghe đúng lớp]\n'
      sudo ss -lntup | grep -E ':8000|10\.66\.0\.1:8080|:51820' || true
      printf '\n[WireGuard peers - không hiển thị khóa riêng]\n'
      sudo wg show wg0
      ;;
  esac
}

stage_model() {
  local role="$1"
  require_role "$role" vm3
  title 'CD2 MODEL - ISOLATIONFOREST CỤC BỘ'
  cd "$PROJECT_DIR"
  python3 - <<'PY'
import json
from pathlib import Path

meta = json.loads(Path('data/isolation_forest_metadata.json').read_text(encoding='utf-8'))
report = json.loads(Path('data/evaluation_report.json').read_text(encoding='utf-8'))
baseline = json.loads(Path('data/baseline.json').read_text(encoding='utf-8'))
names = ['network', 'web', 'os', 'auth']
coverage = {name: 0 for name in names}
unique_vectors = {tuple(row) for row in baseline}
for row in baseline:
    for index, name in enumerate(names):
        if row[index] == 1:
            coverage[name] += 1

print('model_type       =', meta.get('model') or meta.get('model_type') or meta.get('algorithm'))
print('feature_count    =', len(meta.get('feature_names', [])) or meta.get('feature_count'))
print('n_estimators     =', meta.get('n_estimators'))
print('baseline_rows    =', len(baseline))
print('baseline_unique  =', len(unique_vectors))
print('baseline_cover   =', coverage)
print('model_file       =', Path('data/isolation_forest.joblib').is_file())
print('evaluation_keys  =', ', '.join(sorted(report.keys())))
PY
}

stage_reset() {
  local role="$1"
  require_role "$role" vm3
  title 'CD2 RESET - RESTART ANALYZER ĐỂ XÓA BUFFER'
  sudo systemctl restart vms-analyzer
  for attempt in $(seq 1 10); do
    curl -fsS --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS http://127.0.0.1:8000/health
}

stage_benign() {
  local role="$1"
  require_role "$role" vm3
  title 'CD2 BENIGN - ĐĂNG NHẬP HỢP LỆ TỪ IP WHITELIST'
  cd "$PROJECT_DIR"
  printf '[INPUT] data/baseline_samples/normal_ssh_login.json\n'
  python3 -m json.tool data/baseline_samples/normal_ssh_login.json
  printf '\n[ANALYZE]\n'
  curl -fsS -X POST http://127.0.0.1:8000/analyze-alert \
    -H 'Content-Type: application/json' \
    --data-binary @data/baseline_samples/normal_ssh_login.json | print_result_summary
  printf '\n[NOTE] Hoạt động hợp lệ vẫn được ghi nhận cục bộ nhưng không đạt ngưỡng gửi Gotify.\n'
}

stage_watch() {
  local role="$1"
  require_role "$role" vm3
  title 'CD2 REALTIME - THEO DÕI ANALYZER (CTRL+C ĐỂ DỪNG)'
  sudo journalctl -fu vms-analyzer --no-pager
}

stage_live_attack() {
  local role="$1"
  require_role "$role" kali
  title 'CD2 LIVE - TRAVERSAL KALI -> VM1 -> VM2 -> VM3'
  curl --path-as-is -i \
    "http://${VM1_IP}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  printf '\n[WAIT] Chờ 20 giây cho Wazuh và integration xử lý...\n'
  sleep 20
}

stage_evidence() {
  local role="$1"
  require_role "$role" vm2 vm3
  title "CD2 BẰNG CHỨNG - role=$role"
  case "$role" in
    vm2)
      printf '[Alert traversal level 10]\n'
      sudo grep '"id":"100201"' /var/ossec/logs/alerts/alerts.json | tail -n 5 || true
      printf '\n[Integration không báo lỗi gần đây]\n'
      sudo grep -Ei 'custom-ai-soc|integrat' /var/ossec/logs/ossec.log | tail -n 15 || true
      printf '\nDashboard filter: agent.name:vms-production AND rule.id:100201\n'
      ;;
    vm3)
      printf '[POST /analyze-alert gần đây]\n'
      sudo journalctl -u vms-analyzer --since '10 minutes ago' --no-pager | \
        grep -E 'POST /analyze-alert|risk|incident|ERROR' | tail -n 30 || true
      printf '\n[Incident mới nhất: classifier + ML + risk + correlation + DRY_RUN]\n'
      tail -n 45 "$PROJECT_DIR/incidents.md"
      printf '\n[CORRELATION SUMMARY - INCIDENT MỚI NHẤT]\n'
      tail -n 60 "$PROJECT_DIR/incidents.md" | \
        grep -E 'Nhãn phân tích:|Mức độ:|Tổng điểm:|Nguồn bằng chứng:|Độ tin cậy:|Liên kết IP nguồn|IP quan sát được:' | \
        tail -n 12 || true
      printf '\n[Gotify qua WireGuard]\n%s\n' "$GOTIFY_URL"
      ;;
  esac
}

stage_tests() {
  local role="$1"
  require_role "$role" vm3
  title 'CD2 VERIFY DEPLOYMENT - BẰNG CHỨNG NGẮN GỌN'
  cd "$PROJECT_DIR"
  if [[ -f .venv/bin/activate ]]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
  elif [[ -f venv/bin/activate ]]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
  fi
  python verify_deployment.py
}

main() {
  local stage="${1:-help}"
  local role
  role="$(detect_role)"
  case "$stage" in
    preflight) stage_preflight "$role" ;;
    config) stage_config "$role" ;;
    model) stage_model "$role" ;;
    reset) stage_reset "$role" ;;
    benign) stage_benign "$role" ;;
    watch) stage_watch "$role" ;;
    live-attack) stage_live_attack "$role" ;;
    evidence) stage_evidence "$role" ;;
    tests) stage_tests "$role" ;;
    help|-h|--help) usage ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
