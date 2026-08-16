#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="/home/ubuntu/vms-analyzer"

if [[ "$(hostname 2>/dev/null || true)" != "vms-analyzer" ]]; then
  printf '[ERROR] Script này chỉ chạy trên VM3 vms-analyzer.\n' >&2
  exit 2
fi

printf '\n============================================================\n'
printf 'REPLAY ONLY — KHÔNG PHẢI LUỒNG LIVE, KHÔNG DÙNG LÀM ẢNH E2E\n'
printf 'Mục đích: kiểm thử riêng logic correlation Network -> Web -> OS.\n'
printf '============================================================\n'

cd "$PROJECT_DIR"
sudo systemctl restart vms-analyzer
for attempt in $(seq 1 10); do
  curl -fsS --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:8000/health

post_sample() {
  local sample="$1"
  printf '\n--- REPLAY %s ---\n' "$sample"
  curl -fsS -X POST http://127.0.0.1:8000/analyze-alert \
    -H 'Content-Type: application/json' \
    --data-binary "@data/samples/${sample}" | python3 -m json.tool
}

post_sample network_port_scan.json
post_sample nginx_traversal_attempt.json
post_sample webroot_modified.json

printf '\n[EXPECTED] Event cuối là Possible Server Compromise với sources network, web, os.\n'
