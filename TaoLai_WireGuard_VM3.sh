#!/usr/bin/env bash
# Rebuild a single-client WireGuard configuration for the copied VM3 lab.
# Run on VM3 with sudo. It never writes a client private key or Gotify token.
set -Eeuo pipefail

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_ADDRESS="${WG_ADDRESS:-10.66.0.1/24}"
WG_PORT="${WG_PORT:-51820}"
WG_CLIENT_ALLOWED_IP="${WG_CLIENT_ALLOWED_IP:-10.66.0.2/32}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"

if [[ "${EUID}" -ne 0 ]]; then
  printf '[ERROR] Chạy script bằng sudo. Ví dụ: sudo ./TaoLai_WireGuard_VM3.sh\n' >&2
  exit 1
fi

for command in wg systemctl mktemp; do
  command -v "$command" >/dev/null || {
    printf '[ERROR] Thiếu lệnh: %s\n' "$command" >&2
    exit 1
  }
done

printf '%s\n' '[WARNING] Script thay toàn bộ peer WireGuard cũ trên VM3 bằng một Windows client mới.'
printf '%s\n' '[INPUT] Chỉ dán PUBLIC KEY của WireGuard Windows client; không dán PrivateKey.'
read -r -p "Dán PUBLIC KEY của WireGuard Windows client: " CLIENT_PUBLIC_KEY

if [[ ! "$CLIENT_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
  printf '[ERROR] Public key WireGuard không đúng định dạng. Hủy, không thay đổi cấu hình.\n' >&2
  exit 2
fi

install -d -m 700 /etc/wireguard
if [[ -f "$WG_CONFIG" ]]; then
  backup="${WG_CONFIG}.before-rebuild-$(date +%Y%m%d-%H%M%S)"
  cp -a "$WG_CONFIG" "$backup"
  printf '[OK] Backup: %s\n' "$backup"
fi

systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true

umask 077
SERVER_PRIVATE_KEY="$(wg genkey)"
SERVER_PUBLIC_KEY="$(printf '%s' "$SERVER_PRIVATE_KEY" | wg pubkey)"
temporary_config="$(mktemp "/etc/wireguard/.${WG_INTERFACE}.conf.XXXXXX")"

printf "[Interface]\nAddress = %s\nListenPort = %s\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n" \
  "$WG_ADDRESS" "$WG_PORT" "$SERVER_PRIVATE_KEY" "$CLIENT_PUBLIC_KEY" "$WG_CLIENT_ALLOWED_IP" \
  > "$temporary_config"
chmod 600 "$temporary_config"
mv -f "$temporary_config" "$WG_CONFIG"

printf '%s\n' "$SERVER_PUBLIC_KEY" > /etc/wireguard/server-public.key
chmod 600 /etc/wireguard/server-public.key

if ! systemctl restart "wg-quick@${WG_INTERFACE}"; then
  printf '[ERROR] WireGuard chưa khởi động. Xem lỗi bằng: sudo systemctl status wg-quick@%s --no-pager -l\n' "$WG_INTERFACE" >&2
  exit 3
fi

printf '\n[OK] WireGuard server đã active. Public key server mới:\n%s\n' "$SERVER_PUBLIC_KEY"
printf '\n[WINDOWS CLIENT]\n'
printf 'Address = %s\n' "${WG_CLIENT_ALLOWED_IP%/32}/24"
printf 'Peer PublicKey = <dán public key server ở trên>\n'
printf 'AllowedIPs = %s\n' "${WG_ADDRESS%/24}/32"
printf 'Endpoint = <IP Bridged ens38 của VM3>:%s\n' "$WG_PORT"
printf 'PersistentKeepalive = 25\n'
printf '\n[VERIFY] Bật tunnel Windows, rồi trên VM3 chạy: sudo wg show %s\n' "$WG_INTERFACE"
