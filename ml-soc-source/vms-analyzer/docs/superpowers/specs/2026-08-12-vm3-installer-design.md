# Thiết kế script cài đặt VM3 CD2

## Mục tiêu

Thêm `install_vm3_cd2.sh` để triển khai lặp lại được VM3 `vms-analyzer` từ
source đã chép vào `/home/ubuntu/vms-analyzer`. Script thay thế các lệnh cài
Analyzer/ML/service rời rạc và hỗ trợ cài WireGuard + Gotify tự host cho lab.
Không ghi token, private key hoặc IP DHCP Bridged cố định vào source.

## Giao diện chạy

```bash
sudo ./install_vm3_cd2.sh 192.168.245.20 ens33 ens34 ens35
```

Tham số lần lượt là IP VM2, NIC Host-only, NIC NAT và NIC Bridged. Giá trị lab
hiện tại là `.20`, `ens33`, `ens34`, `ens35`; script kiểm tra sự tồn tại của NIC
trước khi thay cấu hình.

## Phần tự động

1. Cài dependency hệ thống cần thiết cho Python, WireGuard, UFW và Gotify.
2. Đặt hostname `vms-analyzer`; ghi Netplan độc lập cho NIC Bridged với
   `dhcp4: true` và `route-metric: 200`, để default route vẫn ưu tiên NAT.
3. Tạo `.venv`, cài `requirements.txt`, khởi tạo `.env` từ `.env.example`,
   dùng baseline 13 mẫu, train/evaluate model và chạy test hiện có.
4. Tạo/bật `vms-analyzer.service` chỉ lắng nghe HTTP 8000 trong mạng lab.
5. Sinh private/public key WireGuard ở `/etc/wireguard` với quyền hạn chế,
   tạo `wg0`, Gotify service và UFW rules tối thiểu.

## Điểm dừng nhập thủ công

Script hỏi theo thứ tự và không echo dữ liệu nhạy cảm:

1. Public key WireGuard của máy Admin (public, có thể hiển thị).
2. IPv4 Wi-Fi/LAN của máy Admin để giới hạn UFW UDP 51820.
3. Sau khi tunnel hoạt động và Admin tạo application trong Gotify, application
   token. Token được nhập ẩn, chỉ ghi vào `.env` quyền `0600`, không in ra màn
   hình.

Script tự phát hiện IPv4 DHCP của NIC Bridged và in nó như WireGuard endpoint.
Không dùng `192.168.245.30` làm endpoint cho máy thật khác.

## Luồng và an toàn

```text
VM2 (.20) -> VM3 HTTP 8000 -> Analyzer/ML -> Gotify 10.66.0.1:8080
Admin -- WireGuard UDP 51820 qua IP Bridged VM3 --> Gotify
```

Gotify chỉ bind `10.66.0.1:8080`; UFW không mở port 8080 qua Host-only, NAT
hoặc Bridged. `DRY_RUN=true` giữ nguyên. Nếu thiếu input thủ công, script dừng
với chỉ dẫn tiếp tục, không tạo peer rỗng hay tắt firewall đang hoạt động.

## Xác minh sau cài

Script chạy các kiểm tra: service `vms-analyzer`, `wg-quick@wg0`, `gotify` là
active; `/health` trả JSON; `verify_deployment.py` thành công; Gotify chỉ nghe
trên `10.66.0.1:8080`; và `wg show` có peer nhưng không in private key.

## Cập nhật tài liệu

`KichBan_CaiDat_CD2.md` sẽ thay phần lệnh rời của Cảnh 1--4 bằng một lệnh chạy
script, sau đó chỉ giữ ba thao tác nhập thủ công và các lệnh kiểm tra có ý nghĩa
khi quay video.
