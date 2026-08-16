# QUY TRÌNH THỰC NGHIỆM VÀ CHỤP ẢNH CHUNG CHO CD1 - CD2

## 1. Mục đích của tài liệu

Tài liệu này dùng để thực hiện các kịch bản bảo mật một lần nhưng thu thập đồng thời hai bộ bằng chứng:

- Chuyên đề 1: chứng minh VM1 sinh log và VM2 Wazuh phát hiện cảnh báo.
- Chuyên đề 2: chứng minh VM3 nhận alert từ VM2, phân loại sự cố, chấm điểm rủi ro, đánh giá bất thường bằng IsolationForest, ghi incident và gửi Gotify tự host theo ngưỡng.

Sau khi hoàn thành từng kịch bản độc lập, Chuyên đề 2 chạy thêm một lượt liên tục `network → web → os` để chứng minh correlation và cảnh báo `Possible Server Compromise`.

## 2. Nguyên tắc bắt buộc

1. Chỉ thực hiện trong môi trường VMware lab do nhóm quản lý.
2. Không xóa log Wazuh, Suricata, Nginx, auditd hoặc `incidents.md` trước khi chụp.
3. Mỗi ảnh phải nhìn thấy thời gian, hostname hoặc địa chỉ IP và nội dung kết quả chính.
4. Không chụp token Gotify, mật khẩu, WireGuard private key hoặc nội dung đầy đủ của `/etc/shadow`.
5. Trước mỗi kịch bản độc lập, chỉ restart dịch vụ VM3 để xóa correlation buffer; không cần restart cả VM1, VM2 hoặc VM3.
6. Không restart VM3 giữa ba bước của lượt correlation cuối.
7. Dữ liệu log và model không bị xóa khi restart `vms-analyzer`; chỉ buffer 10 phút trong RAM được xóa.
8. Việc khôi phục web root, xóa tài khoản mẫu hoặc gỡ SSH key mẫu cũng có thể sinh alert FIM. Hoàn thành dọn dẹp rồi mới restart VM3 để chuyển sang kịch bản tiếp theo.

## 3. Sơ đồ địa chỉ đang sử dụng

### 3.1. Mạng lab trên một máy thật

```text
VMware Host-only      192.168.245.0/24
Kali                  192.168.245.157
VM1 vms-production    192.168.245.10
VM2 vms-soc           192.168.245.20
VM3 vms-analyzer      192.168.245.30
Adapter VMnet1 host   192.168.245.1
```

Tất cả bốn VM chạy trên cùng một máy thật và cùng Virtual Network `VMnet1`. Kali truy cập trực tiếp VM1, VM2 và VM3 qua các địa chỉ Host-only.

Kênh thông báo dùng một tunnel WireGuard riêng, không đi qua Host-only/NAT:

```text
VM3 wg0                  10.66.0.1/24
Máy cá nhân WireGuard    10.66.0.2/24
Gotify                   http://10.66.0.1:8080 (chỉ lắng nghe trên wg0)
```

## 4. Quy ước đặt tên và phân loại ảnh

Tạo ba thư mục lưu ảnh:

```text
Anh_Dung_Chung
Anh_CD1
Anh_CD2
```

Quy ước:

```text
DC_XX_MoTa.png               Ảnh dùng chung cho phần triển khai của cả hai CD
CD1_KBXX_ViTri_MoTa.png      Ảnh kết quả phát hiện của Chuyên đề 1
CD2_KBXX_ViTri_MoTa.png      Ảnh kết quả phân tích đơn lẻ của Chuyên đề 2
CD2_CHAIN_XX_MoTa.png        Ảnh chuỗi correlation cuối của Chuyên đề 2
```

Vị trí đưa vào báo cáo:

- Ảnh `DC_*`: phần mô hình triển khai, cấu hình mạng và kiểm tra trạng thái hệ thống.
- Ảnh `CD1_KB*`: phần kết quả thực nghiệm của Chuyên đề 1, đặt dưới đúng kịch bản tương ứng.
- Ảnh `CD2_KB*`: phần thử nghiệm phân loại, risk scoring và ML cho alert đơn lẻ của Chuyên đề 2.
- Ảnh `CD2_CHAIN*`: phần thử nghiệm correlation `network → web → os` của Chuyên đề 2.

## 5. Chuẩn bị cửa sổ trước khi chạy

Nên chuẩn bị sẵn các cửa sổ sau:

1. Kali terminal.
2. VM1 terminal hoặc SSH trực tiếp tới `192.168.245.10`.
3. VM2 terminal hoặc SSH trực tiếp tới `192.168.245.20`.
4. VM3 terminal hoặc SSH trực tiếp tới `192.168.245.30`.
5. Wazuh Dashboard trên VM2.
6. Gotify client trên máy cá nhân, mở tại `http://10.66.0.1:8080` sau khi WireGuard đã kết nối.

Lệnh SSH trực tiếp trong VMnet1:

```bash
ssh ubuntu@192.168.245.10
ssh ubuntu@192.168.245.20
ssh ubuntu@192.168.245.30
```

Nhập mật khẩu tương tác khi được hỏi; không lưu mật khẩu trong ảnh hoặc file hướng dẫn.

## 6. Kiểm tra ban đầu và chụp ảnh dùng chung

Phần này chỉ làm một lần trước toàn bộ kịch bản.

### 6.1. Trên Kali: kiểm tra IP, route và kết nối VMnet1

```bash
hostname
ip -br -4 addr
ip route
```

Chụp:

```text
[CHỤP DC_01_Kali_IP_Route.png]
Thấy hostname Kali, IP của interface đang dùng và default route.
Vị trí báo cáo: mô hình triển khai/mạng lab của CD1; CD2 có thể dẫn lại cùng ảnh.
```

```bash
ping -c 4 192.168.245.10
```

Chụp:

```text
[CHỤP DC_02_Kali_Ping_VM1.png]
Thấy 0% packet loss hoặc kết quả ping ổn định tới VM1 `192.168.245.10`.
Vị trí báo cáo: kiểm tra kết nối mạng dùng chung.
```

```bash
nc -vz 192.168.245.10 22
nc -vz 192.168.245.20 22
nc -vz 192.168.245.30 22
nc -vz 192.168.245.10 80
```

Chụp:

```text
[CHỤP DC_03_Kali_DichVu_VMnet1.png]
Thấy SSH của VM1, VM2, VM3 và HTTP của VM1 đều mở trong VMnet1.
Vị trí báo cáo: mô hình kết nối nội bộ lab.
```

Kiểm tra Web bình thường:

```bash
curl -i http://192.168.245.10/
```

Chụp:

```text
[CHỤP DC_04_Nginx_BinhThuong.png]
Thấy HTTP 200 và nội dung trang Nginx của vms-production.
Vị trí báo cáo CD1: trạng thái dịch vụ trước kiểm thử.
Vị trí báo cáo CD2: không cần chèn lại; chỉ dẫn rằng dữ liệu nguồn kế thừa CD1.
```

### 6.2. Trên VM1: kiểm tra IP và dịch vụ

```bash
hostname
ip -br -4 addr
date -Iseconds
```

```bash
for service in nginx suricata wazuh-agent auditd ssh; do
  printf '%-14s: ' "$service"
  systemctl is-active "$service"
done
```

Chụp:

```text
[CHỤP DC_05_VM1_IP_DichVu.png]
Thấy hostname vms-production, IP 192.168.245.10 và các dịch vụ active.
Vị trí báo cáo CD1: triển khai VM1.
```

Kiểm tra nguồn log:

```bash
sudo ls -lh /var/log/nginx/access.log /var/log/nginx/error.log
sudo ls -lh /var/log/suricata/eve.json /var/log/audit/audit.log
```

Chụp:

```text
[CHỤP DC_06_VM1_NguonLog.png]
Thấy đủ access.log, error.log, eve.json và audit.log.
Vị trí báo cáo CD1: cấu hình thu thập log.
```

### 6.3. Trên VM2: kiểm tra Wazuh và agent

```bash
hostname
ip -br -4 addr
date -Iseconds
sudo systemctl is-active wazuh-manager
sudo /var/ossec/bin/agent_control -l
```

Chụp:

```text
[CHỤP DC_07_VM2_Manager_Agent.png]
Thấy Wazuh Manager active và agent vms-production Active.
Vị trí báo cáo CD1: triển khai trung tâm Wazuh.
Vị trí báo cáo CD2: thành phần kế thừa từ CD1.
```

Kiểm tra VM2 gọi được VM3:

```bash
ping -c 4 192.168.245.30
curl -sS http://192.168.245.30:8000/health
```

Kiểm tra integration, không hiển thị token:

```bash
sudo grep -nA8 -B2 '<integration>' /var/ossec/etc/ossec.conf
sudo ls -l /var/ossec/integrations/custom-ai-soc
```

Chụp:

```text
[CHỤP DC_08_VM2_KetNoi_Integration_VM3.png]
Thấy /health trả status ok, hook_url tới 192.168.245.30:8000 và level 8.
Vị trí báo cáo CD2: cấu hình chuyển alert từ VM2 sang VM3.
```

### 6.4. Trên VM3: kiểm tra dịch vụ, model và API

```bash
hostname
ip -br -4 addr
date -Iseconds
sudo systemctl is-active vms-analyzer
sudo systemctl is-enabled vms-analyzer
curl -sS http://127.0.0.1:8000/health
```

Chụp:

```text
[CHỤP DC_09_VM3_Service_Health.png]
Thấy vms-analyzer active, enabled và API status ok.
Vị trí báo cáo CD2: triển khai Local ML Analyzer.
```

```bash
cd /home/ubuntu/vms-analyzer
source .venv/bin/activate
python verify_deployment.py
```

Kết quả cần thấy:

```text
BASELINE_HASH_MATCH=True
MODEL_ROWS=16
EVAL=TN:13 FP:0 TP:9 FN:0
ALL_CHECKS_PASSED=True
```

Chụp:

```text
[CHỤP DC_10_VM3_Model_Verify.png]
Vị trí báo cáo CD2: kiểm chứng model và baseline cục bộ.
Ghi chú: model dùng 16 mẫu baseline, gồm 5 network, 5 web, 3 auth và 3 OS.
Ghi chú học thuật: đây là kiểm thử chức năng trên dữ liệu lab, không gọi là độ chính xác production.
```

### 6.5. Trên Wazuh Dashboard

Mở Wazuh Dashboard trên VM2, vào danh sách agent và chọn `vms-production`.

Chụp:

```text
[CHỤP DC_11_Wazuh_Agent_Active.png]
Thấy agent vms-production Active.
Vị trí báo cáo CD1: kết quả kết nối agent.
```

## 7. Chu trình chuẩn cho từng kịch bản độc lập

Thực hiện đúng chu trình này trước từng kịch bản từ 1 đến 8. Khi chụp ảnh,
ưu tiên gọi stage trong script thực thi thay vì gõ từng lệnh tay nhỏ lẻ.
Hai file script dùng chung cho cả bộ ảnh:

```text
./ThucThi_Demo_CD1.sh
./ThucThi_Demo_CD2.sh
```

CD1 được chia thành các stage tương ứng:

```text
preflight, config, benign, network, web, auth, account, sshkey, sudo, fim, evidence, cleanup
```

CD2 được chia thành các stage tương ứng:

```text
preflight, config, model, reset, benign, watch, live-attack, evidence, tests
```

### Bước A - Xóa correlation buffer trên VM3

```bash
./ThucThi_Demo_CD2.sh reset
date -Iseconds
```

Không cần chụp lại lệnh restart ở mọi kịch bản. Chỉ cần chụp một lần ở kịch bản đầu:

```text
[CHỤP CD2_KB00_VM3_ResetBuffer.png]
Vị trí báo cáo CD2: phương pháp cô lập từng kịch bản thử nghiệm.
```

### Bước B - Chạy hành vi kiểm thử

Chạy đúng lệnh được ghi trong từng kịch bản bên dưới.

### Bước C - Đợi pipeline xử lý

```bash
sleep 20
```

Với FIM, Suricata hoặc SSH brute force có thể đợi 30 giây:

```bash
sleep 30
```

### Bước D - Chụp bằng chứng CD1

Chụp nguồn tạo hành vi, raw log VM1 và alert VM2/Wazuh Dashboard.

### Bước E - Chụp bằng chứng CD2

Trên VM3:

```bash
sudo journalctl -u vms-analyzer --since "5 minutes ago" --no-pager | tail -n 40
tail -n 60 /home/ubuntu/vms-analyzer/incidents.md
```

Chụp incident mới nhất, sau đó chụp Gotify nếu risk đạt `GOTIFY_MIN_RISK=60`. Không để lộ Gotify app token hoặc client token trong ảnh.

### Bước F - Dọn trạng thái có thay đổi

Chỉ kịch bản FIM, user và SSH key cần dọn trạng thái. Không xóa log.

### Bước G - Restart VM3 sau khi dọn dẹp

```bash
./ThucThi_Demo_CD2.sh reset
```

## 8. Kịch bản 1 - Port scan tầng network

### 8.1. Điều kiện mạng bắt buộc

Kịch bản Suricata port scan được chạy từ Kali `192.168.245.157`, cùng VMnet1 `192.168.245.0/24` với VM1. Vì lưu lượng đi trực tiếp tới VM1 `192.168.245.10`, đây là bằng chứng hợp lệ cho Suricata port scan.

### 8.2. Chạy từ Kali

Trên Kali chạy:

```bash
./ThucThi_Demo_CD1.sh network
```

Chụp nguồn:

```text
[CHỤP CD1_KB01_Source_Nmap.png]
Thấy IP nguồn kiểm thử, IP đích 192.168.245.10 và các cổng phát hiện.
Vị trí báo cáo CD1: Kịch bản Port scan dò tìm dịch vụ.
```

### 8.3. Đối chiếu trên VM1

Trên VM1 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Chụp:

```text
[CHỤP CD1_KB01_VM1_Suricata_Eve.png]
Thấy event Suricata có src_ip, dest_ip, signature và timestamp.
Vị trí báo cáo CD1: bằng chứng phát hiện tầng network.
```

### 8.4. Đối chiếu trên VM2

Trên VM2 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100106
```

Chụp:

```text
[CHỤP CD1_KB01_VM2_Network_Alert.png]
Thấy agent, rule 100106 level 10, mô tả Suricata ET SCAN/Nmap, IP nguồn/đích và thời gian.
Vị trí báo cáo CD1: kết quả kịch bản Port scan.
```

### 8.5. Đối chiếu trên VM3

Trên VM3 chạy:

```bash
./ThucThi_Demo_CD2.sh evidence
```

Kết quả kỳ vọng sau khi rule 100106 nâng alert Suricata ET SCAN/Nmap lên level 10:

```text
Sự cố: Network Port Scan
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_KB01_VM3_Network_Port_Scan.png]
Vị trí báo cáo CD2: thử nghiệm phân loại alert network đơn lẻ.

[CHỤP CD2_KB01_Gotify_Network.png]
Chỉ chụp nếu Gotify có gửi do risk đạt ngưỡng.
```

Alert Suricata không chứa `ET SCAN`, `Nmap` hoặc `port scan` (ví dụ DHCP policy alert) vẫn giữ level gốc và không được forward. Chỉ dùng `100106` để chứng minh full flow Network → VM3.

## 9. Kịch bản 2 - Web sensitive-path probing

### 9.1. Reset VM3 trước kịch bản

```bash
./ThucThi_Demo_CD2.sh reset
```

### 9.2. Chạy trên Kali tới Web VM1

Trên Kali chạy:

```bash
./ThucThi_Demo_CD1.sh web
```

Chụp:

```text
[CHỤP CD1_KB02_Kali_Sensitive_Path.png]
Thấy các URL được yêu cầu và HTTP response; 404 vẫn là kết quả hợp lệ vì mục tiêu là tạo log dò đường dẫn.
Vị trí báo cáo CD1: Kịch bản Web sensitive path probing.
```

### 9.3. Đối chiếu VM1

Trên VM1 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Chụp:

```text
[CHỤP CD1_KB02_VM1_Nginx_Access.png]
Thấy path, status code, timestamp và IP nguồn quan sát được.
Vị trí báo cáo CD1: bằng chứng log Web/Application.
```

### 9.4. Đối chiếu VM2

Trên VM2 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100200
```

Chụp:

```text
[CHỤP CD1_KB02_VM2_Rule_100200.png]
Vị trí báo cáo CD1: kết quả phát hiện sensitive-path probing.
```

### 9.5. Đối chiếu VM3 và Gotify

Trên VM3 chạy:

```bash
./ThucThi_Demo_CD2.sh evidence
```

Kết quả kỳ vọng:

```text
Sự cố: Web Sensitive Path Scan
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_KB02_VM3_Web_Sensitive_Path.png]
Vị trí báo cáo CD2: phân loại và chấm điểm alert Web probing.

[CHỤP CD2_KB02_Gotify_Web_Sensitive.png]
Chụp Gotify nếu có thông báo đạt ngưỡng.
```

## 10. Kịch bản 3 - Web directory traversal attempt

### 10.1. Restart VM3 trước kịch bản

```bash
./ThucThi_Demo_CD2.sh reset
```

### 10.2. Chạy trên Kali

Giữ nguyên path khi gửi request bằng tùy chọn `--path-as-is`:

Trên Kali chạy:

```bash
./ThucThi_Demo_CD1.sh web
```

Chụp:

```text
[CHỤP CD1_KB03_Kali_Traversal.png]
Thấy request traversal và HTTP response. Phản hồi 404 không có nghĩa hệ thống không phát hiện.
Vị trí báo cáo CD1: Kịch bản directory traversal attempt.
```

### 10.3. Đối chiếu VM1

Trên VM1 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Chụp:

```text
[CHỤP CD1_KB03_VM1_Traversal_AccessLog.png]
Vị trí báo cáo CD1: raw log traversal trên Nginx.
```

### 10.4. Đối chiếu VM2

Trên VM2 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100201
```

Chụp:

```text
[CHỤP CD1_KB03_VM2_Rule_100201.png]
Vị trí báo cáo CD1: kết quả phát hiện directory traversal.
```

### 10.5. Đối chiếu VM3 và Gotify

Trên VM3 chạy:

```bash
./ThucThi_Demo_CD2.sh evidence
```

Kết quả kỳ vọng:

```text
Sự cố: Web Traversal Attempt
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_KB03_VM3_Web_Traversal.png]
Vị trí báo cáo CD2: phân loại, deterministic risk và IsolationForest.

[CHỤP CD2_KB03_Gotify_Traversal.png]
Vị trí báo cáo CD2: cơ chế cảnh báo theo ngưỡng.
```

## 11. Kịch bản 4 - Thay đổi nội dung web root

### 11.1. Reset VM3 và sao lưu trang hiện tại

```bash
./ThucThi_Demo_CD2.sh reset
```

### 11.2. Chạy trên VM1

Không cần gõ tay thêm; stage `fim` đã thay đổi trang và giữ file backup.

Chụp:

```text
[CHỤP CD1_KB04_VM1_WebRoot_Modified.png]
Thấy đường dẫn index.html và thời gian Modify mới.
Vị trí báo cáo CD1: Kịch bản thay đổi nội dung web root.
```

Đợi FIM:

```bash
sleep 30
```

### 11.3. Đối chiếu VM2

Trên VM2 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100202
```

Chụp:

```text
[CHỤP CD1_KB04_VM2_Rule_100202.png]
Vị trí báo cáo CD1: kết quả FIM web root modified.
```

### 11.4. Đối chiếu VM3 và Gotify

Trên VM3 chạy:

```bash
./ThucThi_Demo_CD2.sh evidence
```

Kết quả kỳ vọng:

```text
Sự cố: Web Root Modified
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_KB04_VM3_WebRoot_Modified.png]
[CHỤP CD2_KB04_Gotify_WebRoot.png]
Vị trí báo cáo CD2: phân tích alert FIM đơn lẻ.
```

### 11.5. Khôi phục

```bash
./ThucThi_Demo_CD2.sh reset
```

Không dùng alert khôi phục làm kết quả tấn công.

## 12. Kịch bản 5 - Tạo file nghi vấn trong web root

### 12.1. Reset VM3

```bash
./ThucThi_Demo_CD2.sh reset
```

### 12.2. Tạo tệp mẫu an toàn trên VM1

Tệp chỉ chứa chuỗi đánh dấu, không chứa mã web shell thực thi:

Trên VM1 chạy:

```bash
./ThucThi_Demo_CD1.sh fim
```

Chụp:

```text
[CHỤP CD1_KB05_VM1_Suspicious_File.png]
Thấy file shell.php, owner, permission và thời gian tạo.
Vị trí báo cáo CD1: Kịch bản tạo file nghi vấn trong web root.
```

```bash
sleep 30
```

### 12.3. Đối chiếu VM2

Trên VM2 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100203
```

Chụp:

```text
[CHỤP CD1_KB05_VM2_Rule_100203.png]
Vị trí báo cáo CD1: kết quả phát hiện file nghi vấn.
```

### 12.4. Đối chiếu VM3 và Gotify

Trên VM3 chạy:

```bash
./ThucThi_Demo_CD2.sh evidence
```

Kết quả kỳ vọng:

```text
Sự cố: Suspicious Web File
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_KB05_VM3_Suspicious_Web_File.png]
[CHỤP CD2_KB05_Gotify_Suspicious_File.png]
Vị trí báo cáo CD2: phân tích alert file Web nghi vấn.
```

### 12.5. Dọn file mẫu

```bash
./ThucThi_Demo_CD2.sh reset
```

## 13. Kịch bản 6 - SSH brute force có kiểm soát

### 13.1. Chuẩn bị Kali

```bash
command -v sshpass
```

Nếu chưa có:

```bash
sudo apt update
sudo apt install -y sshpass
```

### 13.2. Reset VM3

```bash
./ThucThi_Demo_CD2.sh reset
```

### 13.3. Tạo tám lần đăng nhập thất bại từ Kali

Lệnh chỉ dùng user không tồn tại và mật khẩu sai, không lưu mật khẩu thật:

Trên Kali chạy:

```bash
./ThucThi_Demo_CD1.sh auth
```

Chụp:

```text
[CHỤP CD1_KB06_Kali_SSH_Failures.png]
Thấy nhiều lần Permission denied từ cùng địa chỉ đích/cổng.
Vị trí báo cáo CD1: Kịch bản SSH brute force.
```

```bash
sleep 30
```

### 13.4. Đối chiếu VM1

Trên VM1 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Chụp:

```text
[CHỤP CD1_KB06_VM1_Auth_Failed.png]
Thấy nhiều failed login gần nhau và cùng IP nguồn quan sát được.
Vị trí báo cáo CD1: raw auth log.
```

### 13.5. Đối chiếu VM2

Trên VM2 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100100
```

Chụp:

```text
[CHỤP CD1_KB06_VM2_Rule_100100.png]
Vị trí báo cáo CD1: kết quả phát hiện SSH brute force.
```

### 13.6. Đối chiếu VM3 và Gotify

Trên VM3 chạy:

```bash
./ThucThi_Demo_CD2.sh evidence
```

Kết quả kỳ vọng:

```text
Sự cố: SSH Brute Force
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_KB06_VM3_SSH_Brute_Force.png]
[CHỤP CD2_KB06_Gotify_SSH_Brute.png]
Vị trí báo cáo CD2: phân loại alert auth và đánh giá ML.
```

### 13.7. Tùy chọn - đăng nhập thành công sau brute force

Ngay sau chuỗi thất bại, đăng nhập tương tác bằng tài khoản lab hợp lệ:

Nếu cần chụp phần tùy chọn này, đăng nhập SSH hợp lệ từ PC2 hoặc Kali bằng
tài khoản lab được phép.

Sau đó chạy:

```bash
whoami
hostname
exit
```

Đối chiếu:

```bash
sudo grep -E '"id":"100101"|Login SSH thanh cong sau brute force' /var/ossec/logs/alerts/alerts.json | tail -n 20
```

Ảnh tùy chọn:

```text
[CHỤP CD1_KB06B_VM2_Rule_100101.png]
[CHỤP CD2_KB06B_VM3_Valid_Login_After_Brute.png]
```

## 14. Kịch bản 7 - Tài khoản và SSH authorized_keys

Kịch bản này có hai phần độc lập. Restart VM3 giữa phần A và phần B để mỗi alert giữ đúng loại.

### 14.1. Phần A - Tạo tài khoản mẫu

Trên VM3, reset buffer trước khi quay:

```bash
./ThucThi_Demo_CD2.sh reset
```

Trên VM1 chạy stage tạo tài khoản:

```bash
./ThucThi_Demo_CD1.sh account
```

Chụp:

```text
[CHỤP CD1_KB07A_VM1_User_Created.png]
Thấy socdemo_user trong /etc/passwd.
Vị trí báo cáo CD1: thay đổi tài khoản hệ thống.
```

```bash
sleep 30
```

Trên VM2:

```bash
sudo grep -E '"id":"100102"|"id":"100103"|Tai khoan moi|/etc/passwd|socdemo_user' /var/ossec/logs/alerts/alerts.json | tail -n 30
```

Dashboard lọc:

```text
agent.name:vms-production AND (rule.id:100102 OR rule.id:100103)
```

Chụp:

```text
[CHỤP CD1_KB07A_VM2_Account_Alert.png]
Vị trí báo cáo CD1: kết quả phát hiện tài khoản mới hoặc /etc/passwd thay đổi.
```

Trên VM3:

```bash
tail -n 60 /home/ubuntu/vms-analyzer/incidents.md
```

Chụp:

```text
[CHỤP CD2_KB07A_VM3_Account_Incident.png]
[CHỤP CD2_KB07A_Gotify_Account.png]
Vị trí báo cáo CD2: Suspicious User Creation hoặc Account File Modified.
```

Dọn tài khoản:

```bash
./ThucThi_Demo_CD1.sh cleanup
```

### 14.2. Phần B - Thay đổi authorized_keys mẫu

Trên VM3, reset buffer trước khi quay:

```bash
./ThucThi_Demo_CD2.sh reset
```

Trên VM1 chạy stage thay đổi authorized_keys:

```bash
./ThucThi_Demo_CD1.sh sshkey
```

Chụp:

```text
[CHỤP CD1_KB07B_VM1_AuthorizedKeys.png]
Thấy dòng public key có comment soc-demo-key; không chụp private key.
Vị trí báo cáo CD1: thay đổi SSH authorized_keys.
```

```bash
sleep 30
```

Trên VM2:

```bash
sudo grep -E '"id":"100104"|authorized_keys|SSH authorized_keys' /var/ossec/logs/alerts/alerts.json | tail -n 20
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100104
```

Chụp:

```text
[CHỤP CD1_KB07B_VM2_Rule_100104.png]
Vị trí báo cáo CD1: kết quả FIM authorized_keys.
```

Trên VM3:

```bash
tail -n 60 /home/ubuntu/vms-analyzer/incidents.md
```

Chụp:

```text
[CHỤP CD2_KB07B_VM3_SSH_Key_Backdoor.png]
[CHỤP CD2_KB07B_Gotify_SSH_Key.png]
Vị trí báo cáo CD2: phân loại SSH Key Backdoor.
```

Dọn key mẫu:

```bash
./ThucThi_Demo_CD1.sh cleanup
```

## 15. Kịch bản 8 - Sử dụng sudo/lệnh quyền cao

### 15.1. Reset VM3

```bash
./ThucThi_Demo_CD2.sh reset
```

### 15.2. Chạy lệnh kiểm thử an toàn trên VM1

Trên VM1 chạy:

```bash
./ThucThi_Demo_CD1.sh sudo
```

Chụp:

```text
[CHỤP CD1_KB08_VM1_Audit_RootCmd.png]
Thấy lệnh quyền cao và bản ghi audit có key root_cmd; không hiển thị nội dung /etc/shadow.
Vị trí báo cáo CD1: Kịch bản lạm dụng sudo/lệnh quyền cao.
```

```bash
sleep 30
```

### 15.3. Đối chiếu VM2

Trên VM2 chạy:

```bash
./ThucThi_Demo_CD1.sh evidence
```

Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100105
```

Chụp:

```text
[CHỤP CD1_KB08_VM2_Rule_100105.png]
Vị trí báo cáo CD1: kết quả phát hiện lệnh quyền cao.
```

### 15.4. Đối chiếu VM3 và Gotify

Trên VM3 chạy:

```bash
./ThucThi_Demo_CD2.sh evidence
```

Kết quả kỳ vọng:

```text
Sự cố: Privilege Escalation
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_KB08_VM3_Privilege_Escalation.png]
[CHỤP CD2_KB08_Gotify_Privilege.png]
Vị trí báo cáo CD2: phân loại và chấm điểm sự kiện quyền cao.
```

## 16. Lượt bổ sung CD2 - Full correlation network → web → os

Đây là lượt riêng của Chuyên đề 2. Không restart VM3 giữa các bước 2, 3 và 4.

### 16.1. Cổng kiểm tra trước khi chạy

Trên VM2, xác nhận alert network có thể được chuyển sang VM3:

```bash
sudo grep -Ei 'suricata|ET SCAN|Nmap|port scan' /var/ossec/logs/alerts/alerts.json | tail -n 5
```

Mở JSON alert rule `100106` và kiểm tra `rule.level=10`. Nếu chỉ có alert Suricata level thấp, scan chưa khớp signature `ET SCAN`/`Nmap`; khi đó dùng phương án replay network alert ở mục 16.3 và ghi rõ đây là replay alert đã thu thập trong lab.

### 16.2. Reset một lần và mở theo dõi VM3

```bash
./ThucThi_Demo_CD2.sh reset
```

Terminal VM3 số 1:

```bash
sudo journalctl -u vms-analyzer -f
```

Terminal VM3 số 2:

```bash
cd /home/ubuntu/vms-analyzer
tail -f incidents.md
```

Chụp:

```text
[CHỤP CD2_CHAIN_01_VM3_Buffer_Sach.png]
Thấy service vừa restart và API health ok.
Vị trí báo cáo CD2: chuẩn bị thử nghiệm correlation.
```

### 16.3. Bước 1 - Network

Phương án live ưu tiên: chạy Nmap trực tiếp tới `192.168.245.10` từ cùng VMnet1 như mục 8.

```bash
sudo nmap -sS -sV -T4 -p 1-1000 192.168.245.10
```

Đợi VM2 forward và kiểm tra VM3:

```bash
sleep 20
tail -n 50 /home/ubuntu/vms-analyzer/incidents.md
```

Kết quả ở bước này phải là:

```text
Sự cố: Network Port Scan
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_CHAIN_02_Network_Stage.png]
Thấy Network Port Scan nhưng chưa correlation.
```

Chỉ tiếp tục lượt full chain khi VM2 có rule `100106` level 10 và VM3 nhận POST
từ integration. Không dùng replay sample trong ảnh hoặc kết luận của lượt này.

### 16.4. Bước 2 - Web

Không restart VM3. Trên Kali chạy traversal:

```bash
curl --path-as-is -i 'http://192.168.245.10/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
```

Đợi pipeline:

```bash
sleep 20
```

Trên VM3:

```bash
tail -n 60 /home/ubuntu/vms-analyzer/incidents.md
```

Kết quả ở bước này vẫn phải là:

```text
Sự cố: Web Traversal Attempt
Trạng thái: Không - cảnh báo đơn lẻ
```

Chụp:

```text
[CHỤP CD2_CHAIN_03_Web_Stage.png]
Thấy Web Traversal Attempt chưa bị nâng thành compromise khi chưa có OS event.
```

### 16.5. Bước 3 - OS/FIM

Không restart VM3. Trên VM1 sao lưu và sửa web root:

```bash
sudo cp -a /var/www/html/index.html /tmp/index.html.before-correlation-demo
printf '%s\n' '<h1>Correlation demo change</h1>' | sudo tee /var/www/html/index.html
sudo stat /var/www/html/index.html
sleep 30
```

Trên VM2:

```bash
sudo grep -E '"id":"100202"|Web root file modified' /var/ossec/logs/alerts/alerts.json | tail -n 10
```

Trên VM3:

```bash
tail -n 80 /home/ubuntu/vms-analyzer/incidents.md
```

Kết quả cuối bắt buộc:

```text
Nhãn phân tích: Possible Server Compromise
Mức độ: Nghiêm trọng (Critical)
Nguồn bằng chứng: Mạng → Web → Hệ điều hành
Độ tin cậy: Cao
Liên kết IP nguồn (Network/Web): Khớp
Chuỗi đầy đủ Mạng → Web → Hệ điều hành được quan sát.
Điểm theo luật: 100/100 hoặc mức Critical theo dữ liệu thời điểm chạy
Bất thường: Có
```

Chụp:

```text
[CHỤP CD2_CHAIN_04_VM1_FIM_Change.png]
Thấy file index.html vừa thay đổi.

[CHỤP CD2_CHAIN_05_VM2_Rule_100202.png]
Thấy Wazuh nhận alert OS/FIM cuối chuỗi.

[CHỤP CD2_CHAIN_06_VM3_Possible_Compromise.png]
Thấy Possible Server Compromise, Critical, confidence Cao và liên kết IP
Network/Web Khớp; không dùng nội dung này để khẳng định cùng tác nhân.

[CHỤP CD2_CHAIN_07_Gotify_Critical.png]
Thấy Gotify có cấu trúc tiếng Việt, icon, risk, ML, correlation và playbook; màn hình client kết nối qua WireGuard.

Vị trí báo cáo CD2: mục thử nghiệm correlation đa nguồn và cảnh báo cuối.
```

### 16.6. Khôi phục sau full chain

```bash
sudo cp -a /tmp/index.html.before-correlation-demo /var/www/html/index.html
sudo rm -f /tmp/index.html.before-correlation-demo
sleep 20
./ThucThi_Demo_CD2.sh reset
```

Lệnh restart cuối đưa VM3 về buffer sạch cho lần demo khác.

## 17. Ảnh kết quả tối thiểu cần giữ

### 17.1. Ảnh dùng chung

```text
DC_01_Kali_IP_Route.png
DC_02_Kali_Ping_VM1.png
DC_03_Kali_DichVu_VMnet1.png
DC_04_Nginx_BinhThuong.png
DC_05_VM1_IP_DichVu.png
DC_06_VM1_NguonLog.png
DC_07_VM2_Manager_Agent.png
DC_08_VM2_KetNoi_Integration_VM3.png
DC_09_VM3_Service_Health.png
DC_10_VM3_Model_Verify.png
DC_11_Wazuh_Agent_Active.png
```

### 17.2. Ảnh tối thiểu cho CD1

```text
CD1_KB01_Source_Nmap.png
CD1_KB01_VM1_Suricata_Eve.png
CD1_KB01_VM2_Network_Alert.png

CD1_KB02_Kali_Sensitive_Path.png
CD1_KB02_VM1_Nginx_Access.png
CD1_KB02_VM2_Rule_100200.png

CD1_KB03_Kali_Traversal.png
CD1_KB03_VM1_Traversal_AccessLog.png
CD1_KB03_VM2_Rule_100201.png

CD1_KB04_VM1_WebRoot_Modified.png
CD1_KB04_VM2_Rule_100202.png

CD1_KB05_VM1_Suspicious_File.png
CD1_KB05_VM2_Rule_100203.png

CD1_KB06_Kali_SSH_Failures.png
CD1_KB06_VM1_Auth_Failed.png
CD1_KB06_VM2_Rule_100100.png

CD1_KB07A_VM1_User_Created.png
CD1_KB07A_VM2_Account_Alert.png
CD1_KB07B_VM1_AuthorizedKeys.png
CD1_KB07B_VM2_Rule_100104.png

CD1_KB08_VM1_Audit_RootCmd.png
CD1_KB08_VM2_Rule_100105.png
```

### 17.3. Ảnh tối thiểu cho CD2

```text
CD2_KB00_VM3_ResetBuffer.png
CD2_KB01_VM3_Network_Port_Scan.png
CD2_KB02_VM3_Web_Sensitive_Path.png
CD2_KB03_VM3_Web_Traversal.png
CD2_KB03_Gotify_Traversal.png
CD2_KB04_VM3_WebRoot_Modified.png
CD2_KB05_VM3_Suspicious_Web_File.png
CD2_KB06_VM3_SSH_Brute_Force.png
CD2_KB07A_VM3_Account_Incident.png
CD2_KB07B_VM3_SSH_Key_Backdoor.png
CD2_KB08_VM3_Privilege_Escalation.png

CD2_CHAIN_01_VM3_Buffer_Sach.png
CD2_CHAIN_02_Network_Stage.png
CD2_CHAIN_03_Web_Stage.png
CD2_CHAIN_04_VM1_FIM_Change.png
CD2_CHAIN_05_VM2_Rule_100202.png
CD2_CHAIN_06_VM3_Possible_Compromise.png
CD2_CHAIN_07_Gotify_Critical.png
```

Không bắt buộc chèn tất cả ảnh Gotify của từng alert đơn lẻ vào báo cáo. Giữ lại trong thư mục minh chứng và chọn 2 đến 3 ảnh rõ nhất; ảnh Gotify của traversal và full correlation nên được ưu tiên.

## 18. Checklist trước khi kết thúc buổi lab

- [ ] Đã chụp IP và kết nối mạng dùng chung.
- [ ] VM1 có đủ Nginx, Suricata, Wazuh Agent và auditd active.
- [ ] VM2 thấy agent vms-production Active.
- [ ] VM2 gọi được API health của VM3.
- [ ] VM3 dùng model persisted-joblib và baseline 16 mẫu, bao phủ network/web/auth/os.
- [ ] Mỗi kịch bản CD1 có ít nhất một ảnh nguồn và một ảnh Wazuh.
- [ ] Mỗi nhóm kịch bản CD2 có ảnh incident VM3.
- [ ] Traversal đơn lẻ có `correlated=false`.
- [ ] Web alert ở bước giữa full chain chưa bị nâng thành compromise.
- [ ] OS/FIM cuối full chain tạo `Possible Server Compromise` khi
  `src_ip_match=true`.
- [ ] Gotify full chain hiển thị nguồn Mạng → Web → Hệ điều hành, confidence
  Cao và liên kết IP Network/Web Khớp.
- [ ] Đã khôi phục index.html.
- [ ] Đã xóa shell.php mẫu.
- [ ] Đã xóa socdemo_user.
- [ ] Đã gỡ key có comment soc-demo-key.
- [ ] Đã xóa private/public key mẫu trong `/tmp`.
- [ ] Đã restart vms-analyzer sau khi dọn dẹp.
- [ ] Không có token, mật khẩu hoặc private key xuất hiện trong ảnh.

## 19. Xử lý lỗi nhanh

### 19.1. Kali không vào được Web hoặc SSH

Từ Kali kiểm tra lại:

```bash
ip -br -4 addr
ping -c 4 192.168.245.10
nc -vz 192.168.245.10 80
nc -vz 192.168.245.10 22
nc -vz 192.168.245.20 22
nc -vz 192.168.245.30 22
```

Xác nhận Kali có địa chỉ `192.168.245.157/24` trên NIC nối `VMnet1`; VM1, VM2 và VM3 phải giữ các địa chỉ `.10`, `.20`, `.30` trong cùng dải.

### 19.2. VM2 không thấy agent

Trên VM1:

```bash
sudo systemctl restart wazuh-agent
sudo tail -n 50 /var/ossec/logs/ossec.log
```

Trên VM2:

```bash
sudo /var/ossec/bin/agent_control -l
```

### 19.3. Wazuh có alert nhưng VM3 không nhận

Trên VM2:

```bash
curl -sS http://192.168.245.30:8000/health
sudo grep -nA8 -B2 '<integration>' /var/ossec/etc/ossec.conf
sudo tail -n 80 /var/ossec/logs/ossec.log
```

Xác nhận alert có `rule.level` từ 8 trở lên.

### 19.4. VM3 nhận alert nhưng không có Gotify

Trên VM3 chỉ kiểm tra trạng thái biến, không in giá trị bí mật:

```bash
cd /home/ubuntu/vms-analyzer
awk -F= '/^GOTIFY_URL=/{print $0} /^GOTIFY_APP_TOKEN=/{print "GOTIFY_APP_TOKEN_SET=" (length($2)>0 ? "yes":"no")} /^GOTIFY_MIN_RISK=/{print $0}' .env
sudo systemctl is-active gotify
curl -fsS -o /dev/null -w 'GOTIFY_HTTP=%{http_code}\n' http://10.66.0.1:8080/
```

Kiểm tra risk có đạt `GOTIFY_MIN_RISK` hay không. Nếu Gotify client ở máy cá nhân không hiển thị được thông báo, kiểm tra tunnel bằng `sudo systemctl is-active wg-quick@wg0` và `sudo wg show` trên VM3.

### 19.5. Alert đơn lẻ bị ghi thành Possible Server Compromise

Restart VM3 để xóa buffer rồi chạy lại đúng một kịch bản:

```bash
./ThucThi_Demo_CD2.sh reset
```

### 19.6. Full chain không correlation

Kiểm tra lần lượt:

1. VM2 có alert live rule `100106` level 10 và VM3 đã nhận POST từ integration.
2. Web alert xuất hiện sau network alert.
3. OS/FIM alert xuất hiện sau web alert.
4. Ba alert cùng server `vms-production`.
5. Toàn bộ chuỗi hoàn thành trong 600 giây.
6. Không restart VM3 giữa ba bước.

Nếu chưa có `100106`, dừng lượt full chain, kiểm tra signature `ET SCAN`/`Nmap`
trên VM1 và cấu hình rule VM2; không thay bằng replay trong phần thực nghiệm live.
