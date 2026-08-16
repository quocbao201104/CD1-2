# KỊCH BẢN QUAY DEMO CHUYÊN ĐỀ 1

## SOC giám sát máy chủ Linux bằng Wazuh

Kịch bản này dành cho video **không thu lời trực tiếp**. Chỉ quay lệnh, kết quả
và Dashboard; lồng tiếng sau. Không quay lại quá trình cài đặt vì đã có video
cài đặt riêng.

## 1. Luồng video ngắn gọn

```text
Kiểm tra IP/kết nối
  -> gói và cấu hình trọng tâm
  -> truy cập hợp lệ từ PC2
  -> Dashboard ở trạng thái sẵn sàng
  -> kiểm thử Network/Web/Auth/Account/SSH key/Sudo/FIM
  -> raw log VM1
  -> alert và Dashboard VM2
  -> phục hồi VM1
```

Thời lượng đề xuất: **10–14 phút**.

## 2. Topology dùng trong video

| Thành phần | Địa chỉ | Vai trò |
|---|---:|---|
| PC2 Windows | `192.168.100.129` | Máy quản trị và quay video |
| Kali | `192.168.245.157` | Máy kiểm thử được phép |
| VM1 `vms-production` | `192.168.245.10` | Nginx, Suricata, auditd, FIM, Wazuh Agent |
| VM2 `vms-soc` | `192.168.245.20` | Wazuh Manager, Indexer, Dashboard |
| VM3 `vms-analyzer` | `192.168.245.30` | Không tham gia xử lý CD1; chỉ giới thiệu ở CD2 |

Các VM và Kali cùng `VMnet1 192.168.245.0/24`. PC2 truy cập trực tiếp các VM
qua adapter VMware Host-only. Toàn bộ hành vi kiểm thử chỉ nhắm tới VM1 trong
lab được phép.

## 3. Chuẩn bị trước khi quay

### 3.1. Chép script

Từ PowerShell PC2, đứng tại thư mục chứa script:

```powershell
scp .\ThucThi_Demo_CD1.sh kali@192.168.245.157:/home/kali/
scp .\ThucThi_Demo_CD1.sh ubuntu@192.168.245.10:/home/ubuntu/
scp .\ThucThi_Demo_CD1.sh ubuntu@192.168.245.20:/home/ubuntu/
```

**Lồng tiếng ngắn:** “Tệp thực thi demo được chép tới đúng các máy tham gia để
các lệnh trong video được chạy thống nhất và hạn chế sai sót khi thao tác.”

Trên từng máy Linux:

```bash
chmod +x ~/ThucThi_Demo_CD1.sh
~/ThucThi_Demo_CD1.sh --help
```

**Lồng tiếng ngắn:** “Tôi cấp quyền thực thi và kiểm tra danh sách stage trước
khi quay. Mỗi stage chỉ chạy trên đúng máy và đúng mục đích đã định.”

### 3.2. Bố trí cửa sổ

Chỉ cần bốn cửa sổ:

1. PowerShell PC2.
2. Kali terminal.
3. Terminal VM1/VM2, đổi qua lại khi đối chiếu.
4. Chrome mở `https://192.168.245.20`.

Trên Dashboard chọn thời gian **Last 15 minutes**. Không quay mật khẩu, token,
private key hoặc nội dung `.env` đầy đủ.

Khi chụp ảnh, ưu tiên gọi stage tương ứng của `ThucThi_Demo_CD1.sh` để giữ
đúng thứ tự và tránh gõ lệnh lẻ:

```text
preflight -> config -> benign -> network -> web -> auth -> account -> sshkey -> sudo -> fim -> evidence -> cleanup
```

## 4. Thứ tự quay chính

## Cảnh 1 — IP, kết nối và dịch vụ

### 1A. Kali

```bash
~/ThucThi_Demo_CD1.sh preflight
```

**Lồng tiếng ngắn:** “Kali đang nằm trong mạng Host-only của phòng lab và có
thể kết nối tới máy chủ cần bảo vệ cùng máy Wazuh.”

Giữ hình ở:

- Kali có IP `192.168.245.157`.
- Ping VM1 và VM2 thành công.

### 1B. VM1

```bash
~/ThucThi_Demo_CD1.sh preflight
```

**Lồng tiếng ngắn:** “Trên VM1, các dịch vụ Web, IDS, audit và Wazuh Agent đều
hoạt động; trang Web nội bộ cũng phản hồi bình thường.”

Giữ hình ở `nginx`, `suricata`, `wazuh-agent`, `auditd` đều `active` và HTTP
local trả `200`.

### 1C. VM2

```bash
~/ThucThi_Demo_CD1.sh preflight
```

**Lồng tiếng ngắn:** “Wazuh Manager, Indexer và Dashboard đang hoạt động. Agent
vms-production đã kết nối và sẵn sàng gửi dữ liệu giám sát.”

Giữ hình ở:

- `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard` đều `active`.
- Agent `vms-production`, ID hiện tại `002`, trạng thái `Active`.

## Cảnh 2 — Gói và cấu hình quan trọng

Không mở toàn bộ file cấu hình. Chỉ chạy ba lệnh sau.

### 2A. Kali: bộ công cụ kiểm thử

```bash
~/ThucThi_Demo_CD1.sh config
```

**Lồng tiếng ngắn:** “Kali đã có các công cụ cần thiết cho những tình huống
kiểm thử được cấp phép trong mạng lab.”

Chỉ giữ hình danh sách `nmap`, `curl`, `hydra`, `nc`, `sshpass`, `jq` và phiên
bản Nmap/Hydra.

### 2B. VM1: nguồn log và cơ chế giám sát

```bash
~/ThucThi_Demo_CD1.sh config
```

**Lồng tiếng ngắn:** “VM1 thu thập ba nhóm bằng chứng chính: lưu lượng mạng từ
Suricata, nhật ký Web từ Nginx và thay đổi hệ thống từ FIM cùng auditd.”

Giữ hình các dòng chứng minh:

- Suricata theo dõi mạng lab.
- Wazuh Agent gửi về Manager `.20`.
- Agent đọc Nginx access/error log và Suricata `eve.json`.
- FIM theo dõi thư mục Web root; auditd ghi lệnh đặc quyền.

### 2C. VM2: local rules

```bash
~/ThucThi_Demo_CD1.sh config
```

**Lồng tiếng ngắn:** “VM2 áp dụng các local rule để nhận diện quét cổng, dò
đường dẫn Web, traversal, brute force và thay đổi Web root.”

Giữ hình các rule chính:

| Rule | Ý nghĩa | Level |
|---:|---|---:|
| `100100` | SSH brute force | 10 |
| `100200` | Sensitive path probing | 8 |
| `100201` | Directory traversal attempt | 10 |
| `100202` | Web root modified | 12 |
| `100203` | Suspicious file in Web root | 12 |

## Cảnh 3 — Hoạt động hợp lệ trước kiểm thử

### 3A. PC2 quản trị hợp lệ

Trong PowerShell PC2:

```powershell
ipconfig | findstr /i "IPv4 VMnet1"
Test-NetConnection 192.168.245.10 -Port 22
curl.exe -I http://192.168.245.10/
ssh ubuntu@192.168.245.10 "whoami; hostname; id"
```

**Lồng tiếng ngắn:** “Trước khi kiểm thử bất thường, tôi xác nhận PC2 có thể
truy cập Web và đăng nhập SSH hợp lệ vào VM1 bằng tài khoản được phép.”

Mật khẩu SSH nhập tương tác, không để hiện trên màn hình. Kết quả cần thấy:

- Web trả HTTP `200`.
- SSH vào đúng `vms-production` bằng user được phép.
- VM1 nhìn nguồn quản trị qua adapter VMnet1 của host, `192.168.245.1`.

### 3B. Kali truy cập trang chủ bình thường

```bash
~/ThucThi_Demo_CD1.sh benign
```

**Lồng tiếng ngắn:** “Kali cũng gửi một yêu cầu trang chủ bình thường để tạo
mốc so sánh với các request đáng ngờ ở những cảnh tiếp theo.”

### 3C. VM1 chứng minh request hợp lệ được ghi log

```bash
sudo tail -n 8 /var/log/nginx/access.log
sudo grep -Ei 'Accepted publickey|Accepted password' /var/log/auth.log | tail -n 5
```

**Lồng tiếng ngắn:** “Nginx và SSH ghi nhận đúng hoạt động hợp lệ, gồm mã phản
hồi thành công và phiên đăng nhập được chấp nhận từ máy quản trị.”

Mở Dashboard một lần để chứng minh hệ thống đang hoạt động. Chưa gọi request
hợp lệ là tấn công và chưa chờ alert level cao ở cảnh này.

## Cảnh 4 — Network scan

### 4A. Kali phát sinh lưu lượng

```bash
~/ThucThi_Demo_CD1.sh network
```

**Lồng tiếng ngắn:** “Từ Kali, tôi thực hiện quét dịch vụ trong phạm vi VM1 của
lab để kiểm tra khả năng phát hiện hành vi Network Service Discovery.”

Giữ hình kết quả phát hiện cổng `22` và `80`.

### 4B. VM1 đối chiếu raw log

```bash
~/ThucThi_Demo_CD1.sh evidence
```

**Lồng tiếng ngắn:** “Suricata trên VM1 ghi lại lưu lượng phát sinh, cho phép
đối chiếu IP nguồn Kali, IP đích VM1 và dịch vụ bị dò quét.”

Giữ hình một dòng Suricata có nguồn Kali và đích VM1.

### 4C. VM2 và Dashboard

```bash
~/ThucThi_Demo_CD1.sh evidence
```

**Lồng tiếng ngắn:** “VM2 tiếp nhận dữ liệu từ Agent và tạo cảnh báo tương ứng.
Tôi sẽ dùng Dashboard để trình bày alert ở dạng trực quan.”

Dashboard dùng filter:

```text
agent.name:vms-production AND rule.id:100106
```

**Lồng tiếng ngắn:** “Rule 100106 chỉ nâng những alert Suricata có dấu hiệu
ET SCAN hoặc Nmap lên level 10, để chuyển sự kiện network có chọn lọc sang VM3.”

Mở một alert và giữ các trường `agent.name`, `rule.level`, `rule.description`,
`data.src_ip`, `data.dest_ip` nếu có. Port scan là **Network Service Discovery**,
không phải bằng chứng máy đã bị xâm nhập.

## Cảnh 5 — Web probing và traversal

### 5A. Kali

```bash
~/ThucThi_Demo_CD1.sh web
```

**Lồng tiếng ngắn:** “Kali lần lượt dò các đường dẫn nhạy cảm và gửi một yêu
cầu traversal đã mã hóa để kiểm tra lớp giám sát Web.”

HTTP `400` hoặc `404` là bình thường: mục tiêu là chứng minh request đáng ngờ
được ghi nhận, không chứng minh đọc được `/etc/passwd`.

### 5B. VM1

```bash
~/ThucThi_Demo_CD1.sh evidence
```

**Lồng tiếng ngắn:** “Nginx access log giữ lại URL, mã HTTP và địa chỉ nguồn,
chứng minh request kiểm thử thực sự đã tới VM1.”

Giữ hình Nginx log có `/.env`, `/.git/config` hoặc chuỗi `%2e%2e`.

### 5C. VM2 và Dashboard

```bash
~/ThucThi_Demo_CD1.sh evidence
```

**Lồng tiếng ngắn:** “Trên VM2, tôi đối chiếu alert Web với raw log vừa quan
sát trên VM1 trước khi mở từng rule trên Dashboard.”

Lần lượt dùng hai filter:

```text
agent.name:vms-production AND rule.id:100200
```

**Lồng tiếng ngắn:** “Rule 100200 nhận diện hành vi dò các đường dẫn nhạy cảm
trên Nginx và được xếp mức cảnh báo từ level 8.”

```text
agent.name:vms-production AND rule.id:100201
```

**Lồng tiếng ngắn:** “Rule 100201 nhận diện nỗ lực directory traversal. Mã HTTP
không thành công vẫn là bằng chứng về hành vi thử khai thác.”

Giữ hình rule ID, level, mô tả, MITRE và `full_log` chứa URL kiểm thử.

## Cảnh 6 — SSH thất bại có kiểm soát

### 6A. Kali

```bash
~/ThucThi_Demo_CD1.sh auth
```

**Lồng tiếng ngắn:** “Kịch bản tạo đúng tám lần đăng nhập thất bại bằng tài
khoản giả, đủ để kiểm tra rule brute force mà không thử mật khẩu thật.”

Script chỉ dùng user không tồn tại và mật khẩu giả, lặp đúng 8 lần; không thử
danh sách tài khoản hoặc mật khẩu thật.

### 6B. VM1, VM2 và Dashboard

VM1:

```bash
~/ThucThi_Demo_CD1.sh evidence
```

**Lồng tiếng ngắn:** “VM1 ghi nhận các lần xác thực thất bại trong auth.log với
IP nguồn và tên tài khoản không hợp lệ.”

VM2:

```bash
~/ThucThi_Demo_CD1.sh evidence
```

**Lồng tiếng ngắn:** “VM2 tổng hợp chuỗi đăng nhập thất bại để tạo cảnh báo brute
force thay vì xem từng lần thử như những sự kiện rời rạc.”

Dashboard:

```text
agent.name:vms-production AND rule.id:100100
```

**Lồng tiếng ngắn:** “Bộ lọc rule 100100 hiển thị cảnh báo SSH brute force,
được ánh xạ với kỹ thuật T1110 trong MITRE ATT&CK.”

Nếu rule tổng hợp chưa xuất hiện ngay, chờ 20–30 giây rồi Refresh. Không tăng số
lần thử vượt quá kịch bản chỉ để ép alert.

## Cảnh 7 — FIM và file nghi vấn an toàn

### 7A. VM1 tạo sự kiện

```bash
~/ThucThi_Demo_CD1.sh fim
```

**Lồng tiếng ngắn:** “Trên VM1, tôi thay đổi trang Web và tạo một tệp marker an
toàn để kiểm tra FIM; tệp này không chứa mã Web shell thực thi.”

Script tự sao lưu trang hiện tại, đổi nội dung marker và tạo `shell.php` chỉ
chứa chuỗi đánh dấu, không chứa mã Web shell thực thi.

### 7B. VM2 và Dashboard

```bash
~/ThucThi_Demo_CD1.sh evidence
```

**Lồng tiếng ngắn:** “Wazuh nhận sự kiện thay đổi Web root và sự kiện tạo tệp
nghi vấn, sau đó áp dụng hai rule FIM mức cao.”

Dashboard:

```text
agent.name:vms-production AND rule.id:(100202 OR 100203)
```

**Lồng tiếng ngắn:** “Bộ lọc này tổng hợp cả thay đổi nội dung Web và việc tạo
tệp có tên đáng ngờ trong cùng thư mục được bảo vệ.”

Nếu cú pháp Dashboard không nhận nhóm ngoặc, dùng lần lượt:

```text
agent.name:vms-production AND rule.id:100202
```

**Lồng tiếng ngắn:** “Rule 100202 cho thấy FIM phát hiện nội dung Web root đã
bị sửa đổi và lưu lại thông tin tệp liên quan.”

```text
agent.name:vms-production AND rule.id:100203
```

**Lồng tiếng ngắn:** “Rule 100203 tập trung vào tệp có tên nghi vấn được tạo
trong Web root, tương ứng với rủi ro Web shell ở mức phát hiện.”

Giữ hình đường dẫn `/var/www/html`, hành động added/modified, hash và rule level
12. Đây là cảnh mạnh nhất để chứng minh giám sát Host/OS.

## Cảnh 8 — Tổng hợp và phục hồi

Dashboard tổng hợp:

```text
agent.name:vms-production AND rule.id:(100100 OR 100200 OR 100201 OR 100202 OR 100203)
```

**Lồng tiếng ngắn:** “Bộ lọc tổng hợp cho thấy Wazuh đã bao phủ các lớp Network,
Web, xác thực và thay đổi hệ thống trong cùng một phiên demo.”

Quay nhanh danh sách alert theo thời gian, không cần mở lại từng alert.

Sau khi đã quay đủ bằng chứng, trên VM1:

```bash
~/ThucThi_Demo_CD1.sh cleanup
```

**Lồng tiếng ngắn:** “Sau khi thu đủ bằng chứng, tôi phục hồi trang Web ban đầu
và xóa tệp marker để đưa VM1 về trạng thái vận hành bình thường.”

Kiểm tra cuối:

```bash
curl -I http://127.0.0.1/
for service in nginx suricata wazuh-agent auditd; do
  printf '%-14s: ' "$service"
  systemctl is-active "$service"
done
```

**Lồng tiếng ngắn:** “Kiểm tra cuối xác nhận Nginx vẫn phản hồi và toàn bộ dịch
vụ giám sát tiếp tục hoạt động sau quá trình thực nghiệm.”

## 5. Lệnh cứu hộ khi Dashboard chậm

VM2 vẫn là bằng chứng gốc nếu Dashboard chưa index kịp:

```bash
sudo grep -E '"id":"(100100|100200|100201|100202|100203)"' \
  /var/ossec/logs/alerts/alerts.json | tail -n 20
sudo tail -n 40 /var/ossec/logs/ossec.log
```

**Lồng tiếng ngắn:** “Nếu Dashboard cập nhật chậm, alerts.json trên VM2 vẫn là
bằng chứng gốc để xác nhận rule đã được kích hoạt và lưu lại.”

Thứ tự xử lý khi thiếu alert:

1. Xác nhận request/raw log có trên VM1.
2. Xác nhận Agent `Active` trên VM2.
3. Xác nhận alert có trong `alerts.json`.
4. Đổi Dashboard về **Last 15 minutes**, xóa filter cũ rồi Refresh.

## 6. Checklist kết thúc CD1

- [ ] IP Kali/VM1/VM2 đúng và ping thông.
- [ ] Dịch vụ VM1/VM2 active; Agent `vms-production` Active.
- [ ] Chỉ show gói và cấu hình trọng tâm.
- [ ] Có hoạt động hợp lệ từ PC2 trước kiểm thử.
- [ ] Có Network raw log/alert.
- [ ] Có rule `100200` và `100201`.
- [ ] Có rule FIM `100202` hoặc `100203`.
- [ ] SSH thất bại chỉ chạy đúng phạm vi lab.
- [ ] Trang Web đã được phục hồi.
- [ ] Không lộ mật khẩu, token hoặc khóa riêng.
