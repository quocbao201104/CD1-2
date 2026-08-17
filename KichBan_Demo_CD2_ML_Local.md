# KỊCH BẢN QUAY DEMO CHUYÊN ĐỀ 2

## Phân tích cảnh báo bảo mật bằng học máy cục bộ

Kịch bản này dành cho video **không thu lời trực tiếp**. Chỉ quay lệnh, kết quả,
Wazuh Dashboard và Gotify; phần thuyết minh lồng sau. Không quay lại quá trình
cài đặt FastAPI, thư viện Python, Gotify hoặc WireGuard.

## 1. Luồng video ngắn gọn

```text
IP/dịch vụ bốn VM
  -> Wazuh integration VM2 -> VM3
  -> cấu hình an toàn + whitelist + DRY_RUN
  -> model/baseline cục bộ
  -> hoạt động hợp lệ từ PC2 và mẫu benign
  -> alert traversal thật Kali -> VM1 -> VM2 -> VM3
  -> incidents.md + ML + Gotify
  -> correlation Web -> OS (medium)
  -> correlation Network -> Web -> OS (high khi IP Network/Web khớp)
  -> verify deployment
```

Thời lượng đề xuất: **11–14 phút**.

## 2. Topology dùng trong video

| Thành phần | Địa chỉ | Vai trò |
|---|---:|---|
| PC2 Windows | `192.168.100.129`, VPN `10.66.0.3` | Quản trị, Dashboard và Gotify |
| Kali | `192.168.245.157` | Máy kiểm thử được phép |
| VM1 | `192.168.245.10` | Sinh log bảo mật |
| VM2 | `192.168.245.20` | Wazuh phát hiện và forward alert level ≥ 8 |
| VM3 | `192.168.245.30` | Analyzer FastAPI và ML |
| VM3 Bridged | Lấy theo runtime của `ens38` | Endpoint WireGuard; kiểm tra bằng `ip -br -4 addr show ens38` |
| VM3 WireGuard | `10.66.0.1` | Gotify riêng tư |

Luồng SOC chính chỉ dùng Host-only:

```text
Kali -> VM1 -> Wazuh Agent -> VM2 -> /analyze-alert VM3
```

Gotify chỉ mở qua VPN:

```text
PC2 10.66.0.3 -> VM3 10.66.0.1:8080
```

## 3. Chuẩn bị trước khi quay

### 3.1. Chép script

Từ PowerShell PC2:

```powershell
scp .\ThucThi_Demo_CD2.sh kali@192.168.245.157:/home/kali/
scp .\ThucThi_Demo_CD2.sh ubuntu@192.168.245.10:/home/ubuntu/
scp .\ThucThi_Demo_CD2.sh ubuntu@192.168.245.20:/home/ubuntu/
scp .\ThucThi_Demo_CD2.sh ubuntu@192.168.245.30:/home/ubuntu/
```

**Lồng tiếng ngắn:** “Tệp thực thi demo CD2 được chép tới bốn máy để các bước
kiểm tra và đối chiếu được thực hiện theo cùng một quy trình.”

Trên từng máy Linux:

```bash
chmod +x ~/ThucThi_Demo_CD2.sh
~/ThucThi_Demo_CD2.sh --help
```

**Lồng tiếng ngắn:** “Tôi cấp quyền chạy và kiểm tra các stage trước khi bắt
đầu. Mỗi stage đã được giới hạn theo đúng vai trò của từng máy.”

### 3.2. Bố trí cửa sổ

1. Kali terminal.
2. VM2 terminal.
3. Hai terminal VM3: một cửa sổ theo dõi realtime, một cửa sổ chạy lệnh.
4. Chrome tab Wazuh Dashboard `https://192.168.245.20`.
5. Chrome tab Gotify `http://10.66.0.1:8080` sau khi bật WireGuard.

Chọn Dashboard **Last 15 minutes**. Không mở `.env` toàn bộ; không quay app
token, client token, private key hoặc mật khẩu.

## 4. Thứ tự quay chính

## Cảnh 1 — IP và dịch vụ bốn máy ảo

Chạy cùng lệnh trên Kali, VM1, VM2 rồi VM3:

```bash
~/ThucThi_Demo_CD2.sh preflight
```

**Lồng tiếng ngắn:** “Bước đầu xác nhận bốn máy liên lạc qua mạng Host-only và
các dịch vụ từ thu thập, phát hiện đến phân tích đều sẵn sàng.”

Chỉ giữ các bằng chứng sau:

- Kali ping được `.10`, `.20`, `.30` và gọi `/health` thành công.
- VM1 có Agent và các dịch vụ sinh log `active`.
- VM2 có Wazuh stack `active`, Agent `vms-production` ID `002` là `Active`.
- VM2 gọi `http://192.168.245.30:8000/health` nhận `{"status":"ok"}`.
- VM3 có `vms-analyzer`, `gotify`, `wg-quick@wg0` active.
- VM3: `ens33=.30`, `wg0=10.66.0.1`; địa chỉ Bridged `ens38` lấy theo runtime tại thời điểm quay.

Không cần đọc toàn bộ route table hoặc danh sách package Python.

## Cảnh 2 — Cấu hình nối VM2 với VM3

### 2A. VM2

```bash
~/ThucThi_Demo_CD2.sh config
```

**Lồng tiếng ngắn:** “Wazuh trên VM2 chỉ chuyển các alert từ level 8 trở lên
sang endpoint phân tích của VM3 dưới định dạng JSON.”

Giữ hình ở đúng các trường:

```text
name        = custom-ai-soc
hook_url    = http://192.168.245.30:8000/analyze-alert
level       = 8
alert_format= json
```

**Lồng tiếng ngắn:** “Bốn trường này xác định rõ tên integration, địa chỉ nhận,
ngưỡng cảnh báo và định dạng dữ liệu giữa VM2 với VM3.”

Và file integration có owner `root:wazuh`, mode thực thi `750`.

### 2B. VM3

```bash
~/ThucThi_Demo_CD2.sh config
```

**Lồng tiếng ngắn:** “VM3 vận hành ở chế độ DRY RUN, dùng whitelist cho hoạt
động quản trị hợp lệ và chỉ công bố Gotify qua đường hầm WireGuard riêng.”

Giữ hình:

- `DRY_RUN=true`.
- `GOTIFY_URL=http://10.66.0.1:8080`.
- `GOTIFY_MIN_RISK=60`.
- Chỉ hiện `GOTIFY_APP_TOKEN_SET=yes`, không hiện token.
- Whitelist có IP quản trị VMnet1 `192.168.245.1`.
- API `:8000`, Gotify chỉ bind `10.66.0.1:8080`, WireGuard UDP `51820`.
- Hai peer VPN `10.66.0.2/32` và `10.66.0.3/32`; private key luôn hidden.

## Cảnh 3 — Model và baseline cục bộ

Trên VM3:

```bash
~/ThucThi_Demo_CD2.sh model
```

**Lồng tiếng ngắn:** “Mô hình IsolationForest đã được huấn luyện và lưu cục bộ,
kèm metadata để kiểm tra số mẫu baseline, đặc trưng và tham số mô hình.”

Giữ hình các ý:

```text
model_type       = IsolationForest
baseline_rows    = 16
baseline_cover   = {'network': 5, 'web': 5, 'os': 3, 'auth': 3}
model_file       = True
feature_count    = 9
n_estimators     = 200
```

**Lồng tiếng ngắn:** “Kết quả cho thấy mô hình dùng 16 mẫu baseline bao phủ
Network, Web, Auth và OS, 9 đặc trưng và 200 cây; đây là mô hình thử nghiệm
chức năng trong phạm vi lab.”

Nếu metadata dùng tên trường khác nhưng file/model vẫn hợp lệ, lấy kết quả
`verify_deployment.py` ở Cảnh 8 làm bằng chứng chính. Không gọi bộ mẫu lab là
độ chính xác production.

## Cảnh 4 — Hoạt động hợp lệ và whitelist

### 4A. PC2 thao tác VM1 bằng user được phép

Trong PowerShell PC2:

```powershell
curl.exe -I http://192.168.245.10/
ssh ubuntu@192.168.245.10 "whoami; hostname; id"
```

**Lồng tiếng ngắn:** “PC2 thực hiện truy cập Web và SSH hợp lệ bằng tài khoản
được phép, tạo mốc bình thường trước khi phát sinh cảnh báo tấn công.”

Mật khẩu nhập tương tác, không hiển thị khi quay. VM1 nhìn thấy nguồn quản trị
qua adapter Host-only `192.168.245.1`, trùng IP trong whitelist VM3.

### 4B. VM3 phân tích mẫu benign

```bash
~/ThucThi_Demo_CD2.sh benign
```

**Lồng tiếng ngắn:** “VM3 phân tích một mẫu đăng nhập hợp lệ từ IP trong
whitelist. Sự kiện vẫn được ghi nhận nhưng không đạt ngưỡng cảnh báo Gotify.”

Giữ hình:

- Input là `normal_ssh_login.json` từ IP whitelist.
- Kết quả được phân tích và ghi cục bộ.
- Risk không đạt ngưỡng gửi Gotify.

Mở Gotify và cho thấy chưa có cảnh báo High mới do hoạt động benign này.

## Cảnh 5 — Chuẩn bị theo dõi live

Terminal VM3 số 1:

```bash
~/ThucThi_Demo_CD2.sh watch
```

**Lồng tiếng ngắn:** “Terminal này theo dõi dịch vụ Analyzer theo thời gian thực
để chứng minh VM3 nhận request trực tiếp từ Wazuh integration.”

Giữ cửa sổ này chạy. `Ctrl+C` sau khi đã thấy `POST /analyze-alert`.

Ở terminal VM3 số 2:

```bash
tail -n 5 /home/ubuntu/vms-analyzer/incidents.md
```

**Lồng tiếng ngắn:** “Terminal thứ hai ghi nhận trạng thái incident trước khi
chạy kiểm thử, giúp xác định chính xác bản ghi mới được tạo.”

## Cảnh 6 — Alert thật từ CD1 đi qua toàn pipeline

### 6A. Kali tạo traversal attempt

```bash
~/ThucThi_Demo_CD2.sh live-attack
```

**Lồng tiếng ngắn:** “Kali gửi một nỗ lực directory traversal tới VM1. Request
này sẽ đi qua toàn bộ chuỗi VM1, Wazuh VM2 và Analyzer VM3.”

HTTP `400/404` không phải lỗi demo. Đây là **nỗ lực traversal bị phát hiện**,
không phải bằng chứng đọc thành công file hệ thống.

### 6B. VM2 đối chiếu Wazuh

```bash
~/ThucThi_Demo_CD2.sh evidence
```

**Lồng tiếng ngắn:** “VM2 đã tạo alert Wazuh thật từ nhật ký Web của VM1 và
chuyển alert đủ level sang VM3 để phân tích tiếp.”

Dashboard filter:

```text
agent.name:vms-production AND rule.id:100201
```

**Lồng tiếng ngắn:** “Bộ lọc này cô lập rule traversal 100201 trên đúng Agent
vms-production để đối chiếu level, MITRE và request gốc.”

Giữ hình rule `100201`, level `10`, MITRE `T1190` và URL trong `full_log`.

### 6C. VM3 đối chiếu phân tích

```bash
~/ThucThi_Demo_CD2.sh evidence
```

**Lồng tiếng ngắn:** “VM3 ghi nhận request POST, tạo nhãn phân tích, chấm điểm rủi
ro, bổ sung kết quả IsolationForest và sinh playbook xử lý.”

Giữ hình các trường trong incident mới nhất:

- Incident type và severity.
- Base risk, tổng risk.
- `IsolationForest`, `is_anomaly`, `anomaly_score`, `risk_delta`.
- Correlation đang đơn lẻ hoặc chưa đủ chuỗi.
- Playbook và action ở chế độ `DRY_RUN`/proposed.

Phát biểu chính xác khi lồng tiếng: classifier, risk và correlation là logic
deterministic; IsolationForest chỉ bổ sung đánh giá bất thường và risk delta.

### 6D. Gotify trên PC2

Bật tunnel `vms-analyzer`, mở:

```text
http://10.66.0.1:8080
```

**Lồng tiếng ngắn:** “Thông báo được xem qua Gotify tự host trên mạng VPN riêng.
Gotify chỉ là kênh chuyển thông tin, không tham gia quyết định phân tích.”

Giữ hình thông báo High/Critical có icon, risk, ML, correlation, phân tích và
khuyến nghị. Gotify là lớp thông báo tự host, không tham gia ra quyết định.

## Cảnh 7 — Kiểm chứng hai mức correlation

Cảnh này gồm **hai lượt độc lập**. Trước mỗi lượt, trên VM3 chạy
`~/ThucThi_Demo_CD2.sh reset` để xóa correlation buffer. Không restart Analyzer
giữa các bước của cùng một lượt.

### 7A. Web → OS: Suspected Web Compromise / medium

Mục tiêu của lượt thứ nhất là chứng minh Network không còn là điều kiện bắt buộc
để hình thành một timeline Web-compromise.

1. Trên VM3 chạy:

```bash
~/ThucThi_Demo_CD2.sh reset
```

2. Trên Kali tạo Web Traversal:

```bash
~/ThucThi_Demo_CD1.sh web
```

3. Trên VM2 xác nhận alert Web của `vms-production`, ưu tiên rule `100201`.

4. Trên VM1 tạo thay đổi Web root/FIM:

```bash
~/ThucThi_Demo_CD1.sh fim
```

5. Trên VM2 xác nhận alert OS/FIM tương ứng, ưu tiên rule `100202`.

6. Trên VM3 chạy:

```bash
~/ThucThi_Demo_CD2.sh evidence
```

Giữ hình các trường:

```text
incident_type         = Suspected Web Compromise
sources               = web, os
has_network_precursor = false
confidence            = medium
src_ip_match          = unknown
observed_ips           = Web=<IP client hoặc chưa ghi nhận>, OS/FIM=<không áp dụng>
IP nguồn alert hiện tại = <không bị mượn từ precursor>
actions               = proposed / DRY_RUN
```

**Lồng tiếng ngắn:** “Khi Web được quan sát trước thay đổi OS/FIM trên cùng máy
chủ và trong cửa sổ 600 giây, Analyzer hình thành Suspected Web Compromise với
độ tin cậy trung bình. Không có network precursor nên hệ thống không nâng kết
quả lên mức cao; policy giữ mức này tối đa High, không diễn giải như compromise
đã xác nhận.”

Không phát biểu rằng máy chủ đã chắc chắn bị xâm nhập. Đây là nhãn phân tích hỗ
trợ ưu tiên điều tra.

### 7B. Network → Web → OS: Possible Server Compromise / high

Lượt thứ hai kiểm tra việc Network precursor làm tăng độ tin cậy của timeline.
Phải reset buffer trước khi bắt đầu:

```bash
~/ThucThi_Demo_CD2.sh reset
```

Sau đó thực hiện đúng thứ tự:

1. Trên Kali:

```bash
~/ThucThi_Demo_CD1.sh network
```

2. Trên VM2 xác nhận Dashboard có alert `rule.id:100106` trên
`agent.name:vms-production`.

3. Trên Kali:

```bash
~/ThucThi_Demo_CD1.sh web
```

4. Trên VM2 xác nhận alert Web và kiểm tra IP nguồn của Network/Web.

5. Trên VM1:

```bash
~/ThucThi_Demo_CD1.sh fim
```

6. Trên VM3:

```bash
~/ThucThi_Demo_CD2.sh evidence
```

Kết quả chỉ được nâng lên mức high khi Network và Web có IP nguồn khớp. Giữ hình:

```text
incident_type         = Possible Server Compromise
sources               = network, web, os
has_network_precursor = true
confidence            = high
src_ip_match          = true
risk                  = Critical / high score
observed_ips           = Network=<IP Kali>, Web=<IP Kali>, OS/FIM=<không áp dụng>
actions               = proposed / DRY_RUN
```

**Lồng tiếng ngắn:** “Network precursor xuất hiện trước Web và có IP nguồn khớp
với Web, vì vậy khi sự kiện OS/FIM tới, Analyzer nâng timeline thành Possible
Server Compromise với độ tin cậy cao. IP khớp chỉ là bằng chứng liên kết giữa
Network và Web, không chứng minh danh tính hoặc cùng một tác nhân.”

Nếu có Network precursor nhưng IP Network/Web thiếu hoặc không khớp, kết quả
không được nâng lên high mà giữ:

```text
incident_type = Suspected Web Compromise
confidence    = medium
src_ip_match  = unknown hoặc false
```

`DRY_RUN=true` nên hệ thống chỉ tạo playbook và hành động đề xuất, không chặn IP
hoặc thay đổi VM1.

### 7C. Yêu cầu về live và replay

Hai lượt trên ưu tiên sử dụng alert live đi theo chuỗi:

```text
Kali -> VM1 -> Wazuh VM2 -> Analyzer VM3
```

Rule `100106` trên VM2 được dùng để đưa alert Suricata port-scan phù hợp lên mức
có thể chuyển tiếp sang VM3. Nếu phải dùng direct POST hoặc sample để kiểm tra
logic, phải ghi rõ đó là **replay/functional test** và không dùng kết quả đó để
mô tả một full live end-to-end flow.

Mở Gotify sau mỗi lượt nếu risk đạt ngưỡng để đối chiếu nhãn phân tích,
confidence, chuỗi evidence và trạng thái IP. Gotify chỉ là lớp thông báo, không
tham gia quyết định correlation.

## Cảnh 8 — Xác minh deployment ngắn gọn

Trên VM3:

```bash
~/ThucThi_Demo_CD2.sh tests
```

**Lồng tiếng ngắn:** “Cuối cùng, tôi chạy bộ xác minh deployment để kiểm tra sự
khớp nhau giữa baseline, model, metadata và cấu hình đang triển khai.”

Giữ dòng cuối:

```text
ALL_CHECKS_PASSED=True
```

**Lồng tiếng ngắn:** “Dòng kết quả này xác nhận toàn bộ kiểm tra chức năng của
deployment hiện tại đã đạt trong môi trường lab.”

Không cần quay toàn bộ unit test và offline test vì phần cài đặt đã có video
riêng. Nếu giảng viên hỏi sâu, chạy ngoài cảnh chính:

```bash
cd /home/ubuntu/vms-analyzer
source .venv/bin/activate
python -m unittest discover -s tests -v
python test_offline.py
```

**Lồng tiếng ngắn:** “Các unit test và offline test mở rộng được giữ làm bằng
chứng bổ sung khi cần kiểm tra sâu hơn ngoài luồng video chính.”

## 5. Lệnh cứu hộ khi luồng live chậm

### VM2 đã có alert nhưng VM3 chưa nhận

```bash
sudo grep '"id":"100201"' /var/ossec/logs/alerts/alerts.json | tail -n 5
sudo grep -nA8 -B2 '<integration>' /var/ossec/etc/ossec.conf
sudo grep -Ei 'custom-ai-soc|integrat|error' /var/ossec/logs/ossec.log | tail -n 30
curl -fsS http://192.168.245.30:8000/health
```

**Lồng tiếng ngắn:** “Nếu luồng live chậm, các lệnh này xác định alert đã tồn
tại trên VM2, integration đúng cấu hình và API VM3 còn phản hồi.”

### VM3 kiểm tra API và incident

```bash
sudo systemctl is-active vms-analyzer
sudo journalctl -u vms-analyzer --since '10 minutes ago' --no-pager | tail -n 50
tail -n 50 /home/ubuntu/vms-analyzer/incidents.md
```

**Lồng tiếng ngắn:** “Nhóm kiểm tra này đối chiếu trạng thái dịch vụ, nhật ký
API và incident cục bộ để xác định cảnh báo đã tới VM3 hay chưa.”

### Gotify không hiện thông báo

```bash
sudo systemctl is-active gotify wg-quick@wg0
sudo wg show wg0
sudo ss -lntup | grep -E '10\.66\.0\.1:8080|:51820'
```

**Lồng tiếng ngắn:** “Nếu chưa thấy thông báo, tôi kiểm tra Gotify, WireGuard,
peer handshake và các cổng riêng tư trước khi kiểm tra lại ngưỡng risk.”

Trên PC2 kiểm tra tunnel đang Active rồi mới mở `http://10.66.0.1:8080`.
Gotify chỉ nhận incident có risk đạt `GOTIFY_MIN_RISK=60`.

## 6. Checklist kết thúc CD2

- [ ] Bốn máy có đúng IP và kết nối Host-only thông.
- [ ] VM2 gọi VM3 `/health` thành công.
- [ ] Integration Wazuh level 8 và hook URL đúng.
- [ ] Chỉ show cấu hình không nhạy cảm, whitelist và `DRY_RUN=true`.
- [ ] Model/baseline/artifact cục bộ tồn tại.
- [ ] Có hoạt động hợp lệ trước khi chạy attack.
- [ ] Có alert thật `100201` từ Kali qua VM1 và VM2 sang VM3.
- [ ] `incidents.md` có classifier, risk, ML, correlation và playbook.
- [ ] Gotify truy cập qua WireGuard và có thông báo theo ngưỡng.
- [ ] Lượt correlation `web -> os` tạo `Suspected Web Compromise`, `confidence=medium`.
- [ ] Lượt `network -> web -> os` có alert VM2 rule `100106` và chỉ lên `high` khi `src_ip_match=true`.
- [ ] `verify_deployment.py` trả `ALL_CHECKS_PASSED=True`.
- [ ] Không nói anomaly score là xác suất bị xâm nhập.
- [ ] Không lộ token, mật khẩu hoặc private key.
