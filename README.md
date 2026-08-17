# Nghiên cứu và triển khai hệ thống tương quan và chấm điểm rủi ro cảnh báo bảo mật máy chủ Linux có hỗ trợ học máy cục bộ

> **Linux Security Monitoring + Wazuh SIEM + Local ML Alert Analyzer**  
> Mô hình thực nghiệm phục vụ Chuyên đề 1 và Chuyên đề 2 trong môi trường phòng thí nghiệm có kiểm soát.

## 1. Giới thiệu

Repository này chứa mã nguồn, cấu hình, script cài đặt, bộ kiểm thử và tài liệu thực nghiệm cho hệ thống giám sát và phân tích cảnh báo bảo mật máy chủ Linux theo kiến trúc nhiều lớp.

Hệ thống được chia thành hai phạm vi chính:

- **Chuyên đề 1 (CD1):** xây dựng lớp giám sát và phát hiện trên máy chủ Linux bằng Suricata, Nginx, OpenSSH, auditd, Wazuh Agent và Wazuh all-in-one.
- **Chuyên đề 2 (CD2):** bổ sung lớp phân tích sau SIEM trên VM3 để chuẩn hóa cảnh báo, phân loại, tương quan theo timeline, chấm điểm rủi ro, bổ sung tín hiệu bất thường bằng IsolationForest, giải thích kết quả và gửi thông báo nội bộ.

VM3 **không thay thế Wazuh** và không đọc trực tiếp toàn bộ log thô trên VM1. Wazuh trên VM2 vẫn giữ vai trò thu thập, phát hiện, lưu trữ và hiển thị cảnh báo; VM3 chỉ xử lý các alert được VM2 lựa chọn và chuyển tiếp.

---

## 2. Mục tiêu kỹ thuật

Hệ thống hướng đến các mục tiêu sau:

1. Thu thập và phát hiện sự kiện bảo mật từ nhiều nguồn trên máy chủ Linux.
2. Chuẩn hóa alert Wazuh về một cấu trúc dùng chung cho lớp phân tích.
3. Phân loại cảnh báo bằng logic deterministic và ánh xạ MITRE ATT&CK theo bằng chứng quan sát được.
4. Tương quan sự kiện theo cùng máy chủ, thứ tự thời gian và cửa sổ 600 giây.
5. Phân biệt hai mức correlation:
   - `Web -> OS/host` → `Suspected Web Compromise`, confidence `medium`.
   - `Network -> Web -> OS/host` → `Possible Server Compromise`, confidence `high` **chỉ khi IP nguồn của Network và Web khớp**.
6. Chấm điểm rủi ro theo luật và ngữ cảnh, có thể truy vết.
7. Sử dụng IsolationForest như tín hiệu hỗ trợ, không thay thế logic deterministic.
8. Sinh giải thích, playbook, ghi `incidents.md` và gửi Gotify theo ngưỡng.
9. Duy trì `DRY_RUN=true` để mọi hành động phản ứng chỉ ở dạng đề xuất.
10. Bảo vệ kênh quản trị bằng WireGuard và UFW trong phạm vi lab.

---

## 3. Kiến trúc tổng thể

```text
                         MẠNG LAB HOST-ONLY
                   192.168.245.0/24 (ví dụ)

     +-------------------+
     | Kali / Attacker   |
     | vms-attacker      |
     +---------+---------+
               |
               | traffic kiểm thử hợp lệ trong lab
               v
+--------------+--------------+
| VM1 - vms-production        |
| Linux server cần bảo vệ     |
|                              |
| - Nginx                     |
| - OpenSSH / auth.log        |
| - Suricata IDS / eve.json   |
| - auditd                    |
| - Wazuh Agent               |
| - File Integrity Monitoring |
+--------------+--------------+
               |
               | Wazuh Agent
               v
+--------------+--------------+
| VM2 - vms-soc / monitor     |
| Wazuh all-in-one            |
|                              |
| - Wazuh Manager             |
| - Wazuh Indexer             |
| - Wazuh Dashboard           |
| - Local rules               |
| - custom-ai-soc integration |
+--------------+--------------+
               |
               | HTTP POST /analyze-alert
               | alert level >= ngưỡng cấu hình
               v
+--------------+--------------+
| VM3 - vms-analyzer          |
| Local Security Analyzer     |
|                              |
| FastAPI                     |
|   -> Normalizer             |
|   -> Classifier             |
|   -> Correlation            |
|   -> Risk Scoring           |
|   -> IsolationForest        |
|   -> Explainer              |
|   -> Playbook / Policy      |
|   -> incidents.md           |
|   -> Gotify                 |
+--------------+--------------+
               |
               | WireGuard
               v
        Máy quản trị / Client
```

### Phân tách trách nhiệm

| Thành phần | Vai trò chính |
|---|---|
| Kali / `vms-attacker` | Tạo traffic kiểm thử trong môi trường được phép |
| VM1 / `vms-production` | Máy chủ Linux cần bảo vệ, phát sinh log và sự kiện |
| VM2 / `vms-monitor` | SIEM Wazuh: thu thập, phát hiện, lưu trữ, hiển thị và chuyển alert |
| VM3 / `vms-analyzer` | Phân tích sau SIEM: correlation, risk, local ML, giải thích và thông báo |
| Gotify | Kênh thông báo; không tham gia quyết định phân tích |
| WireGuard + UFW | Giới hạn và bảo vệ kênh truy cập quản trị |

---

## 4. Nguồn dữ liệu bảo mật

Hệ thống sử dụng bốn nhóm nguồn chính:

| Nhóm | Nguồn | Ví dụ hành vi |
|---|---|---|
| `network` | Suricata EVE JSON | Port scan, network reconnaissance |
| `web` | Nginx access/error log | Sensitive path scan, traversal attempt |
| `auth` | SSH/auth log | Brute force, đăng nhập đáng chú ý |
| `os` | auditd, FIM, Wazuh rules | Web root modified, account/key change, privileged command |

Một alert đơn lẻ chỉ là tín hiệu quan sát được. Hệ thống không mặc định coi alert là một incident đã được xác nhận.

---

## 5. Cơ chế correlation

Correlation được giữ theo **cùng máy chủ**, **đúng thứ tự evidence đến Analyzer** và trong cửa sổ tối đa **600 giây**.

Khi một event thuộc nhóm `os/host` xuất hiện, Correlator truy ngược buffer để tìm Web precursor trên cùng server. Nếu có, hệ thống tiếp tục kiểm tra Network precursor xảy ra trước Web.

### Ma trận quyết định

| Evidence quan sát được | Nhãn phân tích | Confidence |
|---|---|---|
| `Web -> OS/host` | `Suspected Web Compromise` | `medium` |
| `Network -> Web -> OS/host`, IP Network/Web khớp | `Possible Server Compromise` | `high` |
| Có Network nhưng IP Network/Web thiếu hoặc không khớp | `Suspected Web Compromise` | `medium` |
| Network + Web nhưng chưa có OS/host | Không tạo compromise correlation | — |
| Network + OS nhưng không có Web | Không tạo Web-compromise correlation | — |
| Khác server, sai thứ tự hoặc ngoài TTL | Không correlation | — |

Correlation trả về các metadata phục vụ truy vết như:

```text
incident_type
confidence
sources
has_network_precursor
src_ip_match
observed_ips
server_ip
precursor_incidents
time_delta_web_to_os
time_delta_network_to_os
```

> `src_ip_match=true` chỉ tăng bằng chứng liên kết Network/Web, **không chứng minh danh tính hoặc quy kết tuyệt đối cùng một tác nhân**.

`server_ip` là IP của máy chủ/agent được giám sát. `srcip` là IP nguồn của
**alert hiện tại**; nó không bị ghi đè bằng IP của precursor trong correlation.
`observed_ips` chỉ là bảng bằng chứng theo từng lớp Network/Web/OS để điều tra.

---

## 6. Risk scoring và MITRE ATT&CK

Risk scoring là logic deterministic dùng để ưu tiên điều tra, **không phải xác suất tấn công**.

Điểm được hình thành từ:

- taxonomy / loại cảnh báo;
- địa chỉ IP ngoài whitelist;
- thời điểm ngoài giờ;
- evidence correlation;
- `risk_delta` từ ML.

Correlation `medium` không tự động ép điểm lên 100. Nhánh nâng điểm mạnh chỉ áp dụng cho `Possible Server Compromise` có confidence `high`. `Suspected Web Compromise` confidence `medium` được chặn ở `79` (High), nên không bị hiển thị như một compromise Critical.

MITRE ATT&CK được ánh xạ theo evidence thực tế. Hệ thống không gán một kỹ thuật chỉ vì correlation tồn tại; tên tệp nghi vấn hoặc FIM thay đổi web root đơn lẻ không tự khẳng định Web Shell/Defacement tại VM3 khi chưa có bằng chứng nội dung hoặc thực thi.

---

## 7. Học máy cục bộ

VM3 sử dụng `IsolationForest` của scikit-learn để bổ sung tín hiệu bất thường.

### Nguyên tắc

- ML chạy hoàn toàn cục bộ trên VM3.
- Không gọi LLM hoặc API AI bên ngoài.
- ML không tự tạo nhãn compromise.
- ML chỉ sinh `anomaly_score`, `is_anomaly` và `risk_delta`.
- `risk_delta` bị giới hạn để không lấn át rule/correlation deterministic; notifier phân biệt rõ điểm ML đề xuất và điểm ML thực sự áp dụng sau policy cap.
- Nếu model artifact không sử dụng được, hệ thống có cơ chế fallback và thể hiện nguồn model để quản trị viên nhận biết.

### Bộ đặc trưng hiện hành

Vector gồm 9 đặc trưng:

1. `source_network`
2. `source_web`
3. `source_os`
4. `source_auth`
5. `incident_weight`
6. `base_risk`
7. `correlated`
8. `has_network_precursor`
9. `has_srcip`

### Baseline lab hiện hành

- `baseline_rows = 16`
- `baseline_unique = 7`
- Coverage:
  - Network: 5
  - Web: 5
  - Auth: 3
  - OS: 3
- Model: `IsolationForest`
- `n_estimators = 200`
- `contamination = auto`
- `random_state = 42`

Artifact model được lưu cục bộ và kiểm tra tính nhất quán với baseline trước khi sử dụng.

> Các kết quả đánh giá model trong repository chỉ là **kiểm thử chức năng trên tập dữ liệu lab nhỏ**, không đại diện cho accuracy hoặc khả năng khái quát trong production.

---

## 8. Cấu trúc repository

```text
CD1-2/
├── ml-soc-source/
│   ├── vms-attacker/
│   │   └── kich-ban-tan-cong-cd1.md
│   │
│   ├── vms-production/
│   │   ├── install_vm1_cd1.sh
│   │   ├── nginx_wazuh_snippet.xml
│   │   ├── ossec_fim_snippet.xml
│   │   ├── suricata_wazuh_snippet.xml
│   │   ├── suricata_eve_config.py
│   │   ├── soc.rules
│   │   └── tests/
│   │
│   ├── vms-monitor/
│   │   ├── install_vm2_cd1.sh
│   │   └── wazuh/
│   │       ├── local_rules.xml
│   │       ├── integration_snippet.xml
│   │       ├── custom-ai-soc
│   │       └── tests/
│   │
│   ├── vms-analyzer/
│   │   ├── app/
│   │   │   ├── main.py
│   │   │   ├── normalizer.py
│   │   │   ├── classifier.py
│   │   │   ├── correlation.py
│   │   │   ├── scoring.py
│   │   │   ├── ml_anomaly.py
│   │   │   ├── explainer.py
│   │   │   ├── playbook.py
│   │   │   ├── notifier.py
│   │   │   └── policy.py
│   │   ├── data/
│   │   ├── tests/
│   │   ├── collect_baseline.py
│   │   ├── train_model.py
│   │   ├── evaluate_model.py
│   │   ├── verify_deployment.py
│   │   ├── test_offline.py
│   │   ├── install_vm3_cd2.sh
│   │   ├── requirements.txt
│   │   └── .env.example
│   │
│   └── README.md
│
├── KichBan_Demo_CD1_Wazuh.md
├── KichBan_Demo_CD2_ML_Local.md
├── QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md
├── KiemThu_Replay_Correlation_CD2.sh
├── ThucThi_Demo_CD1.sh
├── ThucThi_Demo_CD2.sh
└── README.md
```

---

## 9. Mô hình mạng lab tham khảo

Dải Host-only được sử dụng trong tài liệu thực nghiệm:

| Thành phần | IP Host-only tham khảo |
|---|---|
| VM1 `vms-production` | `192.168.245.10` |
| VM2 `vms-soc` | `192.168.245.20` |
| VM3 `vms-analyzer` | `192.168.245.30` |
| Kali / attacker | Có thể thay đổi theo DHCP hoặc cấu hình lab |
| WireGuard VM3 | `10.66.0.1/24` |

Địa chỉ Bridged của VM3 có thể thay đổi theo Wi-Fi/LAN và không nên hard-code trong tài liệu triển khai tổng quát.

---

## 10. Yêu cầu môi trường

### Phần mềm chính

- VMware Workstation/VMware tương đương
- Ubuntu Server cho VM1, VM2 và VM3
- Kali Linux cho máy kiểm thử
- Wazuh all-in-one trên VM2
- Python 3 trên VM3
- FastAPI + Uvicorn
- scikit-learn + joblib
- Gotify
- WireGuard
- UFW

### Tài nguyên VM tham khảo

| VM | vCPU | RAM | Disk |
|---|---:|---:|---:|
| VM1 | 1–2 | 2 GB | 25 GB |
| VM2 | 4 | 8 GB | 50 GB |
| VM3 | 1–2 | 2 GB | 20 GB |

VM2 nên được ưu tiên tài nguyên vì chạy Wazuh Manager, Indexer và Dashboard.

---

## 11. Cài đặt nhanh

### 11.1. Clone repository

```bash
git clone https://github.com/quocbao201104/CD1-2.git
cd CD1-2
```

### 11.2. Triển khai VM2 trước

Trên **VM2**, từ thư mục gốc của repository:

```bash
cd ml-soc-source/vms-monitor
sudo bash install_vm2_cd1.sh
```

Sau khi Wazuh được cài đặt, lưu lại thông tin quản trị Dashboard và xác nhận các service hoạt động.

### 11.3. Triển khai VM1

Trên **VM1**, từ thư mục gốc của repository:

```bash
cd ml-soc-source/vms-production
sudo bash install_vm1_cd1.sh 192.168.245.20
```

Có thể truyền thêm interface và subnet lab nếu cần:

```bash
sudo bash install_vm1_cd1.sh 192.168.245.20 ens33 192.168.245.0/24
```

Kiểm tra:

```bash
sudo systemctl status nginx
sudo systemctl status suricata
sudo systemctl status wazuh-agent
curl -I http://127.0.0.1/
```

### 11.4. Cài local rules trên VM2

Trên **VM2**, từ thư mục gốc của repository:

```bash
sudo cp ml-soc-source/vms-monitor/wazuh/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml

sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 640 /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Rule local hiện hành có nhánh nâng các alert Suricata liên quan `ET SCAN`, `Nmap` hoặc `port scan` lên mức phù hợp để phục vụ luồng phát hiện/correlation của lab; các alert Suricata không liên quan không bị nâng hàng loạt.

Có thể kiểm tra rule bằng:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

---

## 12. Triển khai Analyzer trên VM3

### Cách 1 — dùng installer của repository

Trên **VM3**, từ thư mục gốc của repository:

```bash
cd ml-soc-source/vms-analyzer
sudo bash install_vm3_cd2.sh
```

### Cách 2 — chạy thủ công để phát triển/test

```bash
cd ml-soc-source/vms-analyzer

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
```

Không commit file `.env` thật lên GitHub.

Khởi động API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Kiểm tra:

```bash
curl http://127.0.0.1:8000/health
```

Kết quả mong đợi:

```json
{"status":"ok"}
```

---

## 13. Cấu hình `.env`

Mẫu cấu hình:

```env
DRY_RUN=true

WHITELIST_PATH=data/whitelist.json
BASELINE_PATH=data/baseline.json
MODEL_PATH=data/isolation_forest.joblib
HOST_MAP_PATH=data/host_map.json

GOTIFY_URL=http://10.66.0.1:8080
GOTIFY_APP_TOKEN=
GOTIFY_MIN_RISK=60

VM1_HOST=soc-responder@192.168.245.10
VM1_KEY=~/.ssh/soc_action_key
```

### Lưu ý

- Giữ `DRY_RUN=true` trong quá trình thực nghiệm và báo cáo.
- Không commit token, password, private key hoặc file `.env`.
- Nếu chưa cấu hình Gotify, để trống `GOTIFY_APP_TOKEN`; hệ thống vẫn ghi local vào `incidents.md`.
- `GOTIFY_MIN_RISK=60` là ngưỡng gửi thông báo mặc định trong lab.

---

## 14. Tích hợp Wazuh VM2 -> VM3

Repository cung cấp:

```text
ml-soc-source/vms-monitor/wazuh/custom-ai-soc
ml-soc-source/vms-monitor/wazuh/integration_snippet.xml
```

Custom integration chuyển các trường cần thiết của alert Wazuh đến:

```text
POST http://<IP_VM3>:8000/analyze-alert
```

Script integration cần quyền thực thi phù hợp, ví dụ:

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-ai-soc
sudo chmod 750 /var/ossec/integrations/custom-ai-soc
```

Sau khi cập nhật cấu hình Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

Ngưỡng forward được cấu hình tại VM2. Alert dưới ngưỡng vẫn có thể tồn tại trong Wazuh nhưng sẽ không đến Analyzer, vì vậy điều này có thể ảnh hưởng đến lượng evidence correlation quan sát được trên VM3.

---

## 15. API Analyzer

### `GET /health`

Kiểm tra trạng thái API:

```bash
curl http://127.0.0.1:8000/health
```

### `POST /analyze-alert`

Ví dụ gửi sample có sẵn:

```bash
curl -X POST http://127.0.0.1:8000/analyze-alert \
  -H "Content-Type: application/json" \
  -d @data/samples/brute_force.json
```

Các sample khác:

```bash
curl -X POST http://127.0.0.1:8000/analyze-alert \
  -H "Content-Type: application/json" \
  -d @data/samples/nginx_sensitive_path.json

curl -X POST http://127.0.0.1:8000/analyze-alert \
  -H "Content-Type: application/json" \
  -d @data/samples/webroot_modified.json
```

Đầu ra của pipeline có thể bao gồm:

```text
incident_type
severity
risk_score
base_risk_score
mitre
correlation
ml
analysis
playbook
```

---

## 16. Baseline và model

### Thu thập/tạo baseline

```bash
cd ml-soc-source/vms-analyzer

python3 collect_baseline.py \
  --input data/baseline_samples \
  --out data/baseline.json
```

### Huấn luyện model

```bash
python3 train_model.py \
  --baseline data/baseline.json \
  --model data/isolation_forest.joblib \
  --metadata data/isolation_forest_metadata.json
```

### Đánh giá model

```bash
python3 evaluate_model.py --output data/evaluation_report.json
```

### Kiểm chứng deployment

```bash
python3 verify_deployment.py
```

Không thay đổi baseline/model trong lúc lấy minh chứng mà không ghi nhận lại phiên bản và kết quả kiểm chứng tương ứng.

---

## 17. Kiểm thử

### Offline functional test

```bash
cd ml-soc-source/vms-analyzer
python3 test_offline.py
```

### Unit tests

```bash
python3 -m unittest discover -s tests -v
```

### Correlation tests

```bash
python3 tests/test_correlation.py
```

### Các test khác của repository

Có thể chạy thêm test cho local rules, replay/live separation và deployment verification tùy theo tài liệu thực nghiệm hiện hành.

> Không hard-code số lượng test pass trong README. Khi đưa vào báo cáo, lấy **số runtime thực tế của phiên bản source được triển khai cuối cùng**.

---

## 18. Demo và tài liệu thực nghiệm

Các tài liệu chính tại thư mục gốc:

- [`KichBan_Demo_CD1_Wazuh.md`](KichBan_Demo_CD1_Wazuh.md)  
  Kịch bản demo lớp giám sát/phát hiện của CD1.

- [`KichBan_Demo_CD2_ML_Local.md`](KichBan_Demo_CD2_ML_Local.md)  
  Kịch bản demo Analyzer, ML, correlation và thông báo của CD2.

- [`QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md`](QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md)  
  Quy trình thực nghiệm, chụp minh chứng và đối chiếu kết quả.

- [`ThucThi_Demo_CD1.sh`](ThucThi_Demo_CD1.sh)  
  Script hỗ trợ các bước demo CD1.

- [`ThucThi_Demo_CD2.sh`](ThucThi_Demo_CD2.sh)  
  Script hỗ trợ preflight, config, model và các stage demo CD2.

- [`KiemThu_Replay_Correlation_CD2.sh`](KiemThu_Replay_Correlation_CD2.sh)  
  Script replay dành riêng cho kiểm thử chức năng correlation.

### Phân biệt live và replay

- Alert được VM2 integration gửi sang VM3 từ quá trình thực nghiệm thực tế được xem là **live evidence**.
- Direct POST/sample/replay vào VM3 chỉ được xem là **functional test/replay evidence**.
- Không mô tả replay như một luồng live end-to-end.

---

## 19. Gotify, WireGuard và UFW

Gotify được self-host trên VM3 và dùng làm kênh thông báo.

Cấu hình lab:

```text
Gotify:    http://10.66.0.1:8080
WireGuard: 10.66.0.1/24
```

Notifier luôn cố gắng ghi kết quả vào:

```text
incidents.md
```

Nếu `GOTIFY_URL` và `GOTIFY_APP_TOKEN` đã được cấu hình và `risk_score` đạt ngưỡng, hệ thống gửi thêm thông báo Gotify.

Thông báo hiện sử dụng nhãn:

```text
Nhãn phân tích
Mức độ
Tổng điểm
Điểm theo luật
ML đề xuất / áp dụng vào điểm
MITRE ATT&CK
Tương quan sự kiện
Phân tích
Khuyến nghị xử lý
```

Gotify chỉ là lớp delivery; nó không tham gia Classifier, Correlator, Risk Scoring hoặc ML.

---

## 20. Nguyên tắc an toàn

Repository này được xây dựng cho **học tập, nghiên cứu và kiểm thử trong môi trường được phép**.

- Chỉ chạy các kịch bản tấn công trên VM/lab thuộc quyền kiểm soát.
- Không quét, khai thác hoặc thử mật khẩu trên hệ thống bên ngoài khi chưa có ủy quyền.
- Ưu tiên Host-only cho traffic thực nghiệm.
- Chỉ bật NAT khi cần tải package/update.
- Không commit `.env`, token, password, private key hoặc credential.
- Không chụp/đưa secret vào báo cáo.
- Duy trì `DRY_RUN=true` nếu không có yêu cầu thực nghiệm phản ứng tự động được kiểm soát.
- Không coi `Possible Server Compromise` là xác nhận forensic rằng máy chủ đã bị xâm nhập.

---

## 21. Giới hạn hiện tại

Đây là một **Proof of Concept**, chưa phải hệ thống production.

Các giới hạn chính:

- correlation buffer lưu trong RAM và mất khi service restart;
- state chưa được chia sẻ giữa nhiều worker/node;
- liên kết IP/user/session/process giữa các nguồn còn hạn chế;
- Web-compromise correlation hiện tập trung vào pattern Web -> OS và Network -> Web -> OS;
- ngưỡng Wazuh integration có thể làm mất một số precursor;
- baseline ML còn nhỏ;
- baseline hiện chủ yếu là event đơn lẻ lành tính, nên anomaly score của chuỗi correlation có tính tham khảo và cần bổ sung mẫu benign theo ngữ cảnh trước khi diễn giải như một xác suất tấn công;
- tập đánh giá ML không đại diện production;
- chưa benchmark đầy đủ latency, throughput, concurrency và CPU/RAM;
- webhook chưa được harden theo chuẩn production bằng HMAC/mTLS/RBAC/rate limiting;
- notifier chưa có durable retry queue/acknowledgement đầy đủ;
- Analyzer và Gotify cùng phụ thuộc VM3 trong mô hình lab.

---

## 22. Hướng phát triển

Các hướng ưu tiên:

1. Persistent correlation store.
2. Entity/session correlation tốt hơn khi dữ liệu cho phép.
3. Mở rộng pattern correlation ngoài Web-compromise.
4. Baseline nhiều ngày và đa dạng hơn.
5. Tách train/validation/test rõ ràng.
6. Model registry, retrain và rollback.
7. HMAC hoặc TLS/mTLS cho webhook.
8. RBAC, rate limiting và structured logging.
9. Durable notification queue và delivery audit.
10. Benchmark tải và khả năng mở rộng nhiều server.
11. Tách các thành phần quan trọng khỏi single point of failure.

---

## 23. Thông tin học thuật

**Đề tài CD2:**  
*Nghiên cứu và triển khai hệ thống tương quan và chấm điểm rủi ro cảnh báo bảo mật máy chủ Linux có hỗ trợ học máy cục bộ*

**Học phần:** Xử lý sự cố an toàn thông tin doanh nghiệp  
**Khoa:** Công nghệ Thông tin – Trường Đại học Văn Hiến  
**Giảng viên hướng dẫn:** ThS. Nguyễn Minh Thi

**Nhóm thực hiện:**

- Võ Đình Quốc Bảo – 221A010539
- Trần Ngọc Quỳnh – 221A010031
- Đặng Văn Nam – 221A010916

---

## 24. Ghi chú về khả năng tái lập

Khi sử dụng repository để tái lập kết quả trong báo cáo:

1. Ghi lại commit/source version đang triển khai.
2. Xác nhận IP, service và `/health`.
3. Kiểm tra Wazuh integration và local rules.
4. Kiểm tra baseline hash/model metadata.
5. Chạy lại offline test và unit test.
6. Ghi nhận **số test thực tế** thay vì dùng số cũ trong tài liệu.
7. Reset correlation buffer trước từng kịch bản độc lập.
8. Phân biệt rõ live evidence và replay.
9. Chỉ báo cáo timestamp, score và kết quả đã có log/ảnh/runtime tương ứng.

---

## 25. Tài liệu trong repository

Đọc thêm:

- [`ml-soc-source/README.md`](ml-soc-source/README.md)
- [`ml-soc-source/vms-production/README.md`](ml-soc-source/vms-production/README.md)
- [`ml-soc-source/vms-monitor/README.md`](ml-soc-source/vms-monitor/README.md)
- [`ml-soc-source/vms-analyzer/README.md`](ml-soc-source/vms-analyzer/README.md)
- [`QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md`](QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md)

---

### Trạng thái dự án

Repository hiện phục vụ mô hình thực nghiệm CD1–CD2 và báo cáo học thuật. Các giá trị cấu hình, IP động, số lượng test và kết quả model cần được xác nhận lại theo **runtime/source cuối cùng** trước khi công bố trong báo cáo.
