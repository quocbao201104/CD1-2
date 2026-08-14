# Local ML Security Log Analyzer (VM3)

Lop phan tich canh bao cho CD2, chay tren VM3. VM3 nhan alert bao mat ke thua
tu CD1 qua Wazuh integration:

- Network: Suricata `eve.json` duoc Wazuh Agent tren VM1 gui ve VM2.
- Web/Application: Nginx `access.log` va `error.log`.
- Auth/OS: SSH/auth log, auditd, FIM va local rules cua Wazuh.

He thong chuan hoa alert, tuong quan network -> web -> host, cham diem rui ro,
chay local ML bang scikit-learn, de xuat playbook va ghi incident cho admin.

## Nguyen tac thiet ke

- Khong dung OpenClaw/LLM/API AI ben ngoai.
- Phan quyet dinh cot loi la deterministic: `normalizer`, `correlation`,
  `classifier`, `scoring`, `policy`.
- Local ML bang scikit-learn chi bo sung `anomaly_score` va `risk_delta` co gioi
  han; ML khong duoc tu y thay the rule/correlation.
- Gotify la kenh thong bao tu host tuy chon. Neu khong co
  `GOTIFY_URL/GOTIFY_APP_TOKEN`, he thong van ghi incident vao `incidents.md`.
- Source chi xu ly alert bao mat tu Wazuh/CD1.

## Diem nhan CD2

Neu cung mot server co chuoi canh bao network/web/host trong khoang 10 phut, he
thong nang incident thanh `Possible Server Compromise`.

Vi du:

```text
Network Port Scan
        +
Web Traversal Attempt
        +
Web Root Modified
        =>
Possible Server Compromise, risk Critical
```

Local ML dung `IsolationForest` de danh gia bat thuong dua tren baseline cuc bo.
Baseline duoc luu tai `data/baseline.json` va co the tao lai tu cac alert/log
binh thuong bang `collect_baseline.py`.

Dac trung ML hien dung:

- source network/web/os/auth
- loai incident
- base risk score
- co correlation hay khong
- co network precursor hay khong
- co IP nguon hay khong

Day la proof-of-concept cho lab CD2, khong khang dinh thay the mo hinh ML
production.

## Cau truc

```text
vm3-ai-analyzer/
|-- app/
|   |-- main.py          # FastAPI: /health, /analyze-alert
|   |-- normalizer.py    # chuan hoa Wazuh alert ve envelope thong nhat
|   |-- correlation.py   # buffer TTL 10 phut + ghep network/web/host cung server
|   |-- classifier.py    # phan loai su co theo rule deterministic
|   |-- scoring.py       # base risk + severity + MITRE
|   |-- ml_anomaly.py    # local ML IsolationForest + heuristic fallback
|   |-- explainer.py     # local explanation template, khong goi LLM
|   |-- playbook.py      # playbook bao mat
|   |-- notifier.py      # incidents.md + Gotify optional
|   `-- policy.py        # policy de xuat hanh dong an toan, DRY_RUN mac dinh
|-- data/
|   |-- whitelist.json
|   |-- host_map.json
|   |-- samples/
|-- train_model.py      # huan luyen va luu artifact IsolationForest
|-- evaluate_model.py   # danh gia baseline VM2 va tap kich ban lab
|-- test_offline.py
|-- requirements.txt
|-- .env.example
`-- .gitignore
```

## Chay nhanh

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Test offline, khong can VM1/VM2 dang chay
python3 test_offline.py

# Tao baseline tu cac alert/log binh thuong da capture
python3 collect_baseline.py --input data/baseline_samples --out data/baseline.json

# Huan luyen mot lan va luu model/metadata tren VM3
python3 train_model.py \
  --baseline data/baseline.json \
  --model data/isolation_forest.joblib \
  --metadata data/isolation_forest_metadata.json

# Danh gia model tren log binh thuong va cac kich ban lab
python3 evaluate_model.py --output data/evaluation_report.json

# Chay API server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Test endpoint
curl localhost:8000/health
curl -X POST localhost:8000/analyze-alert -H "Content-Type: application/json" -d @data/samples/brute_force.json
curl -X POST localhost:8000/analyze-alert -H "Content-Type: application/json" -d @data/samples/nginx_sensitive_path.json
curl -X POST localhost:8000/analyze-alert -H "Content-Type: application/json" -d @data/samples/webroot_modified.json
```

## Gotify tu host va truy cap WireGuard

Trong `.env`:

```text
GOTIFY_URL=http://10.66.0.1:8080
GOTIFY_APP_TOKEN=
GOTIFY_MIN_RISK=60
```

Neu de trong `GOTIFY_APP_TOKEN`, notifier chi ghi local file `incidents.md`.
Neu cau hinh Gotify, VM3 gui them thong bao toi Gotify Server tu host qua
`10.66.0.1:8080`. Analyzer dung application token de gui; client token chi dung
tren may ca nhan. Gotify khong tham gia vao phan tich AI/ML, chi lang nghe tren
giao dien WireGuard va khong mo qua Host-only/NAT.

Neu may ca nhan chay Gotify client nam tren mot may that khac, VM3 can them NIC
`Bridged` lay DHCP tu Wi-Fi/LAN. WireGuard client dung IP cua NIC Bridged lam
`Endpoint=<IP_BRIDGED_VM3>:51820`; Gotify URL va `GOTIFY_URL` van giu
`http://10.66.0.1:8080`. Khong bind Gotify vao IP Bridged.

## Policy hanh dong an toan

```text
DRY_RUN=true
```

Mac dinh he thong chi de xuat hanh dong, khong SSH that vao VM1. Phan cot loi
cua CD2 van la chuan hoa alert, correlation, risk scoring va local ML.

## Ket qua test offline

- Security pipeline: phan loai sample SSH, network, web, FIM/auditd dung.
- Correlation: network + web + host cung server -> `Possible Server Compromise`.
- Network-aware correlation: Suricata alert -> web/host correlation context.
- Local ML: load baseline, tra ve model, anomaly_score, risk_delta va is_anomaly.

## Baseline VM2 dang su dung

- Nguon: 13 su kien binh thuong duoc trich tu archive JSON tren Wazuh/VM2.
- Thanh phan: 5 network/Suricata, 5 web/Nginx va 3 auth.
- So dac trung: 9.
- Model: IsolationForest, 200 cay, `contamination=auto`, `random_state=42`.
- Model duoc luu tai `data/isolation_forest.joblib`; API xac minh SHA-256 cua
  baseline truoc khi tai artifact.
- Neu model thieu hoac khong khop baseline, dich vu fit tam trong bo nho va tra
  `model_source=runtime-fit` de admin nhan biet.

Ket qua ngay 28/07/2026: 13/13 mau binh thuong la inlier va 9/9 kich ban tan
cong lab la outlier. Day la kiem thu chuc nang tren tap du lieu nho do nhom thu
thap/thiet ke, khong phai phep do do chinh xac tren du lieu production doc lap.
