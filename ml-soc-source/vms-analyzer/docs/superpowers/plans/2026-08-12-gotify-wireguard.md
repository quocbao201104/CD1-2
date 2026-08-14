# Gotify and WireGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Telegram notifications with an on-premises Gotify service and make the service reachable from one personal machine only through WireGuard.

**Architecture:** The Analyzer always writes `incidents.md`, then posts a UTF-8 message to Gotify through `http://127.0.0.1:8080/message` if the risk threshold is met. Gotify runs on VM3. WireGuard is a separate access layer between VM3 and one personal machine; Gotify must not listen on VMnet1 or NAT.

**Tech Stack:** Python 3, FastAPI, requests, unittest, Gotify Server, systemd, WireGuard.

## Global Constraints

- Do not change Wazuh rules, classifier, scoring, correlation, baseline, model or DRY_RUN behavior.
- Remove Telegram source/config/test/documentation; do not keep a fallback channel.
- Keep all secret values out of source, console evidence, reports and commits.
- Keep notifier failures non-fatal to `/analyze-alert` and always retain `incidents.md` logging.
- Use `GOTIFY_URL`, `GOTIFY_APP_TOKEN` and `GOTIFY_MIN_RISK=60`.
- Deploy to VM3 without creating a project backup, per user direction.
- Bind Gotify only to loopback and the WireGuard interface; never to VMnet1 or NAT.

---

### Task 1: Define and prove the Gotify notifier contract

**Files:**

- Modify: `tests/test_notifier_threshold.py`
- Modify: `app/notifier.py`

**Interfaces:**

- Consumes: existing `notify(result: dict, md_path: str = "incidents.md") -> str`.
- Produces: the same function, with Gotify POST to `<GOTIFY_URL>/message`, `X-Gotify-Key` application-token header and JSON body `{title, message, priority}`.

- [ ] **Step 1: Replace Telegram-specific test cases with failing Gotify tests**

```python
@patch("app.notifier.requests.post")
def test_low_risk_is_recorded_but_not_sent_to_gotify(self, post):
    with patch.dict(os.environ, {
        "GOTIFY_URL": "http://127.0.0.1:8080",
        "GOTIFY_APP_TOKEN": "test-app-token",
        "GOTIFY_MIN_RISK": "60",
    }, clear=False):
        notify(result_with_risk(30), md_path=path)
    post.assert_not_called()

@patch("app.notifier.requests.post")
def test_high_risk_is_sent_to_gotify_with_utf8_json(self, post):
    with patch.dict(os.environ, {
        "GOTIFY_URL": "http://127.0.0.1:8080/",
        "GOTIFY_APP_TOKEN": "test-app-token",
        "GOTIFY_MIN_RISK": "60",
    }, clear=False):
        notify(result_with_risk(60), md_path=path)
    post.assert_called_once_with(
        "http://127.0.0.1:8080/message",
        headers={"X-Gotify-Key": "test-app-token"},
        json={"title": "⚠️ CẢNH BÁO BẢO MẬT", "message": mock.ANY, "priority": 8},
        timeout=5,
    )
```

- [ ] **Step 2: Run the notifier test to prove the existing Telegram notifier fails the new contract**

Run:

```powershell
python -m unittest tests.test_notifier_threshold -v
```

Expected: the Gotify test fails because the old notifier does not read `GOTIFY_*` or call `/message`.

- [ ] **Step 3: Implement the smallest Gotify-only notifier change**

In `app/notifier.py`, retain `_format()` and local Markdown writing. Replace the `TG_*` block with:

```python
gotify_url = os.getenv("GOTIFY_URL", "").rstrip("/")
app_token = os.getenv("GOTIFY_APP_TOKEN")
try:
    min_risk = int(os.getenv("GOTIFY_MIN_RISK", "60"))
except ValueError:
    min_risk = 60

if gotify_url and app_token and int(result.get("risk_score") or 0) >= min_risk:
    try:
        requests.post(
            f"{gotify_url}/message",
            headers={"X-Gotify-Key": app_token},
            json={"title": _gotify_title(result), "message": text, "priority": _gotify_priority(result)},
            timeout=5,
        ).raise_for_status()
    except Exception:
        pass
```

Implement `_gotify_title()` as `<severity icon> CẢNH BÁO BẢO MẬT` and `_gotify_priority()` as `Critical=10`, `High=8`, `Medium=5`, `Low=3`, default `3`.

- [ ] **Step 4: Run notifier tests and the full Analyzer test suite**

Run:

```powershell
python -m unittest tests.test_notifier_threshold -v
python -m unittest discover -s tests -v
python test_offline.py
```

Expected: all tests pass; a risk-60 result posts once to Gotify; a risk-30 result writes local incident only.

### Task 2: Replace Telegram configuration and documentation

**Files:**

- Modify: `.env.example`
- Modify: `README.md`
- Modify: `QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md`

**Interfaces:**

- Consumes: `GOTIFY_URL`, `GOTIFY_APP_TOKEN`, `GOTIFY_MIN_RISK` from Task 1.
- Produces: source and lab documentation that only names Gotify/WireGuard as the notification/access layer.

- [ ] **Step 1: Replace the sample environment variables**

Replace the Telegram block in `.env.example` with:

```text
# Gotify tu host (de trong token khi chua cau hinh -> chi ghi incidents.md)
GOTIFY_URL=http://127.0.0.1:8080
GOTIFY_APP_TOKEN=
GOTIFY_MIN_RISK=60
```

- [ ] **Step 2: Update the README**

Replace Telegram mentions with Gotify self-host. State that the Analyzer uses an application token to publish, a Gotify client token belongs only on the personal client, and Gotify is reached remotely only over WireGuard. Do not include token examples.

- [ ] **Step 3: Update the lab procedure**

In `QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md`, replace Telegram screenshots/checklist/troubleshooting with Gotify screenshots/checklist/troubleshooting. Retain the threshold wording as `GOTIFY_MIN_RISK=60`; require any Gotify screenshot to hide application/client tokens.

- [ ] **Step 4: Verify stale references are gone**

Run:

```powershell
rg -n -i 'telegram|TG_TOKEN|TG_CHAT|TG_MIN_RISK|api\.telegram\.org' ml-soc-source QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md
```

Expected: no production/source/procedure references, except historical design records intentionally retained under `docs/superpowers`.

### Task 3: Deploy Gotify and Analyzer on VM3

**Files:**

- Modify on VM3 only: `/home/ubuntu/vms-analyzer/app/notifier.py`
- Modify on VM3 only: `/home/ubuntu/vms-analyzer/.env`
- Create on VM3 only: `/etc/gotify/server.env`
- Create on VM3 only: `/etc/systemd/system/gotify.service`

**Interfaces:**

- Consumes: verified source from Tasks 1-2 and a Gotify application token created in the local Gotify Web UI.
- Produces: VM3 Analyzer posts to VM3 Gotify loopback; no Telegram configuration remains in VM3 `.env`.

- [ ] **Step 1: Verify VM3 prerequisites without exposing secrets**

Run on VM3:

```bash
hostname
sudo systemctl is-active vms-analyzer
curl -fsS http://127.0.0.1:8000/health
uname -m
```

Expected: `vms-analyzer`, health JSON, and architecture `x86_64` for the Linux AMD64 Gotify binary.

- [ ] **Step 2: Install Gotify Server as a systemd service**

Download the current official Linux AMD64 Gotify release, install its binary in `/opt/gotify`, and create a dedicated `gotify` system user. Set `/etc/gotify/server.env` to bind `GOTIFY_SERVER_LISTENADDR=127.0.0.1` and port `8080` for the initial local verification. Enable and start `gotify.service`.

Run:

```bash
sudo systemctl is-active gotify
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
sudo ss -ltnp | grep ':8080'
```

Expected: `active`, HTTP response, and a listener only on `127.0.0.1:8080`.

- [ ] **Step 3: Create Gotify application and configure Analyzer secret**

Use the local VM3 Gotify Web UI to create application `SOC Analyzer`. Store only the one-time application token in VM3 `.env` as `GOTIFY_APP_TOKEN`; set `GOTIFY_URL=http://127.0.0.1:8080` and `GOTIFY_MIN_RISK=60`; remove all `TG_*` variables. Do not print the token.

- [ ] **Step 4: Deploy verified source and restart Analyzer**

Copy the verified changed files from workspace to their matching paths in `/home/ubuntu/vms-analyzer` without creating a backup. Restart Analyzer.

Run:

```bash
sudo systemctl restart vms-analyzer
sudo systemctl is-active vms-analyzer
curl -fsS http://127.0.0.1:8000/health
```

Expected: `active` and health `{"status":"ok"}`.

- [ ] **Step 5: Test a local Gotify notification without tokens in output**

From the Analyzer virtual environment, send an existing high-risk sample through the normal `/analyze-alert` endpoint. Verify the Gotify UI message and `incidents.md`; do not print the application token.

### Task 4: Add WireGuard access for one personal machine

**Files:**

- Create on VM3 only: `/etc/wireguard/wg0.conf`
- Create on personal machine only: WireGuard client profile, imported into the official client application.
- Modify on VM3 only: `/etc/gotify/server.env` after the VPN tunnel is confirmed.

**Interfaces:**

- Consumes: functioning local Gotify at `127.0.0.1:8080` from Task 3.
- Produces: one encrypted peer connection and Gotify reachable at VM3 WireGuard address only.

- [ ] **Step 1: Install WireGuard and create one VM3/private-machine key pair set**

Install `wireguard` on VM3. Generate VM3 and client private keys with restrictive permissions; exchange only public keys in peer configuration. Never show private keys in terminal captures, source, report, or chat.

- [ ] **Step 2: Configure the tunnel**

Assign `10.66.0.1/24` to VM3 `wg0` and `10.66.0.2/32` to the personal machine. VM3 listens on UDP `51820`; the personal peer uses `AllowedIPs = 10.66.0.1/32`. Enable `wg-quick@wg0` and import the peer profile into the official WireGuard client.

- [ ] **Step 3: Bind Gotify to VM3 WireGuard address and restart it**

After `wg0` is up, change Gotify bind address to `10.66.0.1`; retain loopback reachability for Analyzer by adding a local reverse proxy or an additional Gotify listener only if the Gotify version supports multiple listeners. Otherwise bind Gotify to `10.66.0.1` and set `GOTIFY_URL=http://10.66.0.1:8080` in Analyzer `.env`. Restrict port `8080` with UFW to interface `wg0` only.

- [ ] **Step 4: Verify secure reachability**

On VM3 verify `wg show`, `gotify.service`, `vms-analyzer.service`, and no port `8080` listener on `192.168.245.30` or the NAT address. On the personal machine, bring up tunnel and open `http://10.66.0.1:8080`; create a Gotify client token only in the client app. Verify a high-risk alert arrives.

### Task 5: Final verification and lab handoff

**Files:**

- Modify: `QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md`

**Interfaces:**

- Consumes: source and VM3 deployment from Tasks 1-4.
- Produces: evidence instructions for Gotify/WireGuard without sensitive material.

- [ ] **Step 1: Run final source verification**

Run:

```powershell
python -m unittest discover -s tests -v
python test_offline.py
python verify_deployment.py
```

Expected: all tests pass and deployment verification reports `ALL_CHECKS_PASSED=True` when executed in the VM3 project environment.

- [ ] **Step 2: Run end-to-end alert verification**

Create one existing, authorized lab event with risk at least 60. Verify the same event appears in VM2 alerts, VM3 `incidents.md`, Gotify Web UI reached through WireGuard, and the personal Gotify client. Do not screenshot credentials, tokens, private keys or full WireGuard configuration.

- [ ] **Step 3: Capture safe evidence**

Capture Gotify service active, WireGuard handshake/latest transfer, Analyzer incident, and a Gotify client notification. Redact any token, private key, QR code, endpoint password, or full peer config.
