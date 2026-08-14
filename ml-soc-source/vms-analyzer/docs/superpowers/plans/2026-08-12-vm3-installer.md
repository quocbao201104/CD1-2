# VM3 CD2 Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cung cấp một script cài VM3 CD2 lặp lại được cho Analyzer/ML,
WireGuard và Gotify, đồng thời tách mọi input bí mật khỏi source.

**Architecture:** `install_vm3_cd2.sh` nhận IP VM2 và ba NIC, kiểm tra mạng rồi
cài Analyzer/ML/service. Script tạo WireGuard/Gotify với public key, IP client
và application token được nhập tương tác, không ghi cứng. Kịch bản video gọi
một lệnh script và chỉ quay các điểm xác nhận quan trọng.

**Tech Stack:** Bash, Ubuntu 22.04, Netplan, Python venv, systemd, WireGuard,
UFW, Gotify, FastAPI, scikit-learn.

## Global Constraints

- Dùng source tại `/home/ubuntu/vms-analyzer`; script chạy với `sudo`.
- Giữ `DRY_RUN=true`, baseline 13 mẫu `data/baseline_vm2_20260722.json`.
- Không ghi Gotify token, private key WireGuard hoặc IP Bridged DHCP cố định vào source/tài liệu.
- Gotify chỉ bind `10.66.0.1:8080`; VM2 `.20` chỉ gọi Analyzer qua HTTP 8000.
- Netplan Bridged phải có `route-metric: 200`; NIC NAT là default route ưu tiên.
- File mới/chỉnh sửa giữ UTF-8 không BOM và LF.

---

### Task 1: Thêm script cài VM3 an toàn, có kiểm tra input

**Files:**
- Create: `ml-soc-source/vms-analyzer/install_vm3_cd2.sh`
- Test: shell syntax and secret scan commands

**Interfaces:**
- Consumes: `sudo ./install_vm3_cd2.sh <IP_VM2> <HOST_ONLY_IFACE> <NAT_IFACE> <BRIDGED_IFACE>`.
- Produces: `.venv`, `.env`, model artifacts, `vms-analyzer.service`, `wg0`, `gotify.service`.

- [x] **Step 1: Write the shell acceptance checks**

```powershell
bash -n ml-soc-source/vms-analyzer/install_vm3_cd2.sh
rg -n -i 'gotify_app_token=.+|privatekey\s*=|server_private=' ml-soc-source/vms-analyzer/install_vm3_cd2.sh
```

Expected before implementation: the script path does not exist.

- [x] **Step 2: Implement preflight, network, Analyzer and ML stages**

The script must validate root/user arguments and all three NICs, save Netplan
`60-bridged.yaml`, install dependencies, create `.venv`, copy the 13-row
baseline into `data/baseline.json`, train/evaluate/test, create `.env` mode
0600 and enable `vms-analyzer.service`.

- [x] **Step 3: Implement WireGuard, Gotify and UFW stages**

Generate server key files only if missing; display only server public key; read
the client public key and Gotify token without echo; read the client Wi-Fi/LAN
IPv4; derive Bridged IPv4 from the selected NIC. Bind Gotify only to wg0 and
apply least-privilege UFW rules.

- [x] **Step 4: Run static verification**

Run the commands from Step 1, plus inspect that all variable expansions in
service/config templates are intentional and no secret literal exists.

### Task 2: Thu gọn kịch bản quay CD2 theo script

**Files:**
- Modify: `KichBan_CaiDat_CD2.md`

**Interfaces:**
- Consumes: `install_vm3_cd2.sh` from source copied to VM3.
- Produces: a linear video flow with manual values clearly separated.

- [x] **Step 1: Replace Cảnh 1--4 implementation commands with the script invocation**

Include the copy-source check, `chmod +x`, the exact invocation for lab
`192.168.245.20 ens33 ens34 ens35`, and the three prompts: client public key,
Admin Wi-Fi IPv4 and Gotify application token.

- [x] **Step 2: Retain observable verification steps**

Keep `systemctl`, `/health`, `verify_deployment.py`, `wg show`, `ss` and the
Gotify browser verification; omit key/token display.

- [x] **Step 3: Check documentation integrity**

Use a UTF-8/LF check and secret-pattern scan. Confirm it does not expose an
actual key or token.

### Task 3: Deploy and test on the clean VM3

**Files:**
- Copy source from local workspace to `/home/ubuntu/vms-analyzer` on VM3.
- Runtime artifacts created only on VM3.

**Interfaces:**
- Consumes: the VM3 source copied over SSH and administrator-supplied public inputs.
- Produces: an operational VM3 ready for VM2 integration.

- [x] **Step 1: Copy source and run installer**

Copy the directory using Windows OpenSSH, then run the script in the VM3
console so secret prompts stay local to the VM.

Source đã được copy và VM3 đã triển khai ngày 2026-08-12. Bản script hiện có
thêm kiểm tra health sau mỗi lần restart Analyzer và kiểm tra handshake
WireGuard trước khi cài Gotify.

- [x] **Step 2: Verify deployment after user finishes prompts**

```bash
sudo systemctl is-active vms-analyzer wg-quick@wg0 gotify
curl -fsS http://127.0.0.1:8000/health
cd /home/ubuntu/vms-analyzer && source .venv/bin/activate
python verify_deployment.py
sudo ss -ltn '( sport = :8080 )'
sudo wg show
```

- [ ] **Step 3: Verify VM2 integration only after VM2 is ready**

```bash
curl -fsS http://192.168.245.30:8000/health
```

Run it on VM2 after the Wazuh Manager installation and VM3 health checks pass.

## Self-review

- Spec coverage: Task 1 covers all automatic and manual boundaries; Task 2
  covers video flow; Task 3 covers the clean-VM validation.
- No placeholder scan: no TODO/TBD or unbounded implementation steps remain.
- Interface consistency: Task 2 and Task 3 use the four script arguments
  declared in Task 1.
