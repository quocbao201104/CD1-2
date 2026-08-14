# Correlation và Telegram Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sửa VM3 để chỉ tương quan đúng chuỗi network -> web -> os và tạo thông báo Telegram tiếng Việt rõ ràng.

**Architecture:** Correlation tiếp tục dùng buffer in-memory 10 phút nhưng chỉ trả kết quả khi alert cuối là os/host và buffer có network đứng trước web trên cùng server. Notifier chỉ định dạng kết quả đã có, không thay đổi classifier, model hoặc công thức risk.

**Tech Stack:** Python 3, FastAPI, unittest, systemd, Telegram Bot API.

## Global Constraints

- Giữ UTF-8 không BOM và LF.
- Không thay model, baseline hoặc ngưỡng Telegram.
- Không ghi token, mật khẩu hoặc chat ID vào source.
- VM3 chạy `DRY_RUN=true`.

---

### Task 1: Correlation ba tầng

**Files:**
- Create: `tests/test_correlation.py`
- Modify: `app/correlation.py`

**Interfaces:**
- Consumes: `remember(source: str, server: str, incident: str, ip)`.
- Produces: `correlate(source: str, server: str) -> dict | None`.

- [ ] Viết test cho chuỗi thiếu tầng, sai thứ tự, khác server và chuỗi hợp lệ.
- [ ] Chạy `python -m unittest tests.test_correlation -v`, xác nhận test mới thất bại với logic cũ.
- [ ] Sửa tối thiểu `correlation.py` để chỉ nhận network -> web -> os/host.
- [ ] Chạy lại test và xác nhận tất cả pass.

### Task 2: Thông báo tiếng Việt

**Files:**
- Modify: `tests/test_notifier_threshold.py`
- Modify: `app/notifier.py`
- Modify: `app/explainer.py`
- Modify: `app/playbook.py`

**Interfaces:**
- Consumes: result dict từ pipeline.
- Produces: plain-text UTF-8 cho `incidents.md` và Telegram.

- [ ] Viết test yêu cầu tiêu đề/icon, tiếng Việt có dấu, điểm deterministic, ML delta và trạng thái tương quan.
- [ ] Chạy test notifier, xác nhận thất bại với định dạng cũ.
- [ ] Cập nhật formatter và Việt hóa explanation/playbook.
- [ ] Chạy lại test notifier và toàn bộ unit test.

### Task 3: Triển khai VM3

**Files:**
- Deploy: `/home/ubuntu/vms-analyzer/app/correlation.py`
- Deploy: `/home/ubuntu/vms-analyzer/app/notifier.py`
- Deploy: `/home/ubuntu/vms-analyzer/app/explainer.py`
- Deploy: `/home/ubuntu/vms-analyzer/app/playbook.py`
- Deploy: `/home/ubuntu/vms-analyzer/tests/test_correlation.py`
- Deploy: `/home/ubuntu/vms-analyzer/tests/test_notifier_threshold.py`

**Interfaces:**
- Consumes: source đã vượt qua unit test cục bộ.
- Produces: `vms-analyzer.service` dùng code mới.

- [ ] Sao lưu các file đang chạy trên VM3 với timestamp.
- [ ] Đồng bộ file qua SSH, giữ token và `.env` nguyên trạng.
- [ ] Chạy unit test trên VM3.
- [ ] Restart service và kiểm tra `systemctl is-active` cùng `/health`.
- [ ] Gửi sample offline không gọi Telegram thật để kiểm tra định dạng Unicode và hai nhánh correlation.
