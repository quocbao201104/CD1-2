# Thiết kế thay Telegram bằng Gotify và WireGuard

## Mục tiêu

Thay toàn bộ Telegram Bot API bằng Gotify tự host. Giữ nguyên luồng phân tích
Wazuh VM2 -> Analyzer VM3, classifier, correlation, risk scoring,
IsolationForest và `incidents.md`. Bổ sung WireGuard để máy cá nhân chỉ truy
cập giao diện/ứng dụng Gotify qua tunnel riêng.

## Phạm vi

- VM3 `vms-analyzer` là Gotify Server và WireGuard Server.
- Máy cá nhân là WireGuard peer duy nhất trong giai đoạn đầu.
- `vms-analyzer` gửi thông báo Gotify nội bộ qua `127.0.0.1`.
- Ngưỡng thông báo giữ ở risk score `>= 60`.
- Xóa toàn bộ cấu hình và hành vi Telegram khỏi source, test và hướng dẫn.

Không thuộc phạm vi: thay đổi model/baseline, thay rule Wazuh, expose Gotify
ra Internet, hoặc tự động chặn phản ứng.

## Kiến trúc

```text
VM1 -> Wazuh VM2 -> Analyzer VM3 -> Gotify Server (loopback)
                                      ^
                                      | WireGuard encrypted tunnel
                                      v
                                 Máy cá nhân
```

Gotify lắng nghe loopback và địa chỉ WireGuard của VM3, không mở trên NIC
Host-only hoặc NAT. Analyzer dùng application token chỉ để publish; máy cá
nhân dùng client token riêng để nhận/xem thông báo. Hai token là bí mật và chỉ
được lưu ở `.env` VM3 hoặc ứng dụng Gotify cá nhân.

## Thay đổi source

`app/notifier.py` định dạng thông báo UTF-8 như hiện tại, luôn append
`incidents.md`, sau đó POST Gotify khi có đủ ba điều kiện: `GOTIFY_URL`,
`GOTIFY_APP_TOKEN`, và `risk_score >= GOTIFY_MIN_RISK`. Lỗi HTTP/timeout không
được làm lỗi endpoint `/analyze-alert`.

`.env.example`, README, test notifier và tài liệu lab đổi từ `TG_*` sang:

```text
GOTIFY_URL=http://127.0.0.1:8080
GOTIFY_APP_TOKEN=
GOTIFY_MIN_RISK=60
```

Không in token trong log, notification, report hoặc ảnh demo.

## Vận hành và kiểm thử

1. Chạy unit test notifier với request Gotify bị mock: dưới ngưỡng không POST;
   đủ ngưỡng POST endpoint Gotify với token trong header và payload UTF-8.
2. Chạy toàn bộ test Analyzer tại source trước khi deploy.
3. Cài Gotify và WireGuard trên VM3; tạo một application Gotify và một client
   token cho máy cá nhân sau khi service đã chạy.
4. Copy source đã kiểm thử sang VM3 mà không tạo backup theo yêu cầu chủ dự án;
   chỉ restart `vms-analyzer` sau khi đặt biến Gotify trong `.env`.
5. Xác minh một alert Wazuh thật tạo incident local và notification Gotify qua
   tunnel. Không cần Telegram.

## Tiêu chí hoàn thành

- Không còn `TG_TOKEN`, `TG_CHAT`, Telegram URL hoặc Telegram test trong
  Analyzer source và tài liệu vận hành đang dùng.
- Alert risk 60 gửi đúng một POST Gotify; alert risk thấp vẫn chỉ ghi incident.
- `incidents.md`, classifier, scoring, correlation và ML giữ hành vi cũ.
- Gotify không truy cập được qua VMnet1/NAT; máy cá nhân truy cập được qua
  WireGuard.
