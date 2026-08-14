# Thiết kế correlation và thông báo Telegram

## Mục tiêu

- Alert đơn lẻ giữ nguyên loại sự cố đã phân loại.
- Chỉ nâng thành `Possible Server Compromise` khi cùng máy chủ xuất hiện đúng thứ tự `network -> web -> os` trong 10 phút.
- Không bắt buộc IP nguồn giống nhau vì FIM không có IP nguồn và Windows portproxy có thể thay đổi IP quan sát được.
- IsolationForest tiếp tục là lớp hỗ trợ, chỉ sinh `anomaly_score`, `is_anomaly` và `risk_delta`; không quyết định loại sự cố.
- Telegram và `incidents.md` dùng tiếng Việt có dấu, bố cục theo từng nhóm thông tin và icon tiết chế.

## Luồng xử lý

1. VM3 phân loại alert hiện tại bằng classifier deterministic.
2. Correlation chỉ được kiểm tra khi alert hiện tại thuộc nguồn `os` hoặc `host`.
3. Buffer phải có alert `network`, sau đó là alert `web`, cùng server và còn trong cửa sổ 600 giây.
4. Nếu đủ chuỗi, incident được nâng thành `Possible Server Compromise`; nếu không, giữ nguyên incident ban đầu.
5. Risk scoring và ML chạy sau correlation như hiện tại.

## Thông báo

Thông báo gồm: tiêu đề, sự cố/mức độ, máy chủ và IP nguồn, điểm deterministic, phần cộng của ML, MITRE ATT&CK, trạng thái tương quan, phân tích và playbook đánh số. Nội dung gửi Telegram là plain text UTF-8 để tránh lỗi escape và hiển thị ổn định.

## Nghiệm thu

- `network -> web` không tương quan.
- `web -> os` không tương quan.
- Sai thứ tự `web -> network -> os` không tương quan.
- Đúng thứ tự `network -> web -> os` trên cùng server tương quan.
- Chuỗi trên hai server khác nhau không tương quan.
- Thông báo có tiếng Việt đúng dấu, điểm deterministic, ML delta và trạng thái chuỗi rõ ràng.
