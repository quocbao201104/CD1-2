"""Playbook xử lý sự cố theo từng loại."""

PLAYBOOKS = {
    "SSH Brute Force": [
        "Kiểm tra IP nguồn và số lần đăng nhập thất bại",
        "Kiểm tra có phiên đăng nhập thành công sau chuỗi thất bại hay không",
        "Chặn tạm thời IP nếu nằm ngoài danh sách cho phép",
        "Tắt đăng nhập root và ưu tiên xác thực bằng SSH key",
        "Ghi nhận sự cố",
    ],
    "Valid Login After Brute Force": [
        "XÁC MINH NGAY tính hợp lệ của phiên đăng nhập",
        "Kiểm tra lịch sử lệnh của phiên bằng history và auditd",
        "Đặt lại mật khẩu và thu hồi phiên nếu có nghi ngờ",
        "Chặn IP nguồn và luân chuyển thông tin xác thực",
        "Ghi nhận sự cố mức cao",
    ],
    "Account File Modified": [
        "Kiểm tra tài khoản mới trong /etc/passwd",
        "Đối chiếu log audit/sudo quanh thời điểm thay đổi",
        "Xác định người đã chạy lệnh useradd",
        "Khóa hoặc xóa tài khoản lạ sau khi quản trị viên xác nhận",
        "Kiểm tra thêm tệp /etc/sudoers",
        "Ghi nhận sự cố",
    ],
    "SSH Key Backdoor": [
        "Liệt kê key mới được thêm vào authorized_keys",
        "Đối chiếu với danh sách key hợp lệ",
        "Xóa key lạ nếu không xác định được nguồn gốc",
        "Kiểm tra log SSH quanh thời điểm thay đổi",
        "Luân chuyển SSH key nếu nghi ngờ bị lộ",
        "Ghi nhận sự cố",
    ],
    "Privilege Escalation": [
        "Kiểm tra lệnh sudo đã chạy trong audit root_cmd",
        "Đối chiếu người thực hiện và tính hợp lệ của thao tác",
        "Kiểm tra thay đổi trong /etc/sudoers",
        "Thu hồi quyền nếu xác định hành vi bất thường",
        "Ghi nhận sự cố",
    ],
    "Suspicious User Creation": [
        "Xác minh tài khoản mới có hợp lệ hay không",
        "Kiểm tra tài khoản có được thêm vào nhóm sudo hay không",
        "Khóa tài khoản nếu không rõ nguồn gốc",
        "Ghi nhận sự cố",
    ],
    "Network Port Scan": [
        "Kiểm tra cảnh báo Suricata và các cổng/dịch vụ bị quét",
        "Đối chiếu IP nguồn với danh sách cho phép và phạm vi mạng lab",
        "Theo dõi tiếp Nginx access log và auth.log từ cùng nguồn",
        "Chặn tạm thời IP nếu hành vi quét lặp lại ngoài kịch bản demo",
        "Ghi nhận sự cố",
    ],
    "Web Sensitive Path Scan": [
        "Lọc Nginx access log theo IP nguồn và các path .env, .git, /admin, /phpmyadmin",
        "Xác minh các tệp/thư mục nhạy cảm không tồn tại công khai trong web root",
        "Bổ sung deny rule hoặc rewrite rule khi cần",
        "Chặn IP nếu truy vấn lặp lại ngoài kịch bản demo",
        "Ghi nhận sự cố",
    ],
    "Web Traversal Attempt": [
        "Kiểm tra request chứa ../, %2e%2e hoặc /etc/passwd trong access log",
        "Kiểm tra ứng dụng Web và cấu hình Nginx có cho phép đọc tệp ngoài web root hay không",
        "Đối chiếu error log quanh thời điểm cảnh báo",
        "Cập nhật cấu hình hoặc ứng dụng để không trả về tệp hệ thống",
        "Ghi nhận sự cố",
    ],
    "Web Root Modified": [
        "Liệt kê các tệp thay đổi trong /var/www/html",
        "Đối chiếu auditd/FIM để xác định tài khoản hoặc lệnh gây thay đổi",
        "Khôi phục tệp hợp lệ nếu nội dung bị sửa ngoài ý muốn",
        "Kiểm tra access log xem tệp mới có được truy cập sau thay đổi hay không",
        "Ghi nhận sự cố",
    ],
    "Suspicious Web File": [
        "Cô lập tệp nghi vấn trong /var/www/html",
        "Kiểm tra nội dung tệp và thời điểm tạo/sửa",
        "Đối chiếu access log xem tệp đã được gọi qua HTTP hay chưa",
        "Xóa tệp sau khi thu thập bằng chứng nếu xác nhận bất thường",
        "Ghi nhận sự cố mức cao",
    ],
    "Possible Server Compromise": [
        "Tổng hợp dòng thời gian Suricata, Nginx access log, FIM và auditd trong cùng cửa sổ 10 phút",
        "Xác định IP nguồn, đường dẫn Web, tệp bị thay đổi và tài khoản/lệnh liên quan trên máy chủ",
        "Chặn IP nguồn nếu nằm ngoài danh sách cho phép và thu thập log điều tra",
        "Kiểm tra tài khoản/key mới, web shell/backdoor và thay đổi cấu hình Nginx",
        "Ghi nhận sự cố mức nghiêm trọng",
    ],
    "Unknown": [
        "Sự kiện chưa được phân loại; quản trị viên cần xem xét thủ công",
        "Thu thập log liên quan để phân tích thêm",
    ],
}


def playbook_for(incident: str):
    return PLAYBOOKS.get(incident, PLAYBOOKS["Unknown"])
