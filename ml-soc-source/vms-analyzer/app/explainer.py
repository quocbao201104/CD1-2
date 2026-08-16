"""Local incident explanation templates.

No OpenClaw, LLM, or external AI API is called here. Explanations are generated
locally from deterministic incident classification, risk score, and optional
local ML anomaly output.
"""

TEMPLATES = {
    "SSH Brute Force":
        "Phát hiện nhiều lần đăng nhập SSH thất bại từ IP {ip} tới {agent}. "
        "Đây là dấu hiệu dò mật khẩu (brute force). Điểm rủi ro {score}/100. "
        "Khuyến nghị: kiểm tra IP nguồn, kiểm tra phiên đăng nhập thành công sau đó và chặn IP nếu nằm ngoài danh sách cho phép.",
    "Valid Login After Brute Force":
        "CẢNH BÁO CAO: có đăng nhập SSH thành công từ IP {ip} ngay sau chuỗi thất bại trên {agent}. "
        "Có khả năng tài khoản đã bị chiếm dụng. Điểm rủi ro {score}/100. "
        "Khuyến nghị: xác minh phiên đăng nhập, thu hồi phiên, đặt lại thông tin xác thực và chặn IP nguồn.",
    "SSH Key Backdoor":
        "Tệp authorized_keys trên {agent} có SSH key mới. "
        "Đây có thể là hành vi duy trì truy cập trái phép. Điểm rủi ro {score}/100. "
        "Khuyến nghị: đối chiếu key hợp lệ, loại bỏ key lạ, luân chuyển key và kiểm tra log SSH.",
    "Account File Modified":
        "Tệp tài khoản hệ thống trên {agent} bị thay đổi. Điểm rủi ro {score}/100. "
        "Khuyến nghị: kiểm tra tài khoản mới và đối chiếu log audit/sudo quanh thời điểm xảy ra sự kiện.",
    "Privilege Escalation":
        "Phát hiện hành vi sử dụng quyền cao trên {agent}. Điểm rủi ro {score}/100. "
        "Khuyến nghị: kiểm tra lệnh sudo/root, đối chiếu người thực hiện và cấu hình /etc/sudoers.",
    "Suspicious User Creation":
        "Tài khoản mới được tạo trên {agent}. Điểm rủi ro {score}/100. "
        "Khuyến nghị: xác minh tính hợp lệ và kiểm tra tài khoản có được thêm vào nhóm sudo hay không.",
    "Network Port Scan":
        "Phát hiện hoạt động quét cổng/dịch vụ từ IP {ip} tới {agent}. Điểm rủi ro {score}/100. "
        "Khuyến nghị: đối chiếu cảnh báo Suricata, xác định cổng bị dò quét và tăng cường theo dõi log Web/SSH tiếp theo.",
    "Web Sensitive Path Scan":
        "Phát hiện truy vấn các đường dẫn nhạy cảm trên máy chủ Web {agent} từ IP {ip}. "
        "Đây có thể là bước dò tìm cấu hình lộ lọt như .env, .git hoặc trang quản trị. Điểm rủi ro {score}/100. "
        "Khuyến nghị: kiểm tra access log, chặn IP nếu hành vi lặp lại và bảo đảm tệp nhạy cảm không được công khai.",
    "Web Traversal Attempt":
        "Phát hiện dấu hiệu thử đọc tệp hệ thống qua HTTP trên {agent} từ IP {ip}. "
        "Đây là hành vi thử khai thác ứng dụng Web hoặc dịch vụ công khai. Điểm rủi ro {score}/100. "
        "Khuyến nghị: kiểm tra access/error log của Nginx, ứng dụng Web, rewrite rule và quyền đọc tệp.",
    "Web Root Modified":
        "Thư mục web root trên {agent} bị thay đổi. Điểm rủi ro {score}/100. "
        "Khuyến nghị: đối chiếu người hoặc lệnh thực hiện, kiểm tra tệp mới trong /var/www/html và khôi phục nội dung hợp lệ khi cần.",
    "Suspicious Web File":
        "Phát hiện tệp có tên hoặc dấu hiệu đáng nghi trong web root trên {agent}. Điểm rủi ro {score}/100. "
        "Khuyến nghị: cô lập tệp, kiểm tra nội dung, đối chiếu log truy cập Web và tìm dấu hiệu web shell/backdoor.",
    "Suspected Web Compromise":
        "Trên {agent} có chuỗi dấu hiệu Web rồi đến OS/host cần điều tra. "
        "Chưa khẳng định máy chủ đã bị xâm nhập. Điểm rủi ro {score}/100. "
        "Khuyến nghị: đối chiếu Nginx access log, FIM/auditd và các tệp thay đổi trong web root.",
    "Possible Server Compromise":
        "CẢNH BÁO NGHIÊM TRỌNG: trên {agent} đã quan sát chuỗi evidence network → web → os trong thời gian ngắn. "
        "Có dấu hiệu dò quét, thử khai thác Web và sau đó xuất hiện thay đổi bất thường ở tầng hệ điều hành. "
        "Điểm rủi ro {score}/100. Khuyến nghị: kiểm tra Suricata, Nginx access log, FIM/auditd và web root; "
        "chặn IP {ip} nếu nằm ngoài danh sách cho phép và thu thập log phục vụ điều tra.",
    "Unknown":
        "Sự kiện chưa được phân loại trên {agent}, IP {ip}, điểm rủi ro {score}/100. Quản trị viên cần xem xét thủ công.",
}


def _ml_sentence(ml_result: dict | None) -> str:
    if not ml_result:
        return ""
    label = "bất thường" if ml_result.get("is_anomaly") else "chưa có dấu hiệu bất thường rõ"
    return (
        " ML cục bộ ({model}) đánh giá sự kiện {label}, anomaly_score={score}/100."
    ).format(
        model=ml_result.get("model", "local"),
        label=label,
        score=ml_result.get("anomaly_score", 0),
    )


def _correlation_sentence(correlation: dict | None) -> str:
    if not correlation:
        return ""
    if correlation.get("incident_type") == "Possible Server Compromise":
        return (
            " Chuỗi đầy đủ Network → Web → OS được quan sát; IP Network/Web "
            "khớp là bằng chứng liên kết, không xác định danh tính tác nhân."
        )
    if not correlation.get("has_network_precursor"):
        return " Không quan sát network precursor cho chuỗi Web → OS này."
    match = correlation.get("src_ip_match")
    label = "không đủ dữ liệu" if match == "unknown" else "không khớp"
    return (
        " Có network precursor nhưng liên kết IP Network/Web "
        f"{label}; không quy kết các sự kiện cho cùng tác nhân."
    )


def ai_explain(a, incident, s, ml_result=None, correlation=None):
    """Return local explanation text.

    The function name is kept for compatibility with the older pipeline, but it
    no longer calls an external LLM/OpenClaw endpoint.
    """

    tpl = TEMPLATES.get(incident, TEMPLATES["Unknown"])
    text = tpl.format(
        ip=a.get("srcip") or "N/A",
        agent=a.get("agent_name") or "N/A",
        score=s,
    )
    return text + _correlation_sentence(correlation) + _ml_sentence(ml_result)
