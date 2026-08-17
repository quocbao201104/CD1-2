"""Ghi incident cục bộ và gửi Gotify khi vượt ngưỡng rủi ro."""
import os
import datetime
import requests

_SOURCE_VI = {
    "network": "Mạng",
    "web": "Web",
    "os": "Hệ điều hành",
    "host": "Hệ điều hành",
}
_CONFIDENCE_VI = {"high": "Cao", "medium": "Trung bình"}
_IP_MATCH_VI = {
    "true": "Khớp",
    "false": "Không khớp",
    "unknown": "Không đủ dữ liệu",
}


def _correlation_text(result: dict) -> str:
    correlation = result.get("correlation")
    if not correlation:
        return "Trạng thái: Không - cảnh báo đơn lẻ"

    sources = correlation.get("sources") or []
    source_text = " → ".join(_SOURCE_VI.get(source, source) for source in sources)
    confidence = _CONFIDENCE_VI.get(
        correlation.get("confidence"), "Chưa xác định"
    )
    ip_match = _IP_MATCH_VI.get(
        correlation.get("src_ip_match"), "Không đủ dữ liệu"
    )
    observed_ips = correlation.get("observed_ips") or {}
    network_ip = observed_ips.get("network") or "Chưa ghi nhận IP nguồn"
    web_ip = observed_ips.get("web") or "Chưa ghi nhận IP nguồn"
    os_ip = observed_ips.get("os") or "Không áp dụng (event FIM/OS không có IP client)"
    ip_text = f"Mạng={network_ip}; Web={web_ip}; OS/FIM={os_ip}"
    evidence = list(correlation.get("precursor_incidents") or [])
    if correlation.get("current_incident"):
        evidence.append(correlation["current_incident"])
    lines = [
        f"Nguồn bằng chứng: {source_text or 'Không xác định'}",
        f"Độ tin cậy: {confidence}",
        f"Liên kết IP nguồn (Network/Web): {ip_match}",
        f"IP quan sát được: {ip_text}",
    ]
    if evidence:
        lines.append(f"Sự kiện đã quan sát: {' → '.join(evidence)}")

    if (
        result.get("incident_type") == "Possible Server Compromise"
        and correlation.get("confidence") == "high"
    ):
        lines.append("Chuỗi đầy đủ Mạng → Web → Hệ điều hành được quan sát.")
    elif (
        result.get("incident_type") == "Suspected Web Compromise"
        and not correlation.get("has_network_precursor")
    ):
        lines.append(
            "Không quan sát network precursor. Chuỗi Web → Hệ điều hành cần "
            "điều tra; chưa khẳng định máy chủ đã bị xâm nhập."
        )
    elif result.get("incident_type") == "Suspected Web Compromise":
        lines.append(
            "Có quan sát network precursor nhưng liên kết IP Network/Web "
            f"{ip_match.lower()}; không quy kết các sự kiện cho cùng tác nhân. "
            "Chuỗi Web → Hệ điều hành cần điều tra; chưa khẳng định máy chủ đã bị xâm nhập."
        )
    return "\n".join(lines)


def _format(result: dict) -> str:
    severity = result.get("severity", "Unknown")
    severity_labels = {
        "Critical": ("🚨", "Nghiêm trọng"),
        "High": ("⚠️", "Cao"),
        "Medium": ("🟠", "Trung bình"),
        "Low": ("🔵", "Thấp"),
    }
    severity_icon, severity_vi = severity_labels.get(severity, ("ℹ️", "Chưa xác định"))

    playbook = result.get("playbook", [])
    pb = "\n".join(f"{index}. {step}" for index, step in enumerate(playbook, 1))
    if not pb:
        pb = "1. Chưa có khuyến nghị tự động; quản trị viên cần kiểm tra thủ công."

    ml = result.get("ml", {})
    anomaly_value = ml.get("is_anomaly")
    anomaly_text = "Có" if anomaly_value is True else "Không" if anomaly_value is False else "Chưa xác định"
    risk_delta = int(ml.get("risk_delta") or 0)
    applied_ml_delta = int(ml.get("risk_delta_applied", risk_delta) or 0)
    correlation_text = _correlation_text(result)
    correlation = result.get("correlation") or {}
    observed_ips = correlation.get("observed_ips") or {}
    linked_ip = ""
    if (
        correlation.get("confidence") == "high"
        and correlation.get("src_ip_match") == "true"
        and observed_ips.get("network")
        and observed_ips.get("network") == observed_ips.get("web")
    ):
        linked_ip = (
            "\nIP nguồn đối tượng nghi ngờ (Network/Web): "
            f"{observed_ips['network']} (Khớp)"
        )

    return (
        f"{severity_icon} CẢNH BÁO BẢO MẬT\n"
        f"Nhãn phân tích: {result.get('incident_type', 'Chưa phân loại')}\n"
        f"Mức độ: {severity_vi} ({severity})\n\n"
        f"🖥️ ĐỐI TƯỢNG\n"
        f"Máy chủ: {result.get('agent') or 'Không xác định'}\n"
        f"IP máy chủ: {result.get('server_ip') or 'Chưa ghi nhận'}\n\n"
        f"📍 NGUỒN CỦA ALERT HIỆN TẠI\n"
        f"IP nguồn alert hiện tại: {result.get('srcip') or 'Chưa ghi nhận'}"
        f"{linked_ip}\n\n"
        f"📊 ĐÁNH GIÁ RỦI RO\n"
        f"Tổng điểm: {result.get('risk_score', 0)}/100\n"
        f"Điểm theo luật: {result.get('base_risk_score', 0)}/100\n"
        f"ML đề xuất: +{risk_delta}; áp dụng vào điểm: +{applied_ml_delta}\n"
        f"MITRE ATT&CK: {result.get('mitre') or 'Không xác định'}\n\n"
        f"🧠 HỌC MÁY CỤC BỘ\n"
        f"Mô hình: {ml.get('model') or 'Không xác định'}\n"
        f"Bất thường: {anomaly_text}\n"
        f"Điểm bất thường: {ml.get('anomaly_score', 0)}/100\n\n"
        f"🔗 TƯƠNG QUAN SỰ KIỆN\n"
        f"Trạng thái: {correlation_text}\n\n"
        f"📝 PHÂN TÍCH\n"
        f"{result.get('analysis') or 'Chưa có phân tích.'}\n\n"
        f"✅ KHUYẾN NGHỊ XỬ LÝ\n{pb}"
    )


def _gotify_title(result: dict) -> str:
    severity = result.get("severity", "Unknown")
    icons = {
        "Critical": "🚨",
        "High": "⚠️",
        "Medium": "🟠",
        "Low": "🔵",
    }
    return f"{icons.get(severity, 'ℹ️')} CẢNH BÁO BẢO MẬT"


def _gotify_priority(result: dict) -> int:
    return {
        "Critical": 10,
        "High": 8,
        "Medium": 5,
        "Low": 3,
    }.get(result.get("severity", "Unknown"), 3)


def notify(result: dict, md_path: str = "incidents.md"):
    text = _format(result)

    # Luôn lưu cục bộ, không phụ thuộc kết nối Gotify.
    try:
        with open(md_path, "a", encoding="utf-8") as f:
            f.write(f"\n## {datetime.datetime.now().isoformat()}\n\n```\n{text}\n```\n")
    except Exception:
        pass

    # Chỉ gửi Gotify khi đã cấu hình và đạt ngưỡng rủi ro.
    gotify_url = os.getenv("GOTIFY_URL", "").rstrip("/")
    app_token = os.getenv("GOTIFY_APP_TOKEN")
    try:
        min_risk = int(os.getenv("GOTIFY_MIN_RISK", "60"))
    except ValueError:
        min_risk = 60
    should_send = int(result.get("risk_score") or 0) >= min_risk
    if gotify_url and app_token and should_send:
        try:
            response = requests.post(
                f"{gotify_url}/message",
                headers={"X-Gotify-Key": app_token},
                json={
                    "title": _gotify_title(result),
                    "message": text,
                    "priority": _gotify_priority(result),
                },
                timeout=5,
            )
            response.raise_for_status()
        except Exception:
            pass

    return text
