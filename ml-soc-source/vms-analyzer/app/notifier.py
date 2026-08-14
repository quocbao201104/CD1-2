"""Ghi incident cục bộ và gửi Gotify khi vượt ngưỡng rủi ro."""
import os
import datetime
import requests


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
    correlation_text = (
        "Có - network → web → os"
        if result.get("correlated")
        else "Không - cảnh báo đơn lẻ"
    )

    return (
        f"{severity_icon} CẢNH BÁO BẢO MẬT\n"
        f"Sự cố: {result.get('incident_type', 'Chưa phân loại')}\n"
        f"Mức độ: {severity_vi} ({severity})\n\n"
        f"🖥️ ĐỐI TƯỢNG\n"
        f"Máy chủ: {result.get('agent') or 'Không xác định'}\n"
        f"IP nguồn: {result.get('srcip') or 'Không xác định'}\n\n"
        f"📊 ĐÁNH GIÁ RỦI RO\n"
        f"Tổng điểm: {result.get('risk_score', 0)}/100\n"
        f"Điểm theo luật: {result.get('base_risk_score', 0)}/100\n"
        f"ML bổ sung: +{risk_delta}\n"
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
