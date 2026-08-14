"""Correlation Engine: phát hiện chuỗi network -> web -> os cùng máy chủ.

Buffer in-memory (deque) có TTL 10 phút, phù hợp cho môi trường demo và được
reset khi dịch vụ khởi động lại. Không bắt buộc IP nguồn giống nhau vì sự kiện
FIM thường không có IP và Windows portproxy có thể làm thay đổi IP quan sát.
"""
import time
from collections import deque

WINDOW = 600  # giay (10 phut)
_buf = deque()  # moi phan tu: (epoch, source, server, incident, ip)


def remember(source: str, server: str, incident: str, ip):
    _buf.append((time.time(), source, server, incident, ip))


def _prune():
    now = time.time()
    while _buf and now - _buf[0][0] > WINDOW:
        _buf.popleft()


def correlate(source: str, server: str):
    """Trả về kết quả khi alert hiện tại hoàn tất chuỗi ba tầng hợp lệ."""
    _prune()

    if source not in {"os", "host"} or not server:
        return None

    events = [event for event in _buf if event[2] == server]
    web_events = [event for event in events if event[1] == "web"]

    matched_web = None
    matched_network = None
    for web_event in reversed(web_events):
        web_ts = web_event[0]
        network_event = next(
            (
                event
                for event in reversed(events)
                if event[1] == "network" and event[0] <= web_ts
            ),
            None,
        )
        if network_event:
            matched_network = network_event
            matched_web = web_event
            break

    if not matched_network or not matched_web:
        return None

    now = time.time()
    network_ts, _, _, network_incident, network_ip = matched_network
    _, _, _, web_incident, web_ip = matched_web
    return {
        "correlated": True,
        "with": "network,web",
        "other_incident": web_incident,
        "precursor_incidents": [network_incident, web_incident],
        "other_ip": web_ip or network_ip,
        "sources": ["network", "web", "os"],
        "has_network_precursor": True,
        "time_delta_network_to_os": int(now - network_ts),
    }


def reset():
    """Xóa buffer; dùng cho test hoặc bắt đầu một lượt demo mới."""
    _buf.clear()
