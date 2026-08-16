"""Correlation Engine: nối evidence Network, Web và OS trên cùng máy chủ.

Buffer in-memory có TTL 10 phút, phù hợp cho môi trường demo và được reset khi
dịch vụ khởi động lại. IP nguồn là bằng chứng liên kết, không là điều kiện cứng:
FIM/OS thường không có IP. Chỉ Network và Web có IP giống nhau mới được nâng
lên confidence cao; không suy diễn danh tính tác nhân từ việc IP khớp.
"""
import time
from collections import deque

WINDOW = 600  # giây (10 phút)
_buf = deque()  # mỗi phần tử: (epoch, source, server, incident, ip)


def remember(source: str, server: str, incident: str, ip):
    _buf.append((time.time(), source, server, incident, ip))


def _prune():
    now = time.time()
    while _buf and now - _buf[0][0] > WINDOW:
        _buf.popleft()


def _src_ip_match(network_ip, web_ip):
    if not network_ip or not web_ip:
        return "unknown"
    return "true" if network_ip == web_ip else "false"


def correlate(
    source: str,
    server: str,
    current_ip=None,
    current_incident: str | None = None,
):
    """Trả về evidence tier khi OS/host xuất hiện sau evidence Web.

    Network là evidence tùy chọn. Nó chỉ nâng Web -> OS lên confidence cao khi
    IP nguồn Network và Web giống nhau; IP khớp không chứng minh danh tính.
    """
    _prune()

    if source not in {"os", "host"} or not server:
        return None

    events = [event for event in _buf if event[2] == server]
    matched_web = next(
        (event for event in reversed(events) if event[1] == "web"),
        None,
    )
    if not matched_web:
        return None

    now = time.time()
    web_ts, _, _, web_incident, web_ip = matched_web
    matched_network = next(
        (
            event
            for event in reversed(events)
            if event[1] == "network" and event[0] <= web_ts
        ),
        None,
    )
    network_ip = matched_network[4] if matched_network else None
    has_network = matched_network is not None
    ip_match = _src_ip_match(network_ip, web_ip)
    high_confidence = has_network and ip_match == "true"

    precursor_incidents = [web_incident]
    sources = ["web", "os"]
    if matched_network:
        precursor_incidents.insert(0, matched_network[3])
        sources.insert(0, "network")

    result = {
        "correlated": True,
        "incident_type": (
            "Possible Server Compromise"
            if high_confidence
            else "Suspected Web Compromise"
        ),
        "confidence": "high" if high_confidence else "medium",
        "with": ",".join(sources[:-1]),
        "other_incident": web_incident,
        "current_incident": current_incident,
        "precursor_incidents": precursor_incidents,
        "other_ip": web_ip or network_ip,
        "sources": sources,
        "has_network_precursor": has_network,
        "src_ip_match": ip_match,
        "observed_ips": {
            "network": network_ip,
            "web": web_ip,
            "os": current_ip,
        },
        "time_delta_web_to_os": int(now - web_ts),
    }
    if matched_network:
        result["time_delta_network_to_os"] = int(now - matched_network[0])
    return result


def reset():
    """Xóa buffer; dùng cho test hoặc bắt đầu một lượt demo mới."""
    _buf.clear()
