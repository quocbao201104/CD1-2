"""Phan loai su co - deterministic, dua tren tu khoa trong rule_description + full_log."""


def classify(desc: str, full_log: str = "") -> str:
    d = (desc + " " + full_log).lower()
    # Thu tu kiem tra co y nghia: case dac biet truoc case chung
    if "suricata" in d or "et scan" in d or "nmap" in d or "port scan" in d:
        return "Network Port Scan"
    if "traversal" in d or "../" in d or "%2e%2e" in d or ("/etc/passwd" in d and "http/1." in d):
        return "Web Traversal Attempt"
    if "sensitive path" in d or "/.env" in d or "/.git" in d or "phpmyadmin" in d or "/admin" in d:
        return "Web Sensitive Path Scan"
    if "/var/www/html" in d and ("shell" in d or "backdoor" in d or "payload" in d):
        return "Suspicious Web File"
    if "/var/www/html" in d or "web root" in d:
        return "Web Root Modified"
    if "after brute" in d or ("login" in d and "sau brute" in d):
        return "Valid Login After Brute Force"
    if "brute" in d or "authentication failure" in d or "authentication failures" in d:
        return "SSH Brute Force"
    if "authorized_keys" in d:
        return "SSH Key Backdoor"
    if "passwd" in d:
        return "Account File Modified"
    if "sudoers" in d or "sudo" in d:
        return "Privilege Escalation"
    if "new account" in d or "user added" in d or "tai khoan moi" in d or "new user" in d:
        return "Suspicious User Creation"
    return "Unknown"
