# VM2 - SOC center

VM2 la trung tam SOC. Trong CD1, VM2 chi can chay Wazuh all-in-one de nhan log
tu VM1, phan tich rule va hien thi alert tren Dashboard.

## CD1 - Thanh phan can cai

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Local rules cho cac kich ban network/web/OS: port scan Suricata, web probing
  Nginx, FIM web root, sua file tai khoan, SSH key va sudo/auditd

## Cai dat CD1

```bash
sudo bash install_vm2_cd1.sh
```

Sau khi installer xong, luu lai user/password admin Wazuh. Truy cap Dashboard:

```text
https://<IP_VM2>
```

## Cai local rules CD1

```bash
sudo cp wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 640 /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Kiem tra rule khong can tan cong that:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Dan thu log:

```text
Failed password for invalid user admin from 45.13.10.10 port 53321 ssh2
```

Co the dan them log web vao `wazuh-logtest` de kiem tra rule web:

```text
192.168.245.40 - - [06/Jul/2026:10:00:00 +0700] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.0"
192.168.245.40 - - [06/Jul/2026:10:01:00 +0700] "GET /../../../../etc/passwd HTTP/1.1" 400 153 "-" "curl/8.0"
```

## Firewall CD1

Gioi han theo IP VM1 va host admin neu co dung `ufw`:

```bash
sudo ufw allow from IP_VM1 to any port 1514 proto tcp
sudo ufw allow from IP_VM1 to any port 1515 proto tcp
sudo ufw allow from IP_ADMIN to any port 443 proto tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

## File CD1

- `install_vm2_cd1.sh`: cai Wazuh all-in-one cho CD1.
- `wazuh/local_rules.xml`: rule SOC custom cho cac kich ban network/web/OS.

## CD2 - Mo rong sau

Khi sang CD2, VM2 chu yeu dong vai tro nguon alert cho VM3:

- Wazuh integration day alert sang VM3 `/analyze-alert`
- Dashboard dung de doi chieu bang chung va chup anh lab
