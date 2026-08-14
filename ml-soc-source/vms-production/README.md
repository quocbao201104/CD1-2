# VM1 - Endpoint can bao ve

VM1 la may chu Linux chay OpenSSH va Nginx duoc giam sat. Trong CD1, VM1 dong
vai tro muc tieu bao ve: sinh log network, web va OS de Wazuh Agent gui ve VM2.

## CD1 - Thanh phan can cai

- Ubuntu Server
- OpenSSH Server: tao log auth, dung cho kich ban phu ve dang nhap
- nginx: dich vu web public trong lab, tao access/error log cho kich ban web
- Suricata IDS: giam sat tang network va ghi alert vao `/var/log/suricata/eve.json`
- auditd: ghi nhan thay doi file tai khoan va lenh quyen cao
- Wazuh Agent: gui log/su kien ve Wazuh Manager tren VM2
- FIM: giam sat `/etc/passwd`, `/etc/sudoers`, `authorized_keys`,
  `/etc/nginx` va `/var/www/html`

## Cai dat CD1

```bash
sudo bash install_vm1_cd1.sh <IP_VM2>
```

Vi du:

```bash
sudo bash install_vm1_cd1.sh 192.168.245.20
```

Neu can chi ro interface Suricata va dai mang lab:

```bash
sudo bash install_vm1_cd1.sh 192.168.245.20 ens33 192.168.245.0/24
```

Sau khi cai xong:

Script `install_vm1_cd1.sh` tu dong:

1. Cai va bat Nginx, tao trang web demo trong `/var/www/html/index.html`.
2. Cai va bat Suricata tren interface lab de ghi alert vao `/var/log/suricata/eve.json`.
3. Cai Wazuh Agent va cau hinh tro ve Wazuh Manager tren VM2.
4. Them FIM cho `/etc/passwd`, `/etc/sudoers`, `authorized_keys`, `/etc/nginx`
   va `/var/www/html`.
5. Them localfile de Wazuh Agent doc Suricata `eve.json`, Nginx access/error log
   va audit log.

Kiem tra sau cai dat:

```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent
sudo systemctl status suricata
sudo systemctl status nginx
curl -I http://127.0.0.1/
```

## File CD1

- `install_vm1_cd1.sh`: cai endpoint SOC thuan cho CD1.
- `soc.rules`: audit rules cho cac file/hang vi can theo doi.
- `ossec_fim_snippet.xml`: noi dung FIM them vao `ossec.conf`.
- `suricata_wazuh_snippet.xml`: cau hinh Wazuh Agent doc alert Suricata `eve.json`.
- `nginx_wazuh_snippet.xml`: cau hinh Wazuh Agent doc Nginx access/error log.
  Hai snippet nay van giu lai de tham khao/chup bao cao, nhung script CD1
  hien da tu them cac khoi tuong ung vao `ossec.conf`.

## Kich ban gia lap CD1

```bash
# Port scan tu vms-attacker de sinh alert Suricata
nmap -sS -T4 192.168.245.10

# Web probing: do cac duong dan nhay cam tren Nginx
curl http://192.168.245.10/.env
curl http://192.168.245.10/.git/config
curl http://192.168.245.10/admin
curl http://192.168.245.10/phpmyadmin

# Thu doc file he thong qua HTTP/path traversal
curl 'http://192.168.245.10/../../../../etc/passwd'
curl 'http://192.168.245.10/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# Sua noi dung web root de FIM phat hien
echo '<h1>changed by lab</h1>' | sudo tee /var/www/html/index.html

# Tao file nghi van trong web root
echo '<?php echo \"demo\"; ?>' | sudo tee /var/www/html/shell.php

# Tao user la
sudo useradd suspicious_user

# Them SSH key backdoor mau
mkdir -p ~/.ssh
echo 'ssh-rsa AAAA-test-key demo' >> ~/.ssh/authorized_keys

# Sudo abuse / lenh quyen cao
sudo cat /etc/shadow

# Brute force SSH chi la kich ban phu, khong phai trong tam duy nhat
for i in {1..8}; do ssh wronguser@192.168.245.10; done
```

Don dep sau demo:

```bash
sudo userdel -r suspicious_user 2>/dev/null || true
sed -i '/AAAA-test-key demo/d' ~/.ssh/authorized_keys 2>/dev/null || true
sudo rm -f /var/www/html/shell.php
echo 'ok' | sudo tee /var/www/html/index.html
```

## CD2 - Mo rong sau

Khi sang CD2, VM1 chu yeu giu vai tro nguon log/canh bao cho VM3 phan tich ML:

- log network tu Suricata
- log web tu Nginx
- log auth/OS tu SSH, auditd va FIM
