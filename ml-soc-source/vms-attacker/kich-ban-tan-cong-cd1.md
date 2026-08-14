# Kịch bản tấn công CD1 - vms-attacker

File này dùng cho máy `vms-attacker` và các bước đối chiếu trên VM1/VM2 khi làm lab CD1.

Mục tiêu là tạo đủ log/cảnh báo cho các lớp giám sát đã cấu hình trong source:

- Network: Suricata trên VM1 ghi `/var/log/suricata/eve.json`.
- Web/Application: Nginx trên VM1 ghi `/var/log/nginx/access.log` và `/var/log/nginx/error.log`.
- Auth/OS: OpenSSH, auditd, FIM và Wazuh Agent trên VM1.
- SOC/SIEM: Wazuh Manager trên VM2 nhận log/cảnh báo và hiển thị trên Dashboard.

## 0. Thông tin lab

```text
VMware Host-only network : 192.168.245.0/24
VM1 vms-production       : 192.168.245.10
VM2 vms-monitor          : 192.168.245.20
Kali vms-attacker        : 192.168.245.40
Admin PC                 : 192.168.245.1
```

Các rule chính đang có trong `vms-monitor/wazuh/local_rules.xml`:

```text
100100 - SOC: Brute force SSH tu cung mot IP
100101 - SOC: Login SSH thanh cong sau brute force
100102 - SOC: Tai khoan moi duoc tao
100103 - SOC: File /etc/passwd bi thay doi
100104 - SOC: SSH authorized_keys bi thay doi
100105 - SOC: Lenh quyen cao duoc thuc thi
100200 - WEB: Sensitive path probing on Nginx
100201 - WEB: Directory traversal attempt on Nginx
100202 - SOC: Web root file modified
100203 - SOC: Suspicious file created in web root
```

## 1. Chuẩn bị và chụp trạng thái ban đầu

### 1.1. Trên Kali/vms-attacker

```bash
ip -br -4 addr
# [CHỤP 01-ATTACKER] Terminal Kali hiển thị IP 192.168.245.40.

ping -c 4 192.168.245.10
# [CHỤP 02-ATTACKER] Kali ping được VM1 192.168.245.10.

curl -I http://192.168.245.10/
# [CHỤP 03-ATTACKER] HTTP trả về header của Nginx trên VM1.
```

Nếu Kali thiếu công cụ, cài thêm:

```bash
sudo apt update
sudo apt install -y nmap curl hydra sshpass
# [CHỤP 04-ATTACKER] Cài đủ nmap, curl, hydra, sshpass.
```

### 1.2. Trên VM1/vms-production

```bash
hostname -I
# [CHỤP 05-VM1] VM1 hiển thị IP 192.168.245.10.

sudo systemctl status nginx --no-pager
# [CHỤP 06-VM1] Nginx đang active.

sudo systemctl status suricata --no-pager
# [CHỤP 07-VM1] Suricata đang active.

sudo systemctl status wazuh-agent --no-pager
# [CHỤP 08-VM1] Wazuh Agent đang active.

sudo systemctl status auditd --no-pager
# [CHỤP 09-VM1] auditd đang active.
```

### 1.3. Trên VM2/vms-monitor

```bash
hostname -I
# [CHỤP 10-VM2] VM2 hiển thị IP 192.168.245.20.

sudo systemctl status wazuh-manager --no-pager
# [CHỤP 11-VM2] Wazuh Manager đang active.

sudo /var/ossec/bin/agent_control -l
# [CHỤP 12-VM2] Agent vms-production đang kết nối/active.
```

Trên trình duyệt máy thật:

```text
https://192.168.245.20
```

```text
[CHỤP 13-VM2-DASHBOARD] Wazuh Dashboard đăng nhập được, thấy agent vms-production.
```

## 2. Kịch bản 1 - Recon và port scan tầng network

Mục tiêu: Kali quét VM1 để Suricata trên VM1 ghi alert network vào `eve.json`, sau đó Wazuh Agent gửi về VM2.

### 2.1. Chạy trên Kali/vms-attacker

```bash
sudo nmap -sS -sV -O -p 22,80 192.168.245.10
# [CHỤP 14-ATTACKER] Kết quả nmap thấy SSH 22 và HTTP 80 trên VM1.

sudo nmap -sS -T4 --script http-title,http-headers -p 22,80 192.168.245.10
# [CHỤP 15-ATTACKER] Kết quả nmap NSE/http script, dùng để tạo dấu hiệu scan rõ hơn cho Suricata.

sleep 30
# [CHỤP 16-ATTACKER] Chờ 30 giây để Suricata và Wazuh xử lý log.
```

### 2.2. Đối chiếu trên VM1/vms-production

```bash
sudo tail -n 40 /var/log/suricata/eve.json
# [CHỤP 17-VM1] eve.json có event từ src_ip 192.168.245.40 tới dest_ip 192.168.245.10.
```

### 2.3. Đối chiếu trên VM2/vms-monitor

```bash
sudo grep -E 'suricata|Suricata|192.168.245.40|192.168.245.10' /var/ossec/logs/alerts/alerts.json | tail -n 20
# [CHỤP 18-VM2] alerts.json có cảnh báo Suricata/network liên quan Kali -> VM1.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND (suricata OR 192.168.245.40)
```

```text
[CHỤP 19-VM2-DASHBOARD] Dashboard hiển thị alert network/Suricata.
```

## 3. Kịch bản 2 - Web sensitive path probing trên Nginx

Mục tiêu: tạo Nginx access log khớp rule `100200`.

### 3.1. Chạy trên Kali/vms-attacker

```bash
curl -i http://192.168.245.10/.env
# [CHỤP 20-ATTACKER] Request dò file .env.

curl -i http://192.168.245.10/.git/config
# [CHỤP 21-ATTACKER] Request dò .git/config.

curl -i http://192.168.245.10/admin
# [CHỤP 22-ATTACKER] Request dò /admin.

curl -i http://192.168.245.10/phpmyadmin
# [CHỤP 23-ATTACKER] Request dò /phpmyadmin.

curl -i http://192.168.245.10/wp-login.php
# [CHỤP 24-ATTACKER] Request dò /wp-login.php.

sleep 20
# [CHỤP 25-ATTACKER] Chờ 20 giây để Wazuh nhận log Nginx.
```

### 3.2. Đối chiếu trên VM1/vms-production

```bash
sudo tail -n 30 /var/log/nginx/access.log
# [CHỤP 26-VM1] access.log có các path .env, .git/config, /admin, /phpmyadmin, /wp-login.php từ 192.168.245.40.
```

### 3.3. Đối chiếu trên VM2/vms-monitor

```bash
sudo grep -E '"id":"100200"|Sensitive path|/\.env|/\.git|/admin|/phpmyadmin|/wp-login' /var/ossec/logs/alerts/alerts.json | tail -n 20
# [CHỤP 27-VM2] alerts.json có rule 100200 hoặc mô tả WEB: Sensitive path probing on Nginx.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100200
```

```text
[CHỤP 28-VM2-DASHBOARD] Dashboard hiển thị cảnh báo WEB sensitive path probing.
```

## 4. Kịch bản 3 - Directory traversal qua HTTP

Mục tiêu: tạo Nginx access log khớp rule `100201`.

### 4.1. Chạy trên Kali/vms-attacker

```bash
curl -i 'http://192.168.245.10/../../../../etc/passwd'
# [CHỤP 29-ATTACKER] Request thử path traversal dạng ../.

curl -i 'http://192.168.245.10/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
# [CHỤP 30-ATTACKER] Request thử path traversal dạng encode %2e%2e.

sleep 20
# [CHỤP 31-ATTACKER] Chờ 20 giây để VM1/VM2 xử lý log.
```

### 4.2. Đối chiếu trên VM1/vms-production

```bash
sudo tail -n 30 /var/log/nginx/access.log
# [CHỤP 32-VM1] access.log có request chứa ../, %2e%2e hoặc /etc/passwd.
```

### 4.3. Đối chiếu trên VM2/vms-monitor

```bash
sudo grep -E '"id":"100201"|Directory traversal|%2e%2e|/etc/passwd' /var/ossec/logs/alerts/alerts.json | tail -n 20
# [CHỤP 33-VM2] alerts.json có rule 100201 hoặc mô tả WEB: Directory traversal attempt on Nginx.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100201
```

```text
[CHỤP 34-VM2-DASHBOARD] Dashboard hiển thị cảnh báo directory traversal.
```

## 5. Kịch bản 4 - SSH brute force có kiểm soát

Mục tiêu: tạo nhiều lần đăng nhập SSH thất bại từ Kali để khớp rule `100100`.

### 5.1. Chạy trên Kali/vms-attacker

```bash
printf "admin\nroot\ntest\nubuntu\nwronguser\n" > users.txt
# [CHỤP 35-ATTACKER] Tạo danh sách user thử nghiệm.

printf "123456\npassword\nadmin\nwrongpass\nLab@12345\n" > pass.txt
# [CHỤP 36-ATTACKER] Tạo danh sách password thử nghiệm.

hydra -L users.txt -P pass.txt ssh://192.168.245.10 -s 22 -t 2 -W 3 -V
# [CHỤP 37-ATTACKER] Hydra tạo nhiều lần SSH failed login tới VM1.

sleep 30
# [CHỤP 38-ATTACKER] Chờ 30 giây để Wazuh gom đủ frequency rule 100100.
```

Nếu Hydra lỗi, dùng phương án dự phòng:

```bash
for i in $(seq 1 8); do sshpass -p wrongpass ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 wronguser@192.168.245.10 'whoami'; done
# [CHỤP 39-ATTACKER] Phương án dự phòng tạo ít nhất 8 lần SSH failed login.
```

### 5.2. Đối chiếu trên VM1/vms-production

```bash
sudo grep -E 'Failed password|Invalid user|authentication failure' /var/log/auth.log | tail -n 30
# [CHỤP 40-VM1] auth.log có nhiều lần SSH đăng nhập thất bại từ 192.168.245.40.
```

### 5.3. Đối chiếu trên VM2/vms-monitor

```bash
sudo grep -E '"id":"100100"|Brute force SSH|192.168.245.40' /var/ossec/logs/alerts/alerts.json | tail -n 20
# [CHỤP 41-VM2] alerts.json có rule 100100.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100100
```

```text
[CHỤP 42-VM2-DASHBOARD] Dashboard hiển thị cảnh báo brute force SSH.
```

## 6. Kịch bản 5 - Login thành công sau brute force

Mục tiêu: nếu cần chứng minh rule `100101`, tạo user lab trên VM1 rồi đăng nhập đúng từ Kali sau khi đã có brute force.

### 6.1. Tạo user lab trên VM1/vms-production

```bash
sudo useradd -m cd1user
# [CHỤP 43-VM1] Tạo user cd1user để test đăng nhập thành công.

echo 'cd1user:Lab@12345' | sudo chpasswd
# [CHỤP 44-VM1] Đặt password lab cho cd1user.
```

Lưu ý: hai lệnh trên cũng có thể sinh thêm cảnh báo tạo/sửa tài khoản, phù hợp với phần Auth/OS.

### 6.2. Đăng nhập từ Kali/vms-attacker

```bash
sshpass -p 'Lab@12345' ssh -o StrictHostKeyChecking=no cd1user@192.168.245.10 'whoami; hostname'
# [CHỤP 45-ATTACKER] Kali đăng nhập SSH thành công vào VM1 bằng user lab.

sleep 20
# [CHỤP 46-ATTACKER] Chờ Wazuh xử lý rule login thành công sau brute force.
```

### 6.3. Đối chiếu trên VM1/vms-production

```bash
sudo grep -E 'Accepted password|session opened|cd1user' /var/log/auth.log | tail -n 30
# [CHỤP 47-VM1] auth.log có Accepted password/session opened cho cd1user từ 192.168.245.40.
```

### 6.4. Đối chiếu trên VM2/vms-monitor

```bash
sudo grep -E '"id":"100101"|Login SSH thanh cong sau brute force|cd1user|192.168.245.40' /var/ossec/logs/alerts/alerts.json | tail -n 20
# [CHỤP 48-VM2] alerts.json có rule 100101 nếu rule tương quan được kích hoạt.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100101
```

```text
[CHỤP 49-VM2-DASHBOARD] Dashboard hiển thị login SSH thành công sau brute force.
```

## 7. Kịch bản 6 - Thay đổi web root và tạo file nghi vấn

Mục tiêu: tạo FIM alert cho `/var/www/html`, khớp rule `100202` và `100203`.

Lệnh chạy trên VM1 vì đây là bước mô phỏng sau khi kẻ tấn công hoặc người kiểm thử đã có quyền thao tác lên máy chủ.

### 7.1. Chạy trên VM1/vms-production

```bash
echo '<h1>changed by CD1 lab</h1>' | sudo tee /var/www/html/index.html
# [CHỤP 50-VM1] Sửa nội dung index.html trong web root.

echo '<?php echo "demo"; ?>' | sudo tee /var/www/html/shell.php
# [CHỤP 51-VM1] Tạo file shell.php trong web root để khớp rule file nghi vấn.

ls -la /var/www/html
# [CHỤP 52-VM1] Hiển thị index.html và shell.php trong /var/www/html.

sleep 30
# [CHỤP 53-VM1] Chờ FIM/Wazuh Agent gửi sự kiện về VM2.
```

### 7.2. Đối chiếu trên VM2/vms-monitor

```bash
sudo grep -E '"id":"100202"|"id":"100203"|Web root file modified|Suspicious file created|/var/www/html|shell.php' /var/ossec/logs/alerts/alerts.json | tail -n 30
# [CHỤP 54-VM2] alerts.json có rule 100202/100203.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND (rule.id:100202 OR rule.id:100203)
```

```text
[CHỤP 55-VM2-DASHBOARD] Dashboard hiển thị cảnh báo web root modified/suspicious file.
```

## 8. Kịch bản 7 - Tài khoản, SSH key và lệnh quyền cao

Mục tiêu: tạo log Auth/OS cho các rule `100102`, `100103`, `100104`, `100105`.

Các lệnh chạy trên VM1 để mô phỏng hành vi hậu xâm nhập hoặc thao tác quản trị bất thường.

### 8.1. Tạo tài khoản lạ trên VM1/vms-production

```bash
sudo useradd suspicious_user
# [CHỤP 56-VM1] Tạo user suspicious_user.

sudo grep suspicious_user /etc/passwd
# [CHỤP 57-VM1] /etc/passwd có user suspicious_user.

sleep 30
# [CHỤP 58-VM1] Chờ Wazuh nhận event tạo/sửa tài khoản.
```

Đối chiếu trên VM2:

```bash
sudo grep -E '"id":"100102"|"id":"100103"|Tai khoan moi|/etc/passwd|suspicious_user' /var/ossec/logs/alerts/alerts.json | tail -n 30
# [CHỤP 59-VM2] alerts.json có cảnh báo tạo tài khoản hoặc /etc/passwd bị thay đổi.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND (rule.id:100102 OR rule.id:100103)
```

```text
[CHỤP 60-VM2-DASHBOARD] Dashboard hiển thị cảnh báo tài khoản mới hoặc /etc/passwd thay đổi.
```

### 8.2. Thêm SSH authorized_keys mẫu trên VM1/vms-production

```bash
sudo mkdir -p /root/.ssh
# [CHỤP 61-VM1] Tạo thư mục /root/.ssh nếu chưa có.

echo 'ssh-rsa AAAA-test-key cd1-demo-key' | sudo tee -a /root/.ssh/authorized_keys
# [CHỤP 62-VM1] Thêm SSH key mẫu vào /root/.ssh/authorized_keys.

sudo tail -n 5 /root/.ssh/authorized_keys
# [CHỤP 63-VM1] Xác nhận key mẫu đã được thêm.

sleep 30
# [CHỤP 64-VM1] Chờ FIM gửi event về VM2.
```

Đối chiếu trên VM2:

```bash
sudo grep -E '"id":"100104"|authorized_keys|SSH authorized_keys' /var/ossec/logs/alerts/alerts.json | tail -n 20
# [CHỤP 65-VM2] alerts.json có rule 100104.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100104
```

```text
[CHỤP 66-VM2-DASHBOARD] Dashboard hiển thị cảnh báo authorized_keys bị thay đổi.
```

### 8.3. Chạy lệnh quyền cao trên VM1/vms-production

```bash
sudo cat /etc/shadow | head -n 5
# [CHỤP 67-VM1] Chạy lệnh quyền cao đọc /etc/shadow.

sudo ausearch -k root_cmd -ts recent | tail -n 40
# [CHỤP 68-VM1] auditd ghi nhận root_cmd gần đây.

sleep 30
# [CHỤP 69-VM1] Chờ Wazuh nhận audit log.
```

Đối chiếu trên VM2:

```bash
sudo grep -E '"id":"100105"|Lenh quyen cao|root_cmd|/etc/shadow' /var/ossec/logs/alerts/alerts.json | tail -n 30
# [CHỤP 70-VM2] alerts.json có rule 100105 hoặc event root_cmd.
```

Trên Wazuh Dashboard lọc:

```text
agent.name:vms-production AND rule.id:100105
```

```text
[CHỤP 71-VM2-DASHBOARD] Dashboard hiển thị cảnh báo lệnh quyền cao.
```

## 9. Tổng hợp ảnh cần có trong báo cáo CD1

Nên chọn ảnh theo nhóm, không cần nhét toàn bộ 71 ảnh vào báo cáo chính.

```text
Nhóm 1 - Mô hình và trạng thái dịch vụ:
01, 02, 06, 07, 08, 11, 12, 13

Nhóm 2 - Network scan:
14 hoặc 15, 17, 18 hoặc 19

Nhóm 3 - Web probing:
20-24, 26, 27 hoặc 28

Nhóm 4 - Directory traversal:
29 hoặc 30, 32, 33 hoặc 34

Nhóm 5 - SSH brute force:
37 hoặc 39, 40, 41 hoặc 42

Nhóm 6 - FIM web root:
50-52, 54 hoặc 55

Nhóm 7 - Auth/OS:
56-57, 59 hoặc 60, 62-63, 65 hoặc 66, 67-68, 70 hoặc 71
```

Gợi ý đặt tên ảnh:

```text
CD1_01_Attacker_IP.png
CD1_02_Attacker_Ping_VM1.png
CD1_14_Nmap_Result.png
CD1_17_VM1_Suricata_Eve.png
CD1_19_VM2_Suricata_Dashboard.png
CD1_28_VM2_Web_Probing.png
CD1_34_VM2_Traversal.png
CD1_42_VM2_SSH_Bruteforce.png
CD1_55_VM2_FIM_Webroot.png
CD1_71_VM2_Root_Command.png
```

## 10. Dọn dẹp sau demo

Chạy trên VM1/vms-production:

```bash
sudo userdel -r suspicious_user 2>/dev/null || true
# [CHỤP 72-VM1] Xóa user suspicious_user nếu đã tạo.

sudo userdel -r cd1user 2>/dev/null || true
# [CHỤP 73-VM1] Xóa user cd1user nếu đã tạo.

sudo sed -i '/AAAA-test-key cd1-demo-key/d' /root/.ssh/authorized_keys 2>/dev/null || true
# [CHỤP 74-VM1] Gỡ SSH key mẫu khỏi authorized_keys.

sudo rm -f /var/www/html/shell.php
# [CHỤP 75-VM1] Xóa file shell.php.

echo '<h1>vms-production</h1><p>Nginx demo service for CD1 SOC/Wazuh/Suricata lab.</p>' | sudo tee /var/www/html/index.html
# [CHỤP 76-VM1] Khôi phục nội dung trang demo.

sudo systemctl restart nginx
# [CHỤP 77-VM1] Restart Nginx sau khi dọn dẹp.
```

## 11. Ghi chú khi dùng cho CD2

Các kịch bản trên vẫn dùng được để tạo dữ liệu cho CD2. Khi VM2 đã cấu hình integration gửi alert sang VM3, luồng kiểm chứng là:

```text
Kali/VM1 tạo hành vi bất thường -> VM1 sinh log -> VM2 Wazuh tạo alert -> VM3 phân tích ML cục bộ.
```

Khi đó chụp thêm trên VM3:

```bash
journalctl -u vms-analyzer --since "10 min ago" --no-pager
# [CHỤP CD2-VM3-01] VM3 nhận request phân tích từ VM2.

curl http://127.0.0.1:8000/health
# [CHỤP CD2-VM3-02] FastAPI Analyzer đang chạy.
```
