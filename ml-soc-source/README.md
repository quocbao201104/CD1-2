# SOC Linux + Local ML Security Log Analyzer - source lab 3 VM tren VMware

Thu muc nay la **master source cho ca 2 chuyen de**. Khong nen dem toan bo 3 VM
vao de cuong Chuyen de 1, vi CD1 chi can chung minh nang luc giam sat/phat hien
bao mat bang Wazuh.

## Phan tach pham vi

### Chuyen de 1 - SOC / he thong an toan bao mat thong tin doanh nghiep

Lam truoc, pham vi gon:

- VM1 `vms-production`: Ubuntu Server chay OpenSSH + Nginx, sinh log network/web/OS.
- VM2 `vms-soc`: Wazuh Manager + Indexer + Dashboard.
- Trong tam: Suricata IDS, Nginx access/error log, SSH/auth log, auditd, FIM,
  Wazuh Agent, local rules, MITRE mapping, alert envelope, cac kich ban phat hien.
- VM3 va phan phan tich ML chua nam trong pham vi trinh bay chinh cua CD1.

### Chuyen de 2 - Local ML phan tich nhat ky/canh bao bao mat tu CD1

Lam sau khi CD1 da on dinh va co snapshot:

- VM1/VM2 giu nguon log va canh bao CD1: network (Suricata), web (Nginx),
  auth/OS (Wazuh, auditd, FIM).
- VM3 `vms-analyzer`: FastAPI analyzer nhan alert bao mat, chuan hoa, tuong quan
  network -> web -> host, cham diem rui ro, local ML bang scikit-learn, de xuat
  playbook va ghi incident.
- Khong trien khai cac thanh phan giam sat van hanh ngoai pham vi bao mat.

## Kien truc khuyen nghi

### CD1

```text
Host Admin/Tester
        |
        | SSH 22/TCP, HTTPS 443/TCP
        v
VM1 (vms-production) -- Wazuh Agent 1514/TCP --> VM2 (vms-soc)
- Ubuntu Server                              - Wazuh Manager
- OpenSSH/Nginx/auditd/Suricata              - Wazuh Indexer
- FIM + audit rules + eve.json + web log     - Wazuh Dashboard
```

### CD2 mo rong theo huong ML cuc bo

```text
VM1 (Linux web server)        VM2 (Wazuh SOC)             VM3 (Local ML analyzer)
- Suricata eve.json --1514--> - Wazuh Manager --webhook--> /analyze-alert
- Nginx access/error log      - Local rules                - normalize
- SSH/auth.log, auditd, FIM   - Dashboard/Indexer          - correlate network/web/host
                                                           - risk + local ML
                                                           - playbook + incident log
```

Diem cham giua 2 CD la **alert envelope** thong nhat tu Wazuh integration
(`source: network|web|auth|os`).

## Cau truc thu muc

```text
ml-soc-noc-source/
|-- vms-attacker/       # Kali: kich ban test attack va checklist chup anh lab
|-- vms-production/     # VM1: Linux web server can bao ve
|-- vms-monitor/        # VM2: Wazuh SOC
\-- vms-analyzer/       # VM3: Local ML security log analyzer
```

## Thu tu trien khai CD1

1. Cai VM2 truoc:

```bash
cd vms-monitor
sudo bash install_vm2_cd1.sh
```

2. Cai VM1 va tro agent ve IP VM2:

```bash
cd vms-production
sudo bash install_vm1_cd1.sh <IP_VM2>
```

3. Tren VM1, them noi dung `ossec_fim_snippet.xml` vao khoi `<syscheck>` cua
   `/var/ossec/etc/ossec.conf`, roi restart agent.

4. Tren VM1, them noi dung `suricata_wazuh_snippet.xml` vao khoi
   `<ossec_config>` cua `/var/ossec/etc/ossec.conf` de Wazuh Agent doc
   `/var/log/suricata/eve.json`, roi restart agent.

5. Tren VM1, them noi dung `nginx_wazuh_snippet.xml` vao khoi
   `<ossec_config>` cua `/var/ossec/etc/ossec.conf` de Wazuh Agent doc
   `/var/log/nginx/access.log` va `/var/log/nginx/error.log`, roi restart agent.

6. Tren VM2, copy `wazuh/local_rules.xml` vao
   `/var/ossec/etc/rules/local_rules.xml`, roi restart manager.

7. Tren Kali/vms-attacker, chay theo checklist trong
   `vms-attacker/kich-ban-tan-cong-cd1.md` de tao log/canh bao va chup anh
   bang chung tren Attacker/VM1/VM2.

## Thu tu mo rong CD2

Sau khi CD1 da demo on, tao snapshot sach roi moi mo rong:

1. VM3: chay `vms-analyzer`, test offline local ML.
2. VM2: cau hinh Wazuh integration day alert CD1 sang VM3 `/analyze-alert`.
3. VM3: tao/cap nhat baseline tu log binh thuong bang `collect_baseline.py`.
4. Chay lai cac kich ban network/web/host de kiem tra classify, correlation,
   risk score va anomaly_score.

## Cau hinh VM toi thieu

| VM | CD1/CD2 | vCPU | RAM | Disk |
|----|--------|------|-----|------|
| VM1 | CD1 | 1-2 | 2GB | 25GB |
| VM2 | CD1 | 4 | 8GB | 50GB SSD |
| VM3 | CD2 | 1-2 | 2GB | 20GB |

May host nen co toi thieu 16GB RAM neu chay ca 3 VM. Voi CD1 chi chay VM1+VM2
thi nhe hon, nhung VM2 van nen uu tien 8GB RAM vi Wazuh Indexer kha nang.

## Luu y IP

IP trong mot so file mau co the la `IP_VM1/IP_VM2/IP_VM3`.
Khi dung VMware Host-only/NAT, doi sang dai IP that cua VMnet, vi du:

- Host Admin: `192.168.245.1`
- VM1 `vms-production`: `192.168.245.10`
- VM2 `vms-soc`: `192.168.245.20`
- VM3 `vms-analyzer`: `192.168.245.30` (CD2)
- Kali `vms-attacker`: `192.168.245.40`

## Luu y bao mat

- CD1 chi gia lap tan cong trong mang Host-only, khong thu nghiem tren he thong that.
- NAT chi nen bat tam thoi de cai package/update.
- `.env` chua secret khong commit; dung `.env.example` lam mau.
- ML CD2 chi chay cuc bo trong lab, khong gui log ra API/AI ben ngoai.
