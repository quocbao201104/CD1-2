#!/bin/bash
# CD1 - Cai dat VM2 SOC center (chi Wazuh all-in-one)
# Chay tren VM2: sudo bash install_vm2_cd1.sh
set -e
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

timedatectl set-timezone Asia/Ho_Chi_Minh
hostnamectl set-hostname vms-soc

apt update
apt upgrade -y -o Dpkg::Options::="--force-confold"
apt install -y -o Dpkg::Options::="--force-confold" curl gnupg apt-transport-https

# Wazuh all-in-one: Manager + Indexer + Dashboard
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
bash ./wazuh-install.sh -a -i

# Giam heap indexer cho lab neu VM2 chi co 8GB RAM
if [ -f /etc/wazuh-indexer/jvm.options ]; then
  sed -i 's/^-Xms.*/-Xms2g/; s/^-Xmx.*/-Xmx2g/' /etc/wazuh-indexer/jvm.options
  systemctl restart wazuh-indexer
fi

echo "[OK] VM2 CD1 da cai Wazuh all-in-one."
echo "[IMPORTANT] Luu user/password admin Wazuh ma installer in ra."
echo "[NEXT] Copy wazuh/local_rules.xml vao /var/ossec/etc/rules/local_rules.xml va restart wazuh-manager."
echo "[DASHBOARD] Truy cap tu host: https://<IP_VM2>"
