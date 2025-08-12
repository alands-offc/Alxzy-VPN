#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
export REPO_URL="https://raw.githubusercontent.com/alands-offc/Alxzy-VPN/main"

timedatectl set-timezone Asia/Jakarta
apt update && apt upgrade -y
apt install -y software-properties-common
add-apt-repository -y ppa:deadsnakes/ppa
apt update -y
apt install -y python3.11
apt install -y nginx stunnel4 openvpn wireguard cron git cmake make gcc build-essential golang-go python3-pip socat unzip pwgen curl net-tools neofetch
apt update -y
apt install -y openssl libssl-dev libnspr4 libnspr4-dev
systemctl enable nginx; systemctl start nginx
systemctl enable stunnel4; systemctl start stunnel4
systemctl enable cron; systemctl start cron

rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "${REPO_URL}/main/nginx.conf"
mkdir -p /home/vps/public_html
echo "<h1>Alxzy VPN</h1>" > /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "${REPO_URL}/main/vps.conf"

cat > /etc/systemd/system/ws.service << END
[Unit]
Description=Python WebSocket Proxy for SSH
After=network.target

[Service]
User=root
ExecStart=/usr/bin/python3 -m http.server 8880 --bind 127.0.0.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
END
systemctl enable ws; systemctl start ws

openssl genrsa -out /etc/stunnel/privkey.pem 2048
openssl req -new -x509 -days 3650 -key /etc/stunnel/privkey.pem -out /etc/stunnel/cert.pem -subj "/CN=alxzy-vpn"
cat /etc/stunnel/privkey.pem /etc/stunnel/cert.pem >> /etc/stunnel/stunnel.pem
wget -O /etc/stunnel/stunnel.conf "${REPO_URL}/main/stunnel.conf"
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
systemctl restart stunnel4

sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 225' /etc/ssh/sshd_config
systemctl restart sshd

git clone https://github.com/XTLS/badvpn.git
cd badvpn
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j"$(nproc)"
make install
cat > /etc/systemd/system/badvpn.service << END
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 2000
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
END
systemctl enable badvpn; systemctl start badvpn

mkdir -p /etc/alxzyvpn/main
touch /var/lib/data-user-list.txt

wget -O /usr/local/bin/menu "${REPO_URL}/main/menu" && chmod +x /usr/local/bin/menu
wget -O /etc/alxzyvpn/main/banner "${REPO_URL}/main/banner"
wget -O /etc/alxzyvpn/main/adduser "${REPO_URL}/main/adduser" && chmod +x /etc/alxzyvpn/main/adduser
wget -O /etc/alxzyvpn/main/deluser "${REPO_URL}/main/deluser" && chmod +x /etc/alxzyvpn/main/deluser
wget -O /etc/alxzyvpn/main/trial "${REPO_URL}/main/trial" && chmod +x /etc/alxzyvpn/main/trial
wget -O /etc/alxzyvpn/main/xp "${REPO_URL}/main/xp" && chmod +x /etc/alxzyvpn/main/xp

cat > /etc/cron.d/xp_user << END
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 1 * * * root /etc/alxzyvpn/main/xp
END
chmod 644 /etc/cron.d/xp_user
crontab /etc/cron.d/xp_user

history -c
rm -f install.sh
neofetch
echo ""
echo "=============================================="
echo "      Instalasi Layanan VPN Selesai!      "
echo "=============================================="
echo ""
echo "Ketik 'menu' untuk menampilkan panel kontrol."
echo ""
