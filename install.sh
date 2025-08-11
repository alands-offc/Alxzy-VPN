#!/bin/bash
# =================================================================
# VPN Auto Installer v3.8.1 - Hybrid Stunnel + Nginx + BadVPN
# =================================================================

set -e
msg_info() { echo -e "\n\e[1;33m[*] $1\e[0m"; }
msg_ok() { echo -e "\n\e[1;32m[+] $1\e[0m"; }
msg_err() { echo -e "\n\e[1;31m[!] $1\e[0m"; exit 1; }
if [ "$(id -u)" -ne 0 ]; then msg_err "Skrip ini harus dijalankan sebagai root."; fi

clear
echo -e "\n\e[1;35m=========================================================\e[0m"
echo -e " \e[1;36m VPN Auto Installer v3.8.1 - Hybrid Final Edition\e[0m"
echo -e "\e[1;35m=========================================================\e[0m"
read -p "➡️  Masukkan domain/subdomain Anda: " DOMAIN
read -p "➡️  Masukkan email Anda untuk SSL: " LETSENCRYPT_EMAIL
if [[ -z "$DOMAIN" || -z "$LETSENCRYPT_EMAIL" ]]; then msg_err "Domain dan Email tidak boleh kosong!"; fi
echo "$DOMAIN" > /root/domain

# --- Tahap 1: Instalasi Paket & Firewall ---
msg_info "Menginstal paket dan mengatur firewall..."
export DEBIAN_FRONTEND=noninteractive
apt update > /dev/null 2>&1 && apt upgrade -y > /dev/null 2>&1
# Menambahkan kembali git, cmake, make, gcc untuk build badvpn
apt install -y stunnel4 nginx ufw dropbear certbot cron git cmake make gcc

# Port UDPGW 7300 ditambahkan kembali
ufw allow 22,80,443,8443,2043/tcp
ufw allow 2253/tcp # Internal Dropbear
ufw allow 7300/udp # BadVPN
ufw --force enable
ufw reload > /dev/null 2>&1

# --- Tahap 2: Konfigurasi Dropbear & Sertifikat SSL ---
msg_info "Konfigurasi Dropbear & meminta sertifikat SSL..."
DROPBEAR_PORT=2253
cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=${DROPBEAR_PORT}
DROPBEAR_EXTRA_ARGS=""
EOF
systemctl restart dropbear && systemctl enable dropbear

systemctl stop nginx > /dev/null 2>&1 || true
systemctl stop stunnel4 > /dev/null 2>&1 || true
certbot certonly --standalone --agree-tos --no-eff-email --email "$LETSENCRYPT_EMAIL" -d "$DOMAIN"
CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

# --- Tahap 3: Konfigurasi BadVPN (UDPGW) ---
msg_info "Menginstal dan konfigurasi BadVPN (UDPGW)..."
cd /root
if [ ! -d "badvpn" ]; then git clone https://github.com/ambrop72/badvpn.git; fi
cd badvpn
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j"$(nproc)"
make install
# Buat service untuk badvpn-udpgw
cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target
[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 512
User=root
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now badvpn.service

# --- Tahap 4: Konfigurasi Stunnel HANYA untuk Port 443 ---
msg_info "Konfigurasi Stunnel untuk menangani port 443 (SSH SSL)..."
cat > /etc/stunnel/stunnel.conf << EOF
pid = /var/run/stunnel4/stunnel.pid
cert = $CERT_PATH
key = $KEY_PATH
client = no
[ssh_ssl]
accept = 443
connect = 127.0.0.1:${DROPBEAR_PORT}
EOF
sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

# --- Tahap 5: Konfigurasi Nginx untuk port 80, 8443, 2043 ---
msg_info "Konfigurasi Nginx untuk menangani port WS & WSS..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/*.conf
cat > /etc/nginx/conf.d/main_config.conf <<EOF
# PORT 80 (UNTUK VMESS & VLESS WS TANPA SSL)
server {
    listen 80;
    server_name vpn.alxzy.xyz;
    location /vmess { 
        proxy_pass http://127.0.0.1:10001; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade $http_upgrade; 
        proxy_set_header Connection "upgrade"; 
    }
    location /vless { 
        proxy_pass http://127.0.0.1:10002; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade $http_upgrade; 
        proxy_set_header Connection "upgrade"; 
    }
}

# PORT 8443 (SSL/WSS KHUSUS UNTUK VMESS)
server {
    listen 8443 ssl http2;
    server_name vpn.alxzy.xyz;

    ssl_certificate /etc/letsencrypt/live/vpn.alxzy.xyz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.alxzy.xyz/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / { 
        proxy_pass http://127.0.0.1:10001; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade $http_upgrade; 
        proxy_set_header Connection "upgrade"; 
    }
}

# PORT 2043 (SSL/WSS KHUSUS UNTUK VLESS)
server {
    listen 2043 ssl http2;
    server_name vpn.alxzy.xyz;

    ssl_certificate /etc/letsencrypt/live/vpn.alxzy.xyz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.alxzy.xyz/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / { 
        proxy_pass http://127.0.0.1:10002; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade $http_upgrade; 
        proxy_set_header Connection "upgrade"; 
    }
}
EOF
systemctl restart nginx

# --- Tahap 6: Konfigurasi Xray ---
msg_info "Menginstal & Konfigurasi Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
mkdir -p /usr/local/etc/xray/users
echo "[]" > /usr/local/etc/xray/users/vmess_users.json
echo "[]" > /usr/local/etc/xray/users/vless_users.json
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "listen": "127.0.0.1", "port": 10001, "protocol": "vmess", "settings": {"clients": []},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess"}}
    },
    {
      "listen": "127.0.0.1", "port": 10002, "protocol": "vless", "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vless"}}
    },
    {
      "listen": "127.0.0.1", "port": 10003, "protocol": "vmess", "settings": {"clients": []},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/"}}
    },
    {
      "listen": "127.0.0.1", "port": 10004, "protocol": "vless", "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/"}}
    }
  ],
  "outbounds": [{"protocol": "freedom","tag": "direct"}]
}
EOF
systemctl enable --now xray

msg_info "Instalasi skrip menu..."
# --- Tahap 8: Instalasi Skrip Menu ---
msg_info "Menginstal skrip panel menu..."
curl -sL "https://raw.githubusercontent.com/alands-offc/Alxzy-VPN/main/menu" -o /usr/local/bin/menu
curl -sL "https://raw.githubusercontent.com/alands-offc/Alxzy-VPN/main/clear-expired" -o /usr/local/bin/clear-expired
chmod +x /usr/local/bin/menu /usr/local/bin/clear-expired
sed -i "s|export DOMAIN=.*|export DOMAIN=${DOMAIN}|" /usr/local/bin/menu
sed -i "s|export XRAY_PUBLIC_KEY=.*|export XRAY_PUBLIC_KEY=${XRAY_PUBLIC_KEY}|" /usr/local/bin/menu
(crontab -l 2>/dev/null | grep -v "clear-expired"; echo "0 4 * * * /usr/local/bin/clear-expired") | crontab -

BASHRC_FILE="/root/.bashrc"
if ! grep -q "menu" "$BASHRC_FILE"; then
    echo -e '\nif [ -n "$SSH_TTY" ]; then\n    /usr/local/bin/menu\nfi' >> "$BASHRC_FILE"
fi

msg_ok "INSTALASI SELESAI"
echo -e "\e[1;35m=====================================================\e[0m"
echo -e "Konfigurasi server Anda sekarang:"
echo -e "  - \e[1;32mPort 443 (SSL):\e[0m \e[1;36mStunnel -> SSH\e[0m"
echo -e "  - \e[1;32mPort 80 (WS):\e[0m   \e[1;36mNginx -> VMess & VLESS\e[0m"
echo -e "  - \e[1;32mPort 8443 (WSS):\e[0m \e[1;36mNginx -> KHUSUS VMess\e[0m"
echo -e "  - \e[1;32mPort 2043 (WSS):\e[0m \e[1;36mNginx -> KHUSUS VLESS\e[0m"
echo -e "  - \e[1;32mPort 7300 (UDP):\e[0m \e[1;36mBadVPN UDP Gateway\e[0m"
echo -e "\e[1;35m=====================================================\e[0m"