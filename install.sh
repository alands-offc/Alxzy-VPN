#!/bin/bash
# =================================================================
# VPN Auto Installer v3.6 - Nginx (80/WS) + Stunnel (443/SSL)
# =================================================================

# Hentikan eksekusi jika terjadi error
set -e

# --- Fungsi Bantuan & Cek Root ---
msg_info() { echo -e "\n\e[1;33m[*] $1\e[0m"; }
msg_ok() { echo -e "\n\e[1;32m[+] $1\e[0m"; }
msg_err() { echo -e "\n\e[1;31m[!] $1\e[0m"; exit 1; }
if [ "$(id -u)" -ne 0 ]; then msg_err "Skrip ini harus dijalankan sebagai root."; fi

# --- Input Pengguna ---
clear
echo -e "\n\e[1;35m=========================================================\e[0m"
echo -e " \e[1;36m VPN Auto Installer v3.6 - Nginx/Stunnel Edition\e[0m"
echo -e "\e[1;35m=========================================================\e[0m"
read -p "➡️  Masukkan domain/subdomain Anda: " DOMAIN
read -p "➡️  Masukkan email Anda untuk SSL: " LETSENCRYPT_EMAIL
if [[ -z "$DOMAIN" || -z "$LETSENCRYPT_EMAIL" ]]; then msg_err "Domain dan Email tidak boleh kosong!"; fi

# --- Tahap 1: Instalasi Paket & Firewall ---
msg_info "Menginstal paket dan mengatur firewall..."
export DEBIAN_FRONTEND=noninteractive
apt update > /dev/null 2>&1 && apt upgrade -y > /dev/null 2>&1
apt install -y stunnel4 nginx ufw dropbear certbot cron

# Firewall hanya untuk port yang kita butuhkan
ufw allow 22,80,443/tcp
ufw allow 2253/tcp # Internal Dropbear
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

# --- Tahap 3: Konfigurasi Stunnel untuk Port 443 ---
msg_info "Konfigurasi Stunnel untuk menangani port 443 (SSL)..."
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

# --- Tahap 4: Konfigurasi Nginx untuk Port 80 ---
msg_info "Konfigurasi Nginx untuk menangani port 80 (WebSocket)..."
# Hapus semua konfigurasi lama untuk menghindari konflik
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/conf.d/*.conf

cat > /etc/nginx/conf.d/port80_websocket.conf <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    # Default ke SSH jika path tidak cocok
    location / {
        proxy_pass http://127.0.0.1:${DROPBEAR_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    # Path untuk VLESS WS
    location /vless {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    # Path untuk VMess WS
    location /vmess {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
systemctl restart nginx

# --- Tahap 5: Konfigurasi Xray ---
msg_info "Menginstal & Konfigurasi Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
# Buat file user kosong
mkdir -p /usr/local/etc/xray/users
echo "[]" > /usr/local/etc/xray/users/vmess_users.json
echo "[]" > /usr/local/etc/xray/users/vless_users.json
# Konfigurasi Xray untuk menerima koneksi dari Nginx
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "listen": "127.0.0.1", "port": 10001, "protocol": "vmess",
      "settings": {"clients": []},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess"}}
    },
    {
      "listen": "127.0.0.1", "port": 10002, "protocol": "vless",
      "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vless"}}
    }
  ],
  "outbounds": [{"protocol": "freedom","tag": "direct"}]
}
EOF
systemctl enable --now xray

# --- Tahap 6: Instalasi & Finalisasi Menu ---
msg_info "Instalasi skrip menu..."
# --- Tahap 8: Instalasi Skrip Menu ---
msg_info "Menginstal skrip panel menu..."
curl -sL "https://raw.githubusercontent.com/alands-offc/Alxzy-VPN/main/menu" -o /usr/local/bin/menu
curl -sL "https://raw.githubusercontent.com/alands-offc/Alxzy-VPN/main/clear-expired" -o /usr/local/bin/clear-expired
chmod +x /usr/local/bin/menu /usr/local/bin/clear-expired
sed -i "s|export DOMAIN=.*|export DOMAIN=${DOMAIN}|" /usr/local/bin/menu
sed -i "s|export XRAY_PUBLIC_KEY=.*|export XRAY_PUBLIC_KEY=${XRAY_PUBLIC_KEY}|" /usr/local/bin/menu
(crontab -l 2>/dev/null | grep -v "clear-expired"; echo "0 4 * * * /usr/local/bin/clear-expired") | crontab -

# --- Tahap 9: Finalisasi ---
# Menambahkan pemanggilan menu ke .bashrc jika belum ada
BASHRC_FILE="/root/.bashrc"
if ! grep -q "menu" "$BASHRC_FILE"; then
    echo -e '\nif [ -n "$SSH_TTY" ]; then\n    /usr/local/bin/menu\nfi' >> "$BASHRC_FILE"
fi

echo "Jangan lupa untuk memperbarui skrip menu Anda agar sesuai dengan konfigurasi baru."

msg_ok "INSTALASI SELESAI"
echo -e "\e[1;35m=====================================================\e[0m"
echo -e "Konfigurasi server Anda sekarang:"
echo -e "  - \e[1;32mPort 443\e[0m -> \e[1;36mStunnel\e[0m -> SSH (Koneksi SSL Murni)"
echo -e "  - \e[1;32mPort 80\e[0m  -> \e[1;36mNginx\e[0m   -> SSH, VLESS, VMess (WebSocket)"
echo -e "\e[1;35m=====================================================\e[0m"