#!/bin/bash
# =================================================================
# VPN Auto Installer v3.4 - Stunnel Edition for Port 443
# Nginx for Port 80, Stunnel for Port 443 (SSL/TLS)
# =================================================================

# Hentikan eksekusi jika terjadi error
set -e

# --- Fungsi Bantuan ---
msg_info() { echo -e "\n\e[1;33m[*] $1\e[0m"; }
msg_ok() { echo -e "\n\e[1;32m[+] $1\e[0m"; }
msg_err() { echo -e "\n\e[1;31m[!] $1\e[0m"; exit 1; }

# --- Cek Root ---
if [ "$(id -u)" -ne 0 ]; then
    msg_err "Skrip ini harus dijalankan sebagai root. Coba gunakan 'sudo -i'."
fi

# --- Tampilan Awal & Input Pengguna ---
clear
echo -e "\n\e[1;35m=========================================================\e[0m"
echo -e " \e[1;36m VPN Auto Installer v3.4 - Stunnel Edition\e[0m"
echo -e "\e[1;35m=========================================================\e[0m"
read -p "➡️  Masukkan domain/subdomain Anda (mis: vpn.domain.com): " DOMAIN
read -p "➡️  Masukkan email Anda untuk sertifikat SSL (Let's Encrypt): " LETSENCRYPT_EMAIL

if [[ -z "$DOMAIN" || -z "$LETSENCRYPT_EMAIL" ]]; then
    msg_err "Domain dan Email tidak boleh kosong!"
fi

# --- Tahap 1: Update & Instalasi Paket ---
msg_info "Mengupdate sistem dan menginstal paket yang diperlukan..."
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt upgrade -y > /dev/null 2>&1
apt install -y stunnel4 nginx ufw dropbear net-tools cmake make gcc screen git jq curl unzip socat certbot cron lsb-release

# --- Tahap 2: Konfigurasi Firewall & Kernel ---
msg_info "Konfigurasi Firewall (UFW) dan Kernel (BBR)..."
ufw allow 22,80,443,8443/tcp
ufw allow 2253/tcp # Internal Dropbear Port
ufw allow 7300/udp # BadVPN
ufw --force enable
ufw reload > /dev/null 2>&1

if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null 2>&1

# --- Tahap 3: Konfigurasi Dropbear ---
msg_info "Konfigurasi Dropbear..."
DROPBEAR_PORT=2253
cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=${DROPBEAR_PORT}
DROPBEAR_EXTRA_ARGS=""
DROPBEAR_BANNER="/etc/issue.net"
EOF
echo -e "\n\e[1;32m   ALXZY VPN SERVER   \e[0m\n" > /etc/issue.net
systemctl restart dropbear && systemctl enable dropbear

# --- Tahap 4: Dapatkan Sertifikat SSL ---
msg_info "Meminta Sertifikat SSL dari Let's Encrypt..."
systemctl stop nginx > /dev/null 2>&1 || true
systemctl stop stunnel4 > /dev/null 2>&1 || true
certbot certonly --standalone --agree-tos --no-eff-email --email "$LETSENCRYPT_EMAIL" -d "$DOMAIN"
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    msg_err "Gagal mendapatkan sertifikat SSL. Pastikan domain sudah diarahkan ke IP server."
fi

CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

# --- Tahap 5: Konfigurasi Stunnel untuk Port 443 ---
msg_info "Konfigurasi Stunnel untuk menangani Port 443..."
cat > /etc/stunnel/stunnel.conf << EOF
pid = /var/run/stunnel4/stunnel.pid
cert = $CERT_PATH
key = $KEY_PATH
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
output = /var/log/stunnel4/stunnel.log

[dropbear_ssl]
accept = 443
connect = 127.0.0.1:${DROPBEAR_PORT}
EOF
sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

# --- Tahap 6: Konfigurasi Nginx HANYA untuk Port 80 ---
msg_info "Konfigurasi Nginx HANYA untuk menangani Port 80..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
cat > /etc/nginx/conf.d/http_only.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:${DROPBEAR_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
systemctl restart nginx

# --- Tahap 7: Instalasi Xray & BadVPN ---
msg_info "Menginstal Xray & BadVPN..."
cd /root
if [ ! -d "badvpn" ]; then git clone -q https://github.com/ambrop72/badvpn.git; fi
cd badvpn; mkdir -p build; cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make -j"$(nproc)" > /dev/null 2>&1 && make install > /dev/null 2>&1
BADVPN_PATH=$(command -v badvpn-udpgw)
if [ -z "$BADVPN_PATH" ]; then msg_err "badvpn-udpgw tidak ditemukan."; fi
cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target
[Service]
ExecStart=$BADVPN_PATH --listen-addr 127.0.0.1:7300 --max-clients 512
User=root
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now badvpn.service > /dev/null 2>&1

bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
XRAY_KEY_PAIR=($(xray x25519))
XRAY_PRIVATE_KEY=${XRAY_KEY_PAIR[0]}
XRAY_PUBLIC_KEY=${XRAY_KEY_PAIR[1]}
if [[ -z "$XRAY_PRIVATE_KEY" || -z "$XRAY_PUBLIC_KEY" ]]; then
    msg_err "Gagal membuat key pair X25519 untuk Xray REALITY."
fi
mkdir -p /usr/local/etc/xray/users
echo "[]" > /usr/local/etc/xray/users/vmess_users.json
echo "[]" > /usr/local/etc/xray/users/vless_users.json
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "127.0.0.1","port": 10001,"protocol": "vmess","settings": {"clients": []},"streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-ws"}}},
    {"listen": "127.0.0.1","port": 10002,"protocol": "vless","settings": {"clients": [], "decryption": "none"},"streamSettings": {"network": "ws", "wsSettings": {"path": "/vless-ws"}}},
    {"listen": "0.0.0.0","port": 8443,"protocol": "vless","settings": {"clients": [],"decryption": "none"},"streamSettings": {"network": "tcp","security": "reality","realitySettings": {"show": false,"dest": "www.microsoft.com:443","xver": 0,"serverNames": ["www.microsoft.com", "microsoft.com"],"privateKey": "${XRAY_PRIVATE_KEY}","shortIds": [""]}}}
  ],
  "outbounds": [{"protocol": "freedom","tag": "direct"}]
}
EOF
systemctl enable --now xray

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

clear
msg_ok "INSTALASI SELESAI (EDISI STUNNEL)"
echo -e "\e[1;35m=====================================================\e[0m"
echo -e "Konfigurasi server Anda sekarang:"
echo -e "  - \e[1;33mPort \e[1;36m443\e[0m -> Ditangani oleh \e[1;32mSTUNNEL\e[0m -> SSH"
echo -e "  - \e[1;33mPort \e[1;36m80\e[0m  -> Ditangani oleh \e[1;36mNGINX\e[0m   -> SSH"
echo -e "\nSilakan coba kembali koneksi Anda ke port 443."
echo -e "Ketik '\e[1;32mmenu\e[0m' untuk menampilkan panel manajemen.\n"

# Menjalankan menu setelah instalasi selesai
sleep 3
/usr/local/bin/menu