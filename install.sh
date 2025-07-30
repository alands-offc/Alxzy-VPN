#!/bin/bash

# Pastikan script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
   echo "Skrip ini harus dijalankan sebagai root" 
   exit 1
fi

# === VPN Auto Installer v3.0 (Nginx Edition) ===
clear
echo -e "\n\e[1;35m=========================================================\e[0m"
echo -e " \e[1;36m VPN Auto Installer v3.0 - Nginx Edition (by alxzy)\e[0m"
echo -e "\e[1;35m=========================================================\e[0m"
read -p "➡️ Masukkan domain/subdomain Anda (mis: vpn.domain.com): " DOMAIN
read -p "➡️ Masukkan email Anda untuk sertifikat SSL (Let's Encrypt): " LETSENCRYPT_EMAIL

if [ -z "$DOMAIN" ] || [ -z "$LETSENCRYPT_EMAIL" ]; then
    echo -e "\n\e[1;31m❌ Domain dan Email tidak boleh kosong!\e[0m"
    exit 1
fi

# === Tahap 1: Update & Instalasi Paket Penting ===
echo -e "\n\e[1;33m[*] Mengupdate sistem dan menginstal paket...\e[0m"
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt upgrade -y
apt install -y nginx ufw dropbear net-tools cmake make gcc screen git jq curl unzip socat certbot cron lsb-release

# === Tahap 2: Konfigurasi Firewall & Kernel ===
echo -e "\e[1;33m[*] Konfigurasi Firewall (UFW) dan Kernel (BBR)...\e[0m"
ufw --force enable
ufw allow 22,80,443,8443/tcp
ufw allow 7300/udp
ufw reload
# Aktifkan Google BBR
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# === Tahap 3: Konfigurasi Dropbear & BadVPN ===
# (Tidak ada perubahan signifikan di sini)
echo -e "\e[1;33m[*] Konfigurasi Dropbear & BadVPN...\e[0m"
DROPBEAR_PORT=2253
cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=${DROPBEAR_PORT}
DROPBEAR_EXTRA_ARGS=""
DROPBEAR_BANNER="/etc/issue.net"
EOF
echo -e "\n\e[1;32m   ALXZY VPN SERVER   \e[0m\n" > /etc/issue.net
systemctl restart dropbear && systemctl enable dropbear
echo "Menambahkan swap ram 2gb"
fallocate -l 2G /vpnswap
chmod 600 /vpnswap
mkswap /vpnswap
swapon /vpnswap
echo "/vpnswap none swap sw 0 0" >> /etc/fstab
echo "atur swappines ke 80"
sudo sysctl -w vm.swappiness=80 && \
sudo sed -i '/^vm.swappiness/d' /etc/sysctl.conf && \
echo 'vm.swappiness=80' | sudo tee -a /etc/sysctl.conf > /dev/null && \
sudo sysctl -p

cd /root
# Clone dan build
git clone -q https://github.com/XTLS/badvpn.git
cd badvpn
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null
make -j$(nproc) > /dev/null
make install > /dev/null

# Deteksi path badvpn-udpgw
BADVPN_PATH=$(command -v badvpn-udpgw)

# Pastikan binary ditemukan
if [ -z "$BADVPN_PATH" ]; then
  echo "❌ badvpn-udpgw tidak ditemukan. Pastikan build sukses dan binary terinstall."
  exit 1
fi

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

# Aktifkan service
systemctl daemon-reload
systemctl enable --now badvpn.service > /dev/null 2>&1


# === Tahap 4: Dapatkan Sertifikat & Konfigurasi Nginx ===
echo -e "\e[1;33m[*] Mempersiapkan Nginx & Sertifikat SSL...\e[0m"
systemctl stop nginx
certbot certonly --standalone --agree-tos --no-eff-email --email $LETSENCRYPT_EMAIL -d $DOMAIN
if [ ! -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
    echo -e "\n\e[1;31m❌ Gagal mendapatkan sertifikat SSL. Pastikan domain Anda sudah diarahkan ke IP server ini dan port 80 terbuka.\e[0m"
    exit 1
fi
CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

# Konfigurasi Nginx sebagai Reverse Proxy
cat > /etc/nginx/conf.d/vpn.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';

    # SSH over WebSocket
    location /ssh {
        proxy_pass http://127.0.0.1:${DROPBEAR_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    # VMess over WebSocket
    location /vmess-ws {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    # VLESS over WebSocket
    location /vless-ws {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
systemctl enable --now nginx

# === Tahap 5: Install & Konfigurasi Xray Core ===
echo -e "\e[1;33m[*] Menginstal dan Konfigurasi Xray Core...\e[0m"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
if ! XRAY_KEY_PAIR=($(xray x25519)); then
   echo "❌ Gagal generate X25519 key. Pastikan binary Xray mendukung perintah ini."
   exit 1
fi

XRAY_PRIVATE_KEY=${XRAY_KEY_PAIR[0]}
XRAY_PUBLIC_KEY=${XRAY_KEY_PAIR[1]}
mkdir -p /usr/local/etc/xray/users
echo "[]" > /usr/local/etc/xray/users/vmess_users.json
echo "[]" > /usr/local/etc/xray/users/vless_users.json

# Buat Config Xray
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vmess",
      "settings": {"clients": []},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-ws"}}
    },
    {
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vless",
      "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vless-ws"}}
    },
    {
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": ["www.microsoft.com"],
          "privateKey": "${XRAY_PRIVATE_KEY}",
          "shortIds": [""]
        }
      }
    }
  ],
  "outbounds": [{"protocol": "freedom","tag": "direct"}]
}
EOF
systemctl enable --now xray

cat > /usr/local/bin/menu <<EOMENU
#!/bin/bash
export DOMAIN=$DOMAIN
export XRAY_PUBLIC_KEY=$XRAY_PUBLIC_KEY
export VMESS_USER_FILE="/usr/local/etc/xray/users/vmess_users.json"
export VLESS_USER_FILE="/usr/local/etc/xray/users/vless_users.json"
export XRAY_CONFIG="/usr/local/etc/xray/config.json"
export DROPBEAR_PORT=$(grep -oP 'DROPBEAR_PORT=\K\d+' /etc/default/dropbear)

# --- FUNGSI UTILITAS ---
function reload_services() {
  systemctl reload xray
  systemctl reload nginx
}

function get_uuid() {
  cat /proc/sys/kernel/random/uuid
}

# --- FUNGSI TAMPILAN ---
function system_info() {
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    local tx_bytes=$(cat /sys/class/net/${iface}/statistics/tx_bytes)
    local rx_bytes=$(cat /sys/class/net/${iface}/statistics/rx_bytes)
    local tx=$(numfmt --to=iec --suffix=B $tx_bytes)
    local rx=$(numfmt --to=iec --suffix=B $rx_bytes)
    local ram_usage=$(free -h | awk '/^Mem:/ {print $3 "/" $2}')
    local disk_usage=$(df -h / | awk 'NR==2 {print $3 "/" $2}')
    local xray_conn=$(journalctl -u xray --since "00:00:00" | grep "accepted" | wc -l)
    
    echo -e "\e[1;35m╔══════════════[ \e[1;36mSYSTEM INFORMATION\e[1;35m ]══════════════╗\e[0m"
    echo -e "║ \e[1;32mOS\e[0m            : \e[1;37m$(lsb_release -ds)\e[1;35m"
    echo -e "║ \e[1;32mUptime\e[0m        : \e[1;37m$(uptime -p)\e[1;35m"
    echo -e "║ \e[1;32mDomain\e[0m        : \e[1;32m$DOMAIN\e[0m"
    echo -e "║ \e[1;32mRAM\e[0m           : \e[1;37m$ram_usage\e[1;35m"
    echo -e "║ \e[1;32mDisk\e[0m          : \e[1;37m$disk_usage\e[1;35m"
    echo -e "║ \e[1;32mBandwidth TX\e[0m 📤: \e[1;37m$tx\e[1;35m"
    echo -e "║ \e[1;32mBandwidth RX\e[0m 📥: \e[1;37m$rx\e[1;35m"
    echo -e "║ \e[1;32mXray Conn\e[0m     : \e[1;37m$xray_conn koneksi hari ini\e[1;35m"
    echo -e "\e[1;35m╚══════════════════════════════════════════════════╝\e[0m"
}


# --- FUNGSI MANAJEMEN PENGGUNA ---
function create_user() {
  clear
  echo -e "\e[1;36m=================================\e[0m"
  echo -e " \e[1;37m       BUAT PENGGUNA BARU      \e[0m"
  echo -e "\e[1;36m=================================\e[0m"
  read -p "Username: " user
  if [[ -z "$user" ]]; then
    echo -e "\n\e[1;31m❌ Username tidak boleh kosong.\e[0m"; sleep 2; return
  fi
  read -p "Masa Aktif (hari): " exp
  exp_date=$(date -d "$exp days" +"%Y-%m-%d")
  uuid=$(get_uuid)
  
  echo "Pilih Protokol: 1. VMess (WS) | 2. VLESS (WS & Reality) | 3. SSH (WS)"; read -p "Pilihan [1-3]: " protocol_choice

  case $protocol_choice in
    1) # VMess
      jq --arg user "$user" --arg uuid "$uuid" --arg exp "$exp_date" '. += [{"user": $user, "uuid": $uuid, "exp": $exp}]' "$VMESS_USER_FILE" > tmp.json && mv tmp.json "$VMESS_USER_FILE"
      jq ".inbounds[0].settings.clients += [{\"id\": \"$uuid\", \"alterId\": 0}]" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
      reload_services
      vmess_ws="vmess://$(echo "{\"v\":\"2\",\"ps\":\"${user}_VMESS_WS\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"/vmess-ws\",\"tls\":\"tls\",\"sni\":\"$DOMAIN\"}" | base64 -w 0)"
      clear; echo -e "\n\e[1;32m✅ User VMess (WS) [$user] Dibuat!\e[0m\n   Expired on: $exp_date\n\n\e[1;36m--- Link Konfigurasi ---\e[0m\n$vmess_ws";;
    2) # VLESS
      jq --arg user "$user" --arg uuid "$uuid" --arg exp "$exp_date" '. += [{"user": $user, "uuid": $uuid, "exp": $exp}]' "$VLESS_USER_FILE" > tmp.json && mv tmp.json "$VLESS_USER_FILE"
      jq ".inbounds[1].settings.clients += [{\"id\": \"$uuid\"}]" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
      jq ".inbounds[2].settings.clients += [{\"id\": \"$uuid\"}]" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
      reload_services
      vless_ws="vless://${uuid}@${DOMAIN}:443?security=tls&encryption=none&headerType=none&type=ws&path=%2Fvless-ws&sni=${DOMAIN}#${user}_VLESS_WS"
      vless_reality="vless://${uuid}@${DOMAIN}:8443?security=reality&encryption=none&pbk=${XRAY_PUBLIC_KEY}&headerType=none&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com#${user}_VLESS_REALITY"
      clear; echo -e "\n\e[1;32m✅ User VLESS [$user] Dibuat!\e[0m\n   Expired on: $exp_date\n\n\e[1;36m--- VLESS WebSocket (Port 443) ---\e[0m\n$vless_ws\n\n\e[1;36m--- VLESS REALITY (Port 8443) ---\e[0m\n$vless_reality";;
    3) # SSH
      read -s -p "Password SSH: " pass; echo ""
      useradd -e $exp_date -s /bin/false -M $user
      echo "$user:$pass" | chpasswd
      clear; echo -e "\n\e[1;32m✅ User SSH [$user] Dibuat!\e[0m\n   Host: $DOMAIN\n   SSH over SSL/WS Port: 443\n   WebSocket Path: /ssh\n   Direct Dropbear Port: $DROPBEAR_PORT\n   Expired on: $exp_date";;
    *) echo "Pilihan tidak valid.";;
  esac
  read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
}

function list_users() {
  clear
  echo -e "\e[1;36m=================================\e[0m\n \e[1;37m        DAFTAR PENGGUNA        \e[0m\n\e[1;36m=================================\e[0m\n"
  echo -e "\e[1;33m--- User SSH ---\e[0m"
  printf "%-20s | %s\n" "Username" "Kadaluwarsa"; printf "%-20s | %s\n" "--------------------" "------------------"
  while IFS=: read -r user _ uid _ _ _ _; do
    if [[ "$uid" -ge 1000 ]]; then
      exp=$(chage -l "$user" | grep "Account expires" | awk -F": " '{print $2}'); printf "\e[1;37m%-20s\e[0m | \e[1;32m%s\e[0m\n" "$user" "$exp"
    fi
  done < /etc/passwd
  echo -e "\n\e[1;33m--- User VMess (WebSocket) ---\e[0m"
  if jq -e '. | length == 0' "$VMESS_USER_FILE" >/dev/null; then echo "Tidak ada user VMess."; else jq -r '.[] | "• \u001b[1;37m\(.user)\u001b[0m (Exp: \u001b[1;32m\(.exp)\u001b[0m)"' "$VMESS_USER_FILE"; fi
  echo -e "\n\e[1;33m--- User VLESS (WS & Reality) ---\e[0m"
  if jq -e '. | length == 0' "$VLESS_USER_FILE" >/dev/null; then echo "Tidak ada user VLESS."; else jq -r '.[] | "• \u001b[1;37m\(.user)\u001b[0m (Exp: \u001b[1;32m\(.exp)\u001b[0m)"' "$VLESS_USER_FILE"; fi
  read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
}

function delete_user() {
  clear
  echo -e "\e[1;36m=================================\e[0m\n \e[1;37m        HAPUS PENGGUNA         \e[0m\n\e[1;36m=================================\e[0m\n"
  read -p "Masukkan Username yang akan dihapus: " user_to_del
  if [[ -z "$user_to_del" ]]; then echo -e "\n\e[1;31m❌ Username tidak boleh kosong.\e[0m"; sleep 2; return; fi
  user_found=false
  if id "$user_to_del" &>/dev/null; then userdel -r "$user_to_del"; echo -e "\e[1;32m✓ User SSH '$user_to_del' dihapus.\e[0m"; user_found=true; fi
  vmess_uuid=$(jq -r --arg user "$user_to_del" '.[] | select(.user == $user) | .uuid' "$VMESS_USER_FILE")
  if [ ! -z "$vmess_uuid" ]; then
    jq "map(select(.user != \"$user_to_del\"))" "$VMESS_USER_FILE" > tmp.json && mv tmp.json "$VMESS_USER_FILE"
    jq "(.inbounds[0].settings.clients) |= map(select(.id != \"$vmess_uuid\"))" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
    echo -e "\e[1;32m✓ User VMess '$user_to_del' dihapus.\e[0m"; user_found=true
  fi
  vless_uuid=$(jq -r --arg user "$user_to_del" '.[] | select(.user == $user) | .uuid' "$VLESS_USER_FILE")
  if [ ! -z "$vless_uuid" ]; then
    jq "map(select(.user != \"$user_to_del\"))" "$VLESS_USER_FILE" > tmp.json && mv tmp.json "$VLESS_USER_FILE"
    jq "(.inbounds[1].settings.clients) |= map(select(.id != \"$vless_uuid\"))" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
    jq "(.inbounds[2].settings.clients) |= map(select(.id != \"$vless_uuid\"))" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
    echo -e "\e[1;32m✓ User VLESS '$user_to_del' dihapus.\e[0m"; user_found=true
  fi
  if [ "$user_found" = true ]; then reload_services; else echo -e "\e[1;31mUser '$user_to_del' tidak ditemukan.\e[0m"; fi
  read -n 1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
}

# --- FUNGSI MENU UTAMA ---
function main_menu() {
  while true; do
    system_info
    echo -e "\e[1;35m╔══════════════[ \e[1;36mMENU UTAMA\e[1;35m ]══════════════╗\e[0m"
    echo -e "║ \e[1;32m1.\e[0m \e[1;37mBuat Pengguna (All-in-One)\e[1;35m             ║"
    echo -e "║ \e[1;32m2.\e[0m \e[1;37mHapus Pengguna\e[1;35m                         ║"
    echo -e "║ \e[1;32m3.\e[0m \e[1;37mDaftar Pengguna\e[1;35m                        ║"
    echo -e "║ \e[1;32m4.\e[0m \e[1;37mPerbarui Sertifikat SSL\e[1;35m                ║"
    echo -e "║ \e[1;32m5.\e[0m \e[1;37mPembersihan Manual (Expired)\e[1;35m         ║"
    echo -e "║ \e[1;32m6.\e[0m \e[1;37mReboot Server\e[1;35m                          ║"
    echo -e "╟──────────────────────────────────────────╢"
    echo -e "║ \e[1;31m0.\e[0m \e[1;37mKeluar\e[1;35m                                 ║"
    echo -e "\e[1;35m╚══════════════════════════════════════════╝\e[0m"
    read -p "➡️  Pilih menu [0-6]: " pilih
    case $pilih in
      1) create_user ;;
      2) delete_user ;;
      3) list_users ;;
      4) systemctl stop nginx; certbot renew --force-renewal; systemctl start nginx; reload_services; read -n 1 -s -r -p "Selesai.";;
      5) /usr/local/bin/clear-expired; read -n 1 -s -r -p "Selesai.";;
      6) read -p "Anda yakin ingin reboot? (y/n): " confirm; if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then reboot; fi;;
      0) exit 0 ;;
      *) echo "Pilihan tidak valid." ; sleep 1 ;;
    esac
  done
}
main_menu
EOMENU
chmod +x /usr/local/bin/menu
cat > /usr/local/bin/clear-expired <<'EOF'
#!/bin/bash
# Skrip untuk membersihkan pengguna yang sudah kedaluwarsa

# --- VARIABEL ---
TODAY=$(date +"%Y-%m-%d")
XRAY_CONFIG="/usr/local/etc/xray/config.json"
VMESS_USERS="/usr/local/etc/xray/users/vmess_users.json"
VLESS_USERS="/usr/local/etc/xray/users/vless_users.json"
LOG_FILE="/var/log/clear-expired.log"
NEEDS_RELOAD=false

echo "=================================================" >> $LOG_FILE
echo "Mulai pembersihan pada $(date)" >> $LOG_FILE

# --- FUNGSI ---
function delete_expired_xray_users() {
    local user_file=$1
    local user_type=$2
    local inbound_indices=($3)
    
    EXPIRED_UUIDS=$(jq -r --arg today "$TODAY" '.[] | select(.exp < $today) | .uuid' "$user_file")

    if [[ ! -z "$EXPIRED_UUIDS" ]]; then
        echo "Menghapus user $user_type kedaluwarsa..." >> $LOG_FILE
        NEEDS_RELOAD=true
        
        # Hapus dari config xray
        for uuid in $EXPIRED_UUIDS; do
            echo "  - Menghapus UUID: $uuid" >> $LOG_FILE
            for i in "${inbound_indices[@]}"; do
                jq "(.inbounds[$i].settings.clients) |= map(select(.id != \"$uuid\"))" "$XRAY_CONFIG" > tmp.json && mv tmp.json "$XRAY_CONFIG"
            done
        done
        
        # Update file data user
        jq --arg today "$TODAY" '[.[] | select(.exp >= $today)]' "$user_file" > tmp.json && mv tmp.json "$user_file"
    else
        echo "Tidak ada user $user_type yang kedaluwarsa." >> $LOG_FILE
    fi
}

function delete_expired_ssh_users() {
    echo "Memeriksa user SSH kedaluwarsa..." >> $LOG_FILE
    for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
        exp_date_str=$(chage -l "$user" | grep 'Account expires' | awk -F': ' '{print $2}')
        if [[ "$exp_date_str" != "never" ]]; then
            exp_timestamp=$(date -d "$exp_date_str" +%s)
            today_timestamp=$(date -d "$TODAY" +%s)
            if (( exp_timestamp < today_timestamp )); then
                echo "  - Menghapus user SSH kedaluwarsa: $user" >> $LOG_FILE
                userdel -r "$user"
            fi
        fi
    done
}

# --- EKSEKUSI ---
delete_expired_xray_users "$VMESS_USERS" "VMess" "0"
delete_expired_xray_users "$VLESS_USERS" "VLESS" "1 2"
delete_expired_ssh_users

if [ "$NEEDS_RELOAD" = true ]; then
  echo "Me-reload Xray dan Nginx..." >> $LOG_FILE
  systemctl reload xray
  systemctl reload nginx
fi

echo "Pembersihan selesai." >> $LOG_FILE
EOF
chmod +x /usr/local/bin/clear-expired
(crontab -l 2>/dev/null | grep -v "clear-expired"; echo "0 4 * * * /usr/local/bin/clear-expired") | crontab -

# Finalisasi
BASHRC_FILE="/root/.bashrc"
if ! grep -q "if \[ \"\$SSH_TTY\" \]; then" "$BASHRC_FILE"; then
  echo -e '\nif [ "$SSH_TTY" ]; then\n  /usr/local/bin/menu\nfi' >> "$BASHRC_FILE"
fi
sed -i "s/export DOMAIN=$/export DOMAIN=$DOMAIN/" /usr/local/bin/menu
sed -i "s/export XRAY_PUBLIC_KEY=$/export XRAY_PUBLIC_KEY=$XRAY_PUBLIC_KEY/" /usr/local/bin/menu

clear
echo -e "\n\e[1;32m====================================================="
echo -e " ✅ INSTALASI SELESAI (NGINX EDITION) ✅"
echo -e "=====================================================\e[0m"
echo -e "Layanan Anda berjalan di belakang Nginx:"
echo -e "  - \e[1;33mSSH, VMess, VLESS (WebSocket) di port \e[1;36m443\e[0m"
echo -e "  - \e[1;33mVLESS (Reality) di port \e[1;36m8443\e[0m"
echo -e "  - \e[1;33mSertifikat SSL untuk \e[1;36m$DOMAIN\e[0m dari Let's Encrypt"
echo -e "\nKetik '\e[1;32mmenu\e[0m' untuk menampilkan panel manajemen."
echo -e "Login ulang untuk menjalankan menu secara otomatis.\n"
sleep 3
/usr/local/bin/menu