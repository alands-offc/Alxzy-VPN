#!/bin/bash

# Pastikan skrip dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
   echo "Skrip ini harus dijalankan sebagai root" 
   exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export REPO_URL="https://raw.githubusercontent.com/alands-offc/Alxzy-VPN/main"

echo "=============================================="
echo "      Memulai Instalasi Alxzy VPN Script      "
echo "=============================================="
sleep 2

# Setel zona waktu
timedatectl set-timezone Asia/Jakarta

# Update & instal semua dependensi dalam satu langkah
echo ">>> Menginstal paket yang dibutuhkan..."
apt update
apt install -y software-properties-common
add-apt-repository -y ppa:deadsnakes/ppa
apt update
apt install -y python3.11 python3-pip nginx stunnel4 openvpn wireguard cron git cmake make gcc build-essential golang-go socat unzip pwgen curl net-tools neofetch openssl libssl-dev libnspr4 libnspr4-dev
pip3 install requests websockets asyncio
echo ">>> Paket berhasil diinstal."
echo ""

# Konfigurasi Nginx sebagai Reverse Proxy
echo ">>> Mengkonfigurasi Nginx..."
systemctl enable nginx
systemctl start nginx
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
curl -sL -o /etc/nginx/nginx.conf "${REPO_URL}/main/nginx.conf"
mkdir -p /home/vps/public_html
echo "<h1>Alxzy VPN</h1>" > /home/vps/public_html/index.html

# Buat file konfigurasi vps.conf untuk reverse proxy WebSocket
cat > /etc/nginx/conf.d/vps.conf << END
server {
    listen 80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8080; # Arahkan ke port ws-ssh.py
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
END
systemctl restart nginx
echo ">>> Nginx berhasil dikonfigurasi."
echo ""

# Buat skrip ws-ssh.py langsung di server
echo ">>> Membuat skrip WebSocket to SSH..."
cat > /root/ws-ssh.py << 'END'
#!/usr/bin/env python3
import asyncio
import websockets
import os
import logging

# Konfigurasi logging dasar untuk melihat aktivitas
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Konfigurasi Port
# Port default untuk WebSocket diubah ke 8080
LISTEN_PORT = int(os.environ.get("WS_LISTEN_PORT", 8080))
SSH_PORT = int(os.environ.get("SSH_PORT", 22))

LISTEN_HOST = "0.0.0.0"
SSH_HOST = "127.0.0.1"

async def handle_client(websocket, path):
    """Fungsi ini menangani setiap koneksi WebSocket yang masuk."""
    client_addr = websocket.remote_address
    logging.info(f"Koneksi WebSocket baru dari: {client_addr}")
    
    try:
        # Buka koneksi ke server SSH lokal
        reader, writer = await asyncio.open_connection(SSH_HOST, SSH_PORT)
    except Exception as e:
        logging.error(f"Gagal terhubung ke server SSH di {SSH_HOST}:{SSH_PORT}: {e}")
        await websocket.close()
        return

    async def ws_to_tcp():
        """Membaca pesan dari WebSocket dan meneruskannya ke TCP (SSH)."""
        try:
            async for message in websocket:
                writer.write(message)
                await writer.drain()
        except websockets.exceptions.ConnectionClosed:
            logging.info(f"Koneksi WebSocket dari {client_addr} ditutup.")
        except Exception as e:
            logging.error(f"Error (ws->tcp) dari {client_addr}: {e}")
        finally:
            writer.close()

    async def tcp_to_ws():
        """Membaca data dari TCP (SSH) dan meneruskannya ke WebSocket."""
        try:
            while not reader.at_eof():
                data = await reader.read(4096)
                if data:
                    await websocket.send(data)
                else:
                    break
        except websockets.exceptions.ConnectionClosed:
            pass  # Klien sudah menutup, tidak perlu lapor error
        except Exception as e:
            logging.error(f"Error (tcp->ws) dari {client_addr}: {e}")
        finally:
            await websocket.close()

    # Jalankan kedua fungsi penerus data secara bersamaan
    await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    logging.info(f"Koneksi dari {client_addr} telah berakhir.")

async def main():
    """Fungsi utama untuk menjalankan server."""
    server = await websockets.serve(handle_client, LISTEN_HOST, LISTEN_PORT)
    logging.info(f"Server WebSocket berjalan di {LISTEN_HOST}:{LISTEN_PORT}, meneruskan ke {SSH_HOST}:{SSH_PORT}")
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server dihentikan oleh pengguna.")
END
chmod +x /root/ws-ssh.py
echo ">>> Skrip WebSocket berhasil dibuat."
echo ""

# Buat service untuk ws-ssh.py
echo ">>> Membuat service untuk WebSocket..."
cat > /etc/systemd/system/ws-ssh.service << END
[Unit]
Description=WebSocket SSH Python Service
After=network.target

[Service]
User=root
Type=simple
ExecStart=/usr/bin/python3.11 /root/ws-ssh.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
END
systemctl enable ws-ssh
systemctl start ws-ssh
echo ">>> Service WebSocket berhasil dibuat dan dijalankan."
echo ""

# Konfigurasi Stunnel
echo ">>> Mengkonfigurasi Stunnel..."
systemctl enable stunnel4
systemctl start stunnel4
openssl genrsa -out /etc/stunnel/privkey.pem 2048
openssl req -new -x509 -days 3650 -key /etc/stunnel/privkey.pem -out /etc/stunnel/cert.pem -subj "/CN=alxzy-vpn"
cat /etc/stunnel/privkey.pem /etc/stunnel/cert.pem >> /etc/stunnel/stunnel.pem
curl -sL -o /etc/stunnel/stunnel.conf "${REPO_URL}/main/stunnel.conf"
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
systemctl restart stunnel4
echo ">>> Stunnel berhasil dikonfigurasi."
echo ""

# Tambah port SSH
echo ">>> Menambahkan port SSH tambahan (225)..."
if ! grep -q "^Port 225" /etc/ssh/sshd_config; then
    echo "Port 225" >> /etc/ssh/sshd_config
fi
systemctl restart sshd
echo ">>> Port SSH berhasil ditambahkan."
echo ""

# Instal dan Konfigurasi BadVPN
echo ">>> Menginstal BadVPN UDP Gateway..."
git clone https://github.com/XTLS/badvpn.git /root/badvpn
cd /root/badvpn
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j"$(nproc)"
make install
cd /root
rm -rf /root/badvpn

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
systemctl enable badvpn
systemctl start badvpn
echo ">>> BadVPN berhasil diinstal."
echo ""

# Siapkan direktori dan skrip menu
echo ">>> Mengunduh skrip menu dan utilitas..."
mkdir -p /etc/alxzyvpn/main
touch /var/lib/data-user-list.txt

# Download utilitas dengan curl
curl -sL -o /usr/local/bin/menu "${REPO_URL}/main/menu"; chmod +x /usr/local/bin/menu
curl -sL -o /etc/alxzyvpn/main/banner "${REPO_URL}/main/banner"
curl -sL -o /etc/alxzyvpn/main/adduser "${REPO_URL}/main/adduser"; chmod +x /etc/alxzyvpn/main/adduser
curl -sL -o /etc/alxzyvpn/main/deluser "${REPO_URL}/main/deluser"; chmod +x /etc/alxzyvpn/main/deluser
curl -sL -o /etc/alxzyvpn/main/trial "${REPO_URL}/main/trial"; chmod +x /etc/alxzyvpn/main/trial
curl -sL -o /etc/alxzyvpn/main/xp "${REPO_URL}/main/xp"; chmod +x /etc/alxzyvpn/main/xp
echo ">>> Skrip menu berhasil diunduh."
echo ""

# Setup Cron job untuk auto-delete user expired
echo ">>> Menyiapkan cron job untuk auto-delete user..."
cat > /etc/cron.d/xp_user << END
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 1 * * * root /etc/alxzyvpn/main/xp
END
chmod 644 /etc/cron.d/xp_user
systemctl enable cron
systemctl start cron
echo ">>> Cron job berhasil dibuat."
echo ""

# Selesai
history -c
rm -f "$0"

echo "=============================================="
echo "      Instalasi Layanan VPN Selesai!      "
echo "=============================================="
echo ""
neofetch
echo ""
echo "Ketik 'menu' untuk menampilkan panel kontrol."
echo ""
