#!/usr/bin/env python3
import re
import time
import subprocess
import os
import sys
import logging
from datetime import datetime, timedelta
from collections import defaultdict

# Konfigurasi
LOG_FILES = {
    'auth': '/var/log/auth.log',
    'syslog': '/var/log/syslog'  # Ubah ke '/var/log/messages' untuk CentOS
}
BLOCK_DURATION = 300  # 5 menit dalam detik
MAX_ATTEMPTS = 5      # Maks percobaan sebelum blokir
CHECK_INTERVAL = 10   # Detik antar pemeriksaan
IPTABLES_CHAIN = "ZOMBI_DEFENSE"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/zombi_defense.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ZombiDefense")

# Daftar IP terblokir dan waktu kadaluarsa
blocked_ips = {}

def setup_iptables():
    """Buat chain khusus di iptables jika belum ada"""
    try:
        subprocess.run(["iptables", "-L", IPTABLES_CHAIN], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.run(["iptables", "-N", IPTABLES_CHAIN], check=True)
        subprocess.run(["iptables", "-I", "INPUT", "-j", IPTABLES_CHAIN], check=True)
        logger.info(f"Chain {IPTABLES_CHAIN} dibuat di iptables.")

def block_ip(ip):
    """Blokir IP via iptables"""
    if ip in blocked_ips:
        return
    try:
        subprocess.run(["iptables", "-A", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], check=True)
        blocked_ips[ip] = datetime.now() + timedelta(seconds=BLOCK_DURATION)
        logger.warning(f"IP {ip} DIBLOKIR selama {BLOCK_DURATION} detik.")
    except Exception as e:
        logger.error(f"Gagal blokir IP {ip}: {e}")

def unblock_expired():
    """Hapus blokir dari IP yang sudah kadaluarsa"""
    now = datetime.now()
    to_remove = [ip for ip, expire in blocked_ips.items() if now > expire]
    for ip in to_remove:
        try:
            subprocess.run(["iptables", "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], check=True)
            del blocked_ips[ip]
            logger.info(f"IP {ip} dibuka (masa blokir habis).")
        except Exception as e:
            logger.error(f"Gagal buka blokir IP {ip}: {e}")

def detect_bruteforce(line):
    """Deteksi brute-force SSH"""
    if "Failed password" in line:
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            return ip_match.group(1)
    return None

def detect_scanning_or_exploit(line):
    """Deteksi scanning atau exploit umum"""
    suspicious_patterns = [
        r"scan", r"nmap", r"nikto", r"sqlmap", r"exploit",
        r"/etc/passwd", r"union select", r"<script>", r"../",
        r"404.*\.php", r"wp-login\.php", r"xmlrpc\.php"
    ]
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    if ip_match:
        ip = ip_match.group(1)
        if any(re.search(pat, line, re.IGNORECASE) for pat in suspicious_patterns):
            return ip
    return None

def monitor_logs():
    """Pantau log secara real-time"""
    # Simpan posisi akhir file agar tidak baca ulang dari awal tiap kali
    file_positions = {name: 0 for name in LOG_FILES}

    ip_attempts = defaultdict(int)

    while True:
        unblock_expired()

        for log_type, path in LOG_FILES.items():
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r') as f:
                    f.seek(file_positions[log_type])
                    lines = f.readlines()
                    file_positions[log_type] = f.tell()

                    for line in lines:
                        ip = detect_bruteforce(line) or detect_scanning_or_exploit(line)
                        if ip and ip != "127.0.0.1":
                            ip_attempts[ip] += 1
                            if ip_attempts[ip] >= MAX_ATTEMPTS:
                                block_ip(ip)
                                ip_attempts[ip] = 0  # Reset agar tidak blokir berulang
            except Exception as e:
                logger.error(f"Error membaca {path}: {e}")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("Skrip ini harus dijalankan sebagai root!")
        sys.exit(1)

    setup_iptables()
    logger.info("Zombi Defense dimulai...")
    try:
        monitor_logs()
    except KeyboardInterrupt:
        logger.info("Zombi Defense dihentikan.")
    except Exception as e:
        logger.critical(f"Kesalahan fatal: {e}")
        
 
 Cara simpan dan autorun 
 sudo mkdir -p /opt
sudo nano /opt/zombi_defense.py
# (Paste kode di atas)
sudo chmod +x /opt/zombi_defense.py
Buat file service:
    sudo nano /etc/systemd/system/zombi-defense.service
    isi dengan
    [Unit]
Description=Zombi Defense - Auto IP Blocker
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/zombi_defense.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

Aktifkan dan jalan otomatis:
    sudo systemctl daemon-reload
sudo systemctl enable zombi-defense.service
sudo systemctl start zombi-defense.service

    Log aktivitas: /var/log/zombi_defense.log
    Cek status: sudo systemctl status zombi-defense
    Lihat IP terblokir: sudo iptables -L ZOMBI_DEFENSE -n
