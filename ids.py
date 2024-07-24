import os
import time
import threading
import requests
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tabulate
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Kamus untuk menyimpan alamat IP dan jumlah paketnya
ip_packet_count = defaultdict(int)
failed_login_attempts = defaultdict(int)

# Nilai ambang batas
UDP_FLOOD_THRESHOLD = 1000
TCP_SYN_FLOOD_THRESHOLD = 2000  # Contoh ambang batas untuk TCP SYN Flood
ICMP_FLOOD_THRESHOLD = 5000
BRUTE_FORCE_THRESHOLD = 5  # Contoh ambang batas untuk upaya login yang gagal

# Daftar untuk menyimpan serangan yang terdeteksi
detected_attacks = []

# Variabel untuk menyimpan jenis serangan terakhir yang terdeteksi
last_detected_attack = None

# Buat folder log jika belum ada
log_folder = "/var/log/attack_logs"
os.makedirs(log_folder, exist_ok=True)

# Konfigurasi logging
logging.basicConfig(
    filename=os.path.join(log_folder, "attack_log.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Konfigurasi Telegram Bot
TELEGRAM_TOKEN = '7496463610:AAFnkmcyyqYQxtfyPbQ9CS6f392hAKuV4wk'
TELEGRAM_CHAT_ID = '5069649818'
def send_telegram_message(message):
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'HTML'
    }
    response = requests.post(url, data=payload)
    return response

# Fungsi untuk mendeteksi serangan DDoS (UDP Flood, TCP SYN Flood, ICMP Flood)
def detect_ddos(packet):
    global last_detected_attack

    if IP in packet:
        src_ip = packet[IP].src
        ip_packet_count[src_ip] += 1

        # Memeriksa UDP Flood
        if UDP in packet and ip_packet_count[src_ip] > UDP_FLOOD_THRESHOLD:
            detected_attack = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Attack Type": "UDP Flood",
                "Source IP": src_ip,
                "Packets Count": ip_packet_count[src_ip]
            }
            detected_attacks.append(detected_attack)
            log_message = f"Detected UDP Flood Attack from IP: {src_ip}, Packets Count: {ip_packet_count[src_ip]}"
            logging.info(log_message)

        # Memeriksa TCP SYN Flood
        if TCP in packet and packet[TCP].flags & 0x02 and ip_packet_count[src_ip] > TCP_SYN_FLOOD_THRESHOLD:
            detected_attack = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Attack Type": "TCP SYN Flood",
                "Source IP": src_ip,
                "Packets Count": ip_packet_count[src_ip]
            }
            detected_attacks.append(detected_attack)
            log_message = f"Detected TCP SYN Flood Attack from IP: {src_ip}, Packets Count: {ip_packet_count[src_ip]}"
            logging.info(log_message)
                 # Memeriksa ICMP Flood
        if ICMP in packet and ip_packet_count[src_ip] > ICMP_FLOOD_THRESHOLD:
            detected_attack = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Attack Type": "ICMP Flood",
                "Source IP": src_ip,
                "Packets Count": ip_packet_count[src_ip]
            }
            detected_attacks.append(detected_attack)
            log_message = f"Detected ICMP Flood Attack from IP: {src_ip}, Packets Count: {ip_packet_count[src_ip]}"
            logging.info(log_message)

        # Memeriksa jika ada serangan baru yang terdeteksi
        if detected_attacks:
            current_detected_attack = detected_attacks[-1]["Attack Type"]
            if current_detected_attack != last_detected_attack:
                last_detected_attack = current_detected_attack
                print(f"Warning!!! Detected {last_detected_attack} Attack.")

# Fungsi untuk mendeteksi serangan brute force (upaya login gagal berulang kali)
def detect_brute_force(packet):
    global last_detected_attack

    if TCP in packet and packet[TCP].dport == 22:  # Misal port SSH
        src_ip = packet[IP].src

        # Memeriksa SYN (inisiasi koneksi) atau RST (reset koneksi, menunjukkan kegagalan)
        if packet[TCP].flags & 0x02 or packet[TCP].flags & 0x04:
            failed_login_attempts[src_ip] += 1

        # Memeriksa jika ambang batas terlampaui
        if failed_login_attempts[src_ip] > BRUTE_FORCE_THRESHOLD:
            detected_attack = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Attack Type": "Brute Force",
                "Source IP": src_ip,
                "Failed Attempts": failed_login_attempts[src_ip]
            }
            detected_attacks.append(detected_attack)
            log_message = f"Detected Brute Force Attack from IP: {src_ip}, Failed Attempts: {failed_login_attempts[src_ip]}"
            logging.info(log_message)
            # Memeriksa jika ada serangan baru yang terdeteksi
            current_detected_attack = detected_attacks[-1]["Attack Type"]
            if current_detected_attack != last_detected_attack:
                last_detected_attack = current_detected_attack
                print(f"Warning!!! Detected {last_detected_attack} Attack from IP: {src_ip}")

# Fungsi untuk mencetak serangan yang terdeteksi dalam format tabel setiap 10 detik
def print_detected_attacks():
    while True:
        if detected_attacks:
            headers = ["Timestamp", "Attack Type", "Source IP", "Details"]
            attack_details = []

            for attack in detected_attacks:
                if attack["Attack Type"] == "Brute Force":
                    details = f"Failed Attempts: {attack['Failed Attempts']}"
                else:
                    details = f"Packets Count: {attack['Packets Count']}"

                attack_details.append([attack["Timestamp"], attack["Attack Type"], attack["Source IP"], details])

            print("\nDetected Attacks:")
            print(tabulate.tabulate(attack_details, headers=headers, tablefmt="grid"))
            print()

            # Mengosongkan daftar serangan yang terdeteksi
            detected_attacks.clear()

        time.sleep(10)  # Cetak setiap 10 detik

# Fungsi untuk mencetak pesan "No attacks detected" setiap 15 detik jika tidak ada serangan terdeteksi
def print_no_attacks():
    while True:
        if not detected_attacks:
            print("No attacks detected.")
        time.sleep(15)  # Cetak setiap 15 detik

# Fungsi untuk mengirim pesan log terbaru ke Telegram
def send_latest_log_to_telegram():
    class LogFileEventHandler(FileSystemEventHandler):
        def on_modified(self, event):
            time.sleep(1)  # Tunggu 1 detik untuk memastikan log sudah terupdate
with open(os.path.join(log_folder, "attack_log.log"), "r") as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1]
                    send_telegram_message(last_line.strip())

event_handler = LogFileEventHandler()
observer = Observer()
observer.schedule(event_handler, log_folder, recursive=False)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
        observer.stop()
observer.join()

# Fungsi sniff untuk menangkap dan menganalisis paket
def start_sniffing(interface):
    print(f"Starting packet capture on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

def packet_callback(packet):
    detect_ddos(packet)
    detect_brute_force(packet)

# Ganti 'ens33' dengan antarmuka jaringan Anda
# Mulai mencetak serangan yang terdeteksi dalam thread terpisah
print_thread = threading.Thread(target=print_detected_attacks)
print_thread.start()

# Mulai mencetak pesan "No attacks detected" dalam thread terpisah
no_attack_thread = threading.Thread(target=print_no_attacks)
no_attack_thread.start()

# Mulai mengirim log terbaru ke Telegram
telegram_log_thread = threading.Thread(target=send_latest_log_to_telegram)
telegram_log_thread.start()

# Mulai mengendus paket
start_sniffing('ens33')