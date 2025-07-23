from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import csv
from datetime import datetime

# 保存用ファイル名
csv_filename = "captured_packets.csv"

# CSVのヘッダーを作成
with open(csv_filename, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Packet Size'])

# パケット受信時の処理
def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)

        # デフォルト値
        src_port = '-'
        dst_port = '-'

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        else:
            protocol = 'Other'

        # CSVに書き込み
        with open(csv_filename, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length])

        # コンソール表示
        print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol} | {length} bytes")


# キャプチャ開始（Ctrl+Cで停止）
print("📡 パケットキャプチャを開始します...")
sniff(prn=packet_callback, store=False)
