from flask import Flask, jsonify, request, render_template
from flask_socketio import SocketIO
import sqlite3
from datetime import datetime, timedelta
import threading
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import os
import subprocess

DB_PATH = "data/captured_packets.db"
app = Flask(__name__)
socketio = SocketIO(app)
os.makedirs("data", exist_ok=True)

# Windowsで現在接続中のWi-Fi名を取得
def get_connected_ssid():
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding='utf-8'
        )
        output = result.stdout
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID") and not line.startswith("SSID name"):  # SSIDだけの行を取得
                ssid = line.split(":", 1)[1].strip()
                if ssid == "":
                    return "未接続"
                return ssid
        return "未接続"
    except Exception as e:
        return "取得失敗"

# --- データベース初期化 ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port TEXT,
            dst_port TEXT,
            protocol TEXT,
            packet_size INTEGER
        )
    ''')
    conn.commit()
    conn.close()

# --- パケット情報をDBに保存 ---
def save_packet(pkt_info):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', pkt_info)
    conn.commit()
    conn.close()

# --- パケットキャプチャのコールバック ---
def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        src_port = '-'
        dst_port = '-'
        protocol = 'Other'

        if TCP in packet:
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
            protocol = 'TCP'
        elif UDP in packet:
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
            protocol = 'UDP'

        pkt_info = (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length)
        save_packet(pkt_info)

# --- パケットキャプチャスレッド ---
def start_packet_capture():
    sniff(prn=packet_callback, store=False)

# --- データ取得API ---
@app.route('/api/data')
def get_data():
    minutes = int(request.args.get('minutes', 60))
    cutoff = datetime.now() - timedelta(minutes=minutes)
    cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT strftime('%Y-%m-%d %H:%M:00', timestamp) AS ts_minute,
               SUM(packet_size) AS total_size
        FROM packets
        WHERE timestamp >= ?
        GROUP BY ts_minute
        ORDER BY ts_minute
    ''', (cutoff_str,))
    traffic = [{'timestamp': row['ts_minute'], 'total_size': row['total_size']} for row in cursor.fetchall()]

    cursor.execute('''
        SELECT protocol, SUM(packet_size) AS total
        FROM packets
        WHERE timestamp >= ?
        GROUP BY protocol
    ''', (cutoff_str,))
    protocols = {row['protocol']: row['total'] for row in cursor.fetchall()}

    cursor.execute('''
        SELECT src_ip AS ip_address, SUM(packet_size) AS total_size
        FROM packets
        WHERE timestamp >= ?
        GROUP BY src_ip
        ORDER BY total_size DESC
        LIMIT 10
    ''', (cutoff_str,))
    devices = [{'ip_address': row['ip_address'], 'total_size': row['total_size']} for row in cursor.fetchall()]

    cursor.execute('''
        SELECT timestamp, src_ip, dst_ip, protocol, packet_size
        FROM packets
        WHERE timestamp >= ?
        ORDER BY timestamp DESC
        LIMIT 100
    ''', (cutoff_str,))
    logs = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return jsonify({
        'traffic_over_time': traffic,
        'protocol_summary': protocols,
        'device_table': devices,
        'traffic_log': logs
    })

# --- トップページ ---
@app.route('/')
def index():
    wifi_name = get_connected_ssid()
    return render_template('index.html', wifi_name=wifi_name)

# --- アプリ起動 ---
if __name__ == '__main__':
    init_db()
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    capture_thread.start()
    print("✅ Flaskアプリとパケットキャプチャを起動中...")
    socketio.run(app, host='0.0.0.0', port=5000)
