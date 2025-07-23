import sqlite3
from datetime import datetime, timedelta
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import os
import threading
import time

DB_PATH = "data/captured_packets.db"
BATCH_SIZE = 50  # まとめてコミットする件数
DELETE_INTERVAL = 300  # 古いデータ削除を5分ごとに実施（秒）

os.makedirs("data", exist_ok=True)

class PacketDB:
    def __init__(self, db_path=DB_PATH):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")  # WALモードで書き込み高速化
        self.create_table()
        self.buffer = []
        self.lock = threading.Lock()

    def create_table(self):
        cursor = self.conn.cursor()
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
        self.conn.commit()
        cursor.close()

    def add_packet(self, pkt_info):
        with self.lock:
            self.buffer.append(pkt_info)
            if len(self.buffer) >= BATCH_SIZE:
                self.flush()

    def flush(self):
        if not self.buffer:
            return
        with self.lock:
            print(f"[{threading.current_thread().name}] [INFO] flush: バッファ書き込み開始", flush=True)
            cursor = self.conn.cursor()
            try:
                cursor.executemany('''
                    INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', self.buffer)
                self.conn.commit()
                print(f"[{threading.current_thread().name}] [INFO] flush: {len(self.buffer)}件のパケットを書き込みました。", flush=True)
                self.buffer.clear()
            except Exception as e:
                print(f"[ERROR] flush中にエラー発生: {e}", flush=True)
            finally:
                cursor.close()

    def delete_old_records(self):
        start_time = datetime.now()
        thread_name = threading.current_thread().name
        cutoff_time = (start_time - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        with self.lock:
            print(f"[{thread_name}] delete_old_records: ロック取得 @ {start_time}", flush=True)
            cursor = self.conn.cursor()
            try:
                cursor.execute('SELECT COUNT(*) FROM packets WHERE timestamp < ?', (cutoff_time,))
                count = cursor.fetchone()[0]
                print(f"[{thread_name}] 削除対象件数: {count}", flush=True)
                if count > 0:
                    cursor.execute('DELETE FROM packets WHERE timestamp < ?', (cutoff_time,))
                    self.conn.commit()
                    print(f"[{thread_name}] {count} 件の古いデータを削除しました。", flush=True)
                else:
                    print(f"[{thread_name}] 削除対象データはありません。", flush=True)
            except Exception as e:
                print(f"[{thread_name}] [ERROR] delete_old_records中にエラー発生: {e}", flush=True)
            finally:
                cursor.close()

    def close(self):
        with self.lock:
            self.flush()
        self.conn.close()
        print("[INFO] DB接続を閉じました。", flush=True)


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

        db.add_packet((timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length))

        print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol} | {length} bytes", flush=True)

def periodic_cleanup():
    while True:
        time.sleep(DELETE_INTERVAL)
        print("[INFO] periodic_cleanup: 古いパケットデータを削除中...", flush=True)
        db.delete_old_records()

if __name__ == "__main__":
    db = PacketDB()

    # 削除スレッド開始
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True, name="CleanupThread")
    cleanup_thread.start()

    print("📡 パケットキャプチャを開始します... Ctrl+Cで停止", flush=True)
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nパケットキャプチャを停止しました。", flush=True)
    finally:
        db.close()
