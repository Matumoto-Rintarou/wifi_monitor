import sqlite3
import pandas as pd
from datetime import datetime
import glob

db_files = glob.glob('data/captured_packets_*.db')
print(f"📂 読み込み対象ファイル: {len(db_files)}件")

dataframes = []
for db_file in db_files:
    print(f"➡️ 読み込み中: {db_file}")
    conn = sqlite3.connect(db_file)
    df = pd.read_sql_query("SELECT * FROM packets", conn)
    dataframes.append(df)
    conn.close()

if not dataframes:
    print("⚠️ データベースに有効なデータがありません")
    df = pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_size'])
else:
    df = pd.concat(dataframes, ignore_index=True)

df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
df['packet_size'] = pd.to_numeric(df['packet_size'], errors='coerce').fillna(0).astype(int)
df = df.dropna(subset=['timestamp'])
df = df.sort_values('timestamp')

# ① 時間別通信量（10分単位）
df['time_bin'] = df['timestamp'].dt.floor('10min')
traffic_over_time = df.groupby('time_bin')['packet_size'].sum().reset_index()
traffic_over_time_records = traffic_over_time.rename(columns={'time_bin': 'timestamp', 'packet_size': 'total_size'}).to_dict(orient='records')

# ② 端末別通信量
device_summary = df.groupby('src_ip')['packet_size'].sum().reset_index()
device_summary = device_summary.sort_values(by='packet_size', ascending=False)
device_summary_records = device_summary.rename(columns={'src_ip': 'ip_address', 'packet_size': 'total_size'}).to_dict(orient='records')

# ③ プロトコル別通信量
protocol_summary = df.groupby('protocol')['packet_size'].sum().reset_index()
protocol_summary['packet_size'] = pd.to_numeric(protocol_summary['packet_size'], errors='coerce').fillna(0).astype(int)
protocol_summary_dict = dict(zip(protocol_summary['protocol'], protocol_summary['packet_size']))

# ④ 通信ログ（最新100件）
traffic_log_records = df[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size']] \
    .sort_values('timestamp', ascending=False) \
    .head(100) \
    .to_dict(orient='records')

print("✅ データ整形完了")
