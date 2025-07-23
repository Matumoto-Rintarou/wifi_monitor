from flask import Flask, jsonify, render_template
from wifi_data_analysis import traffic_over_time_records, device_summary_records, protocol_summary_dict, traffic_log_records

app = Flask(__name__)

@app.route('/api/traffic_over_time')
def get_traffic_over_time():
    return jsonify(traffic_over_time_records)

@app.route('/api/protocol_summary')
def get_protocol_summary():
    return jsonify(protocol_summary_dict)

@app.route('/api/device_table')
def get_device_table():
    return jsonify(device_summary_records)

@app.route('/api/traffic_log')
def get_traffic_log():
    return jsonify(traffic_log_records)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
