// main.js（ダークテーマ＆配色改善＆リアルタイム連携最適化版）

const ctxTraffic = document.getElementById('trafficOverTimeChart').getContext('2d');
const ctxProtocol = document.getElementById('protocolChart').getContext('2d');

const deviceTableBody = document.querySelector('#deviceTable tbody');
const trafficLogBody = document.querySelector('#trafficLogTable tbody');
const timeRangeSelect = document.getElementById('timeRangeSelect');

let trafficOverTimeChart = null;
let protocolChart = null;
let currentMinutes = 60; // 初期時間範囲

// 時間別通信量（折れ線）チャート作成
function createTrafficChart(labels, data) {
  return new Chart(ctxTraffic, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: '通信量 (bytes)',
        data,
        borderColor: '#4FC3F7',
        backgroundColor: 'rgba(79,195,247,0.2)',
        fill: true,
        tension: 0.1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: { color: '#eee' }
        },
        tooltip: {
          bodyColor: '#fff',
          backgroundColor: '#333'
        }
      },
      scales: {
        x: {
          ticks: {
            color: '#ccc',
            maxRotation: 45,
            minRotation: 45,
            autoSkip: true,
            maxTicksLimit: 10,
            callback: function (value) {
              const dt = new Date(this.getLabelForValue(value));
              return dt.getHours().toString().padStart(2, '0') + ':' + dt.getMinutes().toString().padStart(2, '0');
            }
          },
          grid: { color: '#444' }
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#ccc' },
          grid: { color: '#444' }
        }
      }
    }
  });
}

// プロトコル別通信量（ドーナツ）チャート作成
function createProtocolChart(labels, data) {
  const colors = labels.map(label => {
    if (label === 'TCP') return '#4FC3F7';
    if (label === 'UDP') return '#EF5350';
    if (label === 'Other') return '#FFD54F';
    return '#A1887F';
  });

  return new Chart(ctxProtocol, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data, backgroundColor: colors }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { labels: { color: '#eee' } },
        tooltip: { bodyColor: '#fff', backgroundColor: '#333' }
      }
    }
  });
}

function updateDeviceTable(devices) {
  deviceTableBody.innerHTML = '';
  devices.forEach(d => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${d.ip_address}</td><td>${d.total_size}</td>`;
    deviceTableBody.appendChild(tr);
  });
}

function updateTrafficLog(logs) {
  trafficLogBody.innerHTML = '';
  logs.forEach(l => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${l.timestamp}</td>
      <td>${l.src_ip}</td>
      <td>${l.dst_ip}</td>
      <td>${l.protocol}</td>
      <td>${l.packet_size}</td>
    `;
    trafficLogBody.appendChild(tr);
  });
}

async function loadData(minutes) {
  currentMinutes = minutes;
  try {
    const res = await fetch(`/api/data?minutes=${minutes}`);
    const data = await res.json();

    const timeLabels = data.traffic_over_time.map(x => x.timestamp);
    const trafficData = data.traffic_over_time.map(x => x.total_size);

    if (!trafficOverTimeChart) {
      trafficOverTimeChart = createTrafficChart(timeLabels, trafficData);
    } else {
      trafficOverTimeChart.data.labels = timeLabels;
      trafficOverTimeChart.data.datasets[0].data = trafficData;
      trafficOverTimeChart.update();
    }

    const protocolLabels = Object.keys(data.protocol_summary);
    const protocolData = Object.values(data.protocol_summary);

    if (!protocolChart) {
      protocolChart = createProtocolChart(protocolLabels, protocolData);
    } else {
      protocolChart.data.labels = protocolLabels;
      protocolChart.data.datasets[0].data = protocolData;
      protocolChart.data.datasets[0].backgroundColor = protocolLabels.map(label => {
        if (label === 'TCP') return '#4FC3F7';
        if (label === 'UDP') return '#EF5350';
        if (label === 'Other') return '#FFD54F';
        return '#A1887F';
      });
      protocolChart.update();
    }

    updateDeviceTable(data.device_table);
    updateTrafficLog(data.traffic_log);
  } catch (error) {
    console.error('データの取得に失敗しました:', error);
  }
}

timeRangeSelect.addEventListener('change', (e) => {
  const minutes = parseInt(e.target.value);
  loadData(minutes);
});

// 初期表示（過去1時間）
loadData(currentMinutes);

// リアルタイム更新（30秒ごと）
setInterval(() => loadData(currentMinutes), 30000);