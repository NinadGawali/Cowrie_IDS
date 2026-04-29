const statusEl = document.getElementById('status');
const totalEl = document.getElementById('totalEvents');
const uniqueIpsEl = document.getElementById('uniqueIps');
const totalCommandsEl = document.getElementById('totalCommands');
const totalCredsEl = document.getElementById('totalCreds');
const topAttackEl = document.getElementById('topAttack');
const logsBody = document.getElementById('logsBody');
const insightsEl = document.getElementById('insights');
const analyzeBtn = document.getElementById('analyzeBtn');
const modelStatusEl = document.getElementById('modelStatus');
const attackChipsEl = document.getElementById('attackChips');

let ipChart, cmdChart, timelineChart;
function formatConfidence(value) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '-';
  }
  return `${Math.round(Number(value) * 100)}%`;
}

function labelClassName(label) {
  const normalized = (label || '').toLowerCase();
  if (normalized.includes('benign') || normalized === 'no_command') return 'attack-benign';
  if (normalized.includes('critical') || normalized.includes('rce') || normalized.includes('malware')) return 'attack-critical';
  if (normalized.includes('high') || normalized.includes('bruteforce') || normalized.includes('lateral')) return 'attack-high';
  if (normalized.includes('scan') || normalized.includes('recon')) return 'attack-medium';
  if (normalized === 'model_unavailable' || normalized === 'prediction_error') return 'attack-unknown';
  return 'attack-medium';
}

function renderAttackChips(attackLabels) {
  attackChipsEl.innerHTML = '';
  if (!attackLabels || attackLabels.length === 0) {
    attackChipsEl.innerHTML = '<div class="attack-chip attack-unknown">No predictions yet</div>';
    return;
  }

  attackLabels.slice(0, 8).forEach(item => {
    const chip = document.createElement('div');
    chip.className = `attack-chip ${labelClassName(item.value)}`;
    chip.textContent = `${item.value} (${item.count})`;
    attackChipsEl.appendChild(chip);
  });
}

function buildRow(r) {
  const tr = document.createElement('tr');
  const tdTs = document.createElement('td');
  tdTs.textContent = r.timestamp ? r.timestamp.substring(0, 19).replace('T', ' ') : '';
  tr.appendChild(tdTs);

  const tdIp = document.createElement('td');
  tdIp.textContent = r.ip || '';
  tr.appendChild(tdIp);

  const tdUser = document.createElement('td');
  tdUser.textContent = r.username || '';
  tr.appendChild(tdUser);

  const tdCmd = document.createElement('td');
  tdCmd.textContent = r.command ? r.command.substring(0, 60) : '';
  tdCmd.title = r.command || '';
  tr.appendChild(tdCmd);

  const tdEvt = document.createElement('td');
  tdEvt.textContent = r.event_type ? r.event_type.replace('cowrie.', '') : '';
  tr.appendChild(tdEvt);

  const tdPred = document.createElement('td');
  tdPred.textContent = r.attack_label || '-';
  tdPred.className = labelClassName(r.attack_label);
  tr.appendChild(tdPred);

  const tdConf = document.createElement('td');
  tdConf.textContent = formatConfidence(r.attack_confidence);
  tr.appendChild(tdConf);
  return tr;
}

async function fetchJson(path) {
  const url = path;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}

function initCharts() {
  const chartColors = {
    primary: '#00d9ff',
    secondary: '#00a3cc',
    background: 'rgba(0, 217, 255, 0.1)',
    grid: '#2a2f36',
    text: '#9aa0a6'
  };

  const commonOptions = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        labels: { color: chartColors.text }
      }
    }
  };

  // IP Chart
  const ipCtx = document.getElementById('ipChart').getContext('2d');
  ipChart = new Chart(ipCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Requests',
        data: [],
        backgroundColor: chartColors.primary,
        borderColor: chartColors.secondary,
        borderWidth: 1
      }]
    },
    options: {
      ...commonOptions,
      scales: {
        y: {
          beginAtZero: true,
          ticks: { color: chartColors.text },
          grid: { color: chartColors.grid }
        },
        x: {
          ticks: { color: chartColors.text },
          grid: { color: chartColors.grid }
        }
      }
    }
  });

  // Command Chart
  const cmdCtx = document.getElementById('cmdChart').getContext('2d');
  cmdChart = new Chart(cmdCtx, {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: [
          '#00d9ff', '#00a3cc', '#0088aa', '#006d88', '#005266',
          '#ff6b6b', '#ffa07a', '#98d8c8', '#6c5ce7', '#a29bfe'
        ],
        borderWidth: 2,
        borderColor: '#1b1f24'
      }]
    },
    options: {
      ...commonOptions,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: chartColors.text, font: { size: 10 } }
        }
      }
    }
  });

  // Timeline Chart
  const timelineCtx = document.getElementById('timelineChart').getContext('2d');
  timelineChart = new Chart(timelineCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Events',
        data: [],
        borderColor: chartColors.primary,
        backgroundColor: chartColors.background,
        tension: 0.4,
        fill: true,
        pointBackgroundColor: chartColors.primary,
        pointBorderColor: chartColors.secondary,
        pointRadius: 3
      }]
    },
    options: {
      ...commonOptions,
      scales: {
        y: {
          beginAtZero: true,
          ticks: { color: chartColors.text, stepSize: 1 },
          grid: { color: chartColors.grid }
        },
        x: {
          ticks: { color: chartColors.text, maxRotation: 45, minRotation: 45 },
          grid: { color: chartColors.grid }
        }
      }
    }
  });
}

function updateCharts(stats, logs) {
  const topIps = (stats?.top_ips || []).slice(0, 10);
  ipChart.data.labels = topIps.map(i => i.value);
  ipChart.data.datasets[0].data = topIps.map(i => i.count);
  ipChart.update();

  const topCmds = (stats?.top_commands || []).slice(0, 8);
  cmdChart.data.labels = topCmds.map(i => i.value.substring(0, 30));
  cmdChart.data.datasets[0].data = topCmds.map(i => i.count);
  cmdChart.update();

  const recent = (logs || []).slice(0, 50).reverse();
  const timeline = {};

  recent.forEach(log => {
    if (!log.timestamp) return;
    const t = log.timestamp.substring(11, 16);
    timeline[t] = (timeline[t] || 0) + 1;
  });

  timelineChart.data.labels = Object.keys(timeline);
  timelineChart.data.datasets[0].data = Object.values(timeline);
  timelineChart.update();
}

function formatGeminiInsights(summary) {
  if (typeof summary === 'string') {
    return `<p>${summary.replace(/\n/g, '<br>')}</p>`;
  }
  
  let html = '';
  
  if (summary.summary) {
    html += `<h4>📊 Summary</h4><p>${summary.summary}</p>`;
  }

  if (summary.reasoning) {
    html += `<h4>🧠 Reasoning</h4><p>${summary.reasoning}</p>`;
  }

  if (summary.log_context) {
    html += `<h4>🧾 Log Context</h4><p>${summary.log_context}</p>`;
  }
  
  if (summary.tactics && summary.tactics.length > 0) {
    html += '<h4>⚔️ Attack Tactics</h4><ul>';
    summary.tactics.forEach(tactic => {
      html += `<li>${tactic}</li>`;
    });
    html += '</ul>';
  }
  
  if (summary.recommendations && summary.recommendations.length > 0) {
    html += '<h4>🛡️ Recommendations</h4><ul>';
    summary.recommendations.forEach(rec => {
      html += `<li>${rec}</li>`;
    });
    html += '</ul>';
  }
  
  if (summary.risk_level) {
    const riskColors = {
      'low': '#4caf50',
      'medium': '#ff9800',
      'high': '#f44336',
      'critical': '#d32f2f'
    };
    const color = riskColors[summary.risk_level.toLowerCase()] || '#9aa0a6';
    html += `<h4>⚠️ Risk Level</h4><p style="color:${color}; font-weight:bold; font-size:1.2em;">${summary.risk_level.toUpperCase()}</p>`;
  }
  
  return html || '<p>No insights available yet.</p>';
}

function renderLogs(rows) {
  logsBody.innerHTML = '';
  rows.slice(0, 200).forEach(r => {
    logsBody.appendChild(buildRow(r));
  });
}

async function refresh() {
  try {
    statusEl.textContent = 'Refreshing…';

    const [logsRes, stats] = await Promise.all([
      fetchJson('/logs'),
      fetchJson('/stats'),
    ]);

    const logs = logsRes?.data || [];
    const topCommands = stats?.top_commands || [];
    const credentialAttempts = stats?.credential_attempts || [];
    const attackLabels = stats?.attack_labels || [];

    totalEl.textContent = stats?.total_events || 0;

    uniqueIpsEl.textContent = new Set(
      logs.map(x => x?.ip).filter(Boolean)
    ).size;

    totalCommandsEl.textContent = topCommands.reduce(
      (sum, c) => sum + (c?.count || 0), 0
    );

    totalCredsEl.textContent = credentialAttempts.reduce(
      (sum, c) => sum + (c?.count || 0), 0
    );

    topAttackEl.textContent = attackLabels[0]?.value || '-';

    renderAttackChips(attackLabels);
    updateCharts(stats, logs);
    renderLogs(logs);

    statusEl.textContent = 'OK';
  } catch (e) {
    statusEl.textContent = 'Error: ' + e.message;
    console.error(e);
  }
}

async function refreshSummary() {
  try {
    if (analyzeBtn) {
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = 'Analyzing...';
    }
    insightsEl.innerHTML = '<div class="loading">Analyzing latest 10 logs with detailed reasoning...</div>';

    const summary = await fetchJson(`/summary?limit=10&t=${Date.now()}`);
    insightsEl.innerHTML = formatGeminiInsights(summary);
  } catch (e) {
    insightsEl.innerHTML = `<p>Summary unavailable: ${e.message}</p>`;
  } finally {
    if (analyzeBtn) {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = 'Analyze Latest 10 Logs';
    }
  }
}

// Initialize charts on load
initCharts();
refresh();
setInterval(refresh, 10000);

if (analyzeBtn) {
  analyzeBtn.addEventListener('click', refreshSummary);
}

// Real-time logs via SSE
function startLogStream() {
  if (!('EventSource' in window)) {
    console.warn('SSE not supported, falling back to polling only.');
    return;
  }
  const es = new EventSource('/stream/logs');
  es.onmessage = (evt) => {
    try {
      const rec = JSON.parse(evt.data);
      const tr = buildRow(rec);
      if (logsBody.firstChild) {
        logsBody.insertBefore(tr, logsBody.firstChild);
      } else {
        logsBody.appendChild(tr);
      }
      while (logsBody.children.length > 200) {
        logsBody.removeChild(logsBody.lastChild);
      }
    } catch (e) {
      console.error('Bad SSE event', e);
    }
  };
  es.onerror = () => {
    statusEl.textContent = 'SSE error; reconnecting…';
  };
}

startLogStream();
