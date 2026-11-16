// ==========================================================================
// SYSTEM AUDIT LOGS CONTROLLER (16-BIT RETRO PIXEL SOC - IMAGE 4)
// Terminal-Style Stream, Multi-Filter, MITRE Forensics, & IP Ledger
// ==========================================================================

let allLogs = [];
let allIps = [];
let isLivePaused = false;
let currentCategoryFilter = 'ALL';
let logSearchQuery = '';
let ipSearchQuery = '';
let currentPage = 1;
const pageSize = 20;

// Demo logs matching Image 4 reference if buffer is empty
const INITIAL_DEMO_LOGS = [
  {
    timestamp: new Date(Date.now() - 1000 * 180).toISOString(),
    component: 'Router',
    badge: 'INFO',
    message: 'Multi-page route initialized with Sky-Island Layout.',
    path: '/dashboard',
    source_ip: '127.0.0.1',
    agent: 'ubuntu-2',
    level: 1,
    mitre: 'T1082 (Telemetry)'
  },
  {
    timestamp: new Date(Date.now() - 1000 * 150).toISOString(),
    component: 'Charts',
    badge: 'SUCCESS',
    message: 'Rendered real-time status Donut & Bar charts.',
    path: '/analytics',
    source_ip: '127.0.0.1',
    agent: 'center-siem',
    level: 1,
    mitre: 'T1082 (Telemetry)'
  },
  {
    timestamp: new Date(Date.now() - 1000 * 120).toISOString(),
    component: 'RateLimit',
    badge: 'WARN',
    message: 'Burst traffic detected (86% load) on node ubuntu-2.',
    path: '/var/log/nginx/access.log',
    source_ip: '163.52.135.170',
    agent: 'ubuntu-2',
    level: 7,
    mitre: 'T1595 (Active Scan)'
  },
  {
    timestamp: new Date(Date.now() - 1000 * 90).toISOString(),
    component: 'Auth',
    badge: 'INFO',
    message: 'Session verified via separate route middleware.',
    path: '/settings',
    source_ip: '31.56.56.50',
    agent: 'ubuntu',
    level: 1,
    mitre: 'T1078 (Valid Accounts)'
  },
  {
    timestamp: new Date(Date.now() - 1000 * 30).toISOString(),
    component: 'CRON',
    badge: 'SUCCESS',
    message: 'pam_unix(cron:session): session opened for user root.',
    path: '/var/log/auth.log',
    source_ip: '163.52.135.170',
    agent: 'ubuntu-2',
    level: 1,
    mitre: 'T1082 (Telemetry)'
  }
];

document.addEventListener('DOMContentLoaded', () => {
  // Mount Active Route Strip for Audit Logs
  if (typeof mountActiveRouteStrip === 'function') {
    mountActiveRouteStrip(
      'AUDIT LOGS',
      '/LOGS',
      'Halaman terpisah untuk pemantauan log aktivitas, filter level status, dan inspeksi path.'
    );
  }

  // Pre-seed with initial logs
  allLogs = [...INITIAL_DEMO_LOGS];
  renderTerminalLogs();
  renderLogsTable();

  // Load real server logs
  reloadLogsData();

  // Listen to validated security log events
  window.addEventListener('siem-security-log', (e) => {
    handleIncomingSecurityLog(e.detail);
  });

  // Listen to IP update events
  window.addEventListener('siem-ip-update', (e) => {
    handleIncomingIpUpdate(e.detail);
  });
});

/** Muat ulang data log dan IP dari server */
async function reloadLogsData() {
  try {
    const [logsRes, ipsRes] = await Promise.allSettled([
      authFetch('/api/v1/logs'),
      authFetch('/api/v1/ips')
    ]);

    if (logsRes.status === 'fulfilled' && logsRes.value.ok) {
      const rawLogs = await logsRes.value.json() || [];
      const validLogs = rawLogs
        .filter(item => item && (item.message || item.rule_id || item.rule_desc || item.endpoint || item.command))
        .map(item => (typeof normalizeLogItem === 'function' ? normalizeLogItem(item) : item))
        .filter(Boolean);

      if (validLogs.length > 0) {
        allLogs = validLogs;
      }

      renderTerminalLogs();
      renderLogsTable();
    }

    if (ipsRes.status === 'fulfilled' && ipsRes.value.ok) {
      allIps = await ipsRes.value.json() || [];
      const countIps = document.getElementById('countSubIps');
      if (countIps) countIps.textContent = String(allIps.length);
      renderIpsTable();
      renderSuspiciousTable();
    }
  } catch (err) {
    console.warn('Gagal memuat log server, tetap gunakan buffer:', err.message);
  }
}

/** Render Terminal Box (Dark High-Contrast Pixel Rows - Image 4) */
function renderTerminalLogs() {
  const container = document.getElementById('terminalLogList');
  const countBadge = document.getElementById('logsEventCountBadge');
  if (!container) return;

  let filtered = allLogs.filter(log => {
    const badge = (log.badge || log.category || 'INFO').toUpperCase();
    const lvl = Number(log.level || 1);

    if (currentCategoryFilter !== 'ALL') {
      if (currentCategoryFilter === 'INFO' && badge !== 'INFO') return false;
      if (currentCategoryFilter === 'SUCCESS' && badge !== 'SUCCESS' && badge !== 'CLEAN') return false;
      if (currentCategoryFilter === 'WARN' && badge !== 'WARN' && lvl < 7) return false;
      if (currentCategoryFilter === 'ATTACK' && badge !== 'ATTACK' && !badge.includes('SPAM') && lvl < 10) return false;
    }
    return true;
  });

  if (countBadge) {
    countBadge.textContent = `${filtered.length} EVENTS`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; color: #64748B; font-size: 11px; padding: 24px;">
        Tidak ada log yang cocok dengan filter [${currentCategoryFilter}].
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.slice(0, 50).map((log, idx) => {
    const timeStr = formatDateTime(log.timestamp);
    const badge = (log.badge || (log.level >= 10 ? 'ATTACK' : log.level >= 7 ? 'WARN' : log.action === 'SUCCESS' ? 'SUCCESS' : 'INFO')).toUpperCase();
    const component = log.component || (log.raw && log.raw.service) || log.agent || 'System';
    const msg = log.desc || log.message || (log.raw && log.raw.message) || 'Event executed';
    const path = log.path || (log.raw && log.raw.endpoint) || (log.source_ip ? `[${log.source_ip}]` : '/dashboard');

    let badgeClass = 'tag-cyan';
    if (badge === 'SUCCESS') badgeClass = 'tag-clean';
    else if (badge === 'WARN') badgeClass = 'tag-warning';
    else if (badge === 'ATTACK') badgeClass = 'tag-critical';

    return `
      <div class="terminal-log-row" onclick="inspectLog(${idx})" style="cursor: pointer;" title="Klik untuk inspect payload JSON">
        <span class="terminal-log-time">${timeStr}</span>
        <span class="pixel-tag ${badgeClass}">[ ${badge} ]</span>
        <span class="terminal-log-msg">
          <strong style="color: #93C5FD;">[${escapeHtml(component)}]</strong>
          ${escapeHtml(msg)}
        </span>
        <span class="terminal-log-path">[${escapeHtml(path)}]</span>
      </div>
    `;
  }).join('');
}

/** Generate a realistic test event on button click */
function generateSimulatedLog() {
  const routes = ['/dashboard', '/analytics', '/logs', '/settings', '/auth/login', '/api/v1/telemetry'];
  const components = ['Router', 'SigmaEngine', 'Firewall', 'RateLimit', 'Audit', 'Sentinel'];
  const badges = ['INFO', 'SUCCESS', 'WARN', 'ATTACK'];

  const randBadge = badges[Math.floor(Math.random() * badges.length)];
  const randComp = components[Math.floor(Math.random() * components.length)];
  const randRoute = routes[Math.floor(Math.random() * routes.length)];

  let message = 'Transaction verified by Sky-Island Layout.';
  let level = 1;
  let mitre = 'T1082 (Telemetry)';

  if (randBadge === 'WARN') {
    message = `High resource threshold detected on node ${randRoute}.`;
    level = 7;
    mitre = 'T1595 (Active Scan)';
  } else if (randBadge === 'ATTACK') {
    message = `Suspicious payload blocked by iptables DROP rule.`;
    level = 10;
    mitre = 'T1110 (Brute Force)';
  } else if (randBadge === 'SUCCESS') {
    message = `Security validation check passed for ${randRoute}.`;
  }

  const newLog = {
    timestamp: new Date().toISOString(),
    component: randComp,
    badge: randBadge,
    message: message,
    desc: message,
    path: randRoute,
    source_ip: `192.168.1.${Math.floor(Math.random() * 200 + 10)}`,
    agent: 'agent-node-1',
    level: level,
    mitre: mitre,
    raw: {
      timestamp: new Date().toISOString(),
      service: randComp,
      message: message,
      endpoint: randRoute
    }
  };

  allLogs.unshift(newLog);
  if (allLogs.length > 500) allLogs.pop();

  renderTerminalLogs();
  renderLogsTable();
}

/** Filter Category Switcher */
function setLogCategoryFilter(cat) {
  currentCategoryFilter = cat;
  document.querySelectorAll('.pixel-chip').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-filter') === cat);
  });
  renderTerminalLogs();
  renderLogsTable();
}

function toggleLiveStreaming() {
  isLivePaused = !isLivePaused;
  const btn = document.getElementById('btnToggleLive');
  if (btn) {
    btn.innerHTML = isLivePaused ? '<span>▶ RESUME STREAM</span>' : '<span>⏸ PAUSE STREAM</span>';
    btn.classList.toggle('pixel-btn-cyan', !isLivePaused);
  }
}

/** Subview switcher (Events table vs Inbound IP vs Suspicious) */
function switchLogSubview(viewName) {
  document.getElementById('subtab-events').classList.toggle('pixel-btn-cyan', viewName === 'events');
  document.getElementById('subtab-ips').classList.toggle('pixel-btn-cyan', viewName === 'ips');
  document.getElementById('subtab-suspicious').classList.toggle('pixel-btn-cyan', viewName === 'suspicious');

  document.getElementById('subview-events-content').style.display = viewName === 'events' ? 'block' : 'none';
  document.getElementById('subview-ips-content').style.display = viewName === 'ips' ? 'block' : 'none';
  document.getElementById('subview-suspicious-content').style.display = viewName === 'suspicious' ? 'block' : 'none';
}

/** Render Table View */
function renderLogsTable() {
  const tbody = document.getElementById('eventsTableBody');
  if (!tbody) return;

  let filtered = allLogs.filter(log => {
    const badge = (log.badge || log.category || 'INFO').toUpperCase();
    const lvl = Number(log.level || 1);

    if (currentCategoryFilter !== 'ALL') {
      if (currentCategoryFilter === 'INFO' && badge !== 'INFO') return false;
      if (currentCategoryFilter === 'SUCCESS' && badge !== 'SUCCESS' && badge !== 'CLEAN') return false;
      if (currentCategoryFilter === 'WARN' && badge !== 'WARN' && lvl < 7) return false;
      if (currentCategoryFilter === 'ATTACK' && badge !== 'ATTACK' && lvl < 10) return false;
    }

    if (logSearchQuery) {
      const q = logSearchQuery.toLowerCase();
      const str = JSON.stringify(log.raw || log).toLowerCase();
      if (!str.includes(q)) return false;
    }
    return true;
  });

  const total = filtered.length;
  const start = (currentPage - 1) * pageSize;
  const paged = filtered.slice(start, start + pageSize);

  const countSub = document.getElementById('countSubEvents');
  if (countSub) countSub.textContent = String(total);

  const infoEl = document.getElementById('eventsPaginationInfo');
  if (infoEl) infoEl.textContent = `Menampilkan ${total > 0 ? start + 1 : 0} s.d. ${Math.min(start + pageSize, total)} dari ${total} log`;

  if (paged.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">Tidak ada event yang sesuai dengan filter.</td></tr>`;
    renderPaginationControls(total);
    return;
  }

  tbody.innerHTML = paged.map((log, idx) => {
    const globalIdx = start + idx;
    const time = formatDateTime(log.timestamp);
    const ip = log.source_ip || '127.0.0.1';
    const agent = log.agent || 'node';
    const lvl = Number(log.level || 1);
    const badge = log.badge || log.category || 'INFO';
    const action = log.action || (lvl >= 10 ? 'DROP' : 'LOG');
    const signature = log.desc || log.message || (log.raw && log.raw.message) || 'Event recorded';
    const mitre = log.mitre || 'T1082 (Telemetry)';

    const lvlTag = lvl >= 10 ?
      `<span class="pixel-tag tag-critical">CRIT ${lvl}</span>` :
      lvl >= 7 ?
      `<span class="pixel-tag tag-warning">WARN ${lvl}</span>` :
      `<span class="pixel-tag tag-clean">INFO ${lvl}</span>`;

    return `
      <tr>
        <td style="white-space: nowrap;">${time}</td>
        <td><code>${ip}</code></td>
        <td>${agent}</td>
        <td>${lvlTag}</td>
        <td>
          <span class="pixel-tag tag-cyan">${badge}</span>
          <span class="pixel-tag" style="font-size: 8px; margin-left: 2px;">${action}</span>
        </td>
        <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(signature)}">
          ${escapeHtml(signature)}
        </td>
        <td><span class="pixel-tag tag-purple">${mitre}</span></td>
        <td>
          <button class="pixel-btn pixel-btn-sm pixel-btn-cyan" onclick="inspectLog(${globalIdx})">INSPECT</button>
        </td>
      </tr>
    `;
  }).join('');

  renderPaginationControls(total);
}

function renderPaginationControls(total) {
  const controlsEl = document.getElementById('eventsPaginationControls');
  if (!controlsEl) return;
  const totalPages = Math.ceil(total / pageSize) || 1;

  controlsEl.innerHTML = `
    <button class="pixel-btn pixel-btn-sm" ${currentPage <= 1 ? 'disabled' : ''} onclick="changePage(${currentPage - 1})">&laquo; PREV</button>
    <span style="font-family: var(--font-pixel); font-size: 8px; padding: 0 6px;">HALAMAN ${currentPage} / ${totalPages}</span>
    <button class="pixel-btn pixel-btn-sm" ${currentPage >= totalPages ? 'disabled' : ''} onclick="changePage(${currentPage + 1})">NEXT &raquo;</button>
  `;
}

function changePage(p) {
  currentPage = p;
  renderLogsTable();
}

function applyLogFilters() {
  const input = document.getElementById('logSearchInput');
  logSearchQuery = input ? input.value.trim() : '';
  currentPage = 1;
  renderLogsTable();
}

/** Incoming SSE Security Log */
function handleIncomingSecurityLog(normLog) {
  if (!normLog) return;
  allLogs.unshift(normLog);
  if (allLogs.length > 500) allLogs.pop();

  if (!isLivePaused) {
    renderTerminalLogs();
    if (currentPage === 1) renderLogsTable();
  }
}

/** Incoming SSE IP Update */
function handleIncomingIpUpdate(ipRec) {
  if (!ipRec || !ipRec.ip) return;
  const existingIdx = allIps.findIndex(i => i.ip === ipRec.ip);
  if (existingIdx >= 0) {
    allIps[existingIdx] = ipRec;
  } else {
    allIps.unshift(ipRec);
  }

  const countIps = document.getElementById('countSubIps');
  if (countIps) countIps.textContent = String(allIps.length);

  renderIpsTable();
  renderSuspiciousTable();
}

/** Render Tabel Inbound IP Ledger */
function renderIpsTable() {
  const tbody = document.getElementById('ipsTableBody');
  if (!tbody) return;

  let filtered = allIps;
  if (ipSearchQuery) {
    const q = ipSearchQuery.toLowerCase();
    filtered = allIps.filter(ip => JSON.stringify(ip).toLowerCase().includes(q));
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">Tidak ada IP yang terdeteksi.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(item => {
    const ip = item.ip || item.source_ip || '-';
    const node = item.node || item.hostname || 'Cluster';
    const cat = item.category || 'HTTP Web';
    const hits = item.request_count || item.hits || 1;
    const first = formatDateTime(item.first_seen);
    const last = formatDateTime(item.last_seen || item.timestamp);
    const lvl = Number(item.threat_level || item.severity || 1);

    const threatTag = lvl >= 10 ?
      `<span class="pixel-tag tag-critical">CRIT ${lvl}</span>` :
      lvl >= 7 ?
      `<span class="pixel-tag tag-warning">WARN ${lvl}</span>` :
      `<span class="pixel-tag tag-clean">CLEAN</span>`;

    return `
      <tr>
        <td><strong><code>${ip}</code></strong></td>
        <td>${node}</td>
        <td><span class="pixel-tag tag-cyan">${cat}</span></td>
        <td><strong>${hits}</strong></td>
        <td>${first}</td>
        <td>${last}</td>
        <td>${threatTag}</td>
        <td>
          <button class="pixel-btn pixel-btn-sm pixel-btn-danger" onclick="blockIpAction('${ip}')">
            🛡️ BLOCK IP
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function applyIpFilters() {
  const input = document.getElementById('ipSearchInput');
  ipSearchQuery = input ? input.value.trim() : '';
  renderIpsTable();
}

/** Render Tabel Suspicious Watchlist */
function renderSuspiciousTable() {
  const tbody = document.getElementById('suspiciousTableBody');
  if (!tbody) return;

  const suspiciousList = allIps.filter(ip => Number(ip.threat_level || ip.severity || 0) >= 7);
  const countThreats = document.getElementById('countSubThreats');
  if (countThreats) countThreats.textContent = String(suspiciousList.length);

  if (suspiciousList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 20px;">Sistem bersih — Tidak ada ancaman aktif severity &ge; 7.</td></tr>`;
    return;
  }

  tbody.innerHTML = suspiciousList.map(item => {
    const ip = item.ip || item.source_ip || '-';
    const host = item.node || item.hostname || 'Monitored Node';
    const attack = item.suspected_attack || 'Brute-Force Anomaly';
    const hits = item.request_count || item.hits || 1;
    const lvl = Number(item.threat_level || item.severity || 7);
    const contained = item.is_blocked ?
      '<span class="pixel-tag tag-clean">CONTAINED</span>' :
      '<span class="pixel-tag tag-critical">ACTIVE DROP PENDING</span>';

    return `
      <tr>
        <td><strong><code>${ip}</code></strong></td>
        <td>${host}</td>
        <td><span class="pixel-tag tag-purple">${attack}</span></td>
        <td>${hits}</td>
        <td><span class="pixel-tag tag-critical">LVL ${lvl}</span></td>
        <td>${contained}</td>
        <td>
          <button class="pixel-btn pixel-btn-sm pixel-btn-danger" onclick="blockIpAction('${ip}')">
            DROP IPTABLES
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

async function blockIpAction(ip) {
  if (!confirm(`Konfirmasi Zero-Trust: Apakah Anda yakin ingin memblokir IP ${ip} via iptables DROP?`)) return;

  try {
    const res = await authFetch('/api/v1/containment/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Gagal memblokir IP.');
    alert(`Berhasil: Aturan iptables DROP untuk IP ${ip} telah diaktifkan!`);
    reloadLogsData();
  } catch (err) {
    alert(`Gagal memblokir: ${err.message}`);
  }
}

// ==========================================================================
// RAW NDJSON INSPECTOR MODAL
// ==========================================================================
let currentInspectedJson = '';

function inspectLog(idx) {
  const log = allLogs[idx];
  if (!log) return;
  currentInspectedJson = JSON.stringify(log.raw || log, null, 2);
  const modal = document.getElementById('jsonModal');
  const pre = document.getElementById('modalJsonContent');
  if (pre) pre.textContent = currentInspectedJson;
  if (modal) modal.classList.remove('hidden');
}

function closeJsonModal() {
  const modal = document.getElementById('jsonModal');
  if (modal) modal.classList.add('hidden');
}

function copyModalJson() {
  if (!currentInspectedJson) return;
  navigator.clipboard.writeText(currentInspectedJson).then(() => {
    alert('JSON event berhasil disalin!');
  });
}
