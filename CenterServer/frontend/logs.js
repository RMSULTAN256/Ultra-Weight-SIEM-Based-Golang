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
let currentIpPage = 1;
const ipPageSize = 12;

document.addEventListener('DOMContentLoaded', () => {
  // Mount Active Route Strip for Audit Logs
  if (typeof mountActiveRouteStrip === 'function') {
    mountActiveRouteStrip(
      'AUDIT LOGS',
      '/LOGS',
      'Halaman terpisah untuk pemantauan log aktivitas, filter level status, dan inspeksi path.'
    );
  }

  // Render initial loading state
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

      validLogs.forEach((l, i) => {
        if (!l.id) l.id = 'log_' + i + '_' + (l.timestamp || Date.now());
      });

      if (validLogs.length > 0) {
        allLogs = validLogs.slice(0, 500);
      }

      const countBadge = document.getElementById('logsEventCountBadge');
      if (countBadge) countBadge.textContent = `${allLogs.length} EVENTS`;
      const countSub = document.getElementById('countSubEvents');
      if (countSub) countSub.textContent = String(allLogs.length);

      renderTerminalLogs();
      renderLogsTable();
    }

    if (ipsRes.status === 'fulfilled' && ipsRes.value.ok) {
      const rawIps = await ipsRes.value.json() || [];
      allIps = Array.isArray(rawIps) ? rawIps.slice(0, MAX_IPS) : [];
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

    if (logSearchQuery) {
      const q = logSearchQuery.toLowerCase();
      const str = JSON.stringify(log.raw || log).toLowerCase();
      if (!str.includes(q)) return false;
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

  container.innerHTML = filtered.slice(0, 50).map((log) => {
    const logIdStr = escapeHtml(String(log.id || ''));
    const timeStr = formatDateTime(log.timestamp);
    const badge = (log.badge || (log.level >= 10 ? 'ATTACK' : log.level >= 7 ? 'WARN' : log.action === 'SUCCESS' ? 'SUCCESS' : 'INFO')).toUpperCase();
    const component = log.component || (log.raw && log.raw.service) || log.agent || 'System';
    const msg = log.desc || log.message || (log.raw && log.raw.message) || 'Event executed';
    const path = log.path || (log.raw && log.raw.endpoint) || (log.source_ip ? `[${log.source_ip}]` : '/dashboard');

    let badgeClass = 'tag-cyan';
    if (badge === 'SUCCESS') badgeClass = 'tag-clean';
    else if (badge === 'WARN') badgeClass = 'tag-warning';
    else if (badge === 'ATTACK') badgeClass = 'tag-critical';

    // HTTP Status Tag Color Indicator for Web Requests (200 - 504)
    let statusTag = '';
    const code = log.statusCode || (log.raw && (log.raw.status_code || log.raw.statusCode));
    if (code && typeof getHttpStatusTag === 'function') {
      statusTag = getHttpStatusTag(code, log.method);
    } else if (log.action && log.action.match(/\b([1-5][0-9]{2})\b/)) {
      const m = log.action.match(/\b([1-5][0-9]{2})\b/);
      statusTag = getHttpStatusTag(m[1], null);
    }

    return `
      <div class="terminal-log-row" data-log-id="${logIdStr}" onclick="inspectLogById(this.dataset.logId)" style="cursor: pointer;" title="Klik untuk inspect payload JSON">
        <span class="terminal-log-time">${timeStr}</span>
        <span class="pixel-tag ${badgeClass}">[ ${badge} ]</span>
        ${statusTag ? `<span style="margin-left: 2px;">${statusTag}</span>` : ''}
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
  const routes = ['/dashboard', '/analytics', '/logs', '/settings', '/auth/login', '/api/v1/telemetry', '/api/v1/users', '/checkout'];
  const components = ['Nginx Web', 'Router', 'SigmaEngine', 'Firewall', 'RateLimit', 'Audit'];
  const statusCodes = [200, 200, 201, 302, 401, 403, 404, 500, 502, 504];
  const randStatus = statusCodes[Math.floor(Math.random() * statusCodes.length)];
  const randRoute = routes[Math.floor(Math.random() * routes.length)];
  const randComp = components[Math.floor(Math.random() * components.length)];
  const method = Math.random() > 0.3 ? 'GET' : 'POST';

  let randBadge = 'INFO';
  let message = `HTTP ${method} ${randRoute} — Status ${randStatus}`;
  let level = 1;
  let mitre = 'T1082 (Telemetry)';

  if (randStatus >= 500) {
    randBadge = 'WARN';
    level = 8;
    mitre = 'T1499 (Endpoint DoS / Gateway Error)';
    message = `HTTP ${method} ${randRoute} — Server Gateway Error Status ${randStatus}`;
  } else if (randStatus >= 400) {
    randBadge = (randStatus === 401 || randStatus === 403) ? 'ATTACK' : 'WARN';
    level = (randStatus === 401 || randStatus === 403) ? 10 : 7;
    mitre = randStatus === 401 ? 'T1110 (Brute Force)' : 'T1595 (Active Scan)';
    message = `HTTP ${method} ${randRoute} — Client Error Status ${randStatus}`;
  } else if (randStatus >= 200 && randStatus < 300) {
    randBadge = 'SUCCESS';
    message = `HTTP ${method} ${randRoute} — Transaction OK Status ${randStatus}`;
  }

  const isWeb = randComp === 'Nginx Web' || randRoute.startsWith('/api') || randRoute.startsWith('/auth');
  const cat = isWeb ? 'WEB' : randBadge;

  const newLog = {
    id: 'sim_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    timestamp: new Date().toISOString(),
    component: randComp,
    badge: cat,
    category: cat,
    action: isWeb ? `${method} ${randStatus}` : 'EVENT',
    statusCode: isWeb ? randStatus : null,
    method: isWeb ? method : null,
    endpoint: randRoute,
    message: message,
    desc: message,
    path: randRoute,
    source_ip: `192.168.1.${Math.floor(Math.random() * 200 + 10)}`,
    agent: Math.random() > 0.5 ? 'ubuntu-2' : 'ubuntu',
    level: level,
    mitre: mitre,
    raw: {
      timestamp: new Date().toISOString(),
      service: randComp,
      status_code: randStatus,
      method: method,
      message: message,
      endpoint: randRoute
    }
  };

  allLogs.unshift(newLog);
  if (allLogs.length > 500) allLogs.pop();

  const countBadge = document.getElementById('logsEventCountBadge');
  if (countBadge) countBadge.textContent = `${allLogs.length} EVENTS`;
  const countSub = document.getElementById('countSubEvents');
  if (countSub) countSub.textContent = String(allLogs.length);

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

let eventsDisplayMode = 'table'; // 'table' or 'terminal'

/** Ganti Mode Tampilan Log (Tabel Terstruktur vs Terminal Monospace) */
function setEventsDisplayMode(mode) {
  eventsDisplayMode = mode;
  const btnTable = document.getElementById('btnViewTable');
  const btnTerm = document.getElementById('btnViewTerminal');
  const tableCont = document.getElementById('eventsTableViewContainer');
  const termCont = document.getElementById('eventsTerminalViewContainer');

  if (btnTable) btnTable.classList.toggle('pixel-btn-cyan', mode === 'table');
  if (btnTerm) btnTerm.classList.toggle('pixel-btn-cyan', mode === 'terminal');

  if (tableCont) tableCont.style.display = mode === 'table' ? 'block' : 'none';
  if (termCont) termCont.style.display = mode === 'terminal' ? 'block' : 'none';

  if (mode === 'terminal') {
    renderTerminalLogs();
  } else {
    renderLogsTable();
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

  if (viewName === 'suspicious') {
    renderSuspiciousTable();
  } else if (viewName === 'ips') {
    renderIpsTable();
  }

  const modeToggle = document.getElementById('eventsViewModeToggle');
  if (modeToggle) {
    modeToggle.style.display = viewName === 'events' ? 'flex' : 'none';
  }
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

  tbody.innerHTML = paged.map((log) => {
    const logIdStr = escapeHtml(String(log.id || ''));
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

    let actionTag = `<span class="pixel-tag" style="font-size: 8px; margin-left: 2px;">${escapeHtml(action)}</span>`;
    const code = log.statusCode || (log.raw && (log.raw.status_code || log.raw.statusCode));
    if (code && typeof getHttpStatusTag === 'function') {
      actionTag = getHttpStatusTag(code, log.method);
    } else if (badge === 'WEB' && action) {
      const m = action.match(/\b([1-5][0-9]{2})\b/);
      if (m && typeof getHttpStatusTag === 'function') {
        const methodMatch = action.match(/^([A-Z]{3,7})/);
        actionTag = getHttpStatusTag(m[1], methodMatch ? methodMatch[1] : null);
      }
    } else if (action === 'SUCCESS') {
      actionTag = `<span class="pixel-tag tag-clean" style="font-size: 8px; margin-left: 2px;">SUCCESS</span>`;
    } else if (action === 'BLOCK' || action === 'BAN' || action === 'DROP') {
      actionTag = `<span class="pixel-tag tag-critical" style="font-size: 8px; margin-left: 2px;">${escapeHtml(action)}</span>`;
    } else if (action === 'FAILED') {
      actionTag = `<span class="pixel-tag tag-warning" style="font-size: 8px; margin-left: 2px;">FAILED</span>`;
    }

    return `
      <tr>
        <td style="white-space: nowrap;">${time}</td>
        <td><code>${ip}</code></td>
        <td>${agent}</td>
        <td>${lvlTag}</td>
        <td style="white-space: nowrap;">
          <span class="pixel-tag tag-cyan">${badge}</span>
          ${actionTag}
        </td>
        <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(signature)}">
          ${escapeHtml(signature)}
        </td>
        <td><span class="pixel-tag tag-purple">${mitre}</span></td>
        <td>
          <button class="pixel-btn pixel-btn-sm pixel-btn-cyan" data-log-id="${logIdStr}" onclick="inspectLogById(this.dataset.logId)">INSPECT</button>
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
  renderTerminalLogs();
}

/** Incoming SSE Security Log */
function handleIncomingSecurityLog(normLog) {
  if (!normLog) return;
  if (!normLog.id) {
    normLog.id = 'seq_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
  }
  allLogs.unshift(normLog);
  if (allLogs.length > 500) allLogs.pop();

  const countBadge = document.getElementById('logsEventCountBadge');
  if (countBadge) countBadge.textContent = `${allLogs.length} EVENTS`;
  const countSub = document.getElementById('countSubEvents');
  if (countSub) countSub.textContent = String(allLogs.length);

  if (!isLivePaused) {
    renderTerminalLogs();
    if (currentPage === 1) renderLogsTable();
  }

  if (Number(normLog.level || 0) >= 7) {
    renderSuspiciousTable();
  }
}

const MAX_IPS = 1000;

/** Incoming SSE IP Update */
function handleIncomingIpUpdate(ipRec) {
  if (!ipRec || !ipRec.ip) return;
  const existingIdx = allIps.findIndex(i => i.ip === ipRec.ip);
  if (existingIdx >= 0) {
    allIps[existingIdx] = ipRec;
  } else {
    allIps.unshift(ipRec);
    if (allIps.length > MAX_IPS) {
      allIps.length = MAX_IPS;
    }
  }

  const countIps = document.getElementById('countSubIps');
  if (countIps) countIps.textContent = String(allIps.length);

  renderIpsTable();
  renderSuspiciousTable();
}

/** Helper to convert 2-letter ISO country code to emoji flag */
function getCountryFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt());
  return String.fromCodePoint(...codePoints);
}

/** Helper untuk mem-parsing status ancaman (menerima string 'Critical'/'Suspicious' maupun angka 12/7) */
function parseThreatInfo(item, logsByIp = null) {
  if (!item) return { isThreat: false, isCritical: false, isSuspicious: false, level: 1 };

  const rawThreat = String(item.threat_level || item.severity || '').toLowerCase();
  const numThreat = Number(item.threat_level || item.severity || 0);

  let isCritical = false;
  let isSuspicious = false;
  let numericLevel = 1;

  if (rawThreat.includes('crit') || rawThreat.includes('attack') || numThreat >= 10) {
    isCritical = true;
    numericLevel = numThreat >= 10 ? numThreat : 12;
  } else if (rawThreat.includes('susp') || rawThreat.includes('warn') || numThreat >= 7) {
    isSuspicious = true;
    numericLevel = numThreat >= 7 ? numThreat : 7;
  }

  // Cross-reference dengan logs untuk mendeteksi event dengan severity >= 7
  const ip = item.ip || item.source_ip;
  if (ip) {
    if (logsByIp) {
      const entry = logsByIp.get(ip);
      if (entry && entry.maxLevel >= 7) {
        if (entry.maxLevel >= 10) {
          isCritical = true;
          numericLevel = Math.max(numericLevel, entry.maxLevel);
        } else if (!isCritical) {
          isSuspicious = true;
          numericLevel = Math.max(numericLevel, entry.maxLevel);
        }
      }
    } else if (Array.isArray(allLogs)) {
      const matchLog = allLogs.find(l => (l.source_ip || l.ip) === ip && Number(l.level || 0) >= 7);
      if (matchLog) {
        const logLvl = Number(matchLog.level || 0);
        if (logLvl >= 10) {
          isCritical = true;
          numericLevel = Math.max(numericLevel, logLvl);
        } else if (!isCritical) {
          isSuspicious = true;
          numericLevel = Math.max(numericLevel, logLvl);
        }
      }
    }
  }

  return {
    isThreat: isCritical || isSuspicious,
    isCritical,
    isSuspicious,
    level: numericLevel
  };
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

  const total = filtered.length;
  const totalPages = Math.ceil(total / ipPageSize) || 1;
  if (currentIpPage > totalPages) currentIpPage = totalPages;
  if (currentIpPage < 1) currentIpPage = 1;

  const start = (currentIpPage - 1) * ipPageSize;
  const paged = filtered.slice(start, start + ipPageSize);

  const infoEl = document.getElementById('ipsPaginationInfo');
  if (infoEl) infoEl.textContent = `Menampilkan ${total > 0 ? start + 1 : 0} s.d. ${Math.min(start + ipPageSize, total)} dari ${total} IP`;

  if (total === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">Tidak ada IP yang terdeteksi.</td></tr>`;
    renderIpPaginationControls(total);
    return;
  }

  // Pre-index logs by IP for O(1) threatInfo lookups
  const logsByIp = new Map();
  if (Array.isArray(allLogs)) {
    for (let i = 0; i < allLogs.length; i++) {
      const l = allLogs[i];
      const ip = l.source_ip || l.ip;
      if (!ip) continue;
      let entry = logsByIp.get(ip);
      if (!entry) {
        entry = { maxLevel: 0, threatLog: null, attackDesc: '' };
        logsByIp.set(ip, entry);
      }
      const lvl = Number(l.level || 0);
      if (lvl > entry.maxLevel) entry.maxLevel = lvl;
    }
  }

  tbody.innerHTML = paged.map(item => {
    const ip = item.ip || item.source_ip || '-';
    const node = item.node || item.hostname || 'Cluster';
    const cat = item.category || 'HTTP Web';
    const hits = item.request_count || item.hits || 1;
    const first = formatDateTime(item.first_seen);
    const last = formatDateTime(item.last_seen || item.timestamp);
    const threatInfo = parseThreatInfo(item, logsByIp);

    const country = item.country || 'Indonesia';
    const countryCode = item.country_code || 'ID';
    const flag = getCountryFlag(countryCode);
    const city = item.city || '';
    const isp = item.isp || '';
    const geoInfo = [city, country, isp].filter(Boolean).join(' • ');

    const threatTag = threatInfo.isCritical ?
      `<span class="pixel-tag tag-critical">CRIT ${threatInfo.level}</span>` :
      threatInfo.isSuspicious ?
      `<span class="pixel-tag tag-warning">WARN ${threatInfo.level}</span>` :
      `<span class="pixel-tag tag-clean">CLEAN</span>`;

    const isBlocked = item.is_blocked || (item.status && item.status.toLowerCase().includes('block'));

    return `
      <tr>
        <td style="white-space: nowrap;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <strong><code>${ip}</code></strong>
            <span class="pixel-tag tag-clean" style="font-size: 8px; font-weight: normal; padding: 2px 5px;" title="${escapeHtml(geoInfo)}">
              ${flag} ${escapeHtml(country)}
            </span>
          </div>
          ${city ? `<div style="font-size: 8px; color: #64748B; margin-top: 3px; font-family: var(--font-pixel);">${escapeHtml(city)}${isp ? ` • ${escapeHtml(isp)}` : ''}</div>` : ''}
        </td>
        <td>${node}</td>
        <td><span class="pixel-tag tag-cyan">${cat}</span></td>
        <td><strong>${hits}</strong></td>
        <td>${first}</td>
        <td>${last}</td>
        <td>${threatTag}</td>
        <td style="white-space: nowrap;">
          <div style="display: flex; gap: 4px; align-items: center;">
            <button class="pixel-btn pixel-btn-sm pixel-btn-cyan" onclick="inspectIp('${escapeHtml(ip)}')" title="Inspect rincian payload data IP &amp; Geo-telemetri">
              🔍 INSPECT
            </button>
            ${isBlocked ?
              `<button class="pixel-btn pixel-btn-sm pixel-btn-cyan" onclick="unblockIpAction('${escapeHtml(ip)}', '${escapeHtml(node)}')" title="Buka blokir iptables DROP">🔓 UNBLOCK</button>` :
              `<button class="pixel-btn pixel-btn-sm pixel-btn-danger" onclick="blockIpAction('${escapeHtml(ip)}', '${escapeHtml(node)}')" title="Terapkan firewall drop iptables pada IP ini">🛡️ BLOCK IP</button>`
            }
          </div>
        </td>
      </tr>
    `;
  }).join('');

  renderIpPaginationControls(total);
}

function renderIpPaginationControls(total) {
  const controlsEl = document.getElementById('ipsPaginationControls');
  if (!controlsEl) return;
  const totalPages = Math.ceil(total / ipPageSize) || 1;

  controlsEl.innerHTML = `
    <button class="pixel-btn pixel-btn-sm" ${currentIpPage <= 1 ? 'disabled' : ''} onclick="changeIpPage(${currentIpPage - 1})">&laquo; PREV</button>
    <span style="font-family: var(--font-pixel); font-size: 8px; padding: 0 6px;">HALAMAN ${currentIpPage} / ${totalPages}</span>
    <button class="pixel-btn pixel-btn-sm" ${currentIpPage >= totalPages ? 'disabled' : ''} onclick="changeIpPage(${currentIpPage + 1})">NEXT &raquo;</button>
  `;
}

function changeIpPage(p) {
  currentIpPage = p;
  renderIpsTable();
}

function applyIpFilters() {
  const input = document.getElementById('ipSearchInput');
  ipSearchQuery = input ? input.value.trim() : '';
  currentIpPage = 1;
  renderIpsTable();
}

/** Render Tabel Suspicious Watchlist */
function renderSuspiciousTable() {
  const tbody = document.getElementById('suspiciousTableBody');
  const countThreats = document.getElementById('countSubThreats');

  // Pre-index logs by IP for O(1) lookups instead of nested O(N x M) scans
  const logsByIp = new Map();
  if (Array.isArray(allLogs)) {
    for (let i = 0; i < allLogs.length; i++) {
      const l = allLogs[i];
      const ip = l.source_ip || l.ip;
      if (!ip) continue;
      let entry = logsByIp.get(ip);
      if (!entry) {
        entry = { maxLevel: 0, threatLog: null, attackDesc: '' };
        logsByIp.set(ip, entry);
      }
      const lvl = Number(l.level || 0);
      if (lvl > entry.maxLevel) entry.maxLevel = lvl;
      if (lvl >= 7 && (!entry.threatLog || lvl > Number(entry.threatLog.level || 0))) {
        entry.threatLog = l;
      }
      if ((lvl >= 7 || !entry.attackDesc) && (l.mitre_technique || l.rule_desc || l.rule_id)) {
        entry.attackDesc = l.mitre_technique || l.rule_desc || l.rule_id;
      }
    }
  }

  const seenIps = new Set();
  const suspiciousList = [];

  // 1. Ambil semua IP yang tergolong threat dari allIps via pre-indexed lookup
  allIps.forEach(ipItem => {
    const info = parseThreatInfo(ipItem, logsByIp);
    if (info.isThreat) {
      const ip = ipItem.ip || ipItem.source_ip;
      if (ip && !seenIps.has(ip)) {
        seenIps.add(ip);
        suspiciousList.push({
          ...ipItem,
          threatInfo: info
        });
      }
    }
  });

  // 2. Kumpulkan juga IP dari logsByIp yang memiliki severity >= 7 jika belum ada di suspiciousList
  logsByIp.forEach((entry, srcIp) => {
    if (entry.maxLevel >= 7 && !seenIps.has(srcIp)) {
      seenIps.add(srcIp);
      const log = entry.threatLog || {};
      const lvl = entry.maxLevel;
      suspiciousList.push({
        ip: srcIp,
        node: log.agent || log.hostname || 'ubuntu-3',
        hostname: log.agent || log.hostname || 'ubuntu-3',
        suspected_attack: entry.attackDesc || 'T1110.001 Brute Force',
        request_count: 1,
        threat_level: lvl >= 10 ? 'Critical' : 'Suspicious',
        threatInfo: {
          isThreat: true,
          isCritical: lvl >= 10,
          isSuspicious: lvl < 10,
          level: lvl
        },
        country: 'Inbound Threat',
        country_code: 'XX',
        city: '',
        isp: ''
      });
    }
  });

  // Update Badge Counter di Tab Header
  if (countThreats) countThreats.textContent = String(suspiciousList.length);

  if (!tbody) return;

  if (suspiciousList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 20px;">Sistem bersih — Tidak ada ancaman aktif severity &ge; 7.</td></tr>`;
    return;
  }

  tbody.innerHTML = suspiciousList.map(item => {
    const ip = item.ip || item.source_ip || '-';
    const host = item.node || item.hostname || 'Monitored Node';
    const hits = item.request_count || item.hits || 1;
    const threatInfo = item.threatInfo || parseThreatInfo(item, logsByIp);

    // Cari signature serangan dan MITRE dari pre-indexed map
    let attack = item.suspected_attack;
    if (!attack) {
      const entry = logsByIp.get(ip);
      if (entry && entry.attackDesc) {
        attack = entry.attackDesc;
      }
    }
    if (!attack) attack = threatInfo.isCritical ? 'T1110.001 Brute Force' : 'Suspicious Probe';

    const isContained = item.is_blocked || (item.status && item.status.toLowerCase().includes('block'));
    const contained = isContained ?
      '<span class="pixel-tag tag-clean">CONTAINED</span>' :
      '<span class="pixel-tag tag-critical">ACTIVE DROP PENDING</span>';

    const country = item.country || 'Inbound Host';
    const countryCode = item.country_code || 'ID';
    const flag = getCountryFlag(countryCode);
    const city = item.city || '';
    const isp = item.isp || '';

    const badgeClass = threatInfo.isCritical ? 'tag-critical' : 'tag-warning';

    return `
      <tr>
        <td style="white-space: nowrap;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <strong><code>${ip}</code></strong>
            <span class="pixel-tag tag-clean" style="font-size: 8px; font-weight: normal; padding: 2px 5px;">
              ${flag} ${escapeHtml(country)}
            </span>
          </div>
          ${city ? `<div style="font-size: 8px; color: #64748B; margin-top: 3px; font-family: var(--font-pixel);">${escapeHtml(city)}${isp ? ` • ${escapeHtml(isp)}` : ''}</div>` : ''}
        </td>
        <td>${host}</td>
        <td><span class="pixel-tag tag-purple">${escapeHtml(attack)}</span></td>
        <td>${hits}</td>
        <td><span class="pixel-tag ${badgeClass}">LVL ${threatInfo.level}</span></td>
        <td>${contained}</td>
        <td style="white-space: nowrap;">
          <div style="display: flex; gap: 4px; align-items: center;">
            <button class="pixel-btn pixel-btn-sm pixel-btn-cyan" onclick="inspectIp('${escapeHtml(ip)}')" title="Inspect rincian threat telemetri">
              🔍 INSPECT
            </button>
            ${isContained ?
              `<button class="pixel-btn pixel-btn-sm pixel-btn-cyan" onclick="unblockIpAction('${escapeHtml(ip)}', '${escapeHtml(host)}')" title="Buka blokir firewall kernel iptables">🔓 UNBLOCK</button>` :
              `<button class="pixel-btn pixel-btn-sm pixel-btn-danger" onclick="blockIpAction('${escapeHtml(ip)}', '${escapeHtml(host)}')" title="Terapkan firewall drop iptables pada simpul target">🛡️ DROP IPTABLES</button>`
            }
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function blockIpAction(ip, node) {
  if (!confirm(`Konfirmasi Zero-Trust: Apakah Anda yakin ingin memblokir IP ${ip} via firewall iptables DROP pada simpul cluster?`)) return;

  try {
    const res = await authFetch('/api/v1/containment/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip, node: node || '', reason: 'Zero-Trust PEP Admin Action' })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Gagal memblokir IP.');

    let details = '';
    if (data.results && Object.keys(data.results).length > 0) {
      details = '\n\nHasil eksekusi pada simpul agen:\n' + Object.entries(data.results).map(([k, v]) => `• [${k}]: ${v}`).join('\n');
    }
    alert(`Berhasil: Aturan iptables DROP untuk IP ${ip} telah diaktifkan!${details}`);
    reloadLogsData();
  } catch (err) {
    alert(`Gagal memblokir: ${err.message}`);
  }
}

async function unblockIpAction(ip, node) {
  if (!confirm(`Konfirmasi Zero-Trust: Apakah Anda yakin ingin mencabut blokir iptables DROP untuk IP ${ip}?`)) return;

  try {
    const res = await authFetch('/api/v1/containment/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip, node: node || '' })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Gagal membuka blokir IP.');

    let details = '';
    if (data.results && Object.keys(data.results).length > 0) {
      details = '\n\nHasil eksekusi pada simpul agen:\n' + Object.entries(data.results).map(([k, v]) => `• [${k}]: ${v}`).join('\n');
    }
    alert(`Berhasil: Blokir iptables DROP untuk IP ${ip} telah dicabut!${details}`);
    reloadLogsData();
  } catch (err) {
    alert(`Gagal membuka blokir: ${err.message}`);
  }
}

// ==========================================================================
// RAW NDJSON & TELEMETRY INSPECTOR MODAL
// ==========================================================================
let currentInspectedJson = '';

function inspectLogById(logId) {
  let log = allLogs.find(l => String(l.id) === String(logId));
  if (!log) {
    const num = Number(logId);
    if (!isNaN(num) && allLogs[num]) {
      log = allLogs[num];
    }
  }
  if (!log) return;
  currentInspectedJson = JSON.stringify(log.raw || log, null, 2);
  const title = document.getElementById('jsonModalTitle');
  if (title) title.textContent = 'RAW NDJSON LOG INSPECTOR';
  const modal = document.getElementById('jsonModal');
  const pre = document.getElementById('modalJsonContent');
  if (pre) pre.textContent = currentInspectedJson;
  if (modal) modal.classList.remove('hidden');
}
window.inspectLogById = inspectLogById;

function inspectLog(idxOrId) {
  inspectLogById(idxOrId);
}
window.inspectLog = inspectLog;

function inspectIp(ipAddress) {
  const ipRec = allIps.find(i => (i.ip || i.source_ip) === ipAddress);
  if (!ipRec) {
    alert(`Data IP ${ipAddress} tidak ditemukan.`);
    return;
  }
  currentInspectedJson = JSON.stringify(ipRec, null, 2);
  const title = document.getElementById('jsonModalTitle');
  if (title) title.textContent = `INSPECT IP TELEMETRY LEDGER — [ ${ipAddress} ]`;
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
