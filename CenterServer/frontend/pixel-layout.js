// ==========================================================================
// PIXEL-SKY OS SHARED LAYOUT & ROUTE CONTROLLER
// Top HUD Address Bar, Horizontal Route Tabs, Quest Banner, Left Sidebar
// ==========================================================================

const AUTH_KEYS = ['auth_token', 'auth_user', 'auth_role'];
const LOGIN_URL = '/login.html';

function decodeJwtPayload(t) {
  try {
    const b = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const pad = b + '='.repeat((4 - (b.length % 4)) % 4);
    const raw = atob(pad);
    let out = '';
    for (let i = 0; i < raw.length; i++) {
      out += '%' + ('00' + raw.charCodeAt(i).toString(16)).slice(-2);
    }
    return JSON.parse(decodeURIComponent(out));
  } catch (_) {
    return null;
  }
}

function getValidToken() {
  const t = localStorage.getItem('auth_token');
  if (!t) return null;
  const p = decodeJwtPayload(t);
  if (!p) return null;
  if (typeof p.exp === 'number' && p.exp * 1000 <= Date.now()) return null;
  return t;
}

function clearSession() {
  AUTH_KEYS.forEach(k => localStorage.removeItem(k));
}

function redirectToLogin(reason) {
  clearSession();
  window.location.replace(LOGIN_URL + (reason ? '?reason=' + reason : ''));
}

function authHeaders(extra) {
  const t = getValidToken();
  const h = Object.assign({}, extra || {});
  if (t) h['Authorization'] = 'Bearer ' + t;
  return h;
}

async function authFetch(url, options) {
  const opts = Object.assign({}, options || {});
  opts.headers = authHeaders(opts.headers);
  const res = await fetch(url, opts);
  if (res.status === 401) {
    try {
      const clone = res.clone();
      const body = await clone.json();
      // Jangan logout otomatis jika status 401 bukan karena JWT session (misal invalid agent key)
      if (body && body.error && typeof body.error === 'string' && body.error.toLowerCase().includes('agent key')) {
        return res;
      }
    } catch (_) {}
    redirectToLogin('expired');
    throw new Error('Sesi berakhir, silakan login ulang.');
  }
  return res;
}

function handleLogout() {
  try {
    if (window.__pixelSSE) window.__pixelSSE.close();
  } catch (_) {}
  clearSession();
  window.location.replace(LOGIN_URL + '?reason=logout');
}

function formatDateTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '-';
  const hours = String(d.getHours()).padStart(2, '0');
  const mins = String(d.getMinutes()).padStart(2, '0');
  const secs = String(d.getSeconds()).padStart(2, '0');
  return `[${hours}:${mins}:${secs}]`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const KNOWN_PORTS = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
  587: 'Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
  1521: 'Oracle', 3306: 'MySQL', 5432: 'Postgres', 6379: 'Redis',
  8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
  9200: 'Elastic', 27017: 'MongoDB'
};

function parseLogCategoryAndDetails(item) {
  const service = (item.service || item.program || '').toLowerCase();
  const eventType = (item.event_type || '').toLowerCase();
  const status = (item.status || '').toLowerCase();
  const rawMsg = item.message || item.rule_desc || item.desc || item.endpoint || item.command || '';
  const msgLower = rawMsg.toLowerCase();

  let category = 'SYS';
  let categoryLabelShort = 'SYS';
  let actionLabel = 'EVENT';
  let summaryText = rawMsg || 'Log transaction recorded';

  if (service.includes('ufw') || msgLower.includes('ufw block') || status.includes('ufw block')) {
    category = 'UFW';
    categoryLabelShort = 'UFW';
    actionLabel = 'BLOCK';
    summaryText = rawMsg || `UFW BLOCK packet dropped by kernel firewall filter`;
  } else if (service.includes('fail2ban') || msgLower.includes('ban ')) {
    category = 'FAIL2BAN';
    categoryLabelShort = 'F2B';
    actionLabel = 'BAN';
    summaryText = rawMsg || `Fail2ban active jail ban triggered`;
  } else if (eventType === 'web_attack' || msgLower.includes('union select') || msgLower.includes('<script')) {
    category = 'ATTACK';
    categoryLabelShort = 'ATTACK';
    actionLabel = 'SQLi/XSS';
    summaryText = rawMsg || `Web Attack: Anomaly pattern detected`;
  } else if (eventType === 'auth_failure' || msgLower.includes('failed password') || msgLower.includes('authentication failure')) {
    category = 'SPAM';
    categoryLabelShort = 'AUTH';
    actionLabel = 'FAILED';
    const user = item.user || 'root';
    summaryText = rawMsg || `Failed password for user "${user}" on Port 22`;
  } else if (eventType === 'auth_success' || msgLower.includes('accepted password') || msgLower.includes('accepted publickey')) {
    category = 'AUTH';
    categoryLabelShort = 'AUTH';
    actionLabel = 'SUCCESS';
    summaryText = rawMsg || `Authentication accepted on host`;
  } else if (msgLower.includes('cron') || service.includes('cron')) {
    category = 'CRON';
    categoryLabelShort = 'CRON';
    actionLabel = 'EXEC';
    summaryText = rawMsg;
  } else if (service.includes('ssh') || msgLower.includes('sshd')) {
    category = 'AUTH';
    categoryLabelShort = 'SSH';
    actionLabel = 'SESSION';
    summaryText = rawMsg;
  } else if (service.includes('nginx') || service.includes('web') || service.includes('apache') || msgLower.includes('http/1.') || msgLower.includes('http/2') || item.endpoint || item.method) {
    category = 'WEB';
    categoryLabelShort = 'WEB';
    
    let method = (item.method || '').toUpperCase();
    let endpoint = item.endpoint || '';
    let code = item.status_code || item.statusCode || item.status;

    if (rawMsg) {
      // Format Nginx/Apache: "METHOD /path HTTP/x.x" CODE
      const match = rawMsg.match(/"([A-Z]{3,7})\s+([^\s"]+)\s+HTTP\/[0-9.]+"\s+(\d{3})\b/);
      if (match) {
        if (!method) method = match[1];
        if (!endpoint) endpoint = match[2];
        if (!code) code = parseInt(match[3], 10);
      } else {
        const mStatus = rawMsg.match(/"\s+(\d{3})\b/) || rawMsg.match(/\bstatus[:\s=]+(\d{3})\b/i);
        if (!code && mStatus) {
          code = parseInt(mStatus[1], 10);
        }
      }
    }

    if (!method) method = 'GET';
    if (!endpoint) endpoint = '/';
    code = parseInt(code, 10) || 200;

    actionLabel = `${method} ${code}`;
    summaryText = rawMsg || `HTTP ${method} ${endpoint} — Status ${code}`;

    return {
      category,
      categoryLabelShort,
      actionLabel,
      statusCode: code,
      method,
      endpoint,
      summaryText
    };
  } else {
    category = 'SYS';
    categoryLabelShort = 'SYS';
    actionLabel = 'EVENT';
    summaryText = rawMsg || (item.event_type ? `System ${item.event_type} event` : 'System event recorded');
  }

  return {
    category,
    categoryLabelShort,
    actionLabel,
    statusCode: null,
    method: null,
    endpoint: null,
    summaryText
  };
}

/** Helper untuk merender Badge Status HTTP (200 - 504) dengan warna standar SOC */
function getHttpStatusTag(statusCode, method) {
  const code = parseInt(statusCode, 10);
  if (isNaN(code)) return '';

  let colorClass = 'tag-http-2xx';
  let desc = 'OK';

  if (code >= 500 && code <= 504) {
    colorClass = 'tag-http-5xx';
    desc = code === 500 ? 'INTERNAL ERROR' : code === 502 ? 'BAD GATEWAY' : code === 504 ? 'GATEWAY TIMEOUT' : 'SERVER ERROR';
  } else if (code >= 500) {
    colorClass = 'tag-http-5xx';
    desc = 'SERVER ERROR';
  } else if (code >= 400 && code <= 499) {
    colorClass = 'tag-http-4xx';
    desc = code === 400 ? 'BAD REQUEST' : code === 401 ? 'UNAUTHORIZED' : code === 403 ? 'FORBIDDEN' : code === 404 ? 'NOT FOUND' : code === 429 ? 'RATE LIMITED' : 'CLIENT ERROR';
  } else if (code >= 300 && code <= 399) {
    colorClass = 'tag-http-3xx';
    desc = code === 301 ? 'MOVED' : code === 304 ? 'NOT MODIFIED' : 'REDIRECT';
  } else if (code >= 200 && code <= 299) {
    colorClass = 'tag-http-2xx';
    desc = code === 200 ? 'OK' : code === 201 ? 'CREATED' : code === 204 ? 'NO CONTENT' : 'SUCCESS';
  }

  const methodPrefix = method ? `<span style="opacity: 0.85; margin-right: 3px; font-weight: normal;">${escapeHtml(method)}</span>` : '';
  return `<span class="pixel-tag ${colorClass}" title="HTTP ${code} ${desc}">${methodPrefix}${code}</span>`;
}

let logSeqCounter = 0;
function normalizeLogItem(item) {
  if (!item) return null;
  const rawMsg = item.message || item.rule_desc || item.desc || item.endpoint || item.command || '';
  if (!rawMsg && !item.rule_id) return null;

  const parsed = parseLogCategoryAndDetails(item);
  const severity = item.severity || (parsed.category === 'SPAM' ? 7 : parsed.category === 'ATTACK' ? 10 : 1);
  const mitre = item.mitre_id || item.mitre_technique || (severity >= 10 ? 'T1110 (Brute Force)' : severity >= 7 ? 'T1595 (Scan)' : 'T1082 (Telemetry)');
  const hostname = item.hostname || item.agent_id || 'node';

  return {
    id: ++logSeqCounter,
    timestamp: item.timestamp || new Date().toISOString(),
    source_ip: item.source_ip || item.client_ip || item.ip || '127.0.0.1',
    agent: hostname,
    level: severity,
    category: parsed.categoryLabelShort,
    action: parsed.actionLabel,
    statusCode: parsed.statusCode,
    method: parsed.method,
    endpoint: parsed.endpoint,
    desc: parsed.summaryText,
    mitre: mitre,
    raw: item
  };
}

window.escapeHtml = escapeHtml;
window.parseLogCategoryAndDetails = parseLogCategoryAndDetails;
window.normalizeLogItem = normalizeLogItem;
window.getHttpStatusTag = getHttpStatusTag;

// Guard
const validToken = getValidToken();
if (!validToken && !window.location.pathname.endsWith('login.html')) {
  redirectToLogin('no_token');
}

const currentUser = localStorage.getItem('auth_user') || 'Analyst';
const currentRole = (localStorage.getItem('auth_role') || 'analyst').toLowerCase();

// Navigation Definitions
const ROUTES = [
  { path: '/dashboard', label: 'DASHBOARD', icon: '::', file: 'dashboard.html', aliases: ['/', '/index.html'] },
  { path: '/analytics', label: 'ANALYTICS', icon: '||', file: 'status.html', aliases: ['/status'] },
  { path: '/logs', label: 'AUDIT LOGS', icon: '📜', file: 'logs.html', aliases: [] },
  { path: '/settings', label: 'SETTINGS', icon: '⚙️', file: 'settings.html', aliases: [] }
];

function isPathActive(route, currentPath) {
  if (route.path === currentPath) return true;
  if (route.aliases && route.aliases.includes(currentPath)) return true;
  return false;
}

function getActiveRoute(currentPath) {
  return ROUTES.find(r => isPathActive(r, currentPath)) || ROUTES[0];
}

/** 1. Render Topbar Header (Clean Corporate Neo-Brutalist HUD) */
function mountTopHUD() {
  const hudEl = document.getElementById('shared-hud');
  if (!hudEl) return;
  const currentPath = window.location.pathname;
  const activeRoute = getActiveRoute(currentPath);

  hudEl.className = 'pixel-hud';
  hudEl.innerHTML = `
    <!-- Left Corporate Identity -->
    <div class="hud-left">
      <div class="hud-shield-box">🛡️</div>
      <div class="hud-title-col">
        <div class="hud-title-row">
          <span class="hud-os-title">CORP-SOC SIEM</span>
          <span class="hud-os-ver">v2.4</span>
          <span class="hud-badge-ready">SLA 99.98% OPTIMAL</span>
        </div>
        <span class="hud-sla-text">Enterprise Continuous Monitoring &amp; Zero-Trust Telemetry</span>
      </div>
    </div>

    <!-- Center Address Bar (Active Endpoint & Route Name) -->
    <div class="hud-center-address">
      <span class="hud-address-globe">🌐</span>
      <span class="hud-address-path-pill" style="font-size: 11px; padding: 2px 8px; font-weight: 800;">${activeRoute.path}</span>
      <span class="hud-address-url" style="color: #0F172A; font-weight: 800; font-size: 11px; margin-left: 4px;">${activeRoute.label}</span>
      <span class="hud-address-file" style="color: #10B981; font-weight: 700; font-size: 10px;">● ACTIVE</span>
    </div>

    <!-- Right Corporate Actions -->
    <div class="hud-right">
      <div class="hud-clock-box" id="hudClock">
        <span>⏱️</span>
        <span id="hudClockText">--:--:--</span>
      </div>
      <button class="hud-btn hud-btn-sync" onclick="window.location.reload()">
        SYNC DATA
      </button>
      <button class="hud-btn hud-btn-prompt" onclick="window.location.href='/settings'">
        SYS CONFIG
      </button>
    </div>
  `;

  // Live Clock Ticker
  const updateClock = () => {
    const el = document.getElementById('hudClockText');
    if (!el) return;
    const now = new Date();
    el.textContent = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')} WIB`;
  };
  updateClock();
  setInterval(updateClock, 1000);
}

/** 2. Render Horizontal Route Tabs */
function mountHorizontalRouteTabs() {
  const tabsEl = document.getElementById('shared-route-tabs');
  if (!tabsEl) return;
  const currentPath = window.location.pathname;

  tabsEl.className = 'pixel-route-tabs';
  tabsEl.innerHTML = ROUTES.map(r => {
    const isActive = isPathActive(r, currentPath);
    return `
      <a href="${r.path}" class="route-tab-btn ${isActive ? 'active' : ''}">
        <span>${r.icon}</span>
        <span>${r.label}</span>
        <span class="route-tab-pill">${r.path}</span>
      </a>
    `;
  }).join('');
}

/** 3. Quest Banner (Disabled for Clean Corporate Look) */
function mountQuestBanner() {
  const bannerEl = document.getElementById('shared-quest-banner');
  if (!bannerEl) return;
  bannerEl.style.display = 'none';
}

/** 4. Render Left Sidebar */
function mountLeftSidebar() {
  const sidebarEl = document.getElementById('shared-sidebar');
  if (!sidebarEl) return;
  const currentPath = window.location.pathname;
  const activeRoute = getActiveRoute(currentPath);

  sidebarEl.innerHTML = `
    <!-- Card 1: MENU NAVIGASI (System Routing) -->
    <div class="island-card">
      <div class="island-grass-cap"></div>
      <div class="island-header-bar">
        <div class="island-header-title">
          <span>::</span>
          <div>
            <div>MENU NAVIGASI</div>
            <span class="island-header-sub">System Routing</span>
          </div>
        </div>
        <div class="window-dots">
          <div class="window-dot"></div>
          <div class="window-dot"></div>
          <div class="window-dot"></div>
        </div>
      </div>
      <div class="island-body">
        <div class="sidebar-menu-list">
          ${ROUTES.map(r => {
            const isActive = isPathActive(r, currentPath);
            return `
              <a href="${r.path}" class="sidebar-nav-btn ${isActive ? 'active' : ''}">
                <span>${r.icon} ${r.label}</span>
                <span>&gt;</span>
              </a>
            `;
          }).join('')}
        </div>

        <div class="route-status-box">
          <div class="route-status-title">
            <span>⚡</span>
            <span>STATUS STRUKTUR PATH:</span>
          </div>
          <div>Terpisah per route modular. Route aktif:</div>
          <span class="route-status-pill">${activeRoute.path}</span>
        </div>
      </div>
      <div class="island-dirt-crust"></div>
    </div>

    <!-- Card 2: QUICK ACTIONS (System Control) -->
    <div class="island-card">
      <div class="island-grass-cap"></div>
      <div class="island-header-bar">
        <div class="island-header-title">
          <span>✦</span>
          <div>
            <div>QUICK ACTIONS</div>
            <span class="island-header-sub">System Control</span>
          </div>
        </div>
        <div class="window-dots">
          <div class="window-dot"></div>
          <div class="window-dot"></div>
          <div class="window-dot"></div>
        </div>
      </div>
      <div class="island-body">
        <div class="cmd-btn-row">
          <button class="pixel-cmd-btn pixel-cmd-green" onclick="window.location.href='/analytics'">
            + PROBE ALL NODES
          </button>
          <button class="pixel-cmd-btn pixel-cmd-cyan" onclick="window.location.href='/logs'">
            ❐ EXPORT AUDIT LOGS
          </button>
        </div>
      </div>
      <div class="island-dirt-crust"></div>
    </div>
  `;
}

/** Reusable <IslandCard /> component builder */
function createIslandCard(title, subtitle, contentHtml, badge = '') {
  const badgeHtml = badge ? `<span class="pixel-tag tag-cyan">${escapeHtml(badge)}</span>` : '';
  return `
    <div class="island-card">
      <div class="island-grass-cap"></div>
      <div class="island-header-bar">
        <div class="island-header-title">
          <span>::</span>
          <div>
            <div>${escapeHtml(title)}</div>
            ${subtitle ? `<span class="island-header-sub">${escapeHtml(subtitle)}</span>` : ''}
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 6px;">
          ${badgeHtml}
          <div class="window-dots">
            <div class="window-dot"></div>
            <div class="window-dot"></div>
            <div class="window-dot"></div>
          </div>
        </div>
      </div>
      <div class="island-body">
        ${contentHtml}
      </div>
      <div class="island-dirt-crust"></div>
    </div>
  `;
}
window.createIslandCard = createIslandCard;

/** 5. Render Active Route Strip */
function mountActiveRouteStrip(name, path, desc) {
  const stripEl = document.getElementById('active-route-strip');
  if (!stripEl) return;

  stripEl.className = 'active-route-strip';
  stripEl.innerHTML = `
    <div class="active-route-left">
      <div class="active-route-badge-row">
        <span class="active-route-tag">ACTIVE ROUTE</span>
        <span class="active-route-name">${name} (${path})</span>
      </div>
      <span class="active-route-desc">${desc}</span>
    </div>
    <div class="active-route-filter-pills">
      <button class="filter-pill-btn time-range-pill" data-range="7D" onclick="if(window.setTimeRange) setTimeRange('7D')">7D</button>
      <button class="filter-pill-btn time-range-pill" data-range="30D" onclick="if(window.setTimeRange) setTimeRange('30D')">30D</button>
      <button class="filter-pill-btn time-range-pill active" data-range="12M" onclick="if(window.setTimeRange) setTimeRange('12M')">12M</button>
    </div>
  `;
}

/** SSE Setup */
function initGlobalSSE() {
  const token = getValidToken();
  if (!token) return;

  // Close existing SSE connection before opening a new one
  if (window.__pixelSSE) {
    try {
      window.__pixelSSE.close();
    } catch (_) {}
    window.__pixelSSE = null;
  }

  const streamUrl = `/api/v1/stream?token=${encodeURIComponent(token)}`;
  const sse = new EventSource(streamUrl);
  window.__pixelSSE = sse;

  let sseConsecutiveErrors = 0;

  sse.onmessage = (e) => {
    sseConsecutiveErrors = 0;
    try {
      const data = JSON.parse(e.data);
      if (data.event_type === 'ENGINE_STATS') {
        window.dispatchEvent(new CustomEvent('siem-engine-stats', { detail: data }));
        return;
      }
      if (data.event_type === 'IP_UPDATE') {
        const ipPayload = data.data || data;
        window.dispatchEvent(new CustomEvent('siem-ip-update', { detail: ipPayload }));
        return;
      }
      if (data.cpu_usage !== undefined || data.cpu_percent !== undefined) {
        window.dispatchEvent(new CustomEvent('siem-agent-heartbeat', { detail: data }));
        return;
      }
      const norm = normalizeLogItem(data);
      if (norm) {
        window.dispatchEvent(new CustomEvent('siem-security-log', { detail: norm }));
      }
    } catch (_) {}
  };

  sse.onerror = (err) => {
    // Check if token is expired or invalid
    const currentToken = getValidToken();
    if (!currentToken) {
      console.warn('SSE: Token kedaluwarsa atau tidak valid, menghentikan koneksi stream.');
      try {
        sse.close();
      } catch (_) {}
      if (window.__pixelSSE === sse) {
        window.__pixelSSE = null;
      }
      redirectToLogin('token_expired');
      return;
    }

    sseConsecutiveErrors++;
    // If stream was closed or multiple failures occurred, verify authentication with server
    if (sse.readyState === EventSource.CLOSED || sseConsecutiveErrors >= 5) {
      authFetch('/api/v1/agents')
        .then(() => {
          // Server is reachable and token is valid; reset consecutive errors
          sseConsecutiveErrors = 0;
        })
        .catch((fetchErr) => {
          // If authFetch detected 401, redirectToLogin('expired') was already triggered by authFetch.
          // If the stream was closed permanently by the browser, clean up the instance reference.
          if (sse.readyState === EventSource.CLOSED) {
            try {
              sse.close();
            } catch (_) {}
            if (window.__pixelSSE === sse) {
              window.__pixelSSE = null;
            }
          }
        });
    }
  };
}

document.addEventListener('DOMContentLoaded', () => {
  mountTopHUD();
  mountHorizontalRouteTabs();
  mountQuestBanner();
  mountLeftSidebar();
  initGlobalSSE();
});
