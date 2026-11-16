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
  } else if (service.includes('nginx') || service.includes('web') || item.endpoint || item.method) {
    category = 'WEB';
    categoryLabelShort = 'WEB';
    const method = (item.method || 'GET').toUpperCase();
    const endpoint = item.endpoint || '/';
    const code = item.status_code || 200;
    actionLabel = `${method} ${code}`;
    summaryText = rawMsg || `HTTP ${method} ${endpoint} — Status ${code}`;
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
    summaryText
  };
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
    desc: parsed.summaryText,
    mitre: mitre,
    raw: item
  };
}

window.escapeHtml = escapeHtml;
window.parseLogCategoryAndDetails = parseLogCategoryAndDetails;
window.normalizeLogItem = normalizeLogItem;

// Guard
const validToken = getValidToken();
if (!validToken && !window.location.pathname.endsWith('login.html')) {
  redirectToLogin('no_token');
}

const currentUser = localStorage.getItem('auth_user') || 'Analyst';
const currentRole = (localStorage.getItem('auth_role') || 'analyst').toLowerCase();

// Navigation Definitions
const ROUTES = [
  { path: '/dashboard', label: 'DASHBOARD', icon: '::', file: 'pages/dashboard/index.tsx', aliases: ['/', '/index.html'] },
  { path: '/analytics', label: 'ANALYTICS', icon: '||', file: 'pages/analytics/index.tsx', aliases: ['/status'] },
  { path: '/logs', label: 'AUDIT LOGS', icon: '📜', file: 'pages/logs/index.tsx', aliases: [] },
  { path: '/settings', label: 'SETTINGS & PROMPT', icon: '⚙️', file: 'pages/settings/index.tsx', aliases: [] }
];

function isPathActive(route, currentPath) {
  if (route.path === currentPath) return true;
  if (route.aliases && route.aliases.includes(currentPath)) return true;
  return false;
}

function getActiveRoute(currentPath) {
  return ROUTES.find(r => isPathActive(r, currentPath)) || ROUTES[0];
}

/** 1. Render Top HUD Address Bar */
function mountTopHUD() {
  const hudEl = document.getElementById('shared-hud');
  if (!hudEl) return;
  const currentPath = window.location.pathname;
  const activeRoute = getActiveRoute(currentPath);

  hudEl.className = 'pixel-hud';
  hudEl.innerHTML = `
    <!-- Left OS Identity -->
    <div class="hud-left">
      <div class="hud-shield-box">🛡️</div>
      <div class="hud-title-col">
        <div class="hud-title-row">
          <span class="hud-os-title">PIXEL-SKY OS</span>
          <span class="hud-os-ver">v2.4</span>
          <span class="hud-badge-ready">MULTI-PATH READY</span>
        </div>
        <div class="hud-hp-row">
          <span style="font-size: 8px;">❤️</span>
          <div class="hud-hp-bar">
            <div class="hud-hp-fill"></div>
          </div>
          <span class="hud-hp-text">92/100</span>
        </div>
      </div>
    </div>

    <!-- Center Address Bar -->
    <div class="hud-center-address">
      <span class="hud-address-globe">🌐</span>
      <span class="hud-address-url">https://portal.office-internal.id</span>
      <span class="hud-address-path-pill">${activeRoute.path}</span>
      <span class="hud-address-file">${activeRoute.file}</span>
    </div>

    <!-- Right Widgets & Actions -->
    <div class="hud-right">
      <div class="hud-coins-box">
        <span>🪙 600</span>
        <span>⭐ 5</span>
      </div>
      <button class="hud-btn hud-btn-sync" onclick="window.location.reload()">
        SYNC DATA
      </button>
      <button class="hud-btn hud-btn-prompt" onclick="window.location.href='/settings'">
        PROMPT OPSI A
      </button>
    </div>
  `;
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

/** 3. Render Quest Banner */
function mountQuestBanner() {
  const bannerEl = document.getElementById('shared-quest-banner');
  if (!bannerEl) return;

  bannerEl.className = 'quest-banner';
  bannerEl.innerHTML = `
    <span class="quest-badge">QUEST!</span>
    <span class="quest-banner-text">Mode Full Game aktif: lengkap dengan rumput &amp; pulau terbang!</span>
    <button class="quest-close" onclick="this.parentElement.style.display='none'">[X]</button>
  `;
}

/** 4. Render Left Sidebar */
function mountLeftSidebar() {
  const sidebarEl = document.getElementById('shared-sidebar');
  if (!sidebarEl) return;
  const currentPath = window.location.pathname;
  const activeRoute = getActiveRoute(currentPath);

  sidebarEl.innerHTML = `
    <!-- Card 1: MENU NAVIGASI (Multi-Route Controller) -->
    <div class="island-card">
      <div class="island-grass-cap"></div>
      <div class="island-header-bar">
        <div class="island-header-title">
          <span>::</span>
          <div>
            <div>MENU NAVIGASI</div>
            <span class="island-header-sub">Multi-Route Controller</span>
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
          <div>Terpisah per menu (bukan 1 path penumpukan komponen). Route aktif:</div>
          <span class="route-status-pill">${activeRoute.path}</span>
        </div>
      </div>
      <div class="island-dirt-crust"></div>
    </div>

    <!-- Card 2: QUEST COMMAND (Kontrol Cepat) -->
    <div class="island-card">
      <div class="island-grass-cap"></div>
      <div class="island-header-bar">
        <div class="island-header-title">
          <span>✦</span>
          <div>
            <div>QUEST COMMAND</div>
            <span class="island-header-sub">Kontrol Cepat</span>
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
          <button class="pixel-cmd-btn pixel-cmd-green" onclick="window.location.reload()">
            + TAMBAH SERVICE NODE
          </button>
          <button class="pixel-cmd-btn pixel-cmd-cyan" onclick="navigator.clipboard.writeText('PIXEL-SKY OS FULL GAME BLUEPRINT'); alert('Prompt Opsi A berhasil disalin!');">
            ❐ COPY PROMPT OPSI A
          </button>
        </div>
      </div>
      <div class="island-dirt-crust"></div>
    </div>
  `;
}

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
      <button class="filter-pill-btn active">7D</button>
      <button class="filter-pill-btn">30D</button>
      <button class="filter-pill-btn">12M</button>
    </div>
  `;
}

/** SSE Setup */
function initGlobalSSE() {
  const token = getValidToken();
  if (!token) return;

  const streamUrl = `/api/v1/stream?token=${encodeURIComponent(token)}`;
  const sse = new EventSource(streamUrl);
  window.__pixelSSE = sse;

  sse.onmessage = (e) => {
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
}

document.addEventListener('DOMContentLoaded', () => {
  mountTopHUD();
  mountHorizontalRouteTabs();
  mountQuestBanner();
  mountLeftSidebar();
  initGlobalSSE();
});
