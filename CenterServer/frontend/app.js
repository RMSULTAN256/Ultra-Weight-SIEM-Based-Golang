// ==========================================================================
// WAZUH-LIGHTWEIGHT SOC DASHBOARD SCRIPT
// Dynamic State Management, 1,000-Log Cap, & Real-Time Pagination
// ==========================================================================

// 1. AUTH LAYER — JWT guard, header injector, global 401 handler
const AUTH_KEYS = ['auth_token', 'auth_user', 'auth_role'];
const LOGIN_URL = '/login.html';

/** Decode payload JWT tanpa library. Null kalau token rusak. */
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

/** Token dianggap tidak ada kalau kosong / rusak / exp sudah lewat. */
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

/** Header Authorization otomatis, digabung dengan header lain. */
function authHeaders(extra) {
  const t = getValidToken();
  const h = Object.assign({}, extra || {});
  if (t) h['Authorization'] = 'Bearer ' + t;
  return h;
}

/** Semua request API lewat sini: header otomatis + tangkap 401 global. */
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

// Guard halaman
const storedToken = localStorage.getItem('auth_token');
let token = getValidToken();
const AUTH_OK = !!token;
if (!AUTH_OK) {
  redirectToLogin(storedToken ? 'expired' : '');
}

const currentUser = localStorage.getItem('auth_user') || 'Analyst';
const currentRole = (localStorage.getItem('auth_role') || 'analyst').toLowerCase();
const isAdmin = () => currentRole === 'admin';

function handleLogout() {
  try {
    if (window.__sse) window.__sse.close();
  } catch (_) { /* abaikan */ }
  clearSession();
  window.location.replace(LOGIN_URL + '?reason=logout');
}

/** Format waktu lengkap dengan tanggal & bulan (Contoh: "11 Nov 15:23:45") */
function formatDateTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '-';
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
  const day = String(d.getDate()).padStart(2, '0');
  const month = months[d.getMonth()];
  const hours = String(d.getHours()).padStart(2, '0');
  const mins = String(d.getMinutes()).padStart(2, '0');
  const secs = String(d.getSeconds()).padStart(2, '0');
  return `${day} ${month} ${hours}:${mins}:${secs}`;
}

// 2. Application Global State
const MAX_BUFFER_CAP = 1000;

const state = {
  activeAgents: new Map(),
  ipRecords: new Map(),
  eventsList: [],          // Ring buffer of up to 1,000 security logs (newest first)
  totalEventsReceived: 0,
  highAlertsCount: 0,

  // Security Events Pagination & Filtering
  eventsPagination: {
    currentPage: 1,
    pageSize: 25,
    searchQuery: '',
    severityFilter: 'ALL', // 'ALL' | 'CRITICAL' | 'SUSPICIOUS' | 'INFO'
    categoryFilter: 'ALL', // 'ALL' | 'UFW' | 'AUTH' | 'WEB' | 'FAIL2BAN' | 'SYSTEM'
    isLivePaused: false,
    pendingNewCount: 0
  },

  // Overview Recent Events Pagination & Filtering
  overviewPagination: {
    currentPage: 1,
    pageSize: 25,
    searchQuery: '',
    filterType: 'ALL',
    isLivePaused: false
  },

  // Latency Probe Results per Agent
  nodeProbeResults: new Map(),
  currentSshAgent: null,

  // Inbound IP Traffic Pagination & Filtering
  ipsPagination: {
    currentPage: 1,
    pageSize: 15,
    searchQuery: ''
  }
};

// View Titles Mapping
const viewTitles = {
  'view-overview': 'Overview',
  'view-fleet': 'Agents Fleet',
  'view-ip-traffic': 'Inbound IP Traffic',
  'view-events': 'Security Events',
  'view-containment': 'Zero-Trust Containment'
};

// ==========================================================================
// TAB SWITCHING (SIDEBAR NAVIGATION)
// ==========================================================================
function switchTab(targetId) {
  document.querySelectorAll('.nav-item').forEach(btn => {
    if (btn.dataset.target === targetId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  document.querySelectorAll('.tab-pane').forEach(pane => {
    if (pane.id === targetId) {
      pane.classList.add('active');
    } else {
      pane.classList.remove('active');
    }
  });

  const titleEl = document.getElementById('currentViewTitle');
  if (titleEl && viewTitles[targetId]) {
    titleEl.textContent = viewTitles[targetId];
  }
}

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.target;
    if (target) switchTab(target);
  });
});

// ==========================================================================
// MODAL RAW JSON INSPECTOR
// ==========================================================================
const jsonModal = document.getElementById('jsonModal');
const modalJsonContent = document.getElementById('modalJsonContent');
const closeModalBtn = document.getElementById('closeModalBtn');
const copyJsonBtn = document.getElementById('copyJsonBtn');

closeModalBtn.addEventListener('click', () => jsonModal.classList.add('hidden'));
jsonModal.addEventListener('click', (e) => {
  if (e.target === jsonModal) jsonModal.classList.add('hidden');
});

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && jsonModal && !jsonModal.classList.contains('hidden')) {
    jsonModal.classList.add('hidden');
  }
});

if (copyJsonBtn) {
  copyJsonBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(modalJsonContent.textContent).then(() => {
      copyJsonBtn.textContent = 'Copied!';
      setTimeout(() => { copyJsonBtn.textContent = 'Copy JSON'; }, 1500);
    }).catch(err => console.error("Clipboard copy failed:", err));
  });
}

let logIdSeq = 0;

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Port to service mapping for network clarity
const KNOWN_PORTS = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  465: 'SMTPS',
  587: 'Submission',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  3306: 'MySQL',
  5432: 'Postgres',
  6379: 'Redis',
  8000: 'HTTP-Alt',
  8080: 'HTTP-Proxy',
  8443: 'HTTPS-Alt',
  9200: 'Elastic',
  27017: 'MongoDB'
};

function parseLogCategoryAndDetails(item) {
  const service = (item.service || item.program || '').toLowerCase();
  const eventType = (item.event_type || '').toLowerCase();
  const status = (item.status || '').toLowerCase();
  const rawMsg = item.message || item.rule_desc || item.desc || '';
  const msgLower = rawMsg.toLowerCase();

  let category = 'INFO';
  let categoryLabel = 'SYSTEM INFO';
  let categoryLabelShort = 'INFO';
  let categoryClass = 'badge-cat-info';

  let actionLabel = 'EVENT';
  let actionClass = 'badge-act-info';

  const captured = {
    category: 'INFO',
    action: '',
    protocol: '',
    port: item.target_port || null,
    sourcePort: null,
    portService: '',
    user: item.user || null,
    interface: '',
    endpoint: item.endpoint || null,
    method: item.method || null,
    statusCode: item.status_code || null,
    jail: '',
    process: '',
    reason: '',
    summaryText: ''
  };

  const tags = [];

  // 1. UFW / Firewall Packet Drops & Allows
  const isUfw = service.includes('ufw') ||
                status.includes('ufw block') ||
                status.includes('ufw allow') ||
                msgLower.includes('[ufw ') ||
                msgLower.includes('ufw block') ||
                eventType.includes('firewall') ||
                eventType.includes('ufw');

  if (isUfw) {
    category = 'UFW';
    categoryLabel = 'UFW FIREWALL';
    categoryLabelShort = 'UFW';
    categoryClass = 'badge-cat-ufw';

    let action = 'BLOCK';
    if (msgLower.includes('allow') || status.includes('allow')) {
      action = 'ALLOW';
      actionClass = 'badge-act-success';
    } else if (msgLower.includes('audit')) {
      action = 'AUDIT';
      actionClass = 'badge-act-info';
    } else {
      action = 'BLOCK';
      actionClass = 'badge-act-danger';
    }
    captured.action = action;

    const protoMatch = rawMsg.match(/\bPROTO=([A-Za-z0-9]+)/i);
    if (protoMatch) captured.protocol = protoMatch[1].toUpperCase();

    const dptMatch = rawMsg.match(/\bDPT=(\d+)/i);
    if (dptMatch) captured.port = parseInt(dptMatch[1], 10);
    else if (item.target_port) captured.port = item.target_port;

    const sptMatch = rawMsg.match(/\bSPT=(\d+)/i);
    if (sptMatch) captured.sourcePort = parseInt(sptMatch[1], 10);

    const inMatch = rawMsg.match(/\bIN=([a-zA-Z0-9_.-]+)/i);
    if (inMatch) captured.interface = inMatch[1];

    if (captured.port && KNOWN_PORTS[captured.port]) {
      captured.portService = KNOWN_PORTS[captured.port];
    }

    if (captured.port) {
      actionLabel = `${action} ${captured.protocol ? captured.protocol + ':' : ''}${captured.port}`;
    } else if (captured.protocol) {
      actionLabel = `${action} ${captured.protocol}`;
    } else {
      actionLabel = action;
    }

    if (captured.port) {
      tags.push(`<span class="tag-pill tag-pill-port">DPT: ${captured.port}${captured.portService ? ' (' + captured.portService + ')' : ''}</span>`);
    }
    if (captured.protocol) {
      tags.push(`<span class="tag-pill tag-pill-proto">${captured.protocol}</span>`);
    }
    if (captured.interface) {
      tags.push(`<span class="tag-pill tag-pill-iface">IN: ${escapeHtml(captured.interface)}</span>`);
    }
    if (captured.sourcePort) {
      tags.push(`<span class="tag-pill tag-pill-port">SPT: ${captured.sourcePort}</span>`);
    }

    captured.reason = action === 'BLOCK' ? 'Packet dropped by kernel firewall filter' : 'Packet allowed by firewall rule';
    const portDesc = captured.port ? `Port ${captured.port}${captured.portService ? ' (' + captured.portService + ')' : ''}` : (captured.protocol || 'packet');
    captured.summaryText = `UFW ${action} ${captured.protocol || 'packet'} to ${portDesc}${captured.interface ? ' on ' + captured.interface : ''}`;

  // 2. Fail2ban Actions
  } else if (service.includes('fail2ban') || msgLower.includes('fail2ban.actions') || status.includes(' ban ') || status.includes(' unban ') || msgLower.includes(' ban ') || msgLower.includes(' unban ')) {
    category = 'FAIL2BAN';
    categoryLabel = 'FAIL2BAN';
    categoryLabelShort = 'F2B';
    categoryClass = 'badge-cat-fail2ban';

    const isUnban = msgLower.includes('unban');
    const action = isUnban ? 'UNBAN' : 'BAN';
    captured.action = action;
    actionClass = isUnban ? 'badge-act-warn' : 'badge-act-danger';

    const jailMatch = rawMsg.match(/\[([a-zA-Z0-9_-]+)\]\s+(?:Ban|Unban)/i);
    if (jailMatch) captured.jail = jailMatch[1];

    actionLabel = `${action} ${captured.jail ? '[' + captured.jail + ']' : ''}`.trim();

    if (captured.jail) {
      tags.push(`<span class="tag-pill tag-pill-jail">JAIL: ${escapeHtml(captured.jail)}</span>`);
    }
    tags.push(`<span class="tag-pill tag-pill-warn">${action} ACTION</span>`);

    captured.reason = isUnban ? 'Manual or timeout unban' : 'Exceeded authentication failure threshold in jail';
    captured.summaryText = `Fail2ban ${action} IP in jail [${captured.jail || 'default'}] — ${captured.reason}`;

  // 3. Web Attacks (SQLi, RCE, XSS)
  } else if (eventType === 'web_attack' || msgLower.includes('union select') || msgLower.includes('eval(') || msgLower.includes('<script') || status.includes('union select') || status.includes('eval(')) {
    category = 'WEB_ATTACK';
    categoryLabel = 'WEB ATTACK';
    categoryLabelShort = 'ATTACK';
    categoryClass = 'badge-cat-attack';

    let attackType = 'Web Exploit';
    if (msgLower.includes('union select') || status.includes('union select')) attackType = 'SQL Injection';
    else if (msgLower.includes('eval(') || status.includes('eval(')) attackType = 'Remote Code Execution';
    else if (msgLower.includes('<script')) attackType = 'XSS Payload';

    captured.action = 'ATTACK';
    actionClass = 'badge-act-danger';
    actionLabel = attackType;

    tags.push(`<span class="tag-pill tag-pill-warn">${escapeHtml(attackType)}</span>`);

    const methodMatch = rawMsg.match(/"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^"\s]+)/i);
    if (methodMatch) {
      captured.method = methodMatch[1].toUpperCase();
      captured.endpoint = methodMatch[2];
      tags.push(`<span class="tag-pill tag-pill-method">${captured.method}</span>`);
      tags.push(`<span class="tag-pill tag-pill-uri">${escapeHtml(captured.endpoint)}</span>`);
    }

    captured.reason = `Malicious pattern detected: ${attackType}`;
    captured.summaryText = `Web Attack: ${attackType} targeted at application${captured.endpoint ? ' (' + captured.endpoint + ')' : ''}`;

  // 4. Kernel OOM Killer & Segfault
  } else if (msgLower.includes('out of memory') || msgLower.includes('oom-kill') || msgLower.includes('killed process') || msgLower.includes('segfault')) {
    category = 'SYSTEM';
    categoryLabel = 'KERNEL / SYS';
    categoryLabelShort = 'KERNEL';
    categoryClass = 'badge-cat-system';

    if (msgLower.includes('out of memory') || msgLower.includes('oom-kill') || msgLower.includes('killed process')) {
      actionLabel = 'OOM-KILL';
      actionClass = 'badge-act-danger';

      const procMatch = rawMsg.match(/Kill(?:ed)? process \d+ \(([^)]+)\)/i);
      if (procMatch) captured.process = procMatch[1];
      else captured.process = 'system-proc';

      tags.push(`<span class="tag-pill tag-pill-warn">OOM KILLER</span>`);
      tags.push(`<span class="tag-pill tag-pill-proc">PROC: ${escapeHtml(captured.process)}</span>`);
      captured.reason = 'Linux kernel terminated process due to memory exhaustion';
      captured.summaryText = `Kernel Out of Memory: Terminated process ${captured.process}`;
    } else {
      actionLabel = 'SEGFAULT';
      actionClass = 'badge-act-danger';
      tags.push(`<span class="tag-pill tag-pill-warn">SEGFAULT</span>`);
      captured.reason = 'Memory segmentation fault in binary execution';
      captured.summaryText = `Kernel Segfault detected in application execution`;
    }

  // 5. Sudo Privileged Execution
  } else if (msgLower.includes('sudo:') || eventType === 'sudo' || (msgLower.includes('command=') && msgLower.includes('pwd='))) {
    category = 'SYSTEM';
    categoryLabel = 'SUDO / SYS';
    categoryLabelShort = 'SUDO';
    categoryClass = 'badge-cat-system';
    actionLabel = 'SUDO EXEC';
    actionClass = 'badge-act-warn';

    const sudoUserMatch = rawMsg.match(/sudo:\s+([a-zA-Z0-9_.-]+)\s*:/i);
    if (sudoUserMatch) captured.user = sudoUserMatch[1];
    else if (item.user) captured.user = item.user;

    const cmdMatch = rawMsg.match(/COMMAND=(.+)$/i);
    if (cmdMatch) captured.process = cmdMatch[1].trim();
    else if (item.command) captured.process = item.command;

    if (captured.user) tags.push(`<span class="tag-pill tag-pill-user">USER: ${escapeHtml(captured.user)}</span>`);
    if (captured.process) {
      const shortCmd = captured.process.length > 25 ? captured.process.slice(0, 22) + '...' : captured.process;
      tags.push(`<span class="tag-pill tag-pill-proc">CMD: ${escapeHtml(shortCmd)}</span>`);
    }
    captured.reason = 'Administrative privilege escalation via sudo';
    captured.summaryText = `Sudo: User "${captured.user || 'root'}" executed privileged command "${captured.process || 'shell'}"`;

  // 6. Cron, Systemd-logind, PAM Session Management (INFO)
  } else if (msgLower.includes('cron[') || msgLower.includes('systemd-logind') || msgLower.includes('pam_unix(cron:session)') || msgLower.includes('su(pam_unix)') || msgLower.includes('session closed for user') || msgLower.includes('session opened for user')) {
    category = 'INFO';
    categoryLabel = 'SYSTEM INFO';
    categoryLabelShort = 'INFO';
    categoryClass = 'badge-cat-info';
    actionClass = 'badge-act-info';

    const cronUserMatch = rawMsg.match(/user\s+([a-zA-Z0-9_.-]+)/i);
    if (cronUserMatch) captured.user = cronUserMatch[1];

    if (msgLower.includes('cron[')) {
      actionLabel = 'CRON RUN';
      tags.push(`<span class="tag-pill tag-pill-proto">CRON</span>`);
      if (captured.user) tags.push(`<span class="tag-pill tag-pill-user">USER: ${escapeHtml(captured.user)}</span>`);
      const isOpened = msgLower.includes('opened');
      captured.reason = 'Automated scheduled cron task execution';
      captured.summaryText = `Cron session ${isOpened ? 'opened' : 'closed'} for user "${captured.user || 'root'}"`;
    } else if (msgLower.includes('systemd-logind')) {
      actionLabel = 'LOGIND';
      tags.push(`<span class="tag-pill tag-pill-proto">LOGIND</span>`);
      captured.reason = 'Systemd user session management';
      captured.summaryText = rawMsg;
    } else {
      actionLabel = 'PAM SESSION';
      tags.push(`<span class="tag-pill tag-pill-proto">PAM</span>`);
      if (captured.user) tags.push(`<span class="tag-pill tag-pill-user">USER: ${escapeHtml(captured.user)}</span>`);
      captured.reason = 'PAM session state update';
      captured.summaryText = rawMsg;
    }

  // 7. SSH Auth Spam & Brute Force
  } else if (eventType === 'auth_failure' || status === 'failed' ||
             msgLower.includes('failed password') || msgLower.includes('invalid user') ||
             msgLower.includes('authentication failure') || msgLower.includes('user unknown') ||
             msgLower.includes('break-in attempt') ||
             status.includes('failed password') || status.includes('invalid user')) {

    category = 'AUTH_SPAM';
    categoryLabel = 'SPAM / AUTH';
    categoryLabelShort = 'SPAM';
    categoryClass = 'badge-cat-spam';
    actionClass = 'badge-act-danger';

    const userMatch = rawMsg.match(/(?:for\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_.-]+)\s+from|invalid\s+user\s+([a-zA-Z0-9_.-]+)\s+from|user=([a-zA-Z0-9_.-]+)|user\s+unknown\b)/i);
    if (userMatch) {
      captured.user = userMatch[1] || userMatch[2] || userMatch[3] || (msgLower.includes('user unknown') ? 'unknown' : null);
    }
    if (!captured.user && item.user) captured.user = item.user;

    const portMatch = rawMsg.match(/\bport\s+(\d+)/i);
    if (portMatch) captured.sourcePort = parseInt(portMatch[1], 10);

    captured.port = item.target_port || 22;
    captured.portService = 'SSH';

    if (msgLower.includes('invalid user') || msgLower.includes('user unknown')) {
      actionLabel = 'INVALID USER';
      captured.reason = 'Unknown user identity enumeration';
      tags.push(`<span class="tag-pill tag-pill-warn">INVALID USER</span>`);
    } else if (msgLower.includes('break-in attempt')) {
      actionLabel = 'BREAK-IN';
      captured.reason = 'Reverse DNS mismatch / Break-in attempt';
      tags.push(`<span class="tag-pill tag-pill-warn">BREAK-IN</span>`);
    } else {
      actionLabel = 'BAD PASSWD';
      captured.reason = 'Incorrect credentials / password spray';
      tags.push(`<span class="tag-pill tag-pill-warn">BAD PASSWD</span>`);
    }

    if (captured.user) {
      tags.push(`<span class="tag-pill tag-pill-user">USER: ${escapeHtml(captured.user)}</span>`);
    }
    tags.push(`<span class="tag-pill tag-pill-port">PORT: ${captured.port}</span>`);
    if (captured.sourcePort) {
      tags.push(`<span class="tag-pill tag-pill-proto">SRC_PORT: ${captured.sourcePort}</span>`);
    }

    captured.summaryText = `[Auth Spam] Failed SSH login for "${captured.user || 'root'}" on Port ${captured.port} (${captured.reason})`;

  // 8. Legitimate SSH Authentication
  } else if (eventType === 'auth_success' || status === 'success' ||
             msgLower.includes('accepted password') || msgLower.includes('accepted publickey')) {

    category = 'AUTH';
    categoryLabel = 'SSH AUTH';
    categoryLabelShort = 'AUTH';
    categoryClass = 'badge-cat-auth';
    actionClass = 'badge-act-success';

    const userMatch = rawMsg.match(/for\s+([a-zA-Z0-9_.-]+)\s+from/i);
    if (userMatch) captured.user = userMatch[1];
    else if (item.user) captured.user = item.user;

    const portMatch = rawMsg.match(/\bport\s+(\d+)/i);
    if (portMatch) captured.sourcePort = parseInt(portMatch[1], 10);

    captured.port = item.target_port || 22;
    captured.portService = 'SSH';

    const isKey = msgLower.includes('publickey');
    actionLabel = isKey ? 'LOGIN KEY' : 'LOGIN PASS';

    if (captured.user) {
      tags.push(`<span class="tag-pill tag-pill-user">USER: ${escapeHtml(captured.user)}</span>`);
    }
    tags.push(`<span class="tag-pill tag-pill-proto">${isKey ? 'PUBLICKEY' : 'PASSWORD'}</span>`);
    tags.push(`<span class="tag-pill tag-pill-port">PORT: ${captured.port}</span>`);

    captured.reason = 'Valid credential handshake';
    captured.summaryText = `SSH login accepted for user "${captured.user || 'root'}" via ${isKey ? 'publickey' : 'password'} on Port ${captured.port}`;

  // 9. SSH Disconnects & Session Closed
  } else if (msgLower.includes('received disconnect') || msgLower.includes('disconnected from user') || msgLower.includes('connection closed by')) {
    category = 'INFO';
    categoryLabel = 'SSH INFO';
    categoryLabelShort = 'INFO';
    categoryClass = 'badge-cat-info';
    actionLabel = 'DISCONNECT';
    actionClass = 'badge-act-info';

    const discUser = rawMsg.match(/user\s+([a-zA-Z0-9_.-]+)/i);
    if (discUser) captured.user = discUser[1];

    tags.push(`<span class="tag-pill tag-pill-proto">DISCONNECT</span>`);
    if (captured.user) tags.push(`<span class="tag-pill tag-pill-user">USER: ${escapeHtml(captured.user)}</span>`);
    captured.reason = 'Client disconnected SSH session';
    captured.summaryText = `SSH session disconnected${captured.user ? ' for user ' + captured.user : ''}`;

  // 10. Web Access (Nginx / Apache HTTP)
  } else if (service.includes('nginx') || service.includes('web') || eventType === 'resource_access' || /"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+/.test(rawMsg) || item.endpoint || item.method) {
    category = 'WEB';
    categoryLabel = 'WEB ACCESS';
    categoryLabelShort = 'WEB';
    categoryClass = 'badge-cat-web';

    const methodMatch = rawMsg.match(/"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^"\s]+)/i);
    if (methodMatch) {
      captured.method = methodMatch[1].toUpperCase();
      captured.endpoint = methodMatch[2];
    }
    if (!captured.method && item.method) captured.method = item.method.toUpperCase();
    if (!captured.endpoint && item.endpoint) captured.endpoint = item.endpoint;

    const codeMatch = rawMsg.match(/"\s+(\d{3})\b/);
    if (codeMatch) captured.statusCode = parseInt(codeMatch[1], 10);
    else if (item.status_code) captured.statusCode = item.status_code;

    const method = captured.method || 'HTTP';
    const code = captured.statusCode || 200;

    actionLabel = `${method} ${code}`;
    if (code >= 500) actionClass = 'badge-act-danger';
    else if (code >= 400) actionClass = 'badge-act-warn';
    else actionClass = 'badge-act-success';

    tags.push(`<span class="tag-pill tag-pill-method">${escapeHtml(method)}</span>`);
    tags.push(`<span class="tag-pill tag-pill-code ${code >= 400 ? 'code-error' : ''}">${code}</span>`);
    if (captured.endpoint) {
      tags.push(`<span class="tag-pill tag-pill-uri">${escapeHtml(captured.endpoint)}</span>`);
    }

    captured.reason = code >= 400 ? `HTTP Client/Server Error (${code})` : 'Successful HTTP response';
    captured.summaryText = `HTTP ${method} ${captured.endpoint || '/'} — Status ${code}`;

  // 11. Package Management (Dpkg)
  } else if (service.includes('package') || msgLower.includes('install ') || msgLower.includes('remove ') || msgLower.includes('status installed') || msgLower.includes('dpkg')) {
    category = 'PACKAGE';
    categoryLabel = 'PACKAGE DPKG';
    categoryLabelShort = 'DPKG';
    categoryClass = 'badge-cat-package';

    const isInstall = msgLower.includes('install');
    actionLabel = isInstall ? 'INSTALL' : 'REMOVE';
    actionClass = 'badge-act-info';

    tags.push(`<span class="tag-pill tag-pill-proto">${actionLabel}</span>`);
    captured.summaryText = `dpkg package manager: ${rawMsg}`;

  // 12. Default Info / Operational
  } else {
    category = 'INFO';
    categoryLabel = 'SYSTEM INFO';
    categoryLabelShort = 'INFO';
    categoryClass = 'badge-cat-info';

    actionLabel = item.event_type || 'INFO';
    actionClass = 'badge-act-info';

    tags.push(`<span class="tag-pill tag-pill-proto">${escapeHtml(actionLabel)}</span>`);
    captured.summaryText = rawMsg || item.desc || 'System log transaction recorded';
  }

  return {
    category,
    categoryLabel,
    categoryLabelShort,
    categoryClass,
    actionLabel,
    actionClass,
    captured,
    tagsHtml: tags.join(''),
    summaryText: captured.summaryText
  };
}

function showJsonModal(item) {
  const modalCaptureBox = document.getElementById('modalCaptureBreakdown');
  if (modalCaptureBox && item.parsed) {
    const p = item.parsed;
    modalCaptureBox.innerHTML = `
      <div class="modal-capture-head">
        <span class="badge-cat ${p.categoryClass}">${p.categoryLabel}</span>
        <span class="badge-act ${p.actionClass}">${p.actionLabel}</span>
        <span class="modal-capture-summary">${escapeHtml(p.summaryText)}</span>
      </div>
      <div class="modal-capture-grid">
        <div class="modal-capture-item"><div class="k">Log Category</div><div class="v">${p.categoryLabel}</div></div>
        <div class="modal-capture-item"><div class="k">Captured Action</div><div class="v">${p.actionLabel}</div></div>
        <div class="modal-capture-item"><div class="k">Target Port &amp; Proto</div><div class="v">${p.captured.port ? (p.captured.protocol ? p.captured.protocol + '/' : '') + p.captured.port + (p.captured.portService ? ' (' + p.captured.portService + ')' : '') : (p.captured.protocol || '-')}</div></div>
        <div class="modal-capture-item"><div class="k">Source / Client Port</div><div class="v">${p.captured.sourcePort || '-'}</div></div>
        <div class="modal-capture-item"><div class="k">Target User / Identity</div><div class="v">${p.captured.user ? escapeHtml(p.captured.user) : '-'}</div></div>
        <div class="modal-capture-item"><div class="k">Inbound Interface</div><div class="v">${p.captured.interface ? escapeHtml(p.captured.interface) : '-'}</div></div>
        <div class="modal-capture-item"><div class="k">Endpoint / Process / CMD</div><div class="v">${p.captured.endpoint || p.captured.process ? escapeHtml(p.captured.endpoint || p.captured.process) : '-'}</div></div>
        <div class="modal-capture-item"><div class="k">Capture Reason</div><div class="v">${p.captured.reason ? escapeHtml(p.captured.reason) : '-'}</div></div>
        <div class="modal-capture-item"><div class="k">Source Address</div><div class="v">${item.source_ip}</div></div>
        <div class="modal-capture-item"><div class="k">Monitored Node</div><div class="v">${item.agent}</div></div>
        <div class="modal-capture-item"><div class="k">Collector Service</div><div class="v">${escapeHtml(item.raw?.service || '-')}</div></div>
      </div>
    `;
    modalCaptureBox.classList.remove('hidden');
  } else if (modalCaptureBox) {
    modalCaptureBox.classList.add('hidden');
  }

  modalJsonContent.textContent = JSON.stringify(item.raw || item, null, 2);
  jsonModal.classList.remove('hidden');
}

window.inspectEventById = function(id) {
  const item = state.eventsList.find(e => e.id === id);
  if (item) {
    showJsonModal(item);
  }
};

// ==========================================================================
// DATA NORMALIZATION HELPER
// ==========================================================================
function normalizeLogItem(item) {
  const parsed = parseLogCategoryAndDetails(item);

  const severity = item.severity || (parsed.category === 'AUTH_SPAM' ? 7 : parsed.category === 'WEB_ATTACK' ? 10 : 3);
  let levelLabel = "LVL 3 INFO";
  if (severity >= 12) {
    levelLabel = "LVL 12 CRITICAL";
  } else if (severity >= 7) {
    levelLabel = "LVL 7 WARNING";
  }

  let mitre = item.mitre_id;
  if (!mitre) {
    if (parsed.category === 'AUTH_SPAM') mitre = "T1110 Brute Force";
    else if (parsed.category === 'WEB_ATTACK') mitre = "T1190 Exploit Public-Facing";
    else if (parsed.category === 'UFW') mitre = "T1595 Recon Scan";
    else if (severity >= 12) mitre = "T1110.001 Brute Force";
    else if (severity >= 7) mitre = "T1595 Recon Scan";
    else mitre = "T1082 Telemetry";
  }

  return {
    id: ++logIdSeq,
    timestamp: item.timestamp || new Date().toISOString(),
    source_ip: item.source_ip || "127.0.0.1",
    agent: item.hostname || "target-node",
    level: severity,
    level_label: levelLabel,
    status_code: parsed.captured.statusCode,
    status_badge: `<div class="cat-action-col"><span class="badge-cat ${parsed.categoryClass}">${parsed.categoryLabelShort}</span><span class="badge-act ${parsed.actionClass}">${parsed.actionLabel}</span></div>`,
    desc: parsed.summaryText || item.rule_desc || item.message || '',
    mitre: mitre,
    parsed: parsed,
    raw: item
  };
}

// ==========================================================================
// INITIAL DATA HYDRATION (FETCH ON LOAD/REFRESH)
// ==========================================================================

// 1. Load Initial Logs from Server Buffer
async function loadInitialLogs() {
  try {
    const res = await authFetch(`/api/v1/logs?limit=${MAX_BUFFER_CAP}`);
    if (res.ok) {
      const logs = await res.json();
      if (Array.isArray(logs)) {
        state.eventsList = logs.map(normalizeLogItem);
        
        // Baca akumulasi total event dari header backend jika ada
        const totalHeader = res.headers.get("X-Total-Ingested");
        if (totalHeader) {
          state.totalEventsReceived = parseInt(totalHeader, 10);
        } else {
          state.totalEventsReceived = state.eventsList.length;
        }

        // Count high alerts
        state.highAlertsCount = state.eventsList.filter(e => e.level >= 7).length;

        updateKPIStats();
        renderEventsTable();
        renderOverviewRecentEvents();
      }
    }
  } catch (err) {
    console.error("Failed to fetch initial logs:", err);
  }
}

// 2. Load Initial Agents from Server
async function loadInitialAgents() {
  try {
    const res = await authFetch('/api/v1/agents');
    if (res.ok) {
      const list = await res.json();
      if (Array.isArray(list) && list.length > 0) {
        list.forEach(item => updateAgentFleet(item, false));
        renderFleetCards();
      }
    }
  } catch (err) {
    console.error("Failed to fetch initial agents:", err);
  }
}

// 3. Load Initial IPs from Server
async function loadInitialIPs() {
  try {
    const res = await authFetch('/api/v1/ips');
    if (res.ok) {
      const list = await res.json();
      if (Array.isArray(list)) {
        list.forEach(item => updateOrAddIPRecord(item, false));
        renderIPTable();
      }
    }
  } catch (err) {
    console.error("Failed to fetch initial IPs:", err);
  }
}

// ==========================================================================
// SSE STREAM CONNECTION & LIVE ROUTER
// ==========================================================================
function connectSSE() {
  const sideStreamDot = document.getElementById('sideStreamDot');
  const sideStreamText = document.getElementById('sideStreamText');
  const topStreamDot = document.getElementById('topStreamDot');
  const topStreamStatus = document.getElementById('topStreamStatus');

  // EventSource tidak bisa mengirim header custom -> token lewat query string
  const streamToken = getValidToken() || '';
  const evtSource = new EventSource('/api/v1/stream?token=' + encodeURIComponent(streamToken));
  window.__sse = evtSource;

  let streamErrors = 0;

  evtSource.onopen = () => {
    streamErrors = 0;
    if (sideStreamDot) sideStreamDot.className = "dot green";
    if (sideStreamText) sideStreamText.textContent = "Cluster Online";
    if (topStreamDot) topStreamDot.style.backgroundColor = "var(--color-success)";
    if (topStreamStatus) topStreamStatus.textContent = state.eventsPagination.isLivePaused ? "STREAM PAUSED" : "LIVE STREAM";
  };

  evtSource.onerror = () => {
    if (sideStreamDot) sideStreamDot.className = "dot";
    if (sideStreamText) sideStreamText.textContent = "Reconnecting...";
    if (topStreamDot) topStreamDot.style.backgroundColor = "var(--color-danger)";
    if (topStreamStatus) topStreamStatus.textContent = "RECONNECTING";

    // EventSource menutupi status HTTP: setelah 3x gagal, uji sesi lewat request
    // biasa. Kalau token sudah mati, authFetch akan melempar user ke halaman login.
    streamErrors += 1;
    if (streamErrors === 3) {
      authFetch('/api/v1/agents').catch(() => { /* sudah ditangani authFetch */ });
    }
  };

  evtSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      handleIncomingEvent(data);
    } catch (err) {
      console.error("SSE JSON Parse error:", err);
    }
  };
}

function handleIncomingEvent(data) {
  // 0. Agent Deletion Broadcast Event
  if ((data.event_type === "AGENT_DELETE" || data.event_type === "AGENT_DELETED") && data.agent_id) {
    const targetId = data.agent_id;
    state.activeAgents.delete(targetId);
    for (const [k, v] of state.activeAgents.entries()) {
      if (k === targetId || v.data.agent_id === targetId || v.data.hostname === targetId) {
        state.activeAgents.delete(k);
      }
    }
    renderFleetCards();
    refreshAgentFleetCounts();
    renderOverviewFleetSummary();
    return;
  }

  // 0.1 Engine Real-time Memory Stats Event
  if (data.event_type === "ENGINE_STATS") {
    const allocMB = data.ram_alloc_mb || 0;
    const sysMB = data.ram_sys_mb || 0;
    const goroutines = data.goroutines || 0;

    const ramStatEl = document.getElementById('ramStat');
    if (ramStatEl) {
      ramStatEl.textContent = `${allocMB.toFixed(1)} MB / 80 MB RSS`;
    }

    const engineResEl = document.getElementById('engineResourceVal');
    if (engineResEl) {
      engineResEl.textContent = `${allocMB.toFixed(1)} MB`;
    }

    const engineCapEl = document.getElementById('engineResourceCap');
    if (engineCapEl) {
      engineCapEl.textContent = `Sys: ${sysMB.toFixed(1)} MB • ${goroutines} gr`;
    }
    return;
  }

  // 1. IP Update Event
  if (data.event_type === "IP_UPDATE" && data.data) {
    updateOrAddIPRecord(data.data, true);
    return;
  }

  // 2. Hardware Telemetry Heartbeat
  if (data.cpu_usage !== undefined) {
    updateAgentFleet(data, true);
    return;
  }

  // 3. Security/Access Log Event
  if (data.event_type || data.rule_id || data.message || data.timestamp) {
    const norm = normalizeLogItem(data);
    state.totalEventsReceived++;

    if (norm.level >= 7) {
      state.highAlertsCount++;
    }

    // Prepend to ring buffer and cap at MAX_BUFFER_CAP (1,000)
    state.eventsList.unshift(norm);
    if (state.eventsList.length > MAX_BUFFER_CAP) {
      state.eventsList.pop();
    }

    // Always maintain high alerts count accurately within active buffer
    state.highAlertsCount = state.eventsList.filter(e => e.level >= 7).length;

    updateKPIStats();

    // Update Overview Recent Events table respecting pause and page
    if (!state.overviewPagination.isLivePaused && state.overviewPagination.currentPage === 1) {
      renderOverviewRecentEvents();
    } else {
      updateOverviewPaginationOnly();
    }

    // Table update logic respecting analyst pause/pagination state
    if (state.eventsPagination.isLivePaused) {
      state.eventsPagination.pendingNewCount++;
      updateNewEventsToast();
    } else {
      if (state.eventsPagination.currentPage === 1) {
        renderEventsTable();
      } else {
        state.eventsPagination.pendingNewCount++;
        updateNewEventsToast();
      }
    }
  }
}

function updateKPIStats() {
  const totalCount = state.totalEventsReceived;
  const bufferCount = state.eventsList.length;

  const totalEl = document.getElementById('totalEventsCount');
  if (totalEl) totalEl.textContent = totalCount.toLocaleString();

  const navEventEl = document.getElementById('navEventCount');
  if (navEventEl) navEventEl.textContent = bufferCount.toLocaleString();

  const highEl = document.getElementById('highAlertsCount');
  if (highEl) highEl.textContent = state.highAlertsCount.toLocaleString();

  const bufferOverviewEl = document.getElementById('bufferCapacityOverview');
  if (bufferOverviewEl) {
    bufferOverviewEl.textContent = `Buffer: ${bufferCount.toLocaleString()} / ${MAX_BUFFER_CAP.toLocaleString()} in memory`;
  }

  const bufferStatusEl = document.getElementById('bufferStatusText');
  if (bufferStatusEl) {
    bufferStatusEl.textContent = `Ring Buffer: ${bufferCount.toLocaleString()} / ${MAX_BUFFER_CAP.toLocaleString()} logs`;
  }
}

// ==========================================================================
// SECURITY EVENTS PAGINATION & DISCOVERY LOGIC
// ==========================================================================
function getFilteredEvents() {
  let list = state.eventsList;

  // Category Filter
  const cat = state.eventsPagination.categoryFilter;
  if (cat && cat !== 'ALL') {
    list = list.filter(e => {
      const c = e.parsed?.category || '';
      if (cat === 'UFW') return c === 'UFW';
      if (cat === 'SPAM') return c === 'AUTH_SPAM' || c === 'WEB_ATTACK';
      if (cat === 'AUTH') return c === 'AUTH';
      if (cat === 'WEB') return c === 'WEB' || c === 'WEB_ATTACK';
      if (cat === 'INFO') return c === 'INFO' || c === 'PACKAGE';
      if (cat === 'FAIL2BAN') return c === 'FAIL2BAN';
      if (cat === 'SYSTEM') return c === 'SYSTEM';
      if (cat === 'PACKAGE') return c === 'PACKAGE';
      return true;
    });
  }

  // Severity Filter
  const sev = state.eventsPagination.severityFilter;
  if (sev === 'CRITICAL') {
    list = list.filter(e => e.level >= 12);
  } else if (sev === 'SUSPICIOUS') {
    list = list.filter(e => e.level >= 7 && e.level < 12);
  } else if (sev === 'INFO') {
    list = list.filter(e => e.level < 7);
  }

  // Search Query
  const q = state.eventsPagination.searchQuery.toLowerCase().trim();
  if (q) {
    list = list.filter(e => {
      const p = e.parsed;
      const targetStr = `${e.source_ip} ${e.agent} ${e.desc} ${e.mitre} ${e.level_label} ${p?.category || ''} ${p?.categoryLabel || ''} ${p?.actionLabel || ''} ${p?.captured?.port || ''} ${p?.captured?.sourcePort || ''} ${p?.captured?.user || ''} ${p?.captured?.endpoint || ''} ${p?.captured?.protocol || ''} ${p?.captured?.interface || ''} ${p?.captured?.process || ''} ${p?.captured?.reason || ''} ${e.raw?.service || ''} ${e.raw?.message || ''}`.toLowerCase();
      return targetStr.includes(q);
    });
  }

  return list;
}

function renderEventsTable() {
  const tbody = document.getElementById('eventsTableBody');
  const infoEl = document.getElementById('eventsPaginationInfo');
  const controlsEl = document.getElementById('eventsPaginationControls');
  if (!tbody) return;

  const filtered = getFilteredEvents();
  const total = filtered.length;
  const pageSize = state.eventsPagination.pageSize;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  if (state.eventsPagination.currentPage > totalPages) {
    state.eventsPagination.currentPage = totalPages;
  }
  const currentPage = state.eventsPagination.currentPage;

  const startIdx = total === 0 ? 0 : (currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, total);
  const pageItems = filtered.slice(startIdx, endIdx);

  // 1. Render Table Rows
  if (pageItems.length === 0) {
    tbody.innerHTML = `<tr class="placeholder-row"><td colspan="8">${total === 0 ? 'No security events match the criteria.' : 'No events in buffer.'}</td></tr>`;
  } else {
    tbody.innerHTML = pageItems.map(item => {
      const timeStr = formatDateTime(item.timestamp);
      let levelClass = 'badge-level-info';
      if (item.level >= 12) levelClass = 'badge-level-danger';
      else if (item.level >= 7) levelClass = 'badge-level-warn';

      return `
        <tr>
          <td class="time-cell">${timeStr}</td>
          <td class="ip-cell">${item.source_ip}</td>
          <td class="node-cell">${item.agent}</td>
          <td><span class="badge-level ${levelClass}">${item.level_label}</span></td>
          <td>
            <div class="cat-action-col">
              <span class="badge-cat ${item.parsed.categoryClass}">${item.parsed.categoryLabelShort}</span>
              <span class="badge-act ${item.parsed.actionClass}">${item.parsed.actionLabel}</span>
            </div>
          </td>
          <td class="desc-cell-wrap">
            <div class="event-desc-wrapper">
              <div class="capture-tags-row">
                ${item.parsed.tagsHtml}
              </div>
              <div class="desc-line" title="${escapeHtml(item.parsed.summaryText || item.desc)}">
                ${escapeHtml(item.parsed.summaryText || item.desc)}
              </div>
            </div>
          </td>
          <td><span class="mitre-badge">${item.mitre}</span></td>
          <td><button class="btn-action" onclick="inspectEventById(${item.id})">Inspect</button></td>
        </tr>
      `;
    }).join('');
  }

  // 2. Render Pagination Info
  if (infoEl) {
    if (total === 0) {
      infoEl.textContent = `Showing 0 of 0 events`;
    } else {
      const isFiltered = total !== state.eventsList.length;
      infoEl.innerHTML = `Showing <strong>${startIdx + 1}&ndash;${endIdx}</strong> of <strong>${total.toLocaleString()}</strong> events` +
        (isFiltered ? ` <span style="color:#64748b;">(filtered from ${state.eventsList.length.toLocaleString()})</span>` : ``);
    }
  }

  // 3. Render Pagination Buttons
  if (controlsEl) {
    controlsEl.innerHTML = buildPaginationButtons(currentPage, totalPages, 'setEventsPage');
  }
}

function buildPaginationButtons(currentPage, totalPages, callbackName) {
  if (totalPages <= 1) {
    return `
      <button class="page-btn" disabled title="First Page">&laquo;</button>
      <button class="page-btn" disabled title="Previous Page">&lsaquo;</button>
      <button class="page-btn active" disabled>1</button>
      <button class="page-btn" disabled title="Next Page">&rsaquo;</button>
      <button class="page-btn" disabled title="Last Page">&raquo;</button>
    `;
  }

  let html = '';

  // First & Previous Buttons
  html += `<button class="page-btn" ${currentPage === 1 ? 'disabled' : ''} onclick="${callbackName}(1)" title="First Page">&laquo;</button>`;
  html += `<button class="page-btn" ${currentPage === 1 ? 'disabled' : ''} onclick="${callbackName}(${currentPage - 1})" title="Previous Page">&lsaquo;</button>`;

  // Smart Page Numbers Window
  const delta = 2;
  const left = currentPage - delta;
  const right = currentPage + delta + 1;
  const range = [];
  const rangeWithDots = [];
  let l;

  for (let i = 1; i <= totalPages; i++) {
    if (i === 1 || i === totalPages || (i >= left && i < right)) {
      range.push(i);
    }
  }

  for (const i of range) {
    if (l) {
      if (i - l === 2) {
        rangeWithDots.push(l + 1);
      } else if (i - l !== 1) {
        rangeWithDots.push('...');
      }
    }
    rangeWithDots.push(i);
    l = i;
  }

  rangeWithDots.forEach(p => {
    if (p === '...') {
      html += `<span class="page-ellipsis">&hellip;</span>`;
    } else {
      html += `<button class="page-btn ${p === currentPage ? 'active' : ''}" onclick="${callbackName}(${p})">${p}</button>`;
    }
  });

  // Next & Last Buttons
  html += `<button class="page-btn" ${currentPage === totalPages ? 'disabled' : ''} onclick="${callbackName}(${currentPage + 1})" title="Next Page">&rsaquo;</button>`;
  html += `<button class="page-btn" ${currentPage === totalPages ? 'disabled' : ''} onclick="${callbackName}(${totalPages})" title="Last Page">&raquo;</button>`;

  return html;
}

window.setEventsPage = function(page) {
  const total = getFilteredEvents().length;
  const totalPages = Math.max(1, Math.ceil(total / state.eventsPagination.pageSize));
  if (page < 1) page = 1;
  if (page > totalPages) page = totalPages;

  state.eventsPagination.currentPage = page;
  renderEventsTable();
};

function jumpToNewestEvents() {
  state.eventsPagination.currentPage = 1;
  state.eventsPagination.pendingNewCount = 0;
  updateNewEventsToast();
  renderEventsTable();
}

function updateNewEventsToast() {
  const toast = document.getElementById('newEventsNotice');
  const countEl = document.getElementById('newEventsCount');
  if (!toast || !countEl) return;

  if (state.eventsPagination.pendingNewCount > 0) {
    countEl.textContent = state.eventsPagination.pendingNewCount;
    toast.classList.remove('hidden');
  } else {
    toast.classList.add('hidden');
  }
}

// Live Stream Toggle Handler
const btnToggleLive = document.getElementById('btnToggleLive');
if (btnToggleLive) {
  btnToggleLive.addEventListener('click', () => {
    state.eventsPagination.isLivePaused = !state.eventsPagination.isLivePaused;
    const isPaused = state.eventsPagination.isLivePaused;

    if (isPaused) {
      btnToggleLive.classList.remove('active');
      document.getElementById('liveBtnText').textContent = 'Stream Paused';
      document.getElementById('topStreamStatus').textContent = 'STREAM PAUSED';
      document.getElementById('topStreamDot').style.backgroundColor = 'var(--color-warning)';
    } else {
      btnToggleLive.classList.add('active');
      document.getElementById('liveBtnText').textContent = 'Live Stream';
      document.getElementById('topStreamStatus').textContent = 'LIVE STREAM';
      document.getElementById('topStreamDot').style.backgroundColor = 'var(--color-success)';

      if (state.eventsPagination.pendingNewCount > 0) {
        jumpToNewestEvents();
      }
    }
  });
}

// Refresh Buffer Button
const btnRefreshLogs = document.getElementById('btnRefreshLogs');
if (btnRefreshLogs) {
  btnRefreshLogs.addEventListener('click', async () => {
    btnRefreshLogs.disabled = true;
    await loadInitialLogs();
    btnRefreshLogs.disabled = false;
  });
}

// Search Filter Input Listener with 150ms Debounce
const logFilterInput = document.getElementById('logFilter');
const clearLogFilterBtn = document.getElementById('clearLogFilterBtn');
let searchDebounceTimer = null;

if (logFilterInput) {
  logFilterInput.addEventListener('input', (e) => {
    const val = e.target.value;
    if (clearLogFilterBtn) {
      if (val) clearLogFilterBtn.classList.remove('hidden');
      else clearLogFilterBtn.classList.add('hidden');
    }
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
      state.eventsPagination.searchQuery = val;
      state.eventsPagination.currentPage = 1;
      renderEventsTable();
    }, 150);
  });
}

if (clearLogFilterBtn) {
  clearLogFilterBtn.addEventListener('click', () => {
    logFilterInput.value = '';
    state.eventsPagination.searchQuery = '';
    clearLogFilterBtn.classList.add('hidden');
    state.eventsPagination.currentPage = 1;
    renderEventsTable();
  });
}

// Security Events Category Pills Listener
document.querySelectorAll('#eventsCategoryPills .pill-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#eventsCategoryPills .pill-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    state.eventsPagination.categoryFilter = btn.dataset.category || 'ALL';
    state.eventsPagination.currentPage = 1;
    renderEventsTable();
  });
});

// Severity Pills Listener
document.querySelectorAll('.filter-pills .pill-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-pills .pill-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    state.eventsPagination.severityFilter = btn.dataset.severity || 'ALL';
    state.eventsPagination.currentPage = 1;
    renderEventsTable();
  });
});

// Page Size Selector Listener
const eventsPageSizeSelect = document.getElementById('eventsPageSize');
if (eventsPageSizeSelect) {
  eventsPageSizeSelect.addEventListener('change', (e) => {
    state.eventsPagination.pageSize = parseInt(e.target.value, 10) || 25;
    state.eventsPagination.currentPage = 1;
    renderEventsTable();
  });
}

// ==========================================================================
// OVERVIEW OBSERVABILITY CONSOLE (HIGH DENSITY STREAM)
// ==========================================================================
const overviewExpandedRowIds = new Set();

window.toggleOverviewRow = function(id) {
  if (overviewExpandedRowIds.has(id)) {
    overviewExpandedRowIds.delete(id);
  } else {
    overviewExpandedRowIds.add(id);
  }
  renderOverviewRecentEvents();
};

function getFilteredOverviewEvents() {
  let list = state.eventsList;

  // Filter Type Chip
  const fType = state.overviewPagination.filterType;
  if (fType === 'UFW') {
    list = list.filter(e => e.parsed?.category === 'UFW');
  } else if (fType === 'SPAM') {
    list = list.filter(e => e.parsed?.category === 'AUTH_SPAM' || e.parsed?.category === 'WEB_ATTACK');
  } else if (fType === 'AUTH' || fType === 'SSH') {
    list = list.filter(e => e.parsed?.category === 'AUTH');
  } else if (fType === 'WEB' || fType === 'NGINX') {
    list = list.filter(e => e.parsed?.category === 'WEB' || e.parsed?.category === 'WEB_ATTACK');
  } else if (fType === 'INFO') {
    list = list.filter(e => e.parsed?.category === 'INFO' || e.parsed?.category === 'PACKAGE');
  } else if (fType === 'FAIL2BAN') {
    list = list.filter(e => e.parsed?.category === 'FAIL2BAN');
  } else if (fType === 'SYSTEM') {
    list = list.filter(e => e.parsed?.category === 'SYSTEM');
  } else if (fType === 'ERRORS') {
    list = list.filter(e => (e.status_code >= 400) || (e.parsed?.captured?.statusCode >= 400));
  } else if (fType === 'THREATS') {
    list = list.filter(e => e.level >= 7);
  }

  // Search Query
  const q = state.overviewPagination.searchQuery.toLowerCase().trim();
  if (q) {
    list = list.filter(e => {
      const p = e.parsed;
      const targetStr = `${e.source_ip} ${e.agent} ${e.desc} ${e.mitre} ${e.status_code || ''} ${e.raw?.service || ''} ${e.raw?.method || ''} ${p?.category || ''} ${p?.categoryLabel || ''} ${p?.actionLabel || ''} ${p?.captured?.port || ''} ${p?.captured?.sourcePort || ''} ${p?.captured?.user || ''} ${p?.captured?.endpoint || ''} ${p?.captured?.protocol || ''} ${p?.captured?.interface || ''} ${p?.captured?.process || ''} ${p?.captured?.reason || ''} ${e.raw?.message || ''}`.toLowerCase();
      return targetStr.includes(q);
    });
  }

  return list;
}

// Overview Recent Events with Full Pagination & Row Expansion
function renderOverviewRecentEvents() {
  const tbody = document.getElementById('overviewRecentEventsBody');
  const infoEl = document.getElementById('overviewPaginationInfo');
  const controlsEl = document.getElementById('overviewPaginationControls');
  if (!tbody) return;

  const filtered = getFilteredOverviewEvents();
  const total = filtered.length;
  const pageSize = state.overviewPagination.pageSize;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  if (state.overviewPagination.currentPage > totalPages) {
    state.overviewPagination.currentPage = totalPages;
  }
  const currentPage = state.overviewPagination.currentPage;

  const startIdx = total === 0 ? 0 : (currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, total);
  const pageItems = filtered.slice(startIdx, endIdx);

  if (pageItems.length === 0) {
    tbody.innerHTML = `<tr class="placeholder-row"><td colspan="9">${total === 0 ? 'No events match the active filter criteria.' : 'Awaiting live event stream...'}</td></tr>`;
  } else {
    let rowsHtml = '';
    pageItems.forEach(item => {
      const isExpanded = overviewExpandedRowIds.has(item.id);
      const timeStr = formatDateTime(item.timestamp);
      let levelClass = 'badge-level-info';
      if (item.level >= 12) levelClass = 'badge-level-danger';
      else if (item.level >= 7) levelClass = 'badge-level-warn';

      rowsHtml += `
        <tr class="log-row ${isExpanded ? 'expanded' : ''}" onclick="toggleOverviewRow(${item.id})">
          <td>
            <button class="expand-btn ${isExpanded ? 'open' : ''}" onclick="event.stopPropagation(); toggleOverviewRow(${item.id})" title="Toggle inline details">&#9656;</button>
          </td>
          <td class="time-cell">${timeStr}</td>
          <td class="ip-cell">${item.source_ip}</td>
          <td class="node-cell">${item.agent}</td>
          <td><span class="badge-level ${levelClass}">${item.level_label}</span></td>
          <td>
            <div class="cat-action-col">
              <span class="badge-cat ${item.parsed.categoryClass}">${item.parsed.categoryLabelShort}</span>
              <span class="badge-act ${item.parsed.actionClass}">${item.parsed.actionLabel}</span>
            </div>
          </td>
          <td class="desc-cell-wrap">
            <div class="event-desc-wrapper">
              <div class="capture-tags-row">
                ${item.parsed.tagsHtml}
              </div>
              <div class="desc-line" title="${escapeHtml(item.parsed.summaryText || item.desc)}">
                ${escapeHtml(item.parsed.summaryText || item.desc)}
              </div>
            </div>
          </td>
          <td><span class="mitre-badge">${item.mitre}</span></td>
          <td><button class="btn-action" onclick="event.stopPropagation(); inspectEventById(${item.id})">Inspect</button></td>
        </tr>
      `;

      if (isExpanded) {
        rowsHtml += `
          <tr class="log-detail-row">
            <td colspan="9">
              <div class="log-detail-content">
                <div class="log-detail-header-badge">
                  <span class="badge-cat ${item.parsed.categoryClass}">${item.parsed.categoryLabel}</span>
                  <span class="badge-act ${item.parsed.actionClass}">${item.parsed.actionLabel}</span>
                  <span style="color:var(--text-muted); font-size:11px; margin-left:8px;">${escapeHtml(item.parsed.summaryText)}</span>
                </div>
                <div class="log-detail-grid">
                  <div><span class="detail-k">Category:</span> <span class="detail-v">${item.parsed.categoryLabel}</span></div>
                  <div><span class="detail-k">Captured Action:</span> <span class="detail-v">${item.parsed.actionLabel}</span></div>
                  <div><span class="detail-k">Target Port &amp; Proto:</span> <span class="detail-v">${item.parsed.captured.port ? (item.parsed.captured.protocol ? item.parsed.captured.protocol + '/' : '') + item.parsed.captured.port + (item.parsed.captured.portService ? ' (' + item.parsed.captured.portService + ')' : '') : (item.parsed.captured.protocol || '-')}</span></div>
                  <div><span class="detail-k">Source / Client Port:</span> <span class="detail-v">${item.parsed.captured.sourcePort || '-'}</span></div>
                  <div><span class="detail-k">Target User / Identity:</span> <span class="detail-v">${item.parsed.captured.user ? escapeHtml(item.parsed.captured.user) : '-'}</span></div>
                  <div><span class="detail-k">Inbound Interface:</span> <span class="detail-v">${item.parsed.captured.interface ? escapeHtml(item.parsed.captured.interface) : '-'}</span></div>
                  <div><span class="detail-k">URI / Command / Process:</span> <span class="detail-v">${item.parsed.captured.endpoint || item.parsed.captured.process ? escapeHtml(item.parsed.captured.endpoint || item.parsed.captured.process) : '-'}</span></div>
                  <div><span class="detail-k">Capture Trigger / Reason:</span> <span class="detail-v">${item.parsed.captured.reason ? escapeHtml(item.parsed.captured.reason) : '-'}</span></div>
                  <div><span class="detail-k">MITRE Attack:</span> <span class="detail-v">${item.mitre}</span></div>
                  <div><span class="detail-k">Timestamp:</span> <span class="detail-v">${item.timestamp}</span></div>
                  <div><span class="detail-k">Source IP:</span> <span class="detail-v">${item.source_ip}</span></div>
                  <div><span class="detail-k">Monitored Node:</span> <span class="detail-v">${item.agent}</span></div>
                  <div><span class="detail-k">Collector Service:</span> <span class="detail-v">${escapeHtml(item.raw?.service || '-')}</span></div>
                </div>
                <div class="log-detail-raw">
                  <span class="detail-k">Raw Message Payload:</span>
                  <pre>${escapeHtml(item.raw?.message || item.desc)}</pre>
                </div>
              </div>
            </td>
          </tr>
        `;
      }
    });
    tbody.innerHTML = rowsHtml;
  }

  // Update Overview Pagination Info
  if (infoEl) {
    if (total === 0) {
      infoEl.textContent = 'Showing 0 of 0 events';
    } else {
      const isFiltered = total !== state.eventsList.length;
      infoEl.innerHTML = `Showing <strong>${startIdx + 1}&ndash;${endIdx}</strong> of <strong>${total.toLocaleString()}</strong> events` +
        (isFiltered ? ` <span style="color:#64748b;">(filtered from ${state.eventsList.length.toLocaleString()})</span>` : ``);
    }
  }

  // Update Overview Pagination Controls
  if (controlsEl) {
    controlsEl.innerHTML = buildPaginationButtons(currentPage, totalPages, 'setOverviewPage');
  }
}

function updateOverviewPaginationOnly() {
  const infoEl = document.getElementById('overviewPaginationInfo');
  const controlsEl = document.getElementById('overviewPaginationControls');
  const filtered = getFilteredOverviewEvents();
  const total = filtered.length;
  const pageSize = state.overviewPagination.pageSize;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = state.overviewPagination.currentPage;
  const startIdx = total === 0 ? 0 : (currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, total);

  if (infoEl) {
    if (total === 0) {
      infoEl.textContent = 'Showing 0 of 0 events';
    } else {
      infoEl.innerHTML = `Showing <strong>${startIdx + 1}&ndash;${endIdx}</strong> of <strong>${total.toLocaleString()}</strong> events`;
    }
  }
  if (controlsEl) {
    controlsEl.innerHTML = buildPaginationButtons(currentPage, totalPages, 'setOverviewPage');
  }
}

window.setOverviewPage = function(page) {
  const filtered = getFilteredOverviewEvents();
  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / state.overviewPagination.pageSize));
  if (page < 1) page = 1;
  if (page > totalPages) page = totalPages;

  state.overviewPagination.currentPage = page;
  renderOverviewRecentEvents();
};

const overviewPageSizeSelect = document.getElementById('overviewPageSize');
if (overviewPageSizeSelect) {
  overviewPageSizeSelect.addEventListener('change', (e) => {
    state.overviewPagination.pageSize = parseInt(e.target.value, 10) || 25;
    state.overviewPagination.currentPage = 1;
    renderOverviewRecentEvents();
  });
}

// Overview Quick Filter Chips
document.querySelectorAll('.quick-filter-chips .filter-chip').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.quick-filter-chips .filter-chip').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.overviewPagination.filterType = btn.dataset.filter || 'ALL';
    state.overviewPagination.currentPage = 1;
    renderOverviewRecentEvents();
  });
});

// Overview Search Input with debounce
const overviewLogFilter = document.getElementById('overviewLogFilter');
const overviewClearFilterBtn = document.getElementById('overviewClearFilterBtn');
let overviewSearchDebounce = null;

if (overviewLogFilter) {
  overviewLogFilter.addEventListener('input', (e) => {
    const val = e.target.value;
    if (overviewClearFilterBtn) {
      if (val) overviewClearFilterBtn.classList.remove('hidden');
      else overviewClearFilterBtn.classList.add('hidden');
    }
    clearTimeout(overviewSearchDebounce);
    overviewSearchDebounce = setTimeout(() => {
      state.overviewPagination.searchQuery = val;
      state.overviewPagination.currentPage = 1;
      renderOverviewRecentEvents();
    }, 150);
  });
}

if (overviewClearFilterBtn) {
  overviewClearFilterBtn.addEventListener('click', () => {
    overviewLogFilter.value = '';
    overviewClearFilterBtn.classList.add('hidden');
    state.overviewPagination.searchQuery = '';
    state.overviewPagination.currentPage = 1;
    renderOverviewRecentEvents();
  });
}

// Overview Live Stream Toggle
const btnOverviewToggleLive = document.getElementById('btnOverviewToggleLive');
if (btnOverviewToggleLive) {
  btnOverviewToggleLive.addEventListener('click', () => {
    state.overviewPagination.isLivePaused = !state.overviewPagination.isLivePaused;
    const isPaused = state.overviewPagination.isLivePaused;
    if (isPaused) {
      btnOverviewToggleLive.classList.remove('active');
      const textEl = document.getElementById('overviewLiveBtnText');
      if (textEl) textEl.textContent = 'Stream Paused';
    } else {
      btnOverviewToggleLive.classList.add('active');
      const textEl = document.getElementById('overviewLiveBtnText');
      if (textEl) textEl.textContent = 'Live Stream';
      renderOverviewRecentEvents();
    }
  });
}

// Overview Refresh Button
const btnOverviewRefresh = document.getElementById('btnOverviewRefresh');
if (btnOverviewRefresh) {
  btnOverviewRefresh.addEventListener('click', async () => {
    btnOverviewRefresh.disabled = true;
    await loadInitialLogs();
    btnOverviewRefresh.disabled = false;
  });
}

// ==========================================================================
// INBOUND IP TRAFFIC TRACKER WITH PAGINATION
// ==========================================================================
function updateOrAddIPRecord(rec, shouldRender = true) {
  state.ipRecords.set(rec.ip, rec);
  if (shouldRender) renderIPTable();
}

function getFilteredIPs() {
  const list = Array.from(state.ipRecords.values()).sort((a, b) => (b.request_count || 0) - (a.request_count || 0));
  const q = state.ipsPagination.searchQuery.toLowerCase().trim();
  if (!q) return list;

  return list.filter(r => {
    const str = `${r.ip} ${r.hostname || ''} ${r.category || ''} ${r.status || ''} ${r.threat_level || ''}`.toLowerCase();
    return str.includes(q);
  });
}

function renderIPTable() {
  const ipTableBody = document.getElementById('ipTableBody');
  const overviewIpSummary = document.getElementById('overviewIpSummary');
  const containmentList = document.getElementById('containmentList');
  const infoEl = document.getElementById('ipPaginationInfo');
  const controlsEl = document.getElementById('ipPaginationControls');

  const allIPs = Array.from(state.ipRecords.values()).sort((a, b) => (b.request_count || 0) - (a.request_count || 0));

  // Update Global IP Counters
  const totalUnique = allIPs.length;
  let totalReqs = 0;
  let flaggedCount = 0;
  let blockedCount = 0;

  allIPs.forEach(r => {
    totalReqs += r.request_count || 1;
    if (r.threat_level === "Critical" || r.threat_level === "Suspicious") flaggedCount++;
    if (r.status && r.status.includes("Blocked")) blockedCount++;
  });

  const uniqueIpsCountEl = document.getElementById('uniqueIpsCount');
  if (uniqueIpsCountEl) uniqueIpsCountEl.textContent = totalUnique;

  const navIpCountEl = document.getElementById('navIpCount');
  if (navIpCountEl) navIpCountEl.textContent = totalUnique;

  const ipTabTotalCountEl = document.getElementById('ipTabTotalCount');
  if (ipTabTotalCountEl) ipTabTotalCountEl.textContent = totalUnique;

  const ipTabTotalRequestsEl = document.getElementById('ipTabTotalRequests');
  if (ipTabTotalRequestsEl) ipTabTotalRequestsEl.textContent = totalReqs.toLocaleString();

  const ipTabFlaggedCountEl = document.getElementById('ipTabFlaggedCount');
  if (ipTabFlaggedCountEl) ipTabFlaggedCountEl.textContent = flaggedCount;

  const ipTabBlockedCountEl = document.getElementById('ipTabBlockedCount');
  if (ipTabBlockedCountEl) ipTabBlockedCountEl.textContent = blockedCount;

  const navBlockedCountEl = document.getElementById('navBlockedCount');
  if (navBlockedCountEl) navBlockedCountEl.textContent = blockedCount;

  const containmentBadgeCountEl = document.getElementById('containmentBadgeCount');
  if (containmentBadgeCountEl) containmentBadgeCountEl.textContent = `${blockedCount} Blocked`;

  // Render Overview Top 5 IPs
  if (overviewIpSummary) {
    if (allIPs.length > 0) {
      overviewIpSummary.innerHTML = allIPs.slice(0, 5).map(r => `
        <div class="mini-row">
          <div class="mini-row-left">
            <span class="mini-ip-addr">${r.ip}</span>
            <span class="mini-platform">(${r.hostname || 'node'})</span>
          </div>
          <div>
            <span class="mini-req-count">${(r.request_count || 1).toLocaleString()} reqs</span>
          </div>
        </div>
      `).join('');
    } else {
      overviewIpSummary.innerHTML = `<div class="empty-state-mini">No incoming IP requests recorded yet.</div>`;
    }
  }

  // Render Containment Tab
  if (containmentList) {
    const blockedIps = allIPs.filter(r => r.status && r.status.includes("Blocked"));
    if (blockedIps.length > 0) {
      containmentList.innerHTML = blockedIps.map(r => `
        <div class="containment-item">
          <div class="containment-meta">
            <strong class="containment-ip">${r.ip}</strong>
            <span class="containment-rule">Rule: iptables -I INPUT -s ${r.ip} -j DROP</span>
          </div>
          ${isAdmin() ? `<button class="btn-action" onclick="toggleBlockIP('${r.ip}')">Unblock</button>` : ''}
        </div>
      `).join('');
    } else {
      containmentList.innerHTML = `<div class="empty-state">No IP addresses currently under quarantine or blocked.</div>`;
    }
  }

  // Filter & Paginate IP Table
  if (!ipTableBody) return;

  const filtered = getFilteredIPs();
  const total = filtered.length;
  const pageSize = state.ipsPagination.pageSize;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  if (state.ipsPagination.currentPage > totalPages) {
    state.ipsPagination.currentPage = totalPages;
  }
  const currentPage = state.ipsPagination.currentPage;

  const startIdx = total === 0 ? 0 : (currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, total);
  const pageItems = filtered.slice(startIdx, endIdx);

  if (pageItems.length === 0) {
    ipTableBody.innerHTML = `<tr class="placeholder-row"><td colspan="8">No source IP addresses registered yet.</td></tr>`;
  } else {
    ipTableBody.innerHTML = pageItems.map(r => {
      const firstTime = formatDateTime(r.first_seen);
      const lastTime = formatDateTime(r.last_seen);

      let threatClass = 'badge-level-info';
      if (r.threat_level === 'Critical') threatClass = 'badge-level-danger';
      else if (r.threat_level === 'Suspicious') threatClass = 'badge-level-warn';

      const isBlocked = r.status && r.status.includes("Blocked");
      const statusClass = isBlocked ? 'status-blocked' : 'status-monitored';
      const actionBtnText = isBlocked ? 'Unblock' : 'Block (iptables)';
      const btnDanger = isBlocked ? '' : 'btn-danger';

      return `
        <tr>
          <td class="ip-cell">${r.ip}</td>
          <td class="node-cell">${r.hostname || '-'}</td>
          <td>${r.category || 'General Inbound'}</td>
          <td><span class="mini-req-count">${(r.request_count || 1).toLocaleString()} reqs</span></td>
          <td class="time-cell">${firstTime}</td>
          <td class="time-cell">${lastTime}</td>
          <td><span class="badge-level ${threatClass}">${r.threat_level || 'Normal'}</span></td>
          <td>
            <span class="badge-status ${statusClass}">${r.status || 'Monitored'}</span>
            ${isAdmin() ? `<button class="btn-action ${btnDanger}" style="margin-left: 8px;" onclick="toggleBlockIP('${r.ip}')">${actionBtnText}</button>` : ''}
          </td>
        </tr>
      `;
    }).join('');
  }

  // Render IP Pagination Info & Controls
  if (infoEl) {
    if (total === 0) {
      infoEl.textContent = `Showing 0 of 0 IP addresses`;
    } else {
      infoEl.innerHTML = `Showing <strong>${startIdx + 1}&ndash;${endIdx}</strong> of <strong>${total}</strong> IP addresses`;
    }
  }

  if (controlsEl) {
    controlsEl.innerHTML = buildPaginationButtons(currentPage, totalPages, 'setIPPage');
  }
}

window.setIPPage = function(page) {
  const total = getFilteredIPs().length;
  const totalPages = Math.max(1, Math.ceil(total / state.ipsPagination.pageSize));
  if (page < 1) page = 1;
  if (page > totalPages) page = totalPages;

  state.ipsPagination.currentPage = page;
  renderIPTable();
};

const ipFilterInput = document.getElementById('ipFilterInput');
if (ipFilterInput) {
  ipFilterInput.addEventListener('input', (e) => {
    state.ipsPagination.searchQuery = e.target.value;
    state.ipsPagination.currentPage = 1;
    renderIPTable();
  });
}

const ipPageSizeSelect = document.getElementById('ipPageSize');
if (ipPageSizeSelect) {
  ipPageSizeSelect.addEventListener('change', (e) => {
    state.ipsPagination.pageSize = parseInt(e.target.value, 10) || 15;
    state.ipsPagination.currentPage = 1;
    renderIPTable();
  });
}

async function toggleBlockIP(ip) {
  if (!isAdmin()) {
    alert('Akses ditolak: hanya role admin yang boleh mengubah aturan containment.');
    return;
  }
  try {
    const res = await authFetch('/api/v1/containment/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip })
    });
    if (res.ok) {
      const data = await res.json();
      const rec = state.ipRecords.get(ip);
      if (rec) {
        rec.status = data.current_status;
        renderIPTable();
      }
    }
  } catch (err) {
    alert("Gagal mengubah status firewall iptables: " + err);
  }
}

// ==========================================================================
// AGENTS FLEET TELEMETRY LOGIC
// ==========================================================================
function refreshAgentFleetCounts() {
  const now = Date.now();
  let onlineCount = 0;
  state.activeAgents.forEach(agent => {
    if (now - agent.lastSeen < 20000) {
      onlineCount++;
    }
  });
  const totalCount = state.activeAgents.size;

  const activeCountEl = document.getElementById('activeAgentsCount');
  if (activeCountEl) activeCountEl.textContent = onlineCount;

  const navAgentCountEl = document.getElementById('navAgentCount');
  if (navAgentCountEl) navAgentCountEl.textContent = onlineCount;

  const fleetSubtextEl = document.getElementById('agentFleetSubtext');
  if (fleetSubtextEl) {
    if (totalCount === 0) {
      fleetSubtextEl.textContent = "Active Nodes";
    } else if (onlineCount === totalCount) {
      fleetSubtextEl.textContent = onlineCount > 1 ? `Active Nodes (${totalCount} Total)` : `Active Node (${totalCount} Total)`;
    } else {
      fleetSubtextEl.innerHTML = `/ ${totalCount} Active (<span style="color:var(--color-danger);">${totalCount - onlineCount} offline</span>)`;
    }
  }

  const tagsEl = document.getElementById('agentTagsSummary');
  if (tagsEl) {
    if (totalCount === 0) {
      tagsEl.textContent = "Waiting for node heartbeats...";
    } else if (onlineCount === totalCount) {
      tagsEl.innerHTML = `<span style="color:var(--color-success);">&bull; All ${totalCount} nodes reporting</span>`;
    } else {
      tagsEl.innerHTML = `<span style="color:var(--color-danger);">&bull; ${onlineCount}/${totalCount} nodes online (${totalCount - onlineCount} offline)</span>`;
    }
    // Tooltip showing active hostnames
    const hostList = Array.from(state.activeAgents.values()).map(i => i.data.hostname).join(', ');
    tagsEl.title = `Cluster Nodes: ${hostList}`;
  }
}

function renderOverviewFleetSummary() {
  const overviewFleetSummary = document.getElementById('overviewFleetSummary');
  if (!overviewFleetSummary) return;

  if (state.activeAgents.size === 0) {
    overviewFleetSummary.innerHTML = `<div class="empty-state-mini">No agent heartbeats recorded yet.</div>`;
    return;
  }

  const now = Date.now();
  overviewFleetSummary.innerHTML = Array.from(state.activeAgents.values()).map(item => {
    const isOnline = (now - item.lastSeen) < 20000;
    const ipLabel = item.data.source_ip && !item.data.source_ip.startsWith('127.') ? ` [${item.data.source_ip}]` : '';
    return `
      <div class="mini-row ${isOnline ? '' : 'is-offline'}">
        <div class="mini-row-left">
          <span class="status-pill ${isOnline ? 'online' : 'offline'}">
            <span class="status-dot"></span>
            ${isOnline ? 'Online' : 'Offline'}
          </span>
          <strong class="mini-host">${item.data.hostname}${ipLabel}</strong>
          <span class="mini-platform">${item.data.platform || 'Linux'}</span>
        </div>
        <div class="mini-row-metrics">
          <span>CPU: <strong class="metric-accent">${(item.data.cpu_usage || 0).toFixed(1)}%</strong></span>
          <span class="metric-divider">|</span>
          <span>RAM: <strong class="metric-accent-green">${(item.data.ram_used_pct || 0).toFixed(1)}%</strong></span>
          ${item.data.agent_mem_mb ? `<span class="metric-divider">|</span><span>Agent: <strong class="metric-accent-green">${item.data.agent_mem_mb.toFixed(1)}M</strong></span>` : ''}
          ${item.data.latency_ms && item.data.latency_ms > 0 ? `<span class="metric-divider">|</span><span>Ping: <strong class="metric-accent" style="color:var(--color-info);">${item.data.latency_ms.toFixed(1)}ms</strong></span>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

// Periodic check to mark inactive agents as offline without needing page reload
setInterval(() => {
  refreshAgentFleetCounts();
  renderOverviewFleetSummary();
}, 5000);

function updateAgentFleet(d, shouldRender = true) {
  const agentKey = d.agent_id || (d.hostname ? `${d.hostname}-${d.source_ip || 'local'}` : "unknown");
  state.activeAgents.set(agentKey, {
    lastSeen: Date.now(),
    data: d
  });

  refreshAgentFleetCounts();
  renderOverviewFleetSummary();

  if (shouldRender) renderFleetCards();
}

function renderFleetCards() {
  const fleetGrid = document.getElementById('fleetGrid');
  if (!fleetGrid) return;

  if (state.activeAgents.size === 0) {
    fleetGrid.innerHTML = `<div class="empty-state">Waiting for agent nodes to transmit telemetry data...</div>`;
    return;
  }

  const now = Date.now();
  fleetGrid.innerHTML = Array.from(state.activeAgents.values()).map(item => {
    const d = item.data;
    const cpu = d.cpu_usage || 0;
    const ramPct = d.ram_used_pct || 0;
    const disk = d.disk_used_pct || 0;
    const isOnline = (now - item.lastSeen) < 20000;

    const getMeterColor = (pct) => pct >= 85 ? 'danger' : (pct >= 70 ? 'warn' : '');

    const uptimeStr = d.uptime_sec
      ? `${Math.floor(d.uptime_sec / 3600)}h ${Math.floor((d.uptime_sec % 3600) / 60)}m`
      : '-';

    const agentKey = d.agent_id || d.hostname;

    return `
      <div class="fleet-card" id="agent-card-${agentKey}">
        <div class="agent-title-row">
          <div>
            <div class="agent-name">${d.hostname}</div>
            <div class="agent-sub-meta">
              IP: ${d.source_ip || '127.0.0.1'} &bull; ${d.platform || 'Linux'}${d.agent_mem_mb ? ` &bull; <span style="color:var(--color-success);font-weight:600;">Agent: ${d.agent_mem_mb.toFixed(1)} MB</span>` : ''}${d.latency_ms > 0 ? ` &bull; <span style="color:var(--color-info);font-weight:600;">Ping: ${d.latency_ms.toFixed(1)} ms</span>` : ''}
            </div>
          </div>
          <div class="agent-header-actions">
            ${isAdmin() ? `
              <button class="btn-shell-terminal" onclick="openRemoteShell('${agentKey}', '${d.source_ip || ''}')" title="Buka Remote SSH Console (Admin Only)">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="4 17 10 11 4 5"/>
                  <line x1="12" y1="19" x2="20" y2="19"/>
                </svg>
              </button>
            ` : ''}
            <span class="status-pill ${isOnline ? 'online' : 'offline'}">
              <span class="status-dot"></span>
              ${isOnline ? 'Active' : 'Offline'}
            </span>
            ${isAdmin() ? `<button class="btn-remove-node" onclick="removeFleetAgent('${agentKey}')" title="Hapus node ini dari monitoring">&times;</button>` : ''}
          </div>
        </div>

        <div class="meter-group">
          <div class="meter-row">
            <div class="meter-labels">
              <span>CPU Utilization</span>
              <span class="meter-val">${cpu.toFixed(1)}%</span>
            </div>
            <div class="meter-bar-bg">
              <div class="meter-bar-fill meter-cpu ${getMeterColor(cpu)}" style="width: ${Math.min(cpu, 100)}%;"></div>
            </div>
          </div>

          <div class="meter-row">
            <div class="meter-labels">
              <span>RAM Utilization</span>
              <span class="meter-val">${d.ram_used_mb || 0} / ${d.ram_total_mb || 0} MB <span class="meter-sub">(${ramPct.toFixed(1)}%)</span></span>
            </div>
            <div class="meter-bar-bg">
              <div class="meter-bar-fill meter-ram ${getMeterColor(ramPct)}" style="width: ${Math.min(ramPct, 100)}%;"></div>
            </div>
          </div>

          <div class="meter-row">
            <div class="meter-labels">
              <span>Disk Partition</span>
              <span class="meter-val">${disk.toFixed(1)}%</span>
            </div>
            <div class="meter-bar-bg">
              <div class="meter-bar-fill meter-disk ${getMeterColor(disk)}" style="width: ${Math.min(disk, 100)}%;"></div>
            </div>
          </div>
        </div>

        <div class="agent-card-footer">
          <span><span class="footer-meta-key">Uptime:</span> ${uptimeStr}</span>
          ${d.agent_mem_mb ? `<span><span class="footer-meta-key">Binary RAM:</span> <strong style="color:var(--color-success);font-weight:600;">${d.agent_mem_mb.toFixed(1)} MB</strong></span>` : ''}
          ${d.latency_ms > 0 ? `<span><span class="footer-meta-key">Ping:</span> <strong style="color:var(--color-info);font-weight:600;">${d.latency_ms.toFixed(1)} ms</strong></span>` : ''}
          <span><span class="footer-meta-key">Last Seen:</span> ${formatDateTime(item.lastSeen)}</span>
        </div>
      </div>
    `;
  }).join('');
}

// ==========================================================================
// UTILITY FUNCTIONS
// ==========================================================================
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Hapus node agent dari dashboard dan backend
async function removeFleetAgent(agentId) {
  if (!isAdmin()) {
    alert('Akses ditolak: hanya role admin yang boleh menghapus node.');
    return;
  }
  if (!confirm(`Hapus node "${agentId}" dari monitoring fleet?`)) {
    return;
  }

  // Hapus langsung dari state memori frontend
  state.activeAgents.delete(agentId);
  for (const [k, v] of state.activeAgents.entries()) {
    if (k === agentId || v.data.agent_id === agentId || v.data.hostname === agentId) {
      state.activeAgents.delete(k);
    }
  }
  renderFleetCards();
  refreshAgentFleetCounts();
  renderOverviewFleetSummary();

  try {
    const res = await authFetch(`/api/v1/agents/${encodeURIComponent(agentId)}`, {
      method: 'DELETE'
    });
    if (!res.ok) {
      console.warn("Server response not ok for agent deletion:", res.status);
    }
  } catch (err) {
    console.error("Gagal mengirim request delete agent:", err);
  }
}

// Uji latensi pengiriman & koneksi HTTP node website via /api/v1/probe
async function probeAgentNode(agentKey, ip) {
  const btn = document.getElementById(`btn-probe-${agentKey}`);
  const resultEl = document.getElementById(`probe-result-${agentKey}`);
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `
      <svg class="spin-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
      </svg>
      <span>Testing...</span>
    `;
  }
  if (resultEl) {
    resultEl.innerHTML = `<span class="probe-loading">Probing ${escapeHtml(ip)}...</span>`;
  }

  const targetUrl = (ip.startsWith('http://') || ip.startsWith('https://')) ? ip : `http://${ip}`;

  try {
    const res = await authFetch('/api/v1/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });
    const data = await res.json();
    state.nodeProbeResults.set(agentKey, data);
    renderFleetCards();
  } catch (err) {
    state.nodeProbeResults.set(agentKey, {
      is_up: false,
      error_msg: err.message || 'Request Failed',
      latency_ms: 0
    });
    renderFleetCards();
  }
}

// ==========================================================================
// REMOTE SSH CONSOLE & COMMAND EXECUTION (ADMIN ONLY)
// ==========================================================================
function openRemoteShell(agentId, ip) {
  if (!isAdmin()) {
    alert("Akses ditolak: Hanya role admin yang diizinkan membuka Remote SSH Console.");
    return;
  }

  state.currentSshAgent = { id: agentId, ip: ip || '-' };

  const modal = document.getElementById('sshModal');
  const title = document.getElementById('sshModalTitle');
  const sub = document.getElementById('sshModalSub');
  const session = document.getElementById('sshSessionInfo');
  const target = document.getElementById('sshFooterTarget');
  const output = document.getElementById('sshTerminalOutput');

  if (title) title.textContent = `Remote SSH Console — ${agentId}`;
  if (sub) sub.textContent = `Target: ${agentId} (${ip || '127.0.0.1'})`;
  if (session) session.textContent = `node: ${agentId}`;
  if (target) target.textContent = ip || agentId;
  if (output) {
    output.textContent = `[READY] Terkoneksi ke sesi dispatcher node: ${agentId}\nPilih perintah terdaftar di atas dan klik [Run Command] untuk eksekusi via SSH.`;
  }

  if (modal) modal.classList.remove('hidden');
}

function closeRemoteShell() {
  const modal = document.getElementById('sshModal');
  if (modal) modal.classList.add('hidden');
  state.currentSshAgent = null;
}

function selectSshPreset(cmdKey) {
  const select = document.getElementById('sshCommandSelect');
  if (select) {
    select.value = cmdKey;
  }

  document.querySelectorAll('.ssh-preset-btn').forEach(btn => {
    if (btn.getAttribute('data-key') === cmdKey) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
}

function syncPresetSelection() {
  const select = document.getElementById('sshCommandSelect');
  if (!select) return;
  const currentVal = select.value;

  document.querySelectorAll('.ssh-preset-btn').forEach(btn => {
    if (btn.getAttribute('data-key') === currentVal) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
}

async function executeRemoteCommand() {
  if (!isAdmin()) {
    alert("Akses ditolak: Hanya role admin yang boleh mengeksekusi perintah remote.");
    return;
  }

  if (!state.currentSshAgent || !state.currentSshAgent.id) {
    alert("Target agent belum dipilih.");
    return;
  }

  const select = document.getElementById('sshCommandSelect');
  const cmdKey = select ? select.value : 'uptime';
  const outputEl = document.getElementById('sshTerminalOutput');
  const runBtn = document.getElementById('btnRunSsh');

  const agentId = state.currentSshAgent.id;
  const agentIp = state.currentSshAgent.ip;

  if (runBtn) {
    runBtn.disabled = true;
    runBtn.innerHTML = `<span class="spin-icon">⟳</span> Executing...`;
  }

  const nowStr = formatDateTime(new Date());
  if (outputEl) {
    outputEl.textContent += `\n\n[${nowStr}] ${agentId}@${agentIp}:~$ exec ${cmdKey}\nMenunggu respon dari target VPS via SSH...`;
    outputEl.scrollTop = outputEl.scrollHeight;
  }

  try {
    const res = await authFetch(`/api/v1/agents/${encodeURIComponent(agentId)}/exec`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command_key: cmdKey })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}: Gagal mengeksekusi perintah`);
    }

    const timeMs = data.execution_time_ms ? `${data.execution_time_ms.toFixed(1)} ms` : '-';
    const exitCode = data.exit_code !== undefined ? data.exit_code : 0;
    const outText = data.output || '(No stdout returned)';

    if (outputEl) {
      outputEl.textContent += `\n${outText}\n[SUCCESS] Selesai dalam ${timeMs} (Exit Code: ${exitCode})`;
      outputEl.scrollTop = outputEl.scrollHeight;
    }
  } catch (err) {
    if (outputEl) {
      outputEl.textContent += `\n[ERROR] ${err.message}\n(Pastikan endpoint backend sudah terpasang dan target VPS dapat dihubungi via SSH)`;
      outputEl.scrollTop = outputEl.scrollHeight;
    }
  } finally {
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        <span>Run Command</span>
      `;
    }
  }
}

function copyTerminalOutput() {
  const outputEl = document.getElementById('sshTerminalOutput');
  if (!outputEl) return;
  navigator.clipboard.writeText(outputEl.textContent).then(() => {
    alert('Output terminal berhasil disalin ke clipboard!');
  }).catch(() => {
    alert('Gagal menyalin output ke clipboard.');
  });
}

function clearTerminalOutput() {
  const outputEl = document.getElementById('sshTerminalOutput');
  if (outputEl) {
    outputEl.textContent = `[CLEARED] Konsol dibersihkan pada ${formatDateTime(new Date())}\n`;
  }
}

// ==========================================================================
// APPLICATION INITIALIZATION
// ==========================================================================
async function initApp() {
  // Kalau token tidak sah, halaman sedang dialihkan ke login — jangan lanjut.
  if (!AUTH_OK) return;

  const userBadge = document.getElementById('userProfileName');
  if (userBadge) {
    userBadge.textContent = `${currentUser} (${currentRole.toUpperCase()})`;
  }

  // Concurrently fetch initial telemetry data
  await Promise.allSettled([
    loadInitialAgents(),
    loadInitialIPs(),
    loadInitialLogs()
  ]);

  // Connect real-time Server-Sent Events stream
  connectSSE();
}

initApp();
