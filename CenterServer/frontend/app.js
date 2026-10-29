// ==========================================================================
// WAZUH-LIGHTWEIGHT SOC DASHBOARD SCRIPT
// Dynamic State Management, 1,000-Log Cap, & Real-Time Pagination
// ==========================================================================

// 1. Authentication Guard
const token = localStorage.getItem('auth_token');
const currentUser = localStorage.getItem('auth_user') || 'Analyst';
const currentRole = localStorage.getItem('auth_role') || 'analyst';

if (!token) {
  window.location.href = '/login.html';
}

function handleLogout() {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('auth_user');
  localStorage.removeItem('auth_role');
  window.location.href = '/login.html';
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
    isLivePaused: false,
    pendingNewCount: 0
  },

  // Overview Recent Events Pagination
  overviewPagination: {
    currentPage: 1,
    pageSize: 10
  },

  // Inbound IP Traffic Pagination & Filtering
  ipsPagination: {
    currentPage: 1,
    pageSize: 15,
    searchQuery: ''
  }
};

// View Titles Mapping
const viewTitles = {
  'view-overview': 'Security Operations Overview',
  'view-fleet': 'Cluster Fleet Node Telemetry',
  'view-ip-traffic': 'Inbound Request IP Tracker',
  'view-events': 'Security Events & Discover Stream',
  'view-containment': 'Zero-Trust Dynamic Containment Engine'
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

if (copyJsonBtn) {
  copyJsonBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(modalJsonContent.textContent).then(() => {
      copyJsonBtn.textContent = 'Copied!';
      setTimeout(() => { copyJsonBtn.textContent = 'Copy JSON'; }, 1500);
    }).catch(err => console.error("Clipboard copy failed:", err));
  });
}

let logIdSeq = 0;

function showJsonModal(data) {
  modalJsonContent.textContent = JSON.stringify(data, null, 2);
  jsonModal.classList.remove('hidden');
}

window.inspectEventById = function(id) {
  const item = state.eventsList.find(e => e.id === id);
  if (item && item.raw) {
    showJsonModal(item.raw);
  }
};

// ==========================================================================
// DATA NORMALIZATION HELPER
// ==========================================================================
function normalizeLogItem(item) {
  const severity = item.severity || (item.event_type === 'auth_failure' ? 7 : 3);
  let levelLabel = "LVL 3 INFO";
  if (severity >= 12) {
    levelLabel = "LVL 12 CRITICAL";
  } else if (severity >= 7) {
    levelLabel = "LVL 7 WARNING";
  }

  let desc = item.rule_desc || item.message || '';
  if (!desc) {
    if (item.event_type) {
      desc = `Event: ${item.event_type} (${item.service || 'service'}${item.user ? ' user:' + item.user : ''})`;
    } else {
      desc = 'HTTP Transaction Recorded';
    }
  }

  let mitre = item.mitre_id;
  if (!mitre) {
    if (severity >= 12) mitre = "T1110.001 Brute Force";
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
    desc: desc,
    mitre: mitre,
    raw: item
  };
}

// ==========================================================================
// INITIAL DATA HYDRATION (FETCH ON LOAD/REFRESH)
// ==========================================================================

// 1. Load Initial Logs from Server Buffer
async function loadInitialLogs() {
  try {
    const res = await fetch(`/api/v1/logs?limit=${MAX_BUFFER_CAP}`);
    if (res.ok) {
      const logs = await res.json();
      if (Array.isArray(logs)) {
        state.eventsList = logs.map(normalizeLogItem);
        state.totalEventsReceived = state.eventsList.length;

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
    const res = await fetch('/api/v1/agents');
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
    const res = await fetch('/api/v1/ips');
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

  const evtSource = new EventSource('/api/v1/stream');

  evtSource.onopen = () => {
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
    if (!state.eventsPagination.isLivePaused && state.overviewPagination.currentPage === 1) {
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
      return (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
             (e.agent && e.agent.toLowerCase().includes(q)) ||
             (e.desc && e.desc.toLowerCase().includes(q)) ||
             (e.mitre && e.mitre.toLowerCase().includes(q)) ||
             (e.level_label && e.level_label.toLowerCase().includes(q));
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
    tbody.innerHTML = `<tr class="placeholder-row"><td colspan="7">${total === 0 ? 'No security events match the criteria.' : 'No events in buffer.'}</td></tr>`;
  } else {
    tbody.innerHTML = pageItems.map(item => {
      const timeStr = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '-';
      let levelClass = 'badge-level-info';
      if (item.level >= 12) levelClass = 'badge-level-danger';
      else if (item.level >= 7) levelClass = 'badge-level-warn';

      return `
        <tr>
          <td class="time-cell">${timeStr}</td>
          <td class="ip-cell">${item.source_ip}</td>
          <td class="node-cell">${item.agent}</td>
          <td><span class="badge-level ${levelClass}">${item.level_label}</span></td>
          <td class="desc-cell" title="${escapeHtml(item.desc)}">${escapeHtml(item.desc)}</td>
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

// Overview Recent Events with Full Pagination
function renderOverviewRecentEvents() {
  const tbody = document.getElementById('overviewRecentEventsBody');
  const infoEl = document.getElementById('overviewPaginationInfo');
  const controlsEl = document.getElementById('overviewPaginationControls');
  if (!tbody) return;

  const total = state.eventsList.length;
  const pageSize = state.overviewPagination.pageSize;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  if (state.overviewPagination.currentPage > totalPages) {
    state.overviewPagination.currentPage = totalPages;
  }
  const currentPage = state.overviewPagination.currentPage;

  const startIdx = total === 0 ? 0 : (currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, total);
  const pageItems = state.eventsList.slice(startIdx, endIdx);

  if (pageItems.length === 0) {
    tbody.innerHTML = `<tr class="placeholder-row"><td colspan="7">Awaiting live event stream...</td></tr>`;
  } else {
    tbody.innerHTML = pageItems.map(item => {
      const timeStr = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '-';
      let levelClass = 'badge-level-info';
      if (item.level >= 12) levelClass = 'badge-level-danger';
      else if (item.level >= 7) levelClass = 'badge-level-warn';

      return `
        <tr>
          <td class="time-cell">${timeStr}</td>
          <td class="ip-cell">${item.source_ip}</td>
          <td class="node-cell">${item.agent}</td>
          <td><span class="badge-level ${levelClass}">${item.level_label}</span></td>
          <td class="desc-cell" title="${escapeHtml(item.desc)}">${escapeHtml(item.desc)}</td>
          <td><span class="mitre-badge">${item.mitre}</span></td>
          <td><button class="btn-action" onclick="inspectEventById(${item.id})">Inspect</button></td>
        </tr>
      `;
    }).join('');
  }

  // Update Overview Pagination Info
  if (infoEl) {
    if (total === 0) {
      infoEl.textContent = 'Showing 0 of 0 events';
    } else {
      infoEl.innerHTML = `Showing <strong>${startIdx + 1}&ndash;${endIdx}</strong> of <strong>${total.toLocaleString()}</strong> events`;
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
  const total = state.eventsList.length;
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
  const total = state.eventsList.length;
  const totalPages = Math.max(1, Math.ceil(total / state.overviewPagination.pageSize));
  if (page < 1) page = 1;
  if (page > totalPages) page = totalPages;

  state.overviewPagination.currentPage = page;
  renderOverviewRecentEvents();
};

const overviewPageSizeSelect = document.getElementById('overviewPageSize');
if (overviewPageSizeSelect) {
  overviewPageSizeSelect.addEventListener('change', (e) => {
    state.overviewPagination.pageSize = parseInt(e.target.value, 10) || 10;
    state.overviewPagination.currentPage = 1;
    renderOverviewRecentEvents();
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
          <div>
            <span class="mini-ip-addr">${r.ip}</span>
            <small style="color: #64748b; margin-left: 8px;">(${r.hostname || 'node'})</small>
          </div>
          <div>
            <span class="mini-req-count">${(r.request_count || 1).toLocaleString()} reqs</span>
          </div>
        </div>
      `).join('');
    } else {
      overviewIpSummary.innerHTML = `<div class="empty-state">No incoming IP requests recorded yet.</div>`;
    }
  }

  // Render Containment Tab
  if (containmentList) {
    const blockedIps = allIPs.filter(r => r.status && r.status.includes("Blocked"));
    if (blockedIps.length > 0) {
      containmentList.innerHTML = blockedIps.map(r => `
        <div class="containment-item">
          <div>
            <strong style="color: #ef4444; font-family: var(--font-mono); font-size: 13px;">${r.ip}</strong>
            <span style="color: #64748b; font-size: 11px; margin-left: 10px; font-family: var(--font-mono);">Rule: iptables -I INPUT -s ${r.ip} -j DROP</span>
          </div>
          <button class="btn-action" onclick="toggleBlockIP('${r.ip}')">Unblock</button>
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
      const firstTime = r.first_seen ? new Date(r.first_seen).toLocaleTimeString() : '-';
      const lastTime = r.last_seen ? new Date(r.last_seen).toLocaleTimeString() : '-';

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
            <button class="btn-action ${btnDanger}" style="margin-left: 8px;" onclick="toggleBlockIP('${r.ip}')">${actionBtnText}</button>
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
  try {
    const res = await fetch('/api/v1/containment/block', {
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
      fleetSubtextEl.innerHTML = `/ ${totalCount} Active (<span style="color:#ef4444;">${totalCount - onlineCount} offline</span>)`;
    }
  }

  const tagsEl = document.getElementById('agentTagsSummary');
  if (tagsEl) {
    if (totalCount === 0) {
      tagsEl.textContent = "Waiting for node heartbeats...";
    } else {
      tagsEl.innerHTML = Array.from(state.activeAgents.values())
        .map(item => {
          const isOnline = (now - item.lastSeen) < 20000;
          const color = isOnline ? "#38bdf8" : "#94a3b8";
          const dot = isOnline ? "🟢" : "⚪";
          const ipLabel = item.data.source_ip && !item.data.source_ip.startsWith('127.') ? ` (${item.data.source_ip})` : '';
          return `<span style="color:${color};font-family:var(--font-mono);margin-right:8px;">${dot} ${item.data.hostname}${ipLabel}</span>`;
        })
        .join(' ');
    }
  }
}

// Periodic check to mark inactive agents as offline without needing page reload
setInterval(refreshAgentFleetCounts, 5000);

function updateAgentFleet(d, shouldRender = true) {
  const agentKey = d.agent_id || (d.hostname ? `${d.hostname}-${d.source_ip || 'local'}` : "unknown");
  state.activeAgents.set(agentKey, {
    lastSeen: Date.now(),
    data: d
  });

  refreshAgentFleetCounts();

  // Overview Mini Fleet Summary
  const overviewFleetSummary = document.getElementById('overviewFleetSummary');
  if (overviewFleetSummary) {
    const now = Date.now();
    overviewFleetSummary.innerHTML = Array.from(state.activeAgents.values()).map(item => {
      const isOnline = (now - item.lastSeen) < 20000;
      const ipLabel = item.data.source_ip && !item.data.source_ip.startsWith('127.') ? ` [${item.data.source_ip}]` : '';
      return `
      <div class="mini-row" style="${isOnline ? '' : 'opacity: 0.6;'}">
        <div>
          <strong style="color: #fff; font-family: var(--font-mono);">${item.data.hostname}${ipLabel}</strong>
          <span style="color: #64748b; font-size: 11px; margin-left: 8px;">${item.data.platform || 'Linux'}</span>
          ${isOnline ? '<span class="badge-level level-low" style="margin-left:6px;font-size:9px;">ONLINE</span>' : '<span class="badge-level level-critical" style="margin-left:6px;font-size:9px;">OFFLINE</span>'}
        </div>
        <div style="font-family: var(--font-mono); font-size: 11px;">
          CPU: <strong style="color: #38bdf8;">${(item.data.cpu_usage || 0).toFixed(1)}%</strong> | 
          RAM: <strong style="color: #10b981;">${(item.data.ram_used_pct || 0).toFixed(1)}%</strong>
        </div>
      </div>
    `;
    }).join('');
  }

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

    return `
      <div class="fleet-card" id="agent-card-${d.agent_id || d.hostname}">
        <div class="agent-title-row">
          <div>
            <div class="agent-name">${d.hostname}</div>
            <div style="font-size: 10px; color: #64748b; font-family: var(--font-mono); margin-top: 2px;">
              IP: ${d.source_ip || '127.0.0.1'} | ${d.platform || 'Linux'}
            </div>
          </div>
          <span class="agent-tag" style="${isOnline ? '' : 'background:rgba(239,68,68,0.15);color:#fca5a5;border-color:rgba(239,68,68,0.3);'}">${isOnline ? 'ACTIVE' : 'OFFLINE'}</span>
        </div>

        <div class="meter-group">
          <div class="meter-row">
            <div class="meter-labels">
              <span>CPU Utilization</span>
              <span class="meter-val">${cpu.toFixed(1)}%</span>
            </div>
            <div class="meter-bar-bg">
              <div class="meter-bar-fill ${getMeterColor(cpu)}" style="width: ${Math.min(cpu, 100)}%;"></div>
            </div>
          </div>

          <div class="meter-row">
            <div class="meter-labels">
              <span>RAM Utilization</span>
              <span class="meter-val">${d.ram_used_mb || 0} / ${d.ram_total_mb || 0} MB (${ramPct.toFixed(1)}%)</span>
            </div>
            <div class="meter-bar-bg">
              <div class="meter-bar-fill ${getMeterColor(ramPct)}" style="width: ${Math.min(ramPct, 100)}%;"></div>
            </div>
          </div>

          <div class="meter-row">
            <div class="meter-labels">
              <span>Disk Partition</span>
              <span class="meter-val">${disk.toFixed(1)}%</span>
            </div>
            <div class="meter-bar-bg">
              <div class="meter-bar-fill ${getMeterColor(disk)}" style="width: ${Math.min(disk, 100)}%;"></div>
            </div>
          </div>
        </div>

        <div class="agent-card-footer">
          <span>Uptime: ${uptimeStr}</span>
          <span>Last Seen: ${new Date(item.lastSeen).toLocaleTimeString()}</span>
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

// ==========================================================================
// APPLICATION INITIALIZATION
// ==========================================================================
async function initApp() {
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
