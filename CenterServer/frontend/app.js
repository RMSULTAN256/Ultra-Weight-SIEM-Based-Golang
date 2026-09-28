// ==========================================================================
// WAZUH-LIGHTWEIGHT SOC DASHBOARD SCRIPT
// ==========================================================================

const state = {
  activeAgents: new Map(),
  ipRecords: new Map(),
  totalEvents: 0,
  highAlerts: 0,
  eventsList: [],
};

// View Titles
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
  // Update sidebar buttons
  document.querySelectorAll('.nav-item').forEach(btn => {
    if (btn.dataset.target === targetId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Update tab panes
  document.querySelectorAll('.tab-pane').forEach(pane => {
    if (pane.id === targetId) {
      pane.classList.add('active');
    } else {
      pane.classList.remove('active');
    }
  });

  // Update topbar title
  const titleEl = document.getElementById('currentViewTitle');
  if (titleEl && viewTitles[targetId]) {
    titleEl.textContent = viewTitles[targetId];
  }
}

// Attach click listeners to sidebar buttons
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.target;
    if (target) switchTab(target);
  });
});

// Modal Elements
const jsonModal = document.getElementById('jsonModal');
const modalJsonContent = document.getElementById('modalJsonContent');
const closeModalBtn = document.getElementById('closeModalBtn');

closeModalBtn.addEventListener('click', () => jsonModal.classList.add('hidden'));
jsonModal.addEventListener('click', (e) => {
  if (e.target === jsonModal) jsonModal.classList.add('hidden');
});

function showJsonModal(data) {
  modalJsonContent.textContent = JSON.stringify(data, null, 2);
  jsonModal.classList.remove('hidden');
}

// ==========================================================================
// SSE STREAM CONNECTION
// ==========================================================================
function connectSSE() {
  const sideStreamDot = document.getElementById('sideStreamDot');
  const sideStreamText = document.getElementById('sideStreamText');

  const evtSource = new EventSource('/api/v1/stream');

  evtSource.onopen = () => {
    sideStreamDot.className = "dot green";
    sideStreamText.textContent = "Cluster Online";
  };

  evtSource.onerror = () => {
    sideStreamDot.className = "dot";
    sideStreamText.textContent = "Reconnecting...";
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

// Event Router
function handleIncomingEvent(data) {
  // 1. IP Update Event
  if (data.event_type === "IP_UPDATE" && data.data) {
    updateOrAddIPRecord(data.data);
    return;
  }

  state.totalEvents++;
  document.getElementById('totalEventsCount').textContent = state.totalEvents.toLocaleString();
  document.getElementById('navEventCount').textContent = state.totalEvents;

  // 2. Heartbeat (Hardware Telemetry)
  if (data.cpu_usage !== undefined) {
    updateAgentFleet(data);
    appendSecurityEventRow({
      timestamp: data.received_at || new Date().toISOString(),
      source_ip: data.source_ip || "127.0.0.1",
      agent: data.hostname,
      level: 3,
      level_label: "LVL 3 INFO",
      desc: `Telemetry Heartbeat: CPU ${data.cpu_usage.toFixed(1)}%, RAM ${data.ram_used_pct.toFixed(1)}%, Disk ${data.disk_used_pct.toFixed(1)}%`,
      mitre: "T1082 System Info",
      raw: data
    });
  }
  // 3. Security/Access Log
  else if (data.event_type || data.rule_id || data.message) {
    const isAlert = (data.severity || 3) >= 7;
    if (isAlert) {
      state.highAlerts++;
      document.getElementById('highAlertsCount').textContent = state.highAlerts;
    }

    appendSecurityEventRow({
      timestamp: data.timestamp || new Date().toISOString(),
      source_ip: data.source_ip || "127.0.0.1",
      agent: data.hostname || "target-node",
      level: data.severity || 3,
      level_label: data.severity >= 12 ? "LVL 12 CRITICAL" : (data.severity >= 7 ? "LVL 7 WARNING" : "LVL 3 INFO"),
      desc: data.rule_desc || data.message || "HTTP Transaction Recorded",
      mitre: data.mitre_id || "T1595 Recon",
      raw: data
    });
  }
}

// ==========================================================================
// IP TRAFFIC TRACKER LOGIC
// ==========================================================================
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

function updateOrAddIPRecord(rec, shouldRender = true) {
  state.ipRecords.set(rec.ip, rec);
  if (shouldRender) renderIPTable();
}

function renderIPTable() {
  const ipTableBody = document.getElementById('ipTableBody');
  const overviewIpSummary = document.getElementById('overviewIpSummary');
  const containmentList = document.getElementById('containmentList');

  const ips = Array.from(state.ipRecords.values()).sort((a, b) => b.request_count - a.request_count);

  // Update Counters
  const totalUnique = ips.length;
  let totalReqs = 0;
  let flaggedCount = 0;
  let blockedCount = 0;

  ips.forEach(r => {
    totalReqs += r.request_count || 1;
    if (r.threat_level === "Critical" || r.threat_level === "Suspicious") flaggedCount++;
    if (r.status && r.status.includes("Blocked")) blockedCount++;
  });

  document.getElementById('uniqueIpsCount').textContent = totalUnique;
  document.getElementById('navIpCount').textContent = totalUnique;
  document.getElementById('ipTabTotalCount').textContent = totalUnique;
  document.getElementById('ipTabTotalRequests').textContent = totalReqs.toLocaleString();
  document.getElementById('ipTabFlaggedCount').textContent = flaggedCount;
  document.getElementById('ipTabBlockedCount').textContent = blockedCount;

  // Render Overview Top IPs
  if (ips.length > 0) {
    overviewIpSummary.innerHTML = ips.slice(0, 5).map(r => `
      <div class="mini-row">
        <div>
          <span class="mini-ip-addr">${r.ip}</span>
          <small style="color: #64748b; margin-left: 8px;">(${r.hostname || 'node'})</small>
        </div>
        <div>
          <span class="mini-req-count">${r.request_count} reqs</span>
        </div>
      </div>
    `).join('');
  }

  // Render Containment Tab
  const blockedIps = ips.filter(r => r.status && r.status.includes("Blocked"));
  if (blockedIps.length > 0) {
    containmentList.innerHTML = blockedIps.map(r => `
      <div class="containment-item">
        <div>
          <strong style="color: #ef4444; font-family: monospace;">${r.ip}</strong>
          <span style="color: #64748b; font-size: 11px; margin-left: 10px;">Rule: iptables -I INPUT -s ${r.ip} -j DROP</span>
        </div>
        <button class="btn-action" onclick="toggleBlockIP('${r.ip}')">Unblock</button>
      </div>
    `).join('');
  } else {
    containmentList.innerHTML = `<div class="empty-state">No IP addresses currently under quarantine or blocked.</div>`;
  }

  // Render Full IP Table
  if (ips.length === 0) {
    ipTableBody.innerHTML = `<tr class="placeholder-row"><td colspan="8">No source IP addresses registered yet.</td></tr>`;
    return;
  }

  const query = (document.getElementById('ipFilterInput').value || '').toLowerCase().trim();

  ipTableBody.innerHTML = '';
  ips.forEach(r => {
    const textSearch = `${r.ip} ${r.hostname} ${r.category} ${r.status}`.toLowerCase();
    if (query && !textSearch.includes(query)) return;

    const tr = document.createElement('tr');

    const firstTime = r.first_seen ? new Date(r.first_seen).toLocaleTimeString() : '-';
    const lastTime = r.last_seen ? new Date(r.last_seen).toLocaleTimeString() : '-';

    let threatClass = 'badge-level-info';
    if (r.threat_level === 'Critical') threatClass = 'badge-level-danger';
    else if (r.threat_level === 'Suspicious') threatClass = 'badge-level-warn';

    const isBlocked = r.status && r.status.includes("Blocked");
    const statusClass = isBlocked ? 'status-blocked' : 'status-monitored';
    const actionBtnText = isBlocked ? 'Unblock' : 'Block (iptables)';
    const btnDanger = isBlocked ? '' : 'btn-danger';

    tr.innerHTML = `
      <td class="ip-cell">${r.ip}</td>
      <td class="node-cell">🖥️ ${r.hostname || '-'}</td>
      <td>${r.category || 'General Inbound'}</td>
      <td><span class="mini-req-count">${r.request_count} reqs</span></td>
      <td class="time-cell">${firstTime}</td>
      <td class="time-cell">${lastTime}</td>
      <td><span class="badge-level ${threatClass}">${r.threat_level || 'Normal'}</span></td>
      <td>
        <span class="badge-status ${statusClass}">${r.status || 'Monitored'}</span>
        <button class="btn-action ${btnDanger}" style="margin-left: 8px;" onclick="toggleBlockIP('${r.ip}')">${actionBtnText}</button>
      </td>
    `;
    ipTableBody.appendChild(tr);
  });
}

// Block / Unblock IP via Endpoint
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

// IP Filter Input Listener
document.getElementById('ipFilterInput').addEventListener('input', () => {
  renderIPTable();
});

// ==========================================================================
// AGENT FLEET LOGIC
// ==========================================================================
function updateAgentFleet(d) {
  const host = d.hostname || "unknown";
  state.activeAgents.set(host, {
    lastSeen: Date.now(),
    data: d
  });

  const activeCount = state.activeAgents.size;
  document.getElementById('activeAgentsCount').textContent = activeCount;
  document.getElementById('navAgentCount').textContent = activeCount;

  // Overview Tags
  const tags = Array.from(state.activeAgents.keys())
    .map(h => `<span style="color:#00a4e4;font-family:monospace;margin-right:6px;">${h}</span>`)
    .join(' ');
  document.getElementById('agentTagsSummary').innerHTML = tags;

  // Overview Mini Fleet Summary
  const overviewFleetSummary = document.getElementById('overviewFleetSummary');
  overviewFleetSummary.innerHTML = Array.from(state.activeAgents.values()).map(item => `
    <div class="mini-row">
      <div>
        <strong style="color: #fff; font-family: monospace;">🖥️ ${item.data.hostname}</strong>
        <span style="color: #64748b; font-size: 11px; margin-left: 8px;">${item.data.platform || 'Linux'}</span>
      </div>
      <div style="font-family: monospace; font-size: 11px;">
        CPU: <strong style="color: #38bdf8;">${(item.data.cpu_usage || 0).toFixed(1)}%</strong> | 
        RAM: <strong style="color: #10b981;">${item.data.ram_used_pct.toFixed(1)}%</strong>
      </div>
    </div>
  `).join('');

  // Fleet Grid Tab
  const fleetGrid = document.getElementById('fleetGrid');
  let card = document.getElementById(`agent-card-${host}`);
  if (!card) {
    const emptyState = fleetGrid.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    card = document.createElement('div');
    card.id = `agent-card-${host}`;
    card.className = 'fleet-card';
    fleetGrid.appendChild(card);
  }

  const cpu = (d.cpu_usage || 0);
  const ramPct = (d.ram_used_pct || 0);
  const disk = (d.disk_used_pct || 0);

  const getMeterColor = (pct) => pct >= 85 ? 'danger' : (pct >= 70 ? 'warn' : '');

  const uptimeStr = d.uptime_sec 
    ? `${Math.floor(d.uptime_sec / 3600)}h ${Math.floor((d.uptime_sec % 3600) / 60)}m`
    : '-';

  card.innerHTML = `
    <div class="agent-title-row">
      <div>
        <div class="agent-name">🖥️ ${host}</div>
        <div style="font-size: 10px; color: #5c6b82;">IP: ${d.source_ip || '127.0.0.1'} | ${d.platform || 'Linux'}</div>
      </div>
      <span class="agent-tag">ACTIVE</span>
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
      <span>Ping: ${new Date().toLocaleTimeString()}</span>
    </div>
  `;
}

// ==========================================================================
// SECURITY EVENTS & DISCOVER LOGIC
// ==========================================================================
function appendSecurityEventRow(item) {
  state.eventsList.unshift(item);
  if (state.eventsList.length > 50) state.eventsList.pop();

  const eventsTableBody = document.getElementById('eventsTableBody');
  const overviewRecentEventsBody = document.getElementById('overviewRecentEventsBody');

  // Hapus placeholder jika ada
  const p1 = eventsTableBody.querySelector('.placeholder-row');
  if (p1) p1.remove();
  const p2 = overviewRecentEventsBody.querySelector('.placeholder-row');
  if (p2) p2.remove();

  const timeFormatted = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();

  let levelClass = 'badge-level-info';
  if (item.level >= 12) levelClass = 'badge-level-danger';
  else if (item.level >= 7) levelClass = 'badge-level-warn';

  // 1. Row untuk Full Events Table
  const tr = document.createElement('tr');
  tr.dataset.search = `${item.source_ip} ${item.agent} ${item.desc} ${item.mitre}`.toLowerCase();
  tr.innerHTML = `
    <td class="time-cell">${timeFormatted}</td>
    <td class="ip-cell">${item.source_ip}</td>
    <td class="node-cell"><strong>${item.agent}</strong></td>
    <td><span class="badge-level ${levelClass}">${item.level_label}</span></td>
    <td>${item.desc}</td>
    <td><span class="mitre-badge">${item.mitre}</span></td>
    <td><button class="btn-action">Inspect</button></td>
  `;

  tr.querySelector('.btn-action').addEventListener('click', () => showJsonModal(item.raw));
  eventsTableBody.prepend(tr);
  if (eventsTableBody.children.length > 30) eventsTableBody.removeChild(eventsTableBody.lastChild);

  // 2. Row untuk Overview Preview
  const trOverview = document.createElement('tr');
  trOverview.innerHTML = `
    <td class="time-cell">${timeFormatted}</td>
    <td class="ip-cell">${item.source_ip}</td>
    <td class="node-cell"><strong>${item.agent}</strong></td>
    <td><span class="badge-level ${levelClass}">${item.level_label}</span></td>
    <td>${item.desc}</td>
  `;
  overviewRecentEventsBody.prepend(trOverview);
  if (overviewRecentEventsBody.children.length > 8) overviewRecentEventsBody.removeChild(overviewRecentEventsBody.lastChild);
}

// Log Filter Listener
document.getElementById('logFilter').addEventListener('input', (e) => {
  const query = e.target.value.toLowerCase().trim();
  const rows = document.getElementById('eventsTableBody').querySelectorAll('tr:not(.placeholder-row)');

  rows.forEach(row => {
    const text = row.dataset.search || '';
    if (!query || text.includes(query)) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
});

// Run Init
loadInitialIPs();
connectSSE();
