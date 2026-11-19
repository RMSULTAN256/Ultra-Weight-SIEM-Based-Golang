// ==========================================================================
// SYSTEM SETTINGS CONTROLLER (16-BIT RETRO PIXEL SOC)
// Zero-Trust Containment (iptables DROP) & Role-Based User Management
// ==========================================================================

let blockedIps = [];

document.addEventListener('DOMContentLoaded', () => {
  // Mount Active Route Strip for Settings
  if (typeof mountActiveRouteStrip === 'function') {
    mountActiveRouteStrip(
      'SETTINGS',
      '/SETTINGS',
      'Konfigurasi keamanan sistem, isolasi Zero-Trust iptables, dan manajemen akun analis.'
    );
  }

  loadBlockedIps();
});

// ==========================================================================
// ZERO-TRUST CONTAINMENT (IPTABLES DROP TABLE & USER REGISTRATION)
// ==========================================================================
async function loadBlockedIps() {
  const tbody = document.getElementById('containmentTableBody');
  const countBadge = document.getElementById('badgeBlockedCount');

  try {
    const res = await authFetch('/api/v1/containment/blocked');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    blockedIps = await res.json() || [];

    if (countBadge) countBadge.textContent = `${blockedIps.length} QUARANTINED`;

    if (!tbody) return;
    if (blockedIps.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 16px;">Tidak ada IP yang sedang diisolasi / diblokir.</td></tr>`;
      return;
    }

    tbody.innerHTML = blockedIps.map(item => {
      const ip = item.ip || item.blocked_ip || '-';
      const node = item.node || item.target_node || 'All Nodes (Global)';
      const reason = item.reason || item.rule || 'Sigma Brute-Force T1110';

      return `
        <tr>
          <td><strong><code>${ip}</code></strong></td>
          <td>${node}</td>
          <td><span class="pixel-tag tag-critical">${escapeHtml(reason)}</span></td>
          <td>
            <button class="pixel-btn pixel-btn-sm pixel-btn-cyan" onclick="unblockIp('${ip}')">
              UNBLOCK
            </button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 16px;">Belum ada riwayat blokir aktif.</td></tr>`;
    }
  }
}

async function submitManualBlock() {
  const input = document.getElementById('manualBlockIpInput');
  const ip = input ? input.value.trim() : '';

  if (!ip) {
    alert('Silakan masukkan alamat IP target.');
    return;
  }

  if (!confirm(`Terapkan isolasi iptables DROP untuk IP ${ip}?`)) return;

  try {
    const res = await authFetch('/api/v1/containment/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip, reason: 'Manual PEP Admin Trigger' })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Gagal memblokir IP.');

    alert(`Aturan iptables DROP untuk IP ${ip} berhasil diterapkan.`);
    if (input) input.value = '';
    loadBlockedIps();
  } catch (err) {
    alert(`Gagal: ${err.message}`);
  }
}

async function unblockIp(ip) {
  if (!confirm(`Buka blokir iptables untuk IP ${ip}?`)) return;

  try {
    const res = await authFetch('/api/v1/containment/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Gagal membuka blokir IP.');

    alert(`IP ${ip} berhasil dihapus dari daftar blokir.`);
    loadBlockedIps();
  } catch (err) {
    alert(`Gagal: ${err.message}`);
  }
}

async function handleCreateUser(e) {
  e.preventDefault();
  const u = document.getElementById('regUsername')?.value.trim();
  const p = document.getElementById('regPassword')?.value;
  const r = document.getElementById('regRole')?.value || 'analyst';

  if (!u || !p) return;

  try {
    const res = await authFetch('/api/v1/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p, role: r })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Gagal mendaftarkan user.');

    alert(`Akun analis "${u}" (${r}) berhasil dibuat!`);
    document.getElementById('formRegisterUser')?.reset();
  } catch (err) {
    alert(`Registrasi gagal: ${err.message}`);
  }
}
