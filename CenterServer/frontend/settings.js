// ==========================================================================
// SETTINGS & BLUEPRINT CONTROLLER (16-BIT RETRO PIXEL SOC - IMAGE 5)
// Prompt Generator, Multi-Path Blueprint, & Zero-Trust Containment
// ==========================================================================

let blockedIps = [];

document.addEventListener('DOMContentLoaded', () => {
  // Mount Active Route Strip for Settings & Prompt
  if (typeof mountActiveRouteStrip === 'function') {
    mountActiveRouteStrip(
      'SETTINGS & PROMPT',
      '/SETTINGS',
      'Konfigurasi tema warna, struktur folder multi-path, dan Prompt Siap Copy-Paste.'
    );
  }

  updatePromptBlueprint();
  loadBlockedIps();
});

/** Update teks prompt berdasarkan dropdown pilihan (Image 5) */
function updatePromptBlueprint() {
  const stack = document.getElementById('selectTargetStack')?.value || 'Next.js / Laravel Inertia';
  const grass = document.getElementById('selectGrassOrnament')?.value || 'Lush Pixel Grass + Earth Base';
  const neon = document.getElementById('selectNeonIntensity')?.value || 'Bright Sky + High Cyan Glow (#00F0FF)';

  const isFullGame = grass.includes('Lush') || grass.includes('Grass');
  const badge = document.getElementById('badgeGameMode');
  const titleLabel = document.getElementById('promptTitleLabel');

  if (badge) {
    badge.textContent = isFullGame ? 'VERSI PULAU GAME' : 'VERSI CLEAN OFFICE';
    badge.style.background = isFullGame ? '#00F0FF' : '#4ADE80';
  }

  if (titleLabel) {
    titleLabel.textContent = isFullGame ? 'PROMPT OPSI A (MODE FULL GAME)' : 'PROMPT OPSI B (MODE KANTOR MINIMALIS)';
  }

  let ornamentDesc = '- Gunakan ornamen rumput hijau pixel (#22C55E & #4ADE80) pada header card dan aksen tanah/batu pixel (#78350F) di bagian bawah.';
  if (!isFullGame) {
    ornamentDesc = '- Gunakan desain border card stepped pixel yang bersih tanpa rumput/tanah, mempertahankan sudut siku 0 border-radius.';
  }

  let neonPalette = 'Aksen utama Neon Cyan-Blue (#00F0FF) yang menyala terang pada active tabs, buttons, dan status indicators.';
  if (neon.includes('Muted')) {
    neonPalette = 'Aksen biru langit teduh (#38BDF8) dengan intensitas glow moderat.';
  } else if (neon.includes('Cyberpunk')) {
    neonPalette = 'Kontras tinggi Matrix Cyan (#00FFCC) dan Neon Amber (#FBBF24).';
  }

  const promptText = `Tolong redesign tampilan web dan arsitektur struktur navigasi saya (${stack}) dengan spesifikasi lengkap berikut:

1. ARSITEKTUR ROUTING TERPISAH (MULTI-PAGE PATHS):
- Ubah arsitektur yang sebelumnya berkumpul di 1 path (single-page state/tabs) menjadi route halaman yang terpisah per menu:
  * /dashboard -> Halaman ringkasan metrik, grafik status utama, dan tabel cepat.
  * /analytics -> Halaman analisis performa mendalam, perbandingan traffic, dan beban sistem.
  * /logs      -> Halaman pemantauan log aktivitas dan filter status secara terpisah.
  * /settings  -> Halaman konfigurasi sistem dan preferensi tampilan.
- Gunakan Shared Layout untuk Sidebar dan Top Address HUD sehingga perpindahan antar path terasa rapi dan konsisten.

2. TEMA VISUAL (BRIGHT NEON CYAN-BLUE PIXEL ART):
- Jangan gunakan dark mode yang terlalu gelap. Gunakan nuansa cerah seperti langit siang bergaya 16-bit Pixel Art:
  * Background utama: Biru langit cerah (#E0F7FA s.d. #38BDF8) dengan pola dot/grid pixel samar.
  * Warna aksen: ${neonPalette}
  * Tipografi: Font retro pixel/monospace dengan stepped border kontras.

3. CONTAINER PULAU TERBANG (FLOATING ISLAND BORDERS):
${ornamentDesc}
- Stepped pixel borders tanpa border-radius melengkung (sudut siku tajam).
- Header card memiliki ornamen jendela pixel [□ □ □] dan judul tebal ber-shadow.

4. REAL-TIME DATA & CHART VISUALIZATION:
- Di /dashboard sertakan 3 Mini Island KPI cards (Total Requests, Healthy Nodes, Avg System Load).
- Tampilkan Bar Chart 12M, Status Donut Chart, dan Real-time Line Chart telemetry.
- Di /analytics tampilkan perbandingan beban CPU tiap route dan node armada.
- Di /logs tampilkan audit log ala konsol terminal pixel dengan filter level dan inspect NDJSON.`;

  const pre = document.getElementById('promptTextContent');
  if (pre) pre.textContent = promptText;
}

/** Salin isi prompt ke clipboard */
function copyBlueprintPrompt() {
  const pre = document.getElementById('promptTextContent');
  if (!pre) return;

  navigator.clipboard.writeText(pre.textContent).then(() => {
    alert('Prompt Blueprint Arsitektur Opsi A berhasil disalin ke clipboard!');
  }).catch(() => {
    alert('Gagal menyalin otomatis, silakan blok dan salin teks di dalam kotak.');
  });
}

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
