// ==========================================================================
// GEO-IP TRAFFIC & GLOBAL THREAT MAP CONTROLLER (16-BIT RETRO SOC)
// Equirectangular World Map (WGS84), Real-Time IP Pinpoints, & Geo-CTI
// ==========================================================================

const GEO_CACHE = {
  // Local & Cluster Loopback
  '127.0.0.1': { country: 'Indonesia', code: 'ID', city: 'Batam (Center SIEM)', lat: 1.130, lon: 104.052, flag: '🇮🇩', isp: 'Internal PDP Gateway' },
  'localhost': { country: 'Indonesia', code: 'ID', city: 'Batam (Center SIEM)', lat: 1.130, lon: 104.052, flag: '🇮🇩', isp: 'Internal PDP Gateway' },
  '192.168.25.1': { country: 'Indonesia', code: 'ID', city: 'Cluster Private LAN', lat: 1.130, lon: 104.052, flag: '🇮🇩', isp: 'Cluster Switch' },
  '172.18.0.1': { country: 'Indonesia', code: 'ID', city: 'Docker Bridge', lat: 1.130, lon: 104.052, flag: '🇮🇩', isp: 'Docker Gateway' },
  '172.18.0.2': { country: 'Indonesia', code: 'ID', city: 'Docker Bridge', lat: 1.130, lon: 104.052, flag: '🇮🇩', isp: 'Docker Gateway' },

  // Real Cluster Nodes & Live Ingress
  '31.56.56.50': { country: 'Indonesia', code: 'ID', city: 'Bogor, West Java', lat: -6.5945, lon: 106.789, flag: '🇮🇩', isp: 'CV Andhika Pratama' },
  '163.52.135.170': { country: 'Indonesia', code: 'ID', city: 'Madiun, East Java', lat: -7.7163, lon: 111.6152, flag: '🇮🇩', isp: 'CV Griya Cloud' },
  '163.52.135.': { country: 'Indonesia', code: 'ID', city: 'Madiun, East Java', lat: -7.7163, lon: 111.6152, flag: '🇮🇩', isp: 'CV Griya Cloud' },
  '158.140.164.90': { country: 'Indonesia', code: 'ID', city: 'Binjai, North Sumatra', lat: 3.6001, lon: 98.4854, flag: '🇮🇩', isp: 'MyRepublic Indonesia' },
  '203.83.39.23': { country: 'Indonesia', code: 'ID', city: 'Medan, North Sumatra', lat: 3.5833, lon: 98.6667, flag: '🇮🇩', isp: 'PT Eka Mas Republik' },
  '203.83.39.0': { country: 'Indonesia', code: 'ID', city: 'Medan, North Sumatra', lat: 3.5833, lon: 98.6667, flag: '🇮🇩', isp: 'PT Eka Mas Republik' },
  '2402:8780:1': { country: 'Indonesia', code: 'ID', city: 'Jakarta (Telkom IPv6)', lat: -6.2088, lon: 106.8456, flag: '🇮🇩', isp: 'PT Telkom Indonesia' },

  // Common CTI International Nodes (Fallback lookup)
  '103.144.12.88': { country: 'Singapore', code: 'SG', city: 'Singapore', lat: 1.3521, lon: 103.8198, flag: '🇸🇬', isp: 'Cloudflare / APNIC' },
  '194.26.29.112': { country: 'Netherlands', code: 'NL', city: 'Amsterdam', lat: 52.3676, lon: 4.9041, flag: '🇳🇱', isp: 'HostKey Server' },
  '45.33.32.156': { country: 'United States', code: 'US', city: 'Fremont, CA', lat: 37.5483, lon: -121.9886, flag: '🇺🇸', isp: 'Linode Cloud' },
  '185.220.101.5': { country: 'Germany', code: 'DE', city: 'Frankfurt', lat: 50.1109, lon: 8.6821, flag: '🇩🇪', isp: 'Tor Exit Node Relay' },
  '222.186.30.12': { country: 'China', code: 'CN', city: 'Jiangsu', lat: 32.0617, lon: 118.7632, flag: '🇨🇳', isp: 'China Telecom' }
};

const KNOWN_CITIES = {
  // Wilayah Indonesia (Penyebaran Geografis Nusantara)
  'batam': { lat: 1.130, lon: 104.052, city: 'Batam' },
  'pancur biru': { lat: 1.118, lon: 104.048, city: 'Batam (Center)' },
  'jakarta': { lat: -6.2088, lon: 106.8456, city: 'Jakarta' },
  'bogor': { lat: -6.5945, lon: 106.789, city: 'Bogor' },
  'madiun': { lat: -7.7163, lon: 111.6152, city: 'Madiun' },
  'medan': { lat: 3.5833, lon: 98.6667, city: 'Medan' },
  'binjai': { lat: 3.6001, lon: 98.4854, city: 'Binjai' },
  'surabaya': { lat: -7.2575, lon: 112.7521, city: 'Surabaya' },
  'bandung': { lat: -6.9175, lon: 107.6191, city: 'Bandung' },
  'semarang': { lat: -6.9667, lon: 110.4167, city: 'Semarang' },
  'yogyakarta': { lat: -7.7956, lon: 110.3695, city: 'Yogyakarta' },
  'denpasar': { lat: -8.6705, lon: 115.2126, city: 'Denpasar' },
  'bali': { lat: -8.4095, lon: 115.1889, city: 'Bali' },
  'makassar': { lat: -5.1477, lon: 119.4327, city: 'Makassar' },
  'palembang': { lat: -2.9909, lon: 104.7565, city: 'Palembang' },
  'pekanbaru': { lat: 0.5071, lon: 101.4478, city: 'Pekanbaru' },
  'padang': { lat: -0.9471, lon: 100.4172, city: 'Padang' },
  'balikpapan': { lat: -1.2379, lon: 116.8289, city: 'Balikpapan' },
  'manado': { lat: 1.4748, lon: 124.8428, city: 'Manado' },
  'pontianak': { lat: -0.0263, lon: 109.3425, city: 'Pontianak' },
  'banjarmasin': { lat: -3.3194, lon: 114.5908, city: 'Banjarmasin' }
};

let currentMapIps = [];
let isWorldMapLoaded = false;

const BASE_MAP_WIDTH = 1000;
const BASE_MAP_HEIGHT = 500;

const mapViewState = {
  x: 0,
  y: 0,
  w: BASE_MAP_WIDTH,
  h: BASE_MAP_HEIGHT,
  scale: 1.0,
  minScale: 1.0,
  maxScale: 10.0,
  isDragging: false,
  dragStartX: 0,
  dragStartY: 0,
  viewStartX: 0,
  viewStartY: 0
};

document.addEventListener('DOMContentLoaded', () => {
  initGeoMap();
});

/** Inisialisasi Peta Dunia SVG */
async function initGeoMap() {
  const container = document.getElementById('geoMapContainer');
  if (!container) return;

  try {
    const res = await fetch('/world-map.svg?v=2.8');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const svgText = await res.text();
    container.innerHTML = svgText;
    isWorldMapLoaded = true;
    setupMapZoomAndPan();
    renderGeoVisuals();
  } catch (err) {
    console.warn('Gagal memuat world-map.svg, mencoba render ulang:', err.message);
  }
}

/** Konfigurasi Event Zoom & Pan pada Peta SVG */
function setupMapZoomAndPan() {
  const container = document.getElementById('geoMapContainer');
  const svg = document.getElementById('worldMapSvg');
  if (!container || !svg) return;

  // 1. Mouse Wheel Zoom (ke arah kursor mouse)
  container.addEventListener('wheel', (e) => {
    e.preventDefault();
    const rect = container.getBoundingClientRect();
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;

    const svgX = mapViewState.x + (clientX / rect.width) * mapViewState.w;
    const svgY = mapViewState.y + (clientY / rect.height) * mapViewState.h;

    const factor = e.deltaY < 0 ? 1.25 : 0.8;
    zoomMap(factor, svgX, svgY);
  }, { passive: false });

  // 2. Drag & Pan via Mouse
  container.addEventListener('mousedown', (e) => {
    if (e.target.closest('.geo-beacon-node') || e.target.closest('button')) return;
    e.preventDefault();
    mapViewState.isDragging = true;
    mapViewState.dragStartX = e.clientX;
    mapViewState.dragStartY = e.clientY;
    mapViewState.viewStartX = mapViewState.x;
    mapViewState.viewStartY = mapViewState.y;
    container.style.cursor = 'grabbing';
  });

  window.addEventListener('mousemove', (e) => {
    if (!mapViewState.isDragging) return;
    const rect = container.getBoundingClientRect();
    const dx = e.clientX - mapViewState.dragStartX;
    const dy = e.clientY - mapViewState.dragStartY;

    const scaleFactorX = mapViewState.w / rect.width;
    const scaleFactorY = mapViewState.h / rect.height;

    let newX = mapViewState.viewStartX - (dx * scaleFactorX);
    let newY = mapViewState.viewStartY - (dy * scaleFactorY);

    const marginX = 80;
    const marginY = 40;
    newX = Math.max(-marginX, Math.min(BASE_MAP_WIDTH - mapViewState.w + marginX, newX));
    newY = Math.max(-marginY, Math.min(BASE_MAP_HEIGHT - mapViewState.h + marginY, newY));

    mapViewState.x = newX;
    mapViewState.y = newY;
    applyMapTransform();
  });

  window.addEventListener('mouseup', () => {
    if (mapViewState.isDragging) {
      mapViewState.isDragging = false;
      const c = document.getElementById('geoMapContainer');
      if (c) c.style.cursor = 'grab';
    }
  });

  // 3. Touch Drag & Pinch Zoom (Mobile / Tablet)
  let initialTouchDist = null;
  let initialTouchScale = 1;

  container.addEventListener('touchstart', (e) => {
    if (e.touches.length === 1) {
      const touch = e.touches[0];
      mapViewState.isDragging = true;
      mapViewState.dragStartX = touch.clientX;
      mapViewState.dragStartY = touch.clientY;
      mapViewState.viewStartX = mapViewState.x;
      mapViewState.viewStartY = mapViewState.y;
    } else if (e.touches.length === 2) {
      mapViewState.isDragging = false;
      initialTouchDist = Math.hypot(
        e.touches[0].clientX - e.touches[1].clientX,
        e.touches[0].clientY - e.touches[1].clientY
      );
      initialTouchScale = mapViewState.scale;
    }
  }, { passive: true });

  container.addEventListener('touchmove', (e) => {
    if (e.touches.length === 1 && mapViewState.isDragging) {
      const touch = e.touches[0];
      const rect = container.getBoundingClientRect();
      const dx = touch.clientX - mapViewState.dragStartX;
      const dy = touch.clientY - mapViewState.dragStartY;
      const scaleFactorX = mapViewState.w / rect.width;
      const scaleFactorY = mapViewState.h / rect.height;

      mapViewState.x = mapViewState.viewStartX - (dx * scaleFactorX);
      mapViewState.y = mapViewState.viewStartY - (dy * scaleFactorY);
      applyMapTransform();
    } else if (e.touches.length === 2 && initialTouchDist) {
      const dist = Math.hypot(
        e.touches[0].clientX - e.touches[1].clientX,
        e.touches[0].clientY - e.touches[1].clientY
      );
      const ratio = dist / initialTouchDist;
      const targetScale = Math.max(mapViewState.minScale, Math.min(mapViewState.maxScale, initialTouchScale * ratio));
      setMapDirectScale(targetScale);
    }
  }, { passive: true });

  container.addEventListener('touchend', () => {
    mapViewState.isDragging = false;
    initialTouchDist = null;
  }, { passive: true });

  applyMapTransform();
}

/** Fungsi Zoom Relatif (Faktor Pengali) */
function zoomMap(factor, focalX = null, focalY = null) {
  const currentScale = mapViewState.scale;
  const targetScale = Math.max(mapViewState.minScale, Math.min(mapViewState.maxScale, currentScale * factor));
  if (Math.abs(targetScale - currentScale) < 0.001) return;

  const newW = BASE_MAP_WIDTH / targetScale;
  const newH = BASE_MAP_HEIGHT / targetScale;

  const cx = (focalX !== null) ? focalX : (mapViewState.x + mapViewState.w / 2);
  const cy = (focalY !== null) ? focalY : (mapViewState.y + mapViewState.h / 2);

  const ratioX = (cx - mapViewState.x) / mapViewState.w;
  const ratioY = (cy - mapViewState.y) / mapViewState.h;

  let newX = cx - ratioX * newW;
  let newY = cy - ratioY * newH;

  if (targetScale === 1.0) {
    newX = 0;
    newY = 0;
  } else {
    newX = Math.max(-60, Math.min(BASE_MAP_WIDTH - newW + 60, newX));
    newY = Math.max(-30, Math.min(BASE_MAP_HEIGHT - newH + 30, newY));
  }

  mapViewState.scale = targetScale;
  mapViewState.w = newW;
  mapViewState.h = newH;
  mapViewState.x = newX;
  mapViewState.y = newY;

  applyMapTransform();
}

/** Reset Zoom ke Tampilan Global (1.0x) */
function resetMapZoom() {
  mapViewState.scale = 1.0;
  mapViewState.x = 0;
  mapViewState.y = 0;
  mapViewState.w = BASE_MAP_WIDTH;
  mapViewState.h = BASE_MAP_HEIGHT;
  applyMapTransform();
}

/** Pintasan Cepat: Fokus ke Simpul Indonesia & Nusantara */
function focusIndonesiaZoom() {
  // Pusat koordinat kepulauan Nusantara (Batam, Jawa, Sumatera): x=805, y=260
  const targetScale = 3.6;
  const targetW = BASE_MAP_WIDTH / targetScale;
  const targetH = BASE_MAP_HEIGHT / targetScale;
  
  const centerX = 802;
  const centerY = 258;

  mapViewState.scale = targetScale;
  mapViewState.w = targetW;
  mapViewState.h = targetH;
  mapViewState.x = Math.max(0, centerX - targetW / 2);
  mapViewState.y = Math.max(0, centerY - targetH / 2);

  applyMapTransform();

  // Sorot juga daratan Indonesia
  const paths = document.querySelectorAll('.world-country[data-name="Indonesia"]');
  paths.forEach(p => {
    p.style.fill = '#0284C7';
    p.style.stroke = '#38BDF8';
    setTimeout(() => {
      p.style.fill = '';
      p.style.stroke = '';
    }, 1500);
  });
}

function setMapDirectScale(targetScale) {
  const currentScale = mapViewState.scale;
  if (Math.abs(targetScale - currentScale) < 0.001) return;
  const cx = mapViewState.x + mapViewState.w / 2;
  const cy = mapViewState.y + mapViewState.h / 2;

  const newW = BASE_MAP_WIDTH / targetScale;
  const newH = BASE_MAP_HEIGHT / targetScale;
  const ratioX = (cx - mapViewState.x) / mapViewState.w;
  const ratioY = (cy - mapViewState.y) / mapViewState.h;

  let newX = cx - ratioX * newW;
  let newY = cy - ratioY * newH;
  newX = Math.max(-60, Math.min(BASE_MAP_WIDTH - newW + 60, newX));
  newY = Math.max(-30, Math.min(BASE_MAP_HEIGHT - newH + 30, newY));

  mapViewState.scale = targetScale;
  mapViewState.w = newW;
  mapViewState.h = newH;
  mapViewState.x = newX;
  mapViewState.y = newY;
  applyMapTransform();
}

/** Terapkan ViewBox ke SVG & Update Badge */
function applyMapTransform() {
  const svg = document.getElementById('worldMapSvg');
  if (svg) {
    svg.setAttribute('viewBox', `${mapViewState.x} ${mapViewState.y} ${mapViewState.w} ${mapViewState.h}`);
  }

  const badge = document.getElementById('geoZoomLevelBadge');
  if (badge) {
    badge.textContent = `${mapViewState.scale.toFixed(1)}x`;
  }
  const hudText = document.getElementById('geoHudZoomText');
  if (hudText) {
    hudText.textContent = `${mapViewState.scale.toFixed(1)}x`;
  }

  // Update ukuran bulatan titik marker secara dinamis berbanding terbalik dengan zoom!
  updateBeaconTransforms();
}

/** Perbarui Transformasi Skala Bulatan Marker agar Ukuran di Layar Tetap Presisi & Proporsional */
function updateBeaconTransforms() {
  const currentScale = mapViewState.scale || 1.0;
  // Saat zoom 1.0x -> scale marker 1.0
  // Saat zoom 3.6x (Indonesia) -> scale marker 1/3.6 = 0.278 (ukuran lingkaran di layar tetap ~8px, tidak membesar menutupi pulau)
  // Saat zoom 8.0x -> scale marker 0.125
  const markerScale = Math.max(0.12, 1.0 / currentScale);
  const showCityLabel = (currentScale >= 2.0);

  document.querySelectorAll('.geo-beacon-node').forEach(node => {
    const x = parseFloat(node.getAttribute('data-x') || 0);
    const y = parseFloat(node.getAttribute('data-y') || 0);
    node.setAttribute('transform', `translate(${x}, ${y}) scale(${markerScale})`);

    const label = node.querySelector('.geo-beacon-label');
    if (label) {
      label.style.display = showCityLabel ? 'block' : 'none';
    }
  });
}

/** Update data IP untuk Peta (dipanggil dari dashboard.js) */
function updateGeoMapData(ipsList, agentsList) {
  currentMapIps = [];

  // 1. Masukkan semua simpul agen aktif
  if (Array.isArray(agentsList)) {
    agentsList.forEach(ag => {
      const ip = ag.source_ip || ag.ip;
      if (ip && !currentMapIps.some(i => i.ip === ip)) {
        currentMapIps.push({
          ip: ip,
          hostname: ag.hostname || ag.agent_id || 'Cluster Node',
          category: 'Active Agent Node',
          country: ag.country || 'Indonesia',
          country_code: ag.country_code || 'ID',
          city: ag.city || 'Cluster Gateway',
          isp: ag.isp || 'Host Infrastructure',
          request_count: 100,
          threat_level: 'Normal',
          isAgent: true
        });
      }
    });
  }

  // 2. Masukkan semua IP lalu lintas inbound
  if (Array.isArray(ipsList)) {
    ipsList.forEach(item => {
      const ip = item.ip || item.source_ip;
      if (!ip) return;
      const exist = currentMapIps.find(i => i.ip === ip);
      if (exist) {
        exist.request_count = Math.max(exist.request_count, item.request_count || 1);
        if (item.threat_level === 'Critical' || item.threat_level === 'Suspicious') {
          exist.threat_level = item.threat_level;
        }
        if (item.country) exist.country = item.country;
        if (item.country_code) exist.country_code = item.country_code;
        if (item.city) exist.city = item.city;
        if (item.isp) exist.isp = item.isp;
      } else {
        currentMapIps.push({
          ip: ip,
          hostname: item.hostname || 'Inbound Host',
          category: item.category || 'Web/Access Traffic',
          country: item.country || '',
          country_code: item.country_code || '',
          city: item.city || '',
          isp: item.isp || '',
          request_count: item.request_count || 1,
          threat_level: item.threat_level || 'Normal',
          isAgent: false
        });
      }
    });
  }

  // 3. Resolusi Geografis: Seluruh IP telah di-resolve internal oleh Backend SIEM (Go) & database
  if (isWorldMapLoaded) {
    renderGeoVisuals();
  }
}

/** Resolusi Koordinat & Negara Geografis */
function getGeoInfo(target) {
  if (!target) return null;

  let ip = '';
  let country = '';
  let code = '';
  let city = '';
  let isp = '';

  if (typeof target === 'object') {
    ip = (target.ip || target.source_ip || '').trim();
    country = target.country || '';
    code = (target.country_code || '').toUpperCase();
    city = target.city || '';
    isp = target.isp || '';
  } else {
    ip = String(target).trim();
    const found = currentMapIps.find(i => i.ip === ip);
    if (found) {
      country = found.country || '';
      code = (found.country_code || '').toUpperCase();
      city = found.city || '';
      isp = found.isp || '';
    }
  }

  // 1. Cek cache in-memory IP spesifik terlebih dahulu
  if (GEO_CACHE[ip]) return GEO_CACHE[ip];

  // 2. Cek prefix / subnet
  for (const prefix in GEO_CACHE) {
    if (ip.startsWith(prefix)) return GEO_CACHE[prefix];
  }

  // 3. Deteksi IP Private / LAN / Loopback -> Batam PDP Cluster
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || 
      ip.startsWith('172.17.') || ip.startsWith('172.18.') || ip.startsWith('172.19.') || 
      ip.startsWith('127.') || ip === '::1' || ip === 'localhost') {
    return {
      country: 'Indonesia',
      code: 'ID',
      city: 'Batam (Center SIEM)',
      lat: 1.130,
      lon: 104.052,
      flag: '🇮🇩',
      isp: 'Internal PDP Gateway'
    };
  }

  // 4. Jika koordinat riil (lat/lon) sudah disediakan langsung oleh Backend SIEM (Go) dari GeoIP
  const targetLat = (typeof target.lat === 'number' && !isNaN(target.lat)) ? target.lat : 0;
  const targetLon = (typeof target.lon === 'number' && !isNaN(target.lon)) ? target.lon : 0;
  if (targetLat !== 0 || targetLon !== 0) {
    const resolvedCountry = country || getCountryNameByCode(code);
    return {
      country: resolvedCountry,
      code: code || 'XX',
      city: (city && !city.includes('Resolving') && city !== 'ID Gateway') ? city : `${resolvedCountry} Host`,
      lat: targetLat,
      lon: targetLon,
      flag: getCountryFlag(code),
      isp: isp || 'Internet Transit'
    };
  }

  // 5. Cek apakah kota ada di kamus kota presisi Nusantara (KNOWN_CITIES)
  const cityLower = (city || '').toLowerCase();
  for (const key in KNOWN_CITIES) {
    if (cityLower.includes(key)) {
      const kc = KNOWN_CITIES[key];
      return {
        country: country || 'Indonesia',
        code: code || 'ID',
        city: kc.city,
        lat: kc.lat,
        lon: kc.lon,
        flag: getCountryFlag(code || 'ID'),
        isp: isp || 'Internet Transit'
      };
    }
  }

  // 6. Estimasi berdasarkan Kode Negara ISO (Centroid Negara)
  if (code && code !== 'XX') {
    const approxLat = getApproxLat(code);
    const approxLon = getApproxLon(code);
    const resolvedCountry = country || getCountryNameByCode(code);
    const flag = getCountryFlag(code);
    const cleanCity = (city && !city.includes('Resolving') && city !== 'ID Gateway') ? city : `${resolvedCountry} Node`;
    
    // Fallback koordinat aman: jangan pernah lempar IP asing ke Jakarta!
    let finalLat = approxLat;
    let finalLon = approxLon;
    if (finalLat === 0 && finalLon === 0) {
      if (code === 'ID') {
        finalLat = -6.2088;
        finalLon = 106.8456;
      } else {
        finalLat = 30.0;
        finalLon = 50.0;
      }
    }

    return {
      country: resolvedCountry,
      code: code,
      city: cleanCity,
      lat: finalLat,
      lon: finalLon,
      flag: flag,
      isp: isp || 'Internet Transit'
    };
  }

  // 7. Default Fallback untuk IP yang belum ter-resolve
  return {
    country: 'Internet',
    code: 'XX',
    city: 'Global Transit',
    lat: 1.130,
    lon: 104.052,
    flag: '🌐',
    isp: isp || 'Public Transit'
  };
}

/** Resolusi Geografis Asinkron (No-op: Seluruh IP telah di-resolve secara internal oleh Backend Golang SIEM) */
function resolveIpGeoAsync() {
  // Dinonaktifkan untuk mencegah network flood dan blokir ERR_BLOCKED_BY_CLIENT pada browser
}

/** Konversi Lat/Lon ke Koordinat SVG Equirectangular (1000 x 500) */
function projectToSvg(lat, lon, width = 1000, height = 500) {
  const x = (lon + 180.0) * (width / 360.0);
  const y = (90.0 - lat) * (height / 180.0);
  return {
    x: Math.max(10, Math.min(width - 10, Math.round(x * 10) / 10)),
    y: Math.max(10, Math.min(height - 10, Math.round(y * 10) / 10))
  };
}

/** Render Radar Beacons di Peta dan Daftar Negara */
function renderGeoVisuals() {
  renderMapBeacons();
  renderCountryLedger();
}

/** Plot Pinpoint Radar Beacons di Peta */
function renderMapBeacons() {
  const markersGroup = document.getElementById('mapMarkersGroup');
  if (!markersGroup) return;

  if (!currentMapIps || currentMapIps.length === 0) {
    markersGroup.innerHTML = '';
    return;
  }

  // Agregasi per Lokasi Geografis (Kota/Wilayah) agar titik tidak menumpuk sembarangan
  const locationMap = {};

  currentMapIps.forEach(item => {
    const geo = getGeoInfo(item);
    if (!geo || isNaN(geo.lat) || isNaN(geo.lon)) return;

    const coords = projectToSvg(geo.lat, geo.lon);

    // Kunci spasial grid (toleransi 10px SVG) agar titik yang tumpang tindih menyatu menjadi 1 beacon bersih
    const gridX = Math.round(coords.x / 10) * 10;
    const gridY = Math.round(coords.y / 10) * 10;
    const locKey = `${geo.code || 'ID'}_${gridX}_${gridY}`;

    if (!locationMap[locKey]) {
      locationMap[locKey] = {
        city: geo.city,
        country: geo.country,
        code: geo.code,
        flag: geo.flag || getCountryFlag(geo.code),
        lat: geo.lat,
        lon: geo.lon,
        x: coords.x,
        y: coords.y,
        isp: geo.isp,
        items: [],
        ips: new Set(),
        hostnames: new Set(),
        totalRequests: 0,
        hasCritical: false,
        hasSuspicious: false,
        isAgent: false
      };
    } else {
      // Prioritaskan nama kota yang valid dan bersih dari teks internal
      const currentCity = locationMap[locKey].city || '';
      if ((currentCity.includes('Resolving') || currentCity.includes('Gateway') || currentCity === 'Default') &&
          geo.city && !geo.city.includes('Resolving') && !geo.city.includes('Gateway')) {
        locationMap[locKey].city = geo.city;
      }
    }

    const loc = locationMap[locKey];
    loc.items.push(item);
    loc.ips.add(item.ip);
    if (item.hostname) loc.hostnames.add(item.hostname);
    loc.totalRequests += (item.request_count || 1);
    if (item.threat_level === 'Critical') loc.hasCritical = true;
    if (item.threat_level === 'Suspicious') loc.hasSuspicious = true;
    if (item.isAgent) loc.isAgent = true;
  });

  const locations = Object.values(locationMap);
  const currentScale = mapViewState.scale || 1.0;
  // Dynamic inverse scaling: di skala 1x (world) markerScale = 1.0, di skala 3.6x (Indonesia) markerScale = 0.278
  const markerScale = Math.max(0.12, 1.0 / currentScale);
  const showCityLabel = (currentScale >= 2.0);

  markersGroup.innerHTML = locations.map(loc => {
    const isCrit = loc.hasCritical;
    const isWarn = !isCrit && loc.hasSuspicious;

    const beaconColor = isCrit ? '#EF4444' : isWarn ? '#F59E0B' : '#00F0FF';
    const coreColor = isCrit ? '#F87171' : isWarn ? '#FBBF24' : '#10B981';
    const threatLevel = isCrit ? 'Critical' : isWarn ? 'Suspicious' : 'Normal';

    const ipListStr = Array.from(loc.ips).join(', ');
    const hostStr = Array.from(loc.hostnames).join(', ') || 'Cluster Host';
    const flag = loc.flag || '🌐';

    // Nama kota singkat untuk label (bersihkan teks internal & hindari label bertumpuk)
    let shortCity = (loc.city || 'Node').split(',')[0].replace(/\(.*?\)/g, '').trim();
    if (shortCity.includes('Resolving') || shortCity.length === 0) {
      shortCity = loc.country || 'Node';
    }

    return `
      <g class="geo-beacon-node" 
         data-x="${loc.x}" 
         data-y="${loc.y}"
         transform="translate(${loc.x}, ${loc.y}) scale(${markerScale})"
         onmousedown="event.stopPropagation()"
         onmouseenter="showGeoTooltip(event, '${escapeHtml(loc.city)}', '${escapeHtml(loc.country)}', '${flag}', '${escapeHtml(ipListStr)}', '${escapeHtml(hostStr)}', '${loc.totalRequests}', '${threatLevel}', '${escapeHtml(loc.isp)}')"
         onmouseleave="hideGeoTooltip()"
         style="cursor: pointer;">
        
        <!-- Radar Pulse Ripple Animation (Ukuran Tetap di Layar saat Zoom) -->
        <circle r="4" fill="none" stroke="${beaconColor}" stroke-width="1.5" vector-effect="non-scaling-stroke" opacity="0.8">
          <animate attributeName="r" values="3;16" dur="2s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.9;0" dur="2s" repeatCount="indefinite" />
        </circle>
        
        <!-- Outer Ring -->
        <circle r="4" fill="${coreColor}" stroke="#0F172A" stroke-width="1.2" vector-effect="non-scaling-stroke" />
        
        <!-- Crisp Center White Core -->
        <circle r="1.6" fill="#FFFFFF" />

        <!-- Short City Label (muncul saat zoom >= 2.0x) -->
        <text class="geo-beacon-label" x="7" y="3" 
              fill="#FFFFFF" stroke="#071529" stroke-width="2.5" paint-order="stroke" 
              font-size="8.5" font-family="'JetBrains Mono', monospace" font-weight="700" 
              style="display: ${showCityLabel ? 'block' : 'none'}; pointer-events: none; user-select: none;">
          ${escapeHtml(shortCity)}
        </text>
      </g>
    `;
  }).join('');
}

/** Render Panel Sebaran Negara di Samping Peta */
function renderCountryLedger() {
  const ledgerEl = document.getElementById('geoCountryList');
  const totalCountBadge = document.getElementById('geoTotalCountriesBadge');
  const activeIpsBadge = document.getElementById('geoActiveIpsCount');
  const topCountryEl = document.getElementById('geoTopCountry');
  const domesticPctEl = document.getElementById('geoDomesticPct');
  const threatCountEl = document.getElementById('geoThreatCount');

  if (!ledgerEl) return;

  if (!currentMapIps || currentMapIps.length === 0) {
    ledgerEl.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); padding: 24px; font-size: 11px;">
        Menunggu deteksi IP armada simpul dan akses web...
      </div>
    `;
    return;
  }

  // Agregasi per Negara
  const countryMap = {};
  let totalRequests = 0;
  let domesticRequests = 0;
  let threatIpsCount = 0;

  currentMapIps.forEach(item => {
    const geo = getGeoInfo(item);
    const code = geo.code || 'ID';
    const name = geo.country || 'Indonesia';
    const flag = geo.flag || getCountryFlag(code);
    const hits = Number(item.request_count || 1);

    totalRequests += hits;
    if (code === 'ID') domesticRequests += hits;
    if (item.threat_level === 'Critical' || item.threat_level === 'Suspicious') {
      threatIpsCount++;
    }

    if (!countryMap[code]) {
      countryMap[code] = {
        code,
        name,
        flag,
        hits: 0,
        ips: [],
        hasThreat: false
      };
    }

    countryMap[code].hits += hits;
    countryMap[code].ips.push({ ip: item.ip, host: item.hostname, hits: hits, threat: item.threat_level });
    if (item.threat_level === 'Critical' || item.threat_level === 'Suspicious') {
      countryMap[code].hasThreat = true;
    }
  });

  const countries = Object.values(countryMap).sort((a, b) => b.hits - a.hits);

  // Update Summary Badges
  if (totalCountBadge) totalCountBadge.textContent = `${countries.length} NEGARA TERDETEKSI`;
  if (activeIpsBadge) activeIpsBadge.textContent = `${currentMapIps.length} IP AKTIF`;

  if (topCountryEl && countries.length > 0) {
    topCountryEl.textContent = `${countries[0].flag} ${countries[0].name}`;
  }

  if (domesticPctEl) {
    const pct = totalRequests > 0 ? Math.round((domesticRequests / totalRequests) * 100) : 100;
    domesticPctEl.textContent = `${pct}%`;
  }

  if (threatCountEl) {
    threatCountEl.textContent = `${threatIpsCount} IP`;
  }

  // Render List Card per Negara
  ledgerEl.innerHTML = countries.map(c => {
    const pctRaw = totalRequests > 0 ? (c.hits / totalRequests) * 100 : 0;
    let barWidth = 0;
    let pctDisplay = '0%';
    if (c.hits > 0) {
      if (pctRaw >= 1) {
        pctDisplay = `${Math.round(pctRaw)}%`;
        barWidth = Math.min(Math.round(pctRaw), 100);
      } else if (pctRaw >= 0.1) {
        pctDisplay = `${pctRaw.toFixed(1)}%`;
        barWidth = Math.max(pctRaw, 3);
      } else {
        pctDisplay = `<0.1%`;
        barWidth = 3; // Minimal 3% lebar visual bar agar tampak terisi jelas
      }
    }

    const ipPills = c.ips.slice(0, 3).map(i => `<code>${escapeHtml(i.ip)}</code>`).join(', ');
    const moreIps = c.ips.length > 3 ? ` +${c.ips.length - 3}` : '';

    const statusTag = c.hasThreat ?
      `<span class="pixel-tag tag-critical">THREAT</span>` :
      `<span class="pixel-tag tag-clean">CLEAN</span>`;

    return `
      <div class="geo-country-item" onclick="focusCountryPin('${c.code}')">
        <div class="geo-country-header">
          <div class="geo-country-name-wrap">
            <span class="geo-country-flag">${c.flag}</span>
            <span>${escapeHtml(c.name)}</span>
            <span style="font-size: 9px; color: var(--text-muted); font-weight: normal;">(${c.code})</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px;">
            <strong style="font-size: 11px; color: #0284C7;">${c.hits.toLocaleString()} req</strong>
            ${statusTag}
          </div>
        </div>

        <!-- Progress Bar Share -->
        <div class="route-load-bar-wrap" style="height: 6px; margin-top: 4px;">
          <div class="route-load-bar-fill" style="width: ${barWidth}%; height: 100%; background: ${c.hasThreat ? '#EF4444' : '#06B6D4'};"></div>
        </div>

        <div class="geo-country-ips-sub">
          IP: ${ipPills}${moreIps} (${pctDisplay} trafik)
        </div>
      </div>
    `;
  }).join('');
}

/** Tampilkan Tooltip Hover pada Titik Pinpoint Peta */
function showGeoTooltip(e, city, country, flag, ipListStr, hostStr, hits, threat, isp) {
  const tooltip = document.getElementById('geoMapTooltip');
  const screenCard = document.querySelector('.geo-map-screen-card');
  if (!tooltip || !screenCard) return;

  const rect = screenCard.getBoundingClientRect();
  const x = e.clientX - rect.left + 14;
  const y = e.clientY - rect.top - 20;

  const isCrit = (threat === 'Critical');
  const threatBadge = isCrit ?
    `<span class="pixel-tag tag-critical">CRITICAL ATTACK</span>` :
    (threat === 'Suspicious' ? `<span class="pixel-tag tag-warning">SUSPICIOUS</span>` : `<span class="pixel-tag tag-clean">NORMAL</span>`);

  const ipBadges = (ipListStr || '').split(',').map(ip => `<code>${escapeHtml(ip.trim())}</code>`).join(' ');

  tooltip.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; border-bottom: 1px solid #CBD5E1; padding-bottom: 4px;">
      <div style="font-weight: 800; font-size: 11px; color: #0F172A;">
        <span style="font-size: 13px;">${flag}</span> ${city}
      </div>
      ${threatBadge}
    </div>
    <div style="font-size: 10px; margin-bottom: 3px;">
      <span style="color: #64748B;">Negara:</span> <strong>${country}</strong>
    </div>
    <div style="font-size: 10px; margin-bottom: 3px;">
      <span style="color: #64748B;">IP Node:</span> ${ipBadges}
    </div>
    <div style="font-size: 10px; margin-bottom: 3px;">
      <span style="color: #64748B;">Target Host:</span> ${hostStr}
    </div>
    <div style="font-size: 10px; margin-bottom: 3px;">
      <span style="color: #64748B;">Network/ISP:</span> ${isp}
    </div>
    <div style="font-size: 10px; color: #0284C7; font-weight: 700; margin-top: 4px;">
      Total Aktivitas: ${hits} requests
    </div>
  `;

  tooltip.style.left = `${Math.min(x, rect.width - 240)}px`;
  tooltip.style.top = `${Math.max(10, Math.min(y, rect.height - 150))}px`;
  tooltip.classList.remove('hidden');
}

function hideGeoTooltip() {
  const tooltip = document.getElementById('geoMapTooltip');
  if (tooltip) tooltip.classList.add('hidden');
}

function focusCountryPin(code) {
  const countryName = getCountryNameByCode(code);
  const paths = document.querySelectorAll(`.world-country[data-name="${countryName}"]`);
  paths.forEach(p => {
    p.style.fill = '#0284C7';
    p.style.stroke = '#38BDF8';
    p.style.strokeWidth = '1.5px';
    setTimeout(() => {
      p.style.fill = '';
      p.style.stroke = '';
      p.style.strokeWidth = '';
    }, 2000);
  });

  if (code === 'ID') {
    focusIndonesiaZoom();
  } else {
    const lat = getApproxLat(code);
    const lon = getApproxLon(code);
    if (lat !== 0 || lon !== 0) {
      const coords = projectToSvg(lat, lon);
      const targetScale = 3.2;
      const targetW = BASE_MAP_WIDTH / targetScale;
      const targetH = BASE_MAP_HEIGHT / targetScale;
      mapViewState.scale = targetScale;
      mapViewState.w = targetW;
      mapViewState.h = targetH;
      mapViewState.x = Math.max(-50, Math.min(BASE_MAP_WIDTH - targetW + 50, coords.x - targetW / 2));
      mapViewState.y = Math.max(-25, Math.min(BASE_MAP_HEIGHT - targetH + 25, coords.y - targetH / 2));
      applyMapTransform();
    }
  }
}

function refreshGeoMap() {
  if (typeof updateGeoMapData === 'function' && window.dashState) {
    updateGeoMapData(window.dashState.ips, window.dashState.agents);
  }
  renderGeoVisuals();
}

/** Kamus Pusat Koordinat & Nama Negara Dunia (ISO-2 Centroids) */
const WORLD_COUNTRIES = {
  'AF': { name: 'Afghanistan', lat: 33.9391, lon: 67.7099 },
  'AL': { name: 'Albania', lat: 41.1533, lon: 20.1683 },
  'DZ': { name: 'Algeria', lat: 28.0339, lon: 1.6596 },
  'AD': { name: 'Andorra', lat: 42.5063, lon: 1.5218 },
  'AO': { name: 'Angola', lat: -11.2027, lon: 17.8739 },
  'AR': { name: 'Argentina', lat: -38.4161, lon: -63.6167 },
  'AM': { name: 'Armenia', lat: 40.0691, lon: 45.0382 },
  'AU': { name: 'Australia', lat: -25.2744, lon: 133.7751 },
  'AT': { name: 'Austria', lat: 47.5162, lon: 14.5501 },
  'AZ': { name: 'Azerbaijan', lat: 40.1431, lon: 47.5769 },
  'BD': { name: 'Bangladesh', lat: 23.6850, lon: 90.3563 },
  'BY': { name: 'Belarus', lat: 53.7098, lon: 27.9534 },
  'BE': { name: 'Belgium', lat: 50.5039, lon: 4.4699 },
  'BZ': { name: 'Belize', lat: 17.1899, lon: -88.4976 },
  'BO': { name: 'Bolivia', lat: -16.2902, lon: -63.5887 },
  'BA': { name: 'Bosnia and Herzegovina', lat: 43.9159, lon: 17.6791 },
  'BR': { name: 'Brazil', lat: -14.2350, lon: -51.9253 },
  'BG': { name: 'Bulgaria', lat: 42.7339, lon: 25.4858 },
  'KH': { name: 'Cambodia', lat: 12.5657, lon: 104.9910 },
  'CA': { name: 'Canada', lat: 56.1304, lon: -106.3468 },
  'CL': { name: 'Chile', lat: -35.6751, lon: -71.5430 },
  'CN': { name: 'China', lat: 35.8617, lon: 104.1954 },
  'CO': { name: 'Colombia', lat: 4.5709, lon: -74.2973 },
  'CR': { name: 'Costa Rica', lat: 9.7489, lon: -83.7534 },
  'HR': { name: 'Croatia', lat: 45.1000, lon: 15.2000 },
  'CU': { name: 'Cuba', lat: 21.5218, lon: -77.7812 },
  'CY': { name: 'Cyprus', lat: 35.1264, lon: 33.4299 },
  'CZ': { name: 'Czechia', lat: 49.8175, lon: 15.4730 },
  'DK': { name: 'Denmark', lat: 56.2639, lon: 9.5018 },
  'EG': { name: 'Egypt', lat: 26.8206, lon: 30.8025 },
  'EE': { name: 'Estonia', lat: 58.5953, lon: 25.0136 },
  'ET': { name: 'Ethiopia', lat: 9.1450, lon: 40.4897 },
  'FI': { name: 'Finland', lat: 61.9241, lon: 25.7482 },
  'FR': { name: 'France', lat: 46.2276, lon: 2.2137 },
  'GE': { name: 'Georgia', lat: 42.3154, lon: 43.3569 },
  'DE': { name: 'Germany', lat: 51.1657, lon: 10.4515 },
  'GR': { name: 'Greece', lat: 39.0742, lon: 21.8243 },
  'HK': { name: 'Hong Kong', lat: 22.3193, lon: 114.1694 },
  'HU': { name: 'Hungary', lat: 47.1625, lon: 19.5033 },
  'IS': { name: 'Iceland', lat: 64.9631, lon: -19.0208 },
  'IN': { name: 'India', lat: 20.5937, lon: 78.9629 },
  'ID': { name: 'Indonesia', lat: -0.7893, lon: 113.9213 },
  'IR': { name: 'Iran', lat: 32.4279, lon: 53.6880 },
  'IQ': { name: 'Iraq', lat: 33.2232, lon: 43.6793 },
  'IE': { name: 'Ireland', lat: 53.1424, lon: -7.6921 },
  'IL': { name: 'Israel', lat: 31.0461, lon: 34.8516 },
  'IT': { name: 'Italy', lat: 41.8719, lon: 12.5674 },
  'JP': { name: 'Japan', lat: 36.2048, lon: 138.2529 },
  'JO': { name: 'Jordan', lat: 30.5852, lon: 36.2384 },
  'KZ': { name: 'Kazakhstan', lat: 48.0196, lon: 66.9237 },
  'KE': { name: 'Kenya', lat: -0.0236, lon: 37.9062 },
  'KR': { name: 'South Korea', lat: 35.9078, lon: 127.7669 },
  'KW': { name: 'Kuwait', lat: 29.3117, lon: 47.4818 },
  'LV': { name: 'Latvia', lat: 56.8796, lon: 24.6032 },
  'LB': { name: 'Lebanon', lat: 33.8547, lon: 35.8623 },
  'LY': { name: 'Libya', lat: 26.3351, lon: 17.2283 },
  'LT': { name: 'Lithuania', lat: 55.1694, lon: 23.8813 },
  'LU': { name: 'Luxembourg', lat: 49.8153, lon: 6.1296 },
  'MY': { name: 'Malaysia', lat: 3.1390, lon: 101.6869 },
  'MX': { name: 'Mexico', lat: 23.6345, lon: -102.5528 },
  'MD': { name: 'Moldova', lat: 47.4116, lon: 28.3699 },
  'MA': { name: 'Morocco', lat: 31.7917, lon: -7.0926 },
  'MM': { name: 'Myanmar', lat: 21.9162, lon: 95.9560 },
  'NL': { name: 'The Netherlands', lat: 52.1326, lon: 5.2913 },
  'NZ': { name: 'New Zealand', lat: -40.9006, lon: 174.8860 },
  'NG': { name: 'Nigeria', lat: 9.0820, lon: 8.6753 },
  'NO': { name: 'Norway', lat: 60.4720, lon: 8.4689 },
  'OM': { name: 'Oman', lat: 21.5126, lon: 55.9233 },
  'PK': { name: 'Pakistan', lat: 30.3753, lon: 69.3451 },
  'PS': { name: 'Palestine', lat: 31.9522, lon: 35.2332 },
  'PA': { name: 'Panama', lat: 8.5379, lon: -80.7821 },
  'PY': { name: 'Paraguay', lat: -23.4425, lon: -58.4438 },
  'PE': { name: 'Peru', lat: -9.1899, lon: -75.0152 },
  'PH': { name: 'Philippines', lat: 12.8797, lon: 121.7740 },
  'PL': { name: 'Poland', lat: 51.9194, lon: 19.1451 },
  'PT': { name: 'Portugal', lat: 39.3999, lon: -8.2245 },
  'QA': { name: 'Qatar', lat: 25.3548, lon: 51.1839 },
  'RO': { name: 'Romania', lat: 45.9432, lon: 24.9668 },
  'RU': { name: 'Russia', lat: 61.5240, lon: 105.3188 },
  'SA': { name: 'Saudi Arabia', lat: 23.8859, lon: 45.0792 },
  'RS': { name: 'Serbia', lat: 44.0165, lon: 21.0059 },
  'SG': { name: 'Singapore', lat: 1.3521, lon: 103.8198 },
  'SK': { name: 'Slovakia', lat: 48.6690, lon: 19.6990 },
  'SI': { name: 'Slovenia', lat: 46.1512, lon: 14.9955 },
  'ZA': { name: 'South Africa', lat: -30.5595, lon: 22.9375 },
  'ES': { name: 'Spain', lat: 40.4637, lon: -3.7492 },
  'LK': { name: 'Sri Lanka', lat: 7.8731, lon: 80.7718 },
  'SE': { name: 'Sweden', lat: 60.1282, lon: 18.6435 },
  'CH': { name: 'Switzerland', lat: 46.8182, lon: 8.2275 },
  'TW': { name: 'Taiwan', lat: 23.6978, lon: 120.9605 },
  'TH': { name: 'Thailand', lat: 15.8700, lon: 100.9925 },
  'TR': { name: 'Turkey', lat: 38.9637, lon: 35.2433 },
  'UA': { name: 'Ukraine', lat: 48.3794, lon: 31.1656 },
  'AE': { name: 'United Arab Emirates', lat: 23.4241, lon: 53.8478 },
  'GB': { name: 'United Kingdom', lat: 55.3781, lon: -3.4360 },
  'US': { name: 'United States', lat: 37.0902, lon: -95.7129 },
  'UY': { name: 'Uruguay', lat: -32.5228, lon: -55.7658 },
  'UZ': { name: 'Uzbekistan', lat: 41.3775, lon: 64.5853 },
  'VE': { name: 'Venezuela', lat: 6.4238, lon: -66.5897 },
  'VN': { name: 'Vietnam', lat: 14.0583, lon: 108.2772 },
  'YE': { name: 'Yemen', lat: 15.5527, lon: 48.5164 },
  'ZW': { name: 'Zimbabwe', lat: -19.0154, lon: 29.1549 }
};

/** Helper Nama Negara dari Kode ISO */
function getCountryNameByCode(code) {
  if (!code) return 'Internet';
  const c = code.toUpperCase();
  if (WORLD_COUNTRIES[c]) return WORLD_COUNTRIES[c].name;
  return c;
}

function getApproxLat(code) {
  if (!code) return 0;
  const c = code.toUpperCase();
  if (WORLD_COUNTRIES[c]) return WORLD_COUNTRIES[c].lat;
  return 0;
}

function getApproxLon(code) {
  if (!code) return 0;
  const c = code.toUpperCase();
  if (WORLD_COUNTRIES[c]) return WORLD_COUNTRIES[c].lon;
  return 0;
}

function getCountryFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// Global Exports
window.updateGeoMapData = updateGeoMapData;
window.refreshGeoMap = refreshGeoMap;
window.showGeoTooltip = showGeoTooltip;
window.hideGeoTooltip = hideGeoTooltip;
window.focusCountryPin = focusCountryPin;
window.zoomMap = zoomMap;
window.resetMapZoom = resetMapZoom;
window.focusIndonesiaZoom = focusIndonesiaZoom;
