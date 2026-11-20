// ==========================================================================
// CLEAN CORPORATE PIXEL / NEO-BRUTALIST CHART ENGINE (ZERO EXTERNAL DEPENDENCY)
// Electric Cyan (#06B6D4) & Emerald (#10B981) Palette • 2px Borders • Stepped Pixel Highlights
// ==========================================================================

/**
 * 1. PixelBarChart - Dual-Bar Comparison: Request Berhasil (#06B6D4) vs Total Beban (#10B981)
 * Supports dynamic range switching: '7D', '30D', '12M'
 */
class PixelBarChart {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.options = Object.assign({
      colorSuccess: '#06B6D4', // Primary Electric Cyan
      colorLoad: '#10B981',    // Secondary Emerald
      borderColor: '#0F172A',
      textColor: '#0F172A',
      gridColor: '#E2E8F0',
      currentRange: '24H'
    }, options);

    this.currentRange = this.options.currentRange;
    this.datasets = {
      '24H': ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'].map(l => ({ label: l, success: 0, load: 0 })),
      '7D': ['SEN', 'SEL', 'RAB', 'KAM', 'JUM', 'SAB', 'MIN'].map(l => ({ label: l, success: 0, load: 0 })),
      '30D': ['MGG 1', 'MGG 2', 'MGG 3', 'MGG 4', 'MGG 5'].map(l => ({ label: l, success: 0, load: 0 })),
      '12M': ['JAN', 'FEB', 'MAR', 'APR', 'MEI', 'JUN', 'JUL', 'AGU', 'SEP', 'OKT', 'NOV', 'DES'].map(l => ({ label: l, success: 0, load: 0 }))
    };

    this.setupResize();
    this.setupInteractivity();
    this.render();
  }

  setupResize() {
    this._resizeHandler = () => {
      if (!this.canvas || !this.canvas.parentElement) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = (rect.height || 220) * dpr;
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height || 220;
      this.render();
    };
    window.addEventListener('resize', this._resizeHandler);
    this._resizeTimer = setTimeout(this._resizeHandler, 40);
  }

  setupInteractivity() {
    this.hoverIdx = -1;
    if (!this.canvas) return;

    this._mouseMoveHandler = (e) => {
      if (!this.width) return;
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const padLeft = 44;
      const padRight = 16;
      const chartW = this.width - padLeft - padRight;
      const data = this.datasets[this.currentRange] || [];
      if (data.length === 0) return;
      const slotW = chartW / data.length;
      const idx = Math.floor((mouseX - padLeft) / slotW);
      if (idx >= 0 && idx < data.length) {
        if (this.hoverIdx !== idx) {
          this.hoverIdx = idx;
          this.render();
        }
      } else if (this.hoverIdx !== -1) {
        this.hoverIdx = -1;
        this.render();
      }
    };

    this._mouseLeaveHandler = () => {
      if (this.hoverIdx !== -1) {
        this.hoverIdx = -1;
        this.render();
      }
    };

    this.canvas.addEventListener('mousemove', this._mouseMoveHandler);
    this.canvas.addEventListener('mouseleave', this._mouseLeaveHandler);
  }

  destroy() {
    if (this._resizeTimer) {
      clearTimeout(this._resizeTimer);
      this._resizeTimer = null;
    }
    if (this._resizeHandler) {
      window.removeEventListener('resize', this._resizeHandler);
      this._resizeHandler = null;
    }
    if (this.canvas) {
      if (this._mouseMoveHandler) {
        this.canvas.removeEventListener('mousemove', this._mouseMoveHandler);
        this._mouseMoveHandler = null;
      }
      if (this._mouseLeaveHandler) {
        this.canvas.removeEventListener('mouseleave', this._mouseLeaveHandler);
        this._mouseLeaveHandler = null;
      }
    }
    this.canvas = null;
    this.ctx = null;
  }

  setRange(range) {
    if (this.datasets[range]) {
      this.currentRange = range;
      this.hoverIdx = -1;
      this.render();
    }
  }

  updateData(range, data) {
    if (this.datasets[range] && Array.isArray(data)) {
      this.datasets[range] = data;
      if (this.currentRange === range) {
        this.render();
      }
    }
  }

  render() {
    if (!this.ctx || !this.width) return;
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    ctx.clearRect(0, 0, w, h);
    ctx.imageSmoothingEnabled = false;

    const data = this.datasets[this.currentRange] || this.datasets['12M'];
    const padLeft = 44;
    const padBottom = 34;
    const padTop = 40; // Headroom lapang agar angka badge melayang bebas di atas bar
    const padRight = 16;
    const chartW = w - padLeft - padRight;
    const chartH = h - padTop - padBottom;

    // Calculate maximum value across success & load dengan 30% safety headroom
    let max = 10;
    data.forEach(d => {
      const v = Math.max(d.success || 0, d.load || 0, d.value || 0);
      if (v > max) max = v;
    });
    max = Math.ceil((Math.max(max, 10) * 1.30) / 10) * 10;

    // Dotted Grid Lines
    ctx.strokeStyle = this.options.gridColor;
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 3]);

    const gridSteps = 4;
    for (let i = 0; i <= gridSteps; i++) {
      const y = padTop + (chartH / gridSteps) * i;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(w - padRight, y);
      ctx.stroke();

      // Y-axis label - Bold & Kontras Tinggi (#0F172A)
      ctx.setLineDash([]);
      ctx.fillStyle = '#0F172A';
      ctx.font = 'bold 10px "JetBrains Mono", monospace';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      const val = Math.round(max - (max / gridSteps) * i);
      ctx.fillText(String(val), padLeft - 8, y);
      ctx.setLineDash([2, 3]);
    }
    ctx.setLineDash([]);

    // Draw Paired Stepped Bars
    const slotCount = data.length;
    const slotW = chartW / slotCount;
    const barW = Math.min(Math.floor(slotW * 0.36), 22);

    data.forEach((item, idx) => {
      const centerX = padLeft + idx * slotW + slotW / 2;
      const x1 = Math.floor(centerX - barW - 1.5); // Success bar (Cyan)
      const x2 = Math.floor(centerX + 1.5);       // Load bar (Emerald)

      const successVal = item.success !== undefined ? item.success : item.value || 0;
      const loadVal = item.load !== undefined ? item.load : Math.round(successVal * 1.2);

      const h1 = Math.max(Math.floor((successVal / max) * chartH), 2);
      const y1 = Math.floor(padTop + chartH - h1);

      const h2 = Math.max(Math.floor((loadVal / max) * chartH), 2);
      const y2 = Math.floor(padTop + chartH - h2);

      const isHovered = (this.hoverIdx === idx);

      // --- 1. Bar 1: Request Berhasil (#06B6D4) ---
      ctx.fillStyle = isHovered ? '#38BDF8' : this.options.colorSuccess;
      ctx.fillRect(x1, y1, barW, h1);
      ctx.strokeStyle = this.options.borderColor;
      ctx.lineWidth = 1.5;
      ctx.strokeRect(x1, y1, barW, h1);

      // Stepped Top Pixel Cap Highlight
      ctx.fillStyle = '#E0F2FE';
      ctx.fillRect(x1 + 1, y1 + 1, barW - 2, 2);

      // --- 2. Bar 2: Total Beban (#10B981) ---
      ctx.fillStyle = isHovered ? '#34D399' : this.options.colorLoad;
      ctx.fillRect(x2, y2, barW, h2);
      ctx.strokeStyle = this.options.borderColor;
      ctx.lineWidth = 1.5;
      ctx.strokeRect(x2, y2, barW, h2);

      // Stepped Top Pixel Cap Highlight
      ctx.fillStyle = '#D1FAE5';
      ctx.fillRect(x2 + 1, y2 + 1, barW - 2, 2);

      // --- 3. Crisp Neo-Brutalist Value Badge Above Bars ---
      const topY = Math.min(y1, y2);
      
      // Tentukan teks badge yang informatif
      let badgeText = '';
      if (slotCount <= 7) {
        // Pada rentang 7D: tampilkan perbandingan jika berbeda, atau angka tunggal jika sama
        badgeText = (successVal === loadVal) ? String(loadVal) : `${successVal}/${loadVal}`;
      } else {
        // Pada rentang bulanan yang lebih padat
        badgeText = String(loadVal);
      }

      ctx.font = 'bold 10px "JetBrains Mono", monospace';
      const textMetrics = ctx.measureText(badgeText);
      const textW = Math.ceil(textMetrics.width);
      const badgeW = Math.max(textW + 10, 22);
      const badgeH = 17;
      const badgeX = Math.floor(centerX - badgeW / 2);
      // Jarak 6px di atas bar tertinggi, tidak pernah memotong garis hitam bar!
      const badgeY = Math.floor(topY - badgeH - 6);

      // Hard shadow neo-brutalist (2px x 2px)
      ctx.fillStyle = '#0F172A';
      ctx.fillRect(badgeX + 2, badgeY + 2, badgeW, badgeH);

      // Badge Surface (highlight jika di-hover atau aktif)
      if (isHovered) {
        ctx.fillStyle = '#00F0FF';
      } else if (loadVal >= 100) {
        ctx.fillStyle = '#FEF3C7';
      } else {
        ctx.fillStyle = '#FFFFFF';
      }
      ctx.fillRect(badgeX, badgeY, badgeW, badgeH);

      // Border tegas 1.5px
      ctx.strokeStyle = '#0F172A';
      ctx.lineWidth = 1.5;
      ctx.strokeRect(badgeX, badgeY, badgeW, badgeH);

      // Teks angka kontras tinggi di dalam badge
      ctx.fillStyle = '#0F172A';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(badgeText, centerX, badgeY + Math.floor(badgeH / 2) + 1);

      // --- 4. X-Axis Label ---
      ctx.fillStyle = isHovered ? '#0284C7' : '#0F172A';
      ctx.font = isHovered ? 'bold 10px "JetBrains Mono", monospace' : 'bold 9px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(item.label, centerX, padTop + chartH + 8);
    });
  }
}

/**
 * 2. PixelDonutChart - Segmented Ring for System Status Distribution
 * Proportions: ONLINE (#10B981), PROCESSING (#06B6D4), WARNING (#F59E0B)
 */
class PixelDonutChart {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.options = Object.assign({
      borderColor: '#0F172A',
      centerLabel: 'TOTAL NODES'
    }, options);

    this.segments = [
      { label: 'ONLINE', value: 0, color: '#10B981' },
      { label: 'PROCESSING', value: 0, color: '#06B6D4' },
      { label: 'WARNING', value: 0, color: '#F59E0B' }
    ];

    this.setupResize();
    this.render();
  }

  setupResize() {
    this._resizeHandler = () => {
      if (!this.canvas || !this.canvas.parentElement) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = (rect.height || 220) * dpr;
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height || 220;
      this.render();
    };
    window.addEventListener('resize', this._resizeHandler);
    this._resizeTimer = setTimeout(this._resizeHandler, 40);
  }

  destroy() {
    if (this._resizeTimer) {
      clearTimeout(this._resizeTimer);
      this._resizeTimer = null;
    }
    if (this._resizeHandler) {
      window.removeEventListener('resize', this._resizeHandler);
      this._resizeHandler = null;
    }
    this.canvas = null;
    this.ctx = null;
  }

  update(newSegments) {
    if (Array.isArray(newSegments)) {
      this.segments = newSegments;
      this.render();
    }
  }

  render() {
    if (!this.ctx || !this.width) return;
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    ctx.clearRect(0, 0, w, h);
    ctx.imageSmoothingEnabled = false;

    const total = this.segments.reduce((acc, s) => acc + (s.value || 0), 0);
    const centerX = Math.floor(w / 2);
    const centerY = Math.floor(h / 2);
    const outerR = Math.floor(Math.min(w, h) * 0.40);
    const innerR = Math.floor(outerR * 0.54);

    let startAngle = -Math.PI / 2;

    if (total === 0) {
      ctx.beginPath();
      ctx.arc(centerX, centerY, outerR, 0, Math.PI * 2);
      ctx.arc(centerX, centerY, innerR, Math.PI * 2, 0, true);
      ctx.fillStyle = '#F1F5F9';
      ctx.fill();
      ctx.strokeStyle = this.options.borderColor;
      ctx.lineWidth = 2;
      ctx.stroke();
    } else {
      this.segments.forEach(seg => {
        if (!seg.value || seg.value <= 0) return;
        const sliceAngle = (seg.value / total) * Math.PI * 2;
        const endAngle = startAngle + sliceAngle;

        ctx.beginPath();
        ctx.arc(centerX, centerY, outerR, startAngle, endAngle);
        ctx.arc(centerX, centerY, innerR, endAngle, startAngle, true);
        ctx.closePath();

        ctx.fillStyle = seg.color;
        ctx.fill();

        ctx.strokeStyle = this.options.borderColor;
        ctx.lineWidth = 2;
        ctx.stroke();

        startAngle = endAngle;
      });
    }

    // Inner Circle Core (Subtle Slate Background)
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerR - 2, 0, Math.PI * 2);
    ctx.fillStyle = '#FFFFFF';
    ctx.fill();
    ctx.strokeStyle = '#CBD5E1';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Center Total Count & Label
    ctx.fillStyle = this.options.borderColor;
    ctx.font = '800 18px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(String(total), centerX, centerY - 6);

    ctx.font = '800 8px "JetBrains Mono", monospace';
    ctx.fillStyle = '#64748B';
    ctx.fillText(this.options.centerLabel, centerX, centerY + 12);
  }
}

/**
 * 3. PixelLineChart - Real-Time Telemetry Area Chart
 * Dual Series: Throughput / EPS (#06B6D4) with translucent cyan area & Latency / Response Time (#10B981)
 */
class PixelLineChart {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.options = Object.assign({
      colorThroughput: '#06B6D4',
      fillThroughput: 'rgba(6, 182, 212, 0.18)',
      colorLatency: '#10B981',
      fillLatency: 'rgba(16, 185, 129, 0.10)',
      pointColor: '#10B981',
      borderColor: '#0F172A',
      maxPoints: 24,
      title: 'THROUGHPUT & LATENCY'
    }, options);

    // Initial series values (clean 0-state, updated dynamically by live telemetry)
    this.throughputPoints = new Array(this.options.maxPoints).fill(0);
    this.latencyPoints = new Array(this.options.maxPoints).fill(0);

    this.setupResize();
    this.render();
  }

  setupResize() {
    this._resizeHandler = () => {
      if (!this.canvas || !this.canvas.parentElement) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = (rect.height || 220) * dpr;
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height || 220;
      this.render();
    };
    window.addEventListener('resize', this._resizeHandler);
    this._resizeTimer = setTimeout(this._resizeHandler, 40);
  }

  destroy() {
    if (this._resizeTimer) {
      clearTimeout(this._resizeTimer);
      this._resizeTimer = null;
    }
    if (this._resizeHandler) {
      window.removeEventListener('resize', this._resizeHandler);
      this._resizeHandler = null;
    }
    this.canvas = null;
    this.ctx = null;
  }

  pushPoint(eps, latency) {
    this.throughputPoints.push(eps);
    if (this.throughputPoints.length > this.options.maxPoints) {
      this.throughputPoints.shift();
    }

    const latVal = latency !== undefined ? latency : Math.max(Math.round(eps * 0.45) + 12, 10);
    this.latencyPoints.push(latVal);
    if (this.latencyPoints.length > this.options.maxPoints) {
      this.latencyPoints.shift();
    }

    this.render();
  }

  render() {
    if (!this.ctx || !this.width) return;
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    ctx.clearRect(0, 0, w, h);
    ctx.imageSmoothingEnabled = false;

    // Dark Navy Technical Background for Terminal Feel
    ctx.fillStyle = '#071529';
    ctx.fillRect(0, 0, w, h);

    const padLeft = 38;
    const padBottom = 28;
    const padTop = 22;
    const padRight = 20;
    const chartW = w - padLeft - padRight;
    const chartH = h - padTop - padBottom;

    const allVals = [...this.throughputPoints, ...this.latencyPoints];
    let max = Math.max(...allVals, 10);
    max = Math.ceil((max * 1.15) / 10) * 10;

    // Coordinate Grid
    ctx.strokeStyle = '#1E293B';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 4]);

    const gridLines = 3;
    for (let i = 0; i <= gridLines; i++) {
      const y = padTop + (chartH / gridLines) * i;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(w - padRight, y);
      ctx.stroke();

      // Label
      ctx.setLineDash([]);
      ctx.fillStyle = '#64748B';
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      const val = Math.round(max - (max / gridLines) * i);
      ctx.fillText(String(val), padLeft - 6, y);
      ctx.setLineDash([2, 4]);
    }
    ctx.setLineDash([]);

    const stepX = chartW / (this.throughputPoints.length - 1);

    // --- Series 2: Latency Area Fill (Emerald #10B981) ---
    ctx.beginPath();
    this.latencyPoints.forEach((pt, i) => {
      const x = padLeft + i * stepX;
      const y = padTop + chartH - (pt / max) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + chartW, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();
    ctx.fillStyle = this.options.fillLatency;
    ctx.fill();

    // Series 2 Line
    ctx.beginPath();
    this.latencyPoints.forEach((pt, i) => {
      const x = padLeft + i * stepX;
      const y = padTop + chartH - (pt / max) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = this.options.colorLatency;
    ctx.lineWidth = 2;
    ctx.stroke();

    // --- Series 1: Throughput Area Fill (Cyan #06B6D4) ---
    ctx.beginPath();
    this.throughputPoints.forEach((pt, i) => {
      const x = padLeft + i * stepX;
      const y = padTop + chartH - (pt / max) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + chartW, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();
    ctx.fillStyle = this.options.fillThroughput;
    ctx.fill();

    // Series 1 Glowing Neon Line
    ctx.beginPath();
    this.throughputPoints.forEach((pt, i) => {
      const x = padLeft + i * stepX;
      const y = padTop + chartH - (pt / max) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = this.options.colorThroughput;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // 16-bit Square Pixel Data Markers on Throughput Line
    this.throughputPoints.forEach((pt, i) => {
      if (i % 3 === 0 || i === this.throughputPoints.length - 1) {
        const x = Math.floor(padLeft + i * stepX);
        const y = Math.floor(padTop + chartH - (pt / max) * chartH);

        ctx.fillStyle = this.options.colorThroughput;
        ctx.fillRect(x - 3, y - 3, 6, 6);

        ctx.strokeStyle = '#FFFFFF';
        ctx.lineWidth = 1;
        ctx.strokeRect(x - 3, y - 3, 6, 6);
      }
    });

    // Square Data Markers on Latency Line
    this.latencyPoints.forEach((pt, i) => {
      if (i % 3 === 0 || i === this.latencyPoints.length - 1) {
        const x = Math.floor(padLeft + i * stepX);
        const y = Math.floor(padTop + chartH - (pt / max) * chartH);

        ctx.fillStyle = this.options.colorLatency;
        ctx.fillRect(x - 2.5, y - 2.5, 5, 5);

        ctx.strokeStyle = '#0F172A';
        ctx.lineWidth = 1;
        ctx.strokeRect(x - 2.5, y - 2.5, 5, 5);
      }
    });

    // Real-Time Value Badge at latest point
    const lastThroughput = this.throughputPoints[this.throughputPoints.length - 1];
    const lastLat = this.latencyPoints[this.latencyPoints.length - 1];
    const lastX = Math.floor(padLeft + chartW);
    const lastY = Math.floor(padTop + chartH - (lastThroughput / max) * chartH);

    const badgeW = 72;
    const badgeH = 16;
    const bx = Math.min(lastX - badgeW + 8, w - badgeW - 4);
    const by = Math.max(lastY - 22, 6);

    ctx.fillStyle = '#06B6D4';
    ctx.fillRect(bx, by, badgeW, badgeH);
    ctx.strokeStyle = '#0F172A';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(bx, by, badgeW, badgeH);

    ctx.fillStyle = '#0F172A';
    ctx.font = 'bold 9px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`${lastThroughput}/s | ${lastLat}ms`, bx + badgeW / 2, by + badgeH / 2);

    // X Axis Time Markers
    ctx.fillStyle = '#64748B';
    ctx.font = '8px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    const now = new Date();
    const t0 = new Date(now.getTime() - 25 * 60 * 1000);
    const t1 = new Date(now.getTime() - 15 * 60 * 1000);
    const t2 = new Date(now.getTime() - 5 * 60 * 1000);
    const fmt = d => `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;

    ctx.fillText(fmt(t0), padLeft + 10, padTop + chartH + 8);
    ctx.fillText(fmt(t1), padLeft + chartW * 0.5, padTop + chartH + 8);
    ctx.fillText(fmt(now), padLeft + chartW - 10, padTop + chartH + 8);
  }
}

window.PixelBarChart = PixelBarChart;
window.PixelDonutChart = PixelDonutChart;
window.PixelLineChart = PixelLineChart;
