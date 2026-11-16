// ==========================================================================
// 16-BIT RETRO PIXEL CHART ENGINE (ZERO DEPENDENCY / OFFLINE READY)
// Neon Cyan-Blue & Green Pixel Styling • Stepped Bars • Segmented Donut • Moving Line
// ==========================================================================

/**
 * 1. PixelBarChart - Stepped Vertical Bars for Activity by Category
 */
class PixelBarChart {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.options = Object.assign({
      barColor: '#00F0FF',
      barColorAlt: '#4ADE80',
      borderColor: '#0F172A',
      textColor: '#0F172A',
      gridColor: '#E2E8F0',
      maxVal: 50
    }, options);

    this.data = [
      { label: 'UFW', value: 0 },
      { label: 'AUTH', value: 0 },
      { label: 'WEB', value: 0 },
      { label: 'THREAT', value: 0 },
      { label: 'SYSTEM', value: 0 }
    ];

    this.setupResize();
    this.render();
  }

  setupResize() {
    const resize = () => {
      if (!this.canvas) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = (rect.height || 200) * dpr;
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height || 200;
      this.render();
    };
    window.addEventListener('resize', resize);
    setTimeout(resize, 50);
  }

  update(newData) {
    if (Array.isArray(newData)) {
      this.data = newData;
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

    const padLeft = 36;
    const padBottom = 28;
    const padTop = 20;
    const padRight = 16;
    const chartW = w - padLeft - padRight;
    const chartH = h - padTop - padBottom;

    // Hitung max value
    let max = Math.max(...this.data.map(d => d.value), 10);
    max = Math.ceil(max / 5) * 5;

    // Dotted Retro Grid Lines
    ctx.strokeStyle = this.options.gridColor;
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 4]);

    for (let i = 0; i <= 4; i++) {
      const y = padTop + (chartH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(w - padRight, y);
      ctx.stroke();

      // Label Nilai Y
      ctx.setLineDash([]);
      ctx.fillStyle = '#64748B';
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      const val = Math.round(max - (max / 4) * i);
      ctx.fillText(String(val), padLeft - 6, y);
      ctx.setLineDash([2, 4]);
    }
    ctx.setLineDash([]);

    // Draw Stepped Pixel Bars
    const barCount = this.data.length;
    const slotW = chartW / barCount;
    const barW = Math.min(Math.floor(slotW * 0.6), 40);

    this.data.forEach((item, idx) => {
      const x = Math.floor(padLeft + idx * slotW + (slotW - barW) / 2);
      const barH = Math.floor((item.value / max) * chartH);
      const y = Math.floor(padTop + chartH - barH);

      // Bar Fill (Neon Cyan & Lime alternating)
      ctx.fillStyle = idx % 2 === 0 ? this.options.barColor : this.options.barColorAlt;
      ctx.fillRect(x, y, barW, barH);

      // 16-bit Border
      ctx.strokeStyle = this.options.borderColor;
      ctx.lineWidth = 2;
      ctx.strokeRect(x, y, barW, barH);

      // Top Highlight Stepped Cap
      ctx.fillStyle = '#FFFFFF';
      ctx.fillRect(x + 2, y + 2, barW - 4, 2);

      // Value Label on top of bar
      if (item.value > 0) {
        ctx.fillStyle = this.options.borderColor;
        ctx.font = 'bold 9px "Silkscreen", monospace';
        ctx.textAlign = 'center';
        ctx.fillText(String(item.value), x + barW / 2, y - 6);
      }

      // X Label
      ctx.fillStyle = '#334155';
      ctx.font = 'bold 9px "Silkscreen", monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(item.label, x + barW / 2, padTop + chartH + 8);
    });
  }
}

/**
 * 2. PixelDonutChart - Segmented Ring for Threat & Severity Distribution
 */
class PixelDonutChart {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.options = Object.assign({
      borderColor: '#0F172A',
      centerLabel: 'THREATS'
    }, options);

    this.segments = [
      { label: 'Clean/Info', value: 1, color: '#22C55E' },
      { label: 'Suspicious', value: 0, color: '#F59E0B' },
      { label: 'Critical', value: 0, color: '#EF4444' },
      { label: 'Blocked', value: 0, color: '#8B5CF6' }
    ];

    this.setupResize();
    this.render();
  }

  setupResize() {
    const resize = () => {
      if (!this.canvas) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = (rect.height || 200) * dpr;
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height || 200;
      this.render();
    };
    window.addEventListener('resize', resize);
    setTimeout(resize, 50);
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

    const total = this.segments.reduce((acc, s) => acc + s.value, 0);
    const centerX = Math.floor(w / 2);
    const centerY = Math.floor(h / 2);
    const outerR = Math.floor(Math.min(w, h) * 0.42);
    const innerR = Math.floor(outerR * 0.55);

    let startAngle = -Math.PI / 2;

    if (total === 0) {
      // Default placeholder ring
      ctx.beginPath();
      ctx.arc(centerX, centerY, outerR, 0, Math.PI * 2);
      ctx.arc(centerX, centerY, innerR, Math.PI * 2, 0, true);
      ctx.fillStyle = '#E2E8F0';
      ctx.fill();
      ctx.strokeStyle = this.options.borderColor;
      ctx.lineWidth = 2;
      ctx.stroke();
    } else {
      this.segments.forEach(seg => {
        if (seg.value <= 0) return;
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

    // Inner Circle Core (Island Texture Background)
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerR - 2, 0, Math.PI * 2);
    ctx.fillStyle = '#F8FAFC';
    ctx.fill();
    ctx.strokeStyle = '#CBD5E1';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Center Total Count & Label
    ctx.fillStyle = this.options.borderColor;
    ctx.font = 'bold 16px "Silkscreen", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(String(total), centerX, centerY - 6);

    ctx.font = '8px "Silkscreen", monospace';
    ctx.fillStyle = '#64748B';
    ctx.fillText(this.options.centerLabel, centerX, centerY + 10);
  }
}

/**
 * 3. PixelLineChart - Real-Time Moving Stream Velocity (EPS Ingestion Rate)
 */
class PixelLineChart {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.options = Object.assign({
      lineColor: '#00F0FF',
      fillColor: 'rgba(0, 240, 255, 0.15)',
      pointColor: '#4ADE80',
      borderColor: '#0F172A',
      maxPoints: 30,
      title: 'EVENTS PER SEC (EPS)'
    }, options);

    // Initial empty points array
    this.points = new Array(this.options.maxPoints).fill(0);

    this.setupResize();
    this.render();
  }

  setupResize() {
    const resize = () => {
      if (!this.canvas) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = (rect.height || 200) * dpr;
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height || 200;
      this.render();
    };
    window.addEventListener('resize', resize);
    setTimeout(resize, 50);
  }

  pushPoint(val) {
    this.points.push(val);
    if (this.points.length > this.options.maxPoints) {
      this.points.shift();
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

    const padLeft = 34;
    const padBottom = 24;
    const padTop = 20;
    const padRight = 16;
    const chartW = w - padLeft - padRight;
    const chartH = h - padTop - padBottom;

    let max = Math.max(...this.points, 5);
    max = Math.ceil(max / 5) * 5;

    // Coordinate Grid
    ctx.strokeStyle = '#E2E8F0';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 4]);

    for (let i = 0; i <= 3; i++) {
      const y = padTop + (chartH / 3) * i;
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
      const val = Math.round(max - (max / 3) * i);
      ctx.fillText(String(val), padLeft - 6, y);
      ctx.setLineDash([2, 4]);
    }
    ctx.setLineDash([]);

    const stepX = chartW / (this.points.length - 1);

    // Fill under line
    ctx.beginPath();
    this.points.forEach((pt, i) => {
      const x = padLeft + i * stepX;
      const y = padTop + chartH - (pt / max) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + chartW, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();
    ctx.fillStyle = this.options.fillColor;
    ctx.fill();

    // Glowing Neon Line
    ctx.beginPath();
    this.points.forEach((pt, i) => {
      const x = padLeft + i * stepX;
      const y = padTop + chartH - (pt / max) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = this.options.lineColor;
    ctx.lineWidth = 3;
    ctx.stroke();

    // 16-bit Square Pixel Data Markers
    this.points.forEach((pt, i) => {
      // Draw point every 3 steps or on the last one
      if (i % 3 === 0 || i === this.points.length - 1) {
        const x = Math.floor(padLeft + i * stepX);
        const y = Math.floor(padTop + chartH - (pt / max) * chartH);

        ctx.fillStyle = this.options.pointColor;
        ctx.fillRect(x - 3, y - 3, 6, 6);

        ctx.strokeStyle = this.options.borderColor;
        ctx.lineWidth = 1.5;
        ctx.strokeRect(x - 3, y - 3, 6, 6);
      }
    });

    // Real-Time Value Badge at latest point
    const lastVal = this.points[this.points.length - 1];
    const lastX = Math.floor(padLeft + chartW);
    const lastY = Math.floor(padTop + chartH - (lastVal / max) * chartH);

    ctx.fillStyle = '#00F0FF';
    ctx.fillRect(lastX - 28, lastY - 20, 32, 14);
    ctx.strokeStyle = this.options.borderColor;
    ctx.lineWidth = 1.5;
    ctx.strokeRect(lastX - 28, lastY - 20, 32, 14);

    ctx.fillStyle = this.options.borderColor;
    ctx.font = 'bold 9px "Silkscreen", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`${lastVal}/s`, lastX - 12, lastY - 13);
  }
}

window.PixelBarChart = PixelBarChart;
window.PixelDonutChart = PixelDonutChart;
window.PixelLineChart = PixelLineChart;
