/* dashboard/js/charts.js — Apache ECharts Manager */

const Charts = {
  timelineChart: null,
  distributionChart: null,
  attackersChart: null,

  init() {
    this.dispose();

    const timelineDom = document.getElementById('timeline-chart');
    const distDom = document.getElementById('distribution-chart');
    const attackersDom = document.getElementById('attackers-chart');

    if (timelineDom) this.timelineChart = echarts.init(timelineDom);
    if (distDom) this.distributionChart = echarts.init(distDom);
    if (attackersDom) this.attackersChart = echarts.init(attackersDom);

    this.resize();
    window.addEventListener('resize', () => this.resize());
  },

  dispose() {
    if (this.timelineChart) { this.timelineChart.dispose(); this.timelineChart = null; }
    if (this.distributionChart) { this.distributionChart.dispose(); this.distributionChart = null; }
    if (this.attackersChart) { this.attackersChart.dispose(); this.attackersChart = null; }
  },

  resize() {
    if (this.timelineChart) this.timelineChart.resize();
    if (this.distributionChart) this.distributionChart.resize();
    if (this.attackersChart) this.attackersChart.resize();
  },

  // -------------------------------------------------------------------------
  // Render / Update Charts
  // -------------------------------------------------------------------------

  updateTimeline(attackLogs) {
    if (!this.timelineChart) return;

    // Count attacks per minute for the last 60 minutes
    const now = new Date();
    const minutes = {};
    for (let i = 59; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60 * 1000);
      const key = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
      minutes[key] = 0;
    }

    attackLogs.forEach(log => {
      if (!log.timestamp) return;
      // parse log.timestamp (looks like: "2026-07-07 18:45:00" or ISO format)
      // replace space with T if needed to make it ISO compliant
      const d = new Date(log.timestamp.replace(' ', 'T'));
      const key = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
      if (minutes[key] !== undefined) {
        minutes[key]++;
      }
    });

    const xData = Object.keys(minutes);
    const yData = Object.values(minutes);

    const themeColors = this._getThemeColors();

    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'line', lineStyle: { color: themeColors.accent, width: 1 } }
      },
      grid: { left: '4%', right: '4%', bottom: '10%', top: '10%', containLabel: true },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: xData,
        axisLine: { lineStyle: { color: themeColors.textMuted } },
        axisLabel: { color: themeColors.textSecondary, fontSize: 10 }
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        axisLine: { lineStyle: { color: themeColors.textMuted } },
        splitLine: { lineStyle: { color: themeColors.border, type: 'dashed' } },
        axisLabel: { color: themeColors.textSecondary }
      },
      series: [{
        name: 'Alerts',
        type: 'line',
        smooth: true,
        showSymbol: false,
        data: yData,
        itemStyle: { color: themeColors.accent },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: themeColors.accentGradientStart },
            { offset: 1, color: 'transparent' }
          ])
        },
        lineStyle: { width: 3 }
      }]
    };

    this.timelineChart.setOption(option);
  },

  updateDistribution(attackLogs) {
    if (!this.distributionChart) return;

    const counts = {};
    attackLogs.forEach(log => {
      counts[log.attack] = (counts[log.attack] || 0) + 1;
    });

    const data = Object.keys(counts).map(key => ({
      name: key,
      value: counts[key]
    })).sort((a, b) => b.value - a.value);

    const themeColors = this._getThemeColors();

    const option = {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: {
        orient: 'horizontal',
        bottom: 0,
        textStyle: { color: themeColors.textSecondary }
      },
      series: [{
        name: 'Attacks',
        type: 'pie',
        radius: ['45%', '70%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 6,
          borderColor: themeColors.bgSecondary,
          borderWidth: 2
        },
        label: { show: false },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold',
            formatter: '{b}\n{c}',
            color: themeColors.textPrimary
          }
        },
        data: data,
        color: [
          themeColors.critical,
          themeColors.high,
          themeColors.medium,
          themeColors.low,
          themeColors.accent
        ]
      }]
    };

    this.distributionChart.setOption(option);
  },

  updateTopAttackers(attackLogs) {
    if (!this.attackersChart) return;

    const counts = {};
    attackLogs.forEach(log => {
      counts[log.attacker] = (counts[log.attacker] || 0) + 1;
    });

    const sorted = Object.keys(counts)
      .map(ip => ({ ip, count: counts[ip] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5); // top 5

    const yData = sorted.map(d => d.ip).reverse();
    const xData = sorted.map(d => d.count).reverse();

    const themeColors = this._getThemeColors();

    const option = {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: '4%', right: '10%', bottom: '4%', top: '4%', containLabel: true },
      xAxis: {
        type: 'value',
        minInterval: 1,
        axisLine: { show: false },
        splitLine: { lineStyle: { color: themeColors.border, type: 'dashed' } },
        axisLabel: { color: themeColors.textSecondary }
      },
      yAxis: {
        type: 'category',
        data: yData,
        axisLine: { lineStyle: { color: themeColors.textMuted } },
        axisLabel: { color: themeColors.textSecondary, fontFamily: 'JetBrains Mono', fontSize: 11 }
      },
      series: [{
        name: 'Alerts',
        type: 'bar',
        data: xData,
        itemStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
            { offset: 0, color: themeColors.accentGradientStart },
            { offset: 1, color: themeColors.accent }
          ]),
          borderRadius: [0, 4, 4, 0]
        },
        barWidth: 15
      }]
    };

    this.attackersChart.setOption(option);
  },

  // -------------------------------------------------------------------------
  // Theme Helper
  // -------------------------------------------------------------------------

  _getThemeColors() {
    const isLight = document.body.classList.contains('light-theme');
    const isNeon = document.body.classList.contains('neon-theme');
    const isDark = document.body.classList.contains('dark-theme');

    if (isNeon) {
      return {
        bgSecondary: '#0a0a0a',
        border: '#141414',
        textPrimary: '#39ff14',
        textSecondary: '#00ffcc',
        textMuted: '#555555',
        accent: '#ff007f',
        accentGradientStart: 'rgba(255, 0, 127, 0.4)',
        low: '#00ff66',
        medium: '#ffff00',
        high: '#ff9900',
        critical: '#ff0033'
      };
    } else if (isDark) {
      return {
        bgSecondary: '#1e293b',
        border: '#334155',
        textPrimary: '#f8fafc',
        textSecondary: '#cbd5e1',
        textMuted: '#64748b',
        accent: '#38bdf8',
        accentGradientStart: 'rgba(56, 189, 248, 0.4)',
        low: '#34d399',
        medium: '#fbbf24',
        high: '#fb923c',
        critical: '#f87171'
      };
    } else {
      // Default: Light
      return {
        bgSecondary: '#ffffff',
        border: '#e5e7eb',
        textPrimary: '#111827',
        textSecondary: '#4b5563',
        textMuted: '#9ca3af',
        accent: '#0284c7',
        accentGradientStart: 'rgba(2, 132, 199, 0.4)',
        low: '#059669',
        medium: '#d97706',
        high: '#ea580c',
        critical: '#dc2626'
      };
    }
  }
};
