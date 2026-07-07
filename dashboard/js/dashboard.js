/* dashboard/js/dashboard.js — Main UI Controller and Orchestrator */

// Global Toast helper
window.showToast = function(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let icon = 'info';
  if (type === 'error') icon = 'alert-triangle';
  if (type === 'success') icon = 'check-circle';
  if (type === 'warning') icon = 'shield-alert';

  toast.innerHTML = `
    <i data-lucide="${icon}" style="width: 20px; height: 20px;"></i>
    <div style="flex: 1; font-size: 0.85rem; font-weight: 500;">${message}</div>
  `;

  container.appendChild(toast);
  if (typeof lucide !== 'undefined') lucide.createIcons();

  // Fade out and remove
  setTimeout(() => {
    toast.style.transition = 'opacity 0.5s, transform 0.5s';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-20px)';
    setTimeout(() => {
      container.removeChild(toast);
    }, 500);
  }, 4000);
};

// Global App controller
const App = {
  activeTab: 'dashboard',
  refreshInterval: null,
  statsInterval: null,
  cachedAlerts: [],

  init() {
    this.initThemes();
    this.initTabs();
    this.loadSavedConfig();
    this.initThresholdsForm();

    // Re-check sizes on window resize
    window.addEventListener('resize', () => {
      Charts.resize();
    });

    // Check if configuration exists, if so connect automatically
    const config = API.getConfig();
    if (config.key) {
      this.connect();
    } else {
      this.switchTab('settings');
      showToast('Welcome to Mini-IDRS. Please configure your connection.', 'info');
    }
  },

  // -------------------------------------------------------------------------
  // Configuration & Connection
  // -------------------------------------------------------------------------

  loadSavedConfig() {
    const config = API.getConfig();
    const urlInput = document.getElementById('ids-url-input');
    const keyInput = document.getElementById('ids-key-input');

    if (urlInput) urlInput.value = config.url;
    if (keyInput) keyInput.value = config.key;
  },

  saveConfig() {
    const urlInput = document.getElementById('ids-url-input');
    const keyInput = document.getElementById('ids-key-input');

    const url = urlInput ? urlInput.value.trim() : '';
    const key = keyInput ? keyInput.value.trim() : '';

    if (!url || !key) {
      showToast('Please enter both API URL and Authentication Key.', 'warning');
      return;
    }

    API.setConfig(url, key);
    showToast('Configuration saved to session', 'success');
    this.connect();
  },

  async connect() {
    this.disconnect();
    showToast('Connecting to IDS API...', 'info');

    try {
      const health = await API.getHealth();
      document.getElementById('status-ids-api').classList.add('online');
      
      if (health.firewall_api_reachable) {
        document.getElementById('status-firewall-api').classList.add('online');
        document.getElementById('kpi-fw-status').innerText = 'Online';
        document.getElementById('kpi-fw-status').style.color = 'var(--severity-low)';
      } else {
        document.getElementById('status-firewall-api').classList.remove('online');
        document.getElementById('kpi-fw-status').innerText = 'Offline';
        document.getElementById('kpi-fw-status').style.color = 'var(--severity-critical)';
      }

      document.getElementById('kpi-ids-status').innerText = 'Running';
      document.getElementById('kpi-ids-status').style.color = 'var(--severity-low)';

      // Initialise Charts
      Charts.init();

      // Load static data
      await this.loadAllData();

      // Connect WebSockets for real-time alerts
      wsClient.connect();

      // Listen for WebSocket events
      wsClient.onEvent((event) => {
        this.handleIncomingAlert(event);
      });

      wsClient.onStatusChange((online) => {
        const dot = document.getElementById('status-ws-stream');
        if (dot) {
          if (online) {
            dot.classList.add('online');
          } else {
            dot.classList.remove('online');
          }
        }
      });

      // Start periodic updates for non-WS components
      this.startPolling();

      this.switchTab('dashboard');
    } catch (err) {
      console.error('Connection failed:', err);
      document.getElementById('status-ids-api').classList.remove('online');
      document.getElementById('status-firewall-api').classList.remove('online');
      document.getElementById('kpi-ids-status').innerText = 'Disconnected';
      document.getElementById('kpi-ids-status').style.color = 'var(--text-muted)';
      document.getElementById('kpi-fw-status').innerText = 'Unknown';
      document.getElementById('kpi-fw-status').style.color = 'var(--text-muted)';
    }
  },

  disconnect() {
    wsClient.disconnect();
    this.stopPolling();
    Charts.dispose();
    
    // Clear status classes
    document.getElementById('status-ids-api').classList.remove('online');
    document.getElementById('status-firewall-api').classList.remove('online');
    const wsDot = document.getElementById('status-ws-stream');
    if (wsDot) wsDot.classList.remove('online');
  },

  // -------------------------------------------------------------------------
  // Data Loading & Polling
  // -------------------------------------------------------------------------

  async loadAllData() {
    await Promise.all([
      this.loadAlerts(),
      BlockList.load(),
      Whitelist.load(),
      this.loadSystemStats(),
      this.loadThresholds()
    ]);
  },

  async loadAlerts() {
    try {
      const alerts = await API.getAttacks(200);
      this.cachedAlerts = alerts || [];
      
      // Update KPI Counter
      const kpiTotal = document.getElementById('kpi-alerts-count');
      if (kpiTotal) kpiTotal.innerText = this.cachedAlerts.length;

      this.renderAlertsTable();
      
      // Update Charts
      Charts.updateTimeline(this.cachedAlerts);
      Charts.updateDistribution(this.cachedAlerts);
      Charts.updateTopAttackers(this.cachedAlerts);
    } catch (err) {
      console.error('Failed to load alert log:', err);
    }
  },

  renderAlertsTable() {
    const listDom = document.getElementById('alert-log-items');
    if (!listDom) return;

    if (this.cachedAlerts.length === 0) {
      listDom.innerHTML = '<tr><td colspan="5" class="text-secondary" style="text-align: center;">No alerts detected.</td></tr>';
      return;
    }

    listDom.innerHTML = this.cachedAlerts.slice(0, 100).map(alert => {
      const sevClass = (alert.severity || 'medium').toLowerCase();
      let rowStyle = '';
      if (alert.severity === 'CRITICAL') rowStyle = 'class="row-sev-critical"';
      else if (alert.severity === 'HIGH') rowStyle = 'class="row-sev-high"';

      return `
        <tr ${rowStyle}>
          <td class="mono font-semibold">${alert.attacker}</td>
          <td class="mono font-semibold">${alert.victim}</td>
          <td class="mono text-secondary">${alert.attack}</td>
          <td><span class="badge-sev ${sevClass}">${alert.severity}</span></td>
          <td class="mono text-secondary" style="font-size: 0.8rem;">${alert.timestamp}</td>
        </tr>
      `;
    }).join('');
  },

  async loadSystemStats() {
    try {
      const stats = await API.getSystemStats();
      if (stats.cpu !== undefined) {
        document.getElementById('status-cpu').innerText = `${stats.cpu}%`;
      }
      if (stats.memory !== undefined) {
        document.getElementById('status-ram').innerText = `${stats.memory}%`;
      }
    } catch (err) {
      // psutil might fail or mock fallback
    }
  },

  async loadThresholds() {
    try {
      const data = await API.getThresholds();
      const thr = data.thresholds || {};

      if (thr.syn_flood) {
        document.getElementById('syn-threshold-input').value = thr.syn_flood.threshold || 25;
        document.getElementById('syn-window-input').value = thr.syn_flood.window_seconds || 5;
      }
      if (thr.ssh_brute_force) {
        document.getElementById('ssh-threshold-input').value = thr.ssh_brute_force.threshold || 8;
        document.getElementById('ssh-window-input').value = thr.ssh_brute_force.window_seconds || 60;
      }
    } catch (err) {}
  },

  async submitThresholds() {
    const synT = parseInt(document.getElementById('syn-threshold-input').value);
    const synW = parseInt(document.getElementById('syn-window-input').value);
    const sshT = parseInt(document.getElementById('ssh-threshold-input').value);
    const sshW = parseInt(document.getElementById('ssh-window-input').value);

    try {
      await API.patchThresholds({
        syn_flood: { threshold: synT, window_seconds: synW },
        ssh_brute_force: { threshold: sshT, window_seconds: sshW }
      });
      showToast('Thresholds updated successfully', 'success');
    } catch (err) {
      showToast('Failed to update thresholds', 'error');
    }
  },

  startPolling() {
    this.stopPolling();
    // System CPU/RAM and API health checks every 10s
    this.refreshInterval = setInterval(async () => {
      try {
        const health = await API.getHealth();
        if (health.firewall_api_reachable) {
          document.getElementById('status-firewall-api').classList.add('online');
          document.getElementById('kpi-fw-status').innerText = 'Online';
          document.getElementById('kpi-fw-status').style.color = 'var(--severity-low)';
        } else {
          document.getElementById('status-firewall-api').classList.remove('online');
          document.getElementById('kpi-fw-status').innerText = 'Offline';
          document.getElementById('kpi-fw-status').style.color = 'var(--severity-critical)';
        }
      } catch (e) {
        document.getElementById('status-firewall-api').classList.remove('online');
      }
      this.loadSystemStats();
    }, 10000);

    // Refresh blocks list and whitelist every 15s to keep things synced
    this.statsInterval = setInterval(() => {
      BlockList.load();
      Whitelist.load();
    }, 15000);
  },

  stopPolling() {
    if (this.refreshInterval) { clearInterval(this.refreshInterval); this.refreshInterval = null; }
    if (this.statsInterval) { clearInterval(this.statsInterval); this.statsInterval = null; }
  },

  // -------------------------------------------------------------------------
  // WebSocket Handler
  // -------------------------------------------------------------------------

  handleIncomingAlert(event) {
    // Add to cached alerts array at the top
    const formattedAlert = {
      attacker: event.attacker,
      victim: event.victim,
      attack: event.attack,
      severity: event.severity,
      timestamp: new Date(event.timestamp).toLocaleString(),
      confidence: event.confidence
    };

    this.cachedAlerts.unshift(formattedAlert);
    
    // Cap at 300 logs in memory
    if (this.cachedAlerts.length > 300) {
      this.cachedAlerts.pop();
    }

    // Update alerts counter
    const kpiTotal = document.getElementById('kpi-alerts-count');
    if (kpiTotal) kpiTotal.innerText = this.cachedAlerts.length;

    // Render Table
    this.renderAlertsTable();

    // Highlight top row briefly (flashing animation)
    const tableBody = document.getElementById('alert-log-items');
    if (tableBody && tableBody.firstElementChild) {
      tableBody.firstElementChild.classList.add('new-alert-row');
    }

    // Refresh BlockList if it was a block event
    BlockList.load();

    // Trigger toast notification if severity is high/critical
    if (event.severity === 'CRITICAL' || event.severity === 'HIGH') {
      showToast(`[${event.severity}] ${event.attack} detected from ${event.attacker}!`, event.severity === 'CRITICAL' ? 'error' : 'warning');
    } else {
      showToast(`Alert: ${event.attack} from ${event.attacker}`, 'info');
    }

    // Update charts dynamically without redrawing everything
    Charts.updateTimeline(this.cachedAlerts);
    Charts.updateDistribution(this.cachedAlerts);
    Charts.updateTopAttackers(this.cachedAlerts);
  },

  // -------------------------------------------------------------------------
  // Tabs & Navigation
  // -------------------------------------------------------------------------

  initTabs() {
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const tabName = item.getAttribute('data-tab');
        this.switchTab(tabName);
      });
    });
  },

  switchTab(tabName) {
    this.activeTab = tabName;

    // Update sidebar state
    document.querySelectorAll('.menu-item').forEach(item => {
      if (item.getAttribute('data-tab') === tabName) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Toggle view containers
    document.querySelectorAll('.tab-content').forEach(content => {
      if (content.id === `tab-${tabName}`) {
        content.classList.add('active');
      } else {
        content.classList.remove('active');
      }
    });

    // Specific tab activations
    if (tabName === 'dashboard') {
      Charts.resize();
    } else if (tabName === 'alerts') {
      this.loadAlerts();
    } else if (tabName === 'blocked') {
      BlockList.load();
    } else if (tabName === 'whitelist') {
      Whitelist.load();
    }
  },

  // -------------------------------------------------------------------------
  // Theme Switching
  // -------------------------------------------------------------------------

  initThemes() {
    const selector = document.getElementById('theme-selector');
    if (!selector) return;

    // Load saved theme
    const savedTheme = window.sessionStorage.getItem('ids_theme') || 'light';
    selector.value = savedTheme;
    this.applyTheme(savedTheme);

    selector.addEventListener('change', () => {
      const theme = selector.value;
      window.sessionStorage.setItem('ids_theme', theme);
      this.applyTheme(theme);
    });
  },

  applyTheme(theme) {
    document.body.classList.remove('light-theme', 'neon-theme', 'dark-theme');
    
    if (theme === 'light') {
      document.body.classList.add('light-theme');
    } else if (theme === 'neon') {
      document.body.classList.add('neon-theme');
    } else if (theme === 'dark') {
      document.body.classList.add('dark-theme');
    }

    // Refresh charts colors
    if (this.cachedAlerts.length > 0) {
      Charts.updateTimeline(this.cachedAlerts);
      Charts.updateDistribution(this.cachedAlerts);
      Charts.updateTopAttackers(this.cachedAlerts);
    }
  },

  // -------------------------------------------------------------------------
  // Form Setup
  // -------------------------------------------------------------------------

  initThresholdsForm() {
    const form = document.getElementById('thresholds-form');
    if (form) {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        this.submitThresholds();
      });
    }
  }
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
