/* dashboard/js/api.js — API client and config manager */

const API = {
  // Read configuration from sessionStorage
  getConfig() {
    return {
      url: window.sessionStorage.getItem('ids_api_url') || 'http://127.0.0.1:5000',
      key: window.sessionStorage.getItem('ids_api_key') || ''
    };
  },

  setConfig(url, key) {
    window.sessionStorage.setItem('ids_api_url', url.replace(/\/$/, ''));
    window.sessionStorage.setItem('ids_api_key', key);
  },

  clearConfig() {
    window.sessionStorage.removeItem('ids_api_url');
    window.sessionStorage.removeItem('ids_api_key');
  },

  // Base HTTP requests
  async request(endpoint, method = 'GET', body = null) {
    const config = this.getConfig();
    const headers = {
      'X-API-Key': config.key,
      'Content-Type': 'application/json'
    };

    const options = {
      method,
      headers
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    try {
      const response = await fetch(`${config.url}/api/v1/${endpoint}`, options);
      
      if (response.status === 401) {
        showToast('Authentication failed. Check your API key.', 'error');
        throw new Error('Unauthorized');
      }

      if (!response.ok) {
        const errorText = await response.text();
        showToast(`Request failed: ${errorText || response.statusText}`, 'error');
        throw new Error(response.statusText);
      }

      return await response.json();
    } catch (error) {
      console.error(`API Error: ${method} ${endpoint}`, error);
      throw error;
    }
  },

  // REST wrappers
  getHealth() { return this.request('health'); },
  getStats() { return this.request('stats'); },
  getSystemStats() { return this.request('system/stats'); },
  getAttacks(n = 200) { return this.request(`attacks?n=${n}`); },
  getBlocks() { return this.request('blocks'); },
  blockIP(ip, reason = 'manual') { return this.request('block', 'POST', { ip, reason }); },
  unblockIP(ip) { return this.request(`block/${ip}`, 'DELETE'); },
  getWhitelist() { return this.request('whitelist'); },
  addWhitelist(ip) { return this.request('whitelist', 'POST', { ip }); },
  removeWhitelist(ip) { return this.request(`whitelist/${ip}`, 'DELETE'); },
  getThresholds() { return this.request('config/thresholds'); },
  patchThresholds(payload) { return this.request('config/thresholds', 'PATCH', payload); }
};
