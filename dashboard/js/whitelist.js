/* dashboard/js/whitelist.js — Whitelist Manager */

const Whitelist = {
  async load() {
    const listDom = document.getElementById('whitelist-items');
    if (!listDom) return;

    try {
      const data = await API.getWhitelist();
      const list = data.whitelist || [];

      if (list.length === 0) {
        listDom.innerHTML = '<tr><td colspan="2" class="text-secondary" style="text-align: center;">No IPs whitelisted.</td></tr>';
        return;
      }

      listDom.innerHTML = list.map(ip => `
        <tr>
          <td class="mono font-semibold" style="color: var(--severity-low);">${ip}</td>
          <td style="text-align: right; width: 80px;">
            <button class="btn btn-secondary btn-sm" onclick="Whitelist.remove('${ip}')" style="padding: 4px 8px; font-size: 0.8rem;">
              <i data-lucide="trash-2" style="width: 14px; height: 14px;"></i>
            </button>
          </td>
        </tr>
      `).join('');
      
      // Re-trigger Lucide icons render
      if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch (err) {
      listDom.innerHTML = '<tr><td colspan="2" style="color: var(--severity-critical); text-align: center;">Failed to load whitelist.</td></tr>';
    }
  },

  async add() {
    const input = document.getElementById('whitelist-ip-input');
    const ip = input ? input.value.trim() : '';

    if (!ip) {
      showToast('Please enter a valid IP address', 'warning');
      return;
    }

    try {
      await API.addWhitelist(ip);
      showToast(`Added ${ip} to whitelist`, 'success');
      if (input) input.value = '';
      await this.load();
      // Notify WebSocket/Dashboard to refresh whitelist in local states if any
    } catch (err) {
      showToast(`Failed to add ${ip}: ${err.message}`, 'error');
    }
  },

  async remove(ip) {
    if (!confirm(`Are you sure you want to remove ${ip} from the whitelist?`)) return;

    try {
      await API.removeWhitelist(ip);
      showToast(`Removed ${ip} from whitelist`, 'success');
      await this.load();
    } catch (err) {
      showToast(`Failed to remove ${ip}: ${err.message}`, 'error');
    }
  }
};
