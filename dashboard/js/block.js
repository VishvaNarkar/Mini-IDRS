/* dashboard/js/block.js — Blocked IPs Manager */

const BlockList = {
  async load() {
    const listDom = document.getElementById('blocked-items');
    if (!listDom) return;

    try {
      const data = await API.getBlocks();
      const list = data.blocks || [];

      // Update KPI Counter
      const kpiBlocked = document.getElementById('kpi-blocked-count');
      if (kpiBlocked) kpiBlocked.innerText = list.length;

      if (list.length === 0) {
        listDom.innerHTML = '<tr><td colspan="6" class="text-secondary" style="text-align: center;">No active blocks.</td></tr>';
        return;
      }

      listDom.innerHTML = list.map(item => {
        // Format timestamp safely
        let displayTime = item.timestamp || '';
        try {
          if (item.timestamp) {
            const date = new Date(item.timestamp);
            displayTime = date.toLocaleString();
          }
        } catch (e) {}

        const sevClass = (item.severity || 'medium').toLowerCase();
        
        return `
          <tr>
            <td class="mono font-semibold">${item.ip}</td>
            <td class="mono text-secondary">${item.attack}</td>
            <td><span class="badge-sev ${sevClass}">${item.severity}</span></td>
            <td class="mono text-muted" style="font-size: 0.8rem;">${(item.confidence * 100).toFixed(0)}%</td>
            <td class="text-secondary" style="font-size: 0.8rem; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.reason || ''}">
              ${item.reason || ''}
            </td>
            <td class="mono text-secondary" style="font-size: 0.8rem;">${displayTime}</td>
            <td style="text-align: right;">
              <button class="btn btn-secondary btn-sm" onclick="BlockList.unblock('${item.ip}')" style="padding: 4px 8px; font-size: 0.8rem;">
                <i data-lucide="unlock" style="width: 14px; height: 14px; color: var(--severity-low);"></i> Unblock
              </button>
            </td>
          </tr>
        `;
      }).join('');
      
      if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch (err) {
      listDom.innerHTML = '<tr><td colspan="6" style="color: var(--severity-critical); text-align: center;">Failed to load blocks.</td></tr>';
    }
  },

  async block() {
    const ipInput = document.getElementById('block-ip-input');
    const reasonInput = document.getElementById('block-reason-input');

    const ip = ipInput ? ipInput.value.trim() : '';
    const reason = reasonInput ? reasonInput.value.trim() : 'manual';

    if (!ip) {
      showToast('Please enter a valid IP to block', 'warning');
      return;
    }

    try {
      showToast(`Issuing block for ${ip}...`, 'info');
      const res = await API.blockIP(ip, reason);
      
      const fwStatus = res.firewall_ok ? 'Firewall: OK' : 'Firewall: FAILED';
      const vicStatus = res.victim_ok ? 'Victim: OK' : 'Victim: FAILED';
      
      showToast(`Block complete: ${fwStatus} | ${vicStatus}`, res.firewall_ok && res.victim_ok ? 'success' : 'warning');
      
      if (ipInput) ipInput.value = '';
      if (reasonInput) reasonInput.value = '';

      await this.load();
    } catch (err) {
      showToast(`Manual block failed: ${err.message}`, 'error');
    }
  },

  async unblock(ip) {
    if (!confirm(`Are you sure you want to unblock ${ip}?`)) return;

    try {
      showToast(`Issuing unblock for ${ip}...`, 'info');
      const res = await API.unblockIP(ip);
      
      const fwStatus = res.firewall_ok ? 'Firewall: OK' : 'Firewall: FAILED';
      const vicStatus = res.victim_ok ? 'Victim: OK' : 'Victim: FAILED';
      
      showToast(`Unblock complete: ${fwStatus} | ${vicStatus}`, 'success');
      await this.load();
    } catch (err) {
      showToast(`Failed to unblock ${ip}: ${err.message}`, 'error');
    }
  }
};
