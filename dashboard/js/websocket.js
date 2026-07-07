/* dashboard/js/websocket.js — Real-Time WebSocket Alerts */

class IDRSWebSocket {
  constructor() {
    this.ws = null;
    this.reconnectTimer = null;
    this.manualClose = false;
    this.onEventCallbacks = [];
    this.onStatusChangeCallbacks = [];
  }

  connect() {
    const config = API.getConfig();
    if (!config.key) return;

    // Convert http(s):// to ws(s)://
    let wsUrl = config.url.replace(/^http/, 'ws');
    // Include the token in the connection URL as a query param or header
    // FastAPI WebSockets don't easily read custom headers on connect, so query param is standard
    wsUrl = `${wsUrl}/api/v1/ws?token=${encodeURIComponent(config.key)}`;

    console.log(`Connecting to WebSocket: ${wsUrl}`);
    this.manualClose = false;
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log('WebSocket Connected');
      this._updateStatus(true);
      showToast('Real-time connection established', 'success');
      if (this.reconnectTimer) {
        clearInterval(this.reconnectTimer);
        this.reconnectTimer = null;
      }
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('WebSocket Event received:', data);
        this._dispatch(data);
      } catch (err) {
        console.error('Error parsing WebSocket message:', err);
      }
    };

    this.ws.onerror = (err) => {
      console.error('WebSocket Error:', err);
      this._updateStatus(false);
    };

    this.ws.onclose = () => {
      this._updateStatus(false);
      if (!this.manualClose) {
        console.log('WebSocket connection closed. Attempting reconnect...');
        this._startReconnect();
      }
    };
  }

  disconnect() {
    this.manualClose = true;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    if (this.reconnectTimer) {
      clearInterval(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  onEvent(callback) {
    this.onEventCallbacks.push(callback);
  }

  onStatusChange(callback) {
    this.onStatusChangeCallbacks.push(callback);
  }

  // -------------------------------------------------------------------------
  // Internal Helpers
  // -------------------------------------------------------------------------

  _startReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setInterval(() => {
      console.log('Attempting to reconnect WebSocket...');
      this.connect();
    }, 5000);
  }

  _updateStatus(online) {
    this.onStatusChangeCallbacks.forEach(cb => cb(online));
  }

  _dispatch(event) {
    this.onEventCallbacks.forEach(cb => cb(event));
  }
}

// Global WebSocket Singleton
const wsClient = new IDRSWebSocket();
