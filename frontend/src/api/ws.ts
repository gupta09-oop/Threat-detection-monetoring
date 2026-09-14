/**
 * Centralized WebSocket Manager for Sh4d0w_St4lk3r SOC Frontend.
 * Connects to /ws/events, automatically reconnects on disconnect,
 * and distributes live alert/case events to listeners.
 */

export type WebSocketStatus = 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED';

export interface WebSocketMessage {
  type: 'alert.created' | 'alert.updated' | 'alert.status_changed' | 'case.created' | 'case.updated' | 'case.status_changed' | string;
  data: any;
  timestamp: string;
}

type MessageListener = (msg: WebSocketMessage) => void;
type StatusListener = (status: WebSocketStatus) => void;

class WebSocketManager {
  private ws: WebSocket | null = null;
  private messageListeners: Set<MessageListener> = new Set();
  private statusListeners: Set<StatusListener> = new Set();
  private status: WebSocketStatus = 'DISCONNECTED';
  private reconnectTimeout: any = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 50;
  private pingInterval: any = null;

  constructor() {
    this.connect();
  }

  public getStatus(): WebSocketStatus {
    return this.status;
  }

  public subscribeMessages(listener: MessageListener): () => void {
    this.messageListeners.add(listener);
    return () => this.messageListeners.delete(listener);
  }

  public subscribeStatus(listener: StatusListener): () => void {
    this.statusListeners.add(listener);
    listener(this.status);
    return () => this.statusListeners.delete(listener);
  }

  private setStatus(newStatus: WebSocketStatus) {
    this.status = newStatus;
    this.statusListeners.forEach((fn) => fn(newStatus));
  }

  private connect() {
    if (typeof window === 'undefined') return;

    const wsUrl = import.meta.env.VITE_WS_URL || 'ws://127.0.0.1:8099/ws/events';
    this.setStatus('CONNECTING');

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.setStatus('CONNECTED');
        this.reconnectAttempts = 0;
        if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);

        // Keep-alive ping every 25s
        this.pingInterval = setInterval(() => {
          if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send('ping');
          }
        }, 25000);
      };

      this.ws.onmessage = (event) => {
        try {
          if (event.data === 'pong') return;
          const parsed = JSON.parse(event.data);
          this.messageListeners.forEach((fn) => fn(parsed));
        } catch {
          // Ignore parse errors on raw strings
        }
      };

      this.ws.onclose = () => {
        this.setStatus('DISCONNECTED');
        if (this.pingInterval) clearInterval(this.pingInterval);
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.setStatus('DISCONNECTED');
        if (this.ws) this.ws.close();
      };
    } catch {
      this.setStatus('DISCONNECTED');
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) return;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), 10000);
    this.reconnectAttempts++;
    this.reconnectTimeout = setTimeout(() => {
      this.connect();
    }, delay);
  }
}

export const wsManager = new WebSocketManager();
