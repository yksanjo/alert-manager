/**
 * Alert Manager
 * 
 * Standalone library for managing security alerts and notifications.
 */

export type AlertSeverity = 'info' | 'warning' | 'error' | 'critical';

export interface Alert {
  id: string;
  title: string;
  message: string;
  severity: AlertSeverity;
  timestamp: string;
  source: string;
  metadata?: Record<string, any>;
  acknowledged: boolean;
}

export interface AlertRule {
  id: string;
  name: string;
  condition: (alert: Alert) => boolean;
  severity: AlertSeverity;
}

export interface AlertStats {
  total: number;
  bySeverity: Record<AlertSeverity, number>;
  acknowledged: number;
}

export class AlertManager {
  private alerts: Map<string, Alert>;
  private rules: AlertRule[];
  private listeners: Array<(alert: Alert) => void>;

  constructor() {
    this.alerts = new Map();
    this.rules = [];
    this.listeners = [];
  }

  /**
   * Create alert
   */
  create(alert: Omit<Alert, 'id' | 'timestamp' | 'acknowledged'>): Alert {
    const newAlert: Alert = {
      ...alert,
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      acknowledged: false
    };

    this.alerts.set(newAlert.id, newAlert);
    this.notifyListeners(newAlert);
    this.applyRules(newAlert);

    return newAlert;
  }

  /**
   * Add alert rule
   */
  addRule(rule: AlertRule): void {
    this.rules.push(rule);
  }

  /**
   * Apply rules to alert
   */
  private applyRules(alert: Alert): void {
    for (const rule of this.rules) {
      if (rule.condition(alert)) {
        // Rule matched - could trigger additional actions
      }
    }
  }

  /**
   * Subscribe to alerts
   */
  subscribe(listener: (alert: Alert) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  /**
   * Notify listeners
   */
  private notifyListeners(alert: Alert): void {
    for (const listener of this.listeners) {
      try {
        listener(alert);
      } catch (e) {
        console.error('Alert listener error:', e);
      }
    }
  }

  /**
   * Acknowledge alert
   */
  acknowledge(alertId: string): boolean {
    const alert = this.alerts.get(alertId);
    if (!alert) return false;
    alert.acknowledged = true;
    return true;
  }

  /**
   * Get alert by ID
   */
  get(alertId: string): Alert | null {
    return this.alerts.get(alertId) || null;
  }

  /**
   * Get all alerts
   */
  getAll(): Alert[] {
    return Array.from(this.alerts.values())
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  /**
   * Get alerts by severity
   */
  getBySeverity(severity: AlertSeverity): Alert[] {
    return this.getAll().filter(a => a.severity === severity);
  }

  /**
   * Get unacknowledged alerts
   */
  getUnacknowledged(): Alert[] {
    return this.getAll().filter(a => !a.acknowledged);
  }

  /**
   * Get statistics
   */
  getStats(): AlertStats {
    const alerts = this.getAll();
    const bySeverity: Record<AlertSeverity, number> = {
      info: 0,
      warning: 0,
      error: 0,
      critical: 0
    };

    for (const alert of alerts) {
      bySeverity[alert.severity]++;
    }

    return {
      total: alerts.length,
      bySeverity,
      acknowledged: alerts.filter(a => a.acknowledged).length
    };
  }

  /**
   * Clear old alerts
   */
  clearOlderThan(timestamp: string): number {
    const cutoff = new Date(timestamp).getTime();
    let cleared = 0;

    for (const [id, alert] of this.alerts) {
      if (new Date(alert.timestamp).getTime() < cutoff) {
        this.alerts.delete(id);
        cleared++;
      }
    }

    return cleared;
  }
}

export default AlertManager;
