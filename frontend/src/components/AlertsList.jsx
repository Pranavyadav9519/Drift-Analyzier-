// AlertsList.jsx — Shows security alerts with resolve action
import React from 'react';
import { AlertTriangle, ShieldAlert, Info, CheckCircle } from 'lucide-react';

const severityConfig = {
  critical: {
    icon: ShieldAlert,
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-400',
    badge: 'bg-red-500/20 text-red-400',
  },
  warning: {
    icon: AlertTriangle,
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    text: 'text-yellow-400',
    badge: 'bg-yellow-500/20 text-yellow-400',
  },
  info: {
    icon: Info,
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    text: 'text-blue-400',
    badge: 'bg-blue-500/20 text-blue-400',
  },
};

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function AlertsList({ alerts, onResolve }) {
  const active = alerts.filter((a) => !a.resolved);
  const resolved = alerts.filter((a) => a.resolved);

  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-6">
      <h3 className="text-white font-semibold text-base mb-4">
        Security Alerts
        {active.length > 0 && (
          <span className="ml-2 text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
            {active.length} active
          </span>
        )}
      </h3>

      {alerts.length === 0 ? (
        <div className="flex items-center gap-2 text-green-400 text-sm">
          <CheckCircle className="w-4 h-4" />
          No security alerts — all clear!
        </div>
      ) : (
        <div className="space-y-3">
          {/* Active alerts first */}
          {active.map((alert) => {
            const cfg = severityConfig[alert.severity] || severityConfig.info;
            const Icon = cfg.icon;
            return (
              <div
                key={alert._id}
                className={`flex items-start justify-between gap-4 rounded-lg border p-4 ${cfg.bg} ${cfg.border}`}
              >
                <div className="flex items-start gap-3">
                  <Icon className={`w-5 h-5 mt-0.5 flex-shrink-0 ${cfg.text}`} />
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded ${cfg.badge}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span className="text-xs text-slate-500">{timeAgo(alert.createdAt)}</span>
                    </div>
                    <p className={`text-sm mt-1 ${cfg.text}`}>{alert.message}</p>
                    {alert.action && (
                      <p className="text-xs text-slate-500 mt-0.5">
                        Action: <span className="font-medium capitalize">{alert.action.replace('_', ' ')}</span>
                      </p>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => onResolve(alert._id)}
                  className="text-xs text-slate-400 hover:text-white bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded-lg transition-colors flex-shrink-0"
                >
                  Resolve
                </button>
              </div>
            );
          })}

          {/* Resolved alerts (collapsed) */}
          {resolved.length > 0 && (
            <p className="text-xs text-slate-500 mt-2">
              {resolved.length} resolved alert{resolved.length !== 1 ? 's' : ''} hidden
            </p>
          )}
        </div>
      )}
    </div>
  );
}
