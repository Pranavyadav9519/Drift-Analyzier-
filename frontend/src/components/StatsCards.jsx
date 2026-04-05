// StatsCards.jsx — Summary stat cards at the top of the dashboard
import React from 'react';
import { LogIn, AlertTriangle, ShieldAlert, Bell } from 'lucide-react';

const cards = [
  {
    key: 'totalLogins',
    label: 'Total Logins',
    icon: LogIn,
    color: 'text-indigo-400',
    bg: 'bg-indigo-500/10',
  },
  {
    key: 'anomalyCount',
    label: 'Anomalies Detected',
    icon: AlertTriangle,
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/10',
  },
  {
    key: 'highRiskCount',
    label: 'High Risk Events',
    icon: ShieldAlert,
    color: 'text-red-400',
    bg: 'bg-red-500/10',
  },
  {
    key: 'unresolvedAlerts',
    label: 'Open Alerts',
    icon: Bell,
    color: 'text-orange-400',
    bg: 'bg-orange-500/10',
  },
];

export default function StatsCards({ stats }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map(({ key, label, icon: Icon, color, bg }) => (
        <div
          key={key}
          className="bg-sentinel-card border border-sentinel-border rounded-xl p-5"
        >
          <div className={`inline-flex items-center justify-center w-10 h-10 rounded-lg ${bg} mb-3`}>
            <Icon className={`w-5 h-5 ${color}`} />
          </div>
          <div className="text-2xl font-bold text-white">{stats?.[key] ?? 0}</div>
          <div className="text-sm text-slate-400 mt-1">{label}</div>
        </div>
      ))}
    </div>
  );
}
