// LoginHistoryTable.jsx — Table of recent login events
import React from 'react';
import { CheckCircle, AlertTriangle, ShieldAlert, Monitor, Smartphone } from 'lucide-react';

function formatTime(iso) {
  return new Date(iso).toLocaleString();
}

const riskBadge = {
  low: 'bg-green-500/10 text-green-400 border border-green-500/20',
  medium: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  high: 'bg-red-500/10 text-red-400 border border-red-500/20',
};

export default function LoginHistoryTable({ events }) {
  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-sentinel-border">
        <h3 className="text-white font-semibold text-base">Login History</h3>
        <p className="text-slate-400 text-sm">Last 10 login attempts</p>
      </div>

      {events.length === 0 ? (
        <div className="px-6 py-8 text-center text-slate-500 text-sm">No login events recorded yet</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-sentinel-border">
                {['Time', 'IP Address', 'Device', 'Hour', 'Risk Score', 'Level', 'Action'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr key={ev._id} className="border-b border-sentinel-border/50 hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-3 text-slate-300 whitespace-nowrap">{formatTime(ev.createdAt)}</td>
                  <td className="px-4 py-3 text-slate-300 font-mono text-xs">{ev.ipAddress}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 text-slate-300">
                      {ev.userAgent?.toLowerCase().includes('mobile') ? (
                        <Smartphone className="w-3.5 h-3.5 text-slate-400" />
                      ) : (
                        <Monitor className="w-3.5 h-3.5 text-slate-400" />
                      )}
                      <span className="truncate max-w-[120px]" title={ev.userAgent}>
                        {ev.isNewDevice ? (
                          <span className="text-yellow-400">New Device</span>
                        ) : (
                          'Known Device'
                        )}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-slate-300">{ev.loginHour}:00</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div
                        className={`w-16 bg-slate-700 rounded-full h-1.5`}
                      >
                        <div
                          className={`h-1.5 rounded-full ${
                            ev.riskLevel === 'high' ? 'bg-red-500' : ev.riskLevel === 'medium' ? 'bg-yellow-400' : 'bg-green-400'
                          }`}
                          style={{ width: `${ev.riskScore}%` }}
                        />
                      </div>
                      <span className="text-slate-300 text-xs font-mono">{ev.riskScore}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded capitalize ${riskBadge[ev.riskLevel]}`}>
                      {ev.riskLevel}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs capitalize">
                    {ev.action?.replace('_', ' ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
