// IdentityHealthBadge.jsx — Shows user's identity health status
import React from 'react';
import { ShieldCheck, ShieldAlert, Shield } from 'lucide-react';

const config = {
  normal: {
    label: 'Identity Healthy',
    icon: ShieldCheck,
    classes: 'bg-green-500/10 border-green-500/30 text-green-400',
  },
  at_risk: {
    label: 'Identity At Risk',
    icon: Shield,
    classes: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
  },
  compromised: {
    label: 'Identity Compromised',
    icon: ShieldAlert,
    classes: 'bg-red-500/10 border-red-500/30 text-red-400',
  },
};

export default function IdentityHealthBadge({ status }) {
  const cfg = config[status] || config.normal;
  const Icon = cfg.icon;

  return (
    <div className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-semibold ${cfg.classes}`}>
      <Icon className="w-4 h-4" />
      {cfg.label}
    </div>
  );
}
