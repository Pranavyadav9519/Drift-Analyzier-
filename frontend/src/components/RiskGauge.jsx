// RiskGauge.jsx — Visual risk score gauge
import React from 'react';
import { Shield, ShieldAlert, ShieldCheck } from 'lucide-react';

export default function RiskGauge({ riskScore, riskLevel }) {
  const color =
    riskLevel === 'high'
      ? { ring: 'stroke-red-500', text: 'text-red-400', label: 'HIGH RISK', icon: ShieldAlert }
      : riskLevel === 'medium'
      ? { ring: 'stroke-yellow-400', text: 'text-yellow-400', label: 'MEDIUM RISK', icon: Shield }
      : { ring: 'stroke-green-400', text: 'text-green-400', label: 'LOW RISK', icon: ShieldCheck };

  // SVG arc calculation
  const radius = 60;
  const circumference = Math.PI * radius; // half circle
  const progress = ((100 - riskScore) / 100) * circumference;

  const Icon = color.icon;

  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-6">
      <h3 className="text-white font-semibold text-base mb-4">Current Risk Score</h3>

      <div className="flex flex-col items-center">
        {/* SVG Gauge */}
        <svg width="180" height="100" viewBox="0 0 180 100">
          {/* Background track */}
          <path
            d="M 10 90 A 80 80 0 0 1 170 90"
            fill="none"
            stroke="#334155"
            strokeWidth="14"
            strokeLinecap="round"
          />
          {/* Progress arc */}
          <path
            d="M 10 90 A 80 80 0 0 1 170 90"
            fill="none"
            className={color.ring}
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={`${circumference}`}
            strokeDashoffset={`${progress}`}
            style={{ transition: 'stroke-dashoffset 0.8s ease' }}
          />
          {/* Score text */}
          <text x="90" y="78" textAnchor="middle" className="fill-white text-2xl font-bold" fontSize="26" fontWeight="bold" fill="white">
            {riskScore}
          </text>
          <text x="90" y="95" textAnchor="middle" fontSize="10" fill="#94a3b8">
            out of 100
          </text>
        </svg>

        {/* Level badge */}
        <div className={`flex items-center gap-2 mt-2 ${color.text}`}>
          <Icon className="w-5 h-5" />
          <span className="font-bold text-sm tracking-wider">{color.label}</span>
        </div>

        {/* Score bar */}
        <div className="w-full mt-4">
          <div className="flex justify-between text-xs text-slate-400 mb-1">
            <span>0</span>
            <span>50</span>
            <span>100</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all duration-700 ${
                riskLevel === 'high' ? 'bg-red-500' : riskLevel === 'medium' ? 'bg-yellow-400' : 'bg-green-400'
              }`}
              style={{ width: `${riskScore}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
