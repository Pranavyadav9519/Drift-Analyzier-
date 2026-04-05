// RiskTrendChart.jsx — Line chart of risk score over recent logins
import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';

function formatDate(iso) {
  const d = new Date(iso);
  return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`;
}

export default function RiskTrendChart({ data }) {
  const chartData = data.map((d) => ({
    time: formatDate(d.createdAt),
    score: d.riskScore,
    level: d.riskLevel,
  }));

  const CustomDot = (props) => {
    const { cx, cy, payload } = props;
    const fill =
      payload.level === 'high' ? '#ef4444' : payload.level === 'medium' ? '#f59e0b' : '#22c55e';
    return <circle cx={cx} cy={cy} r={5} fill={fill} stroke="#1e293b" strokeWidth={2} />;
  };

  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-6">
      <h3 className="text-white font-semibold text-base mb-4">Risk Score Trend</h3>

      {chartData.length === 0 ? (
        <div className="flex items-center justify-center h-40 text-slate-500 text-sm">
          No login history yet
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" tick={{ fill: '#94a3b8', fontSize: 10 }} />
            <YAxis domain={[0, 100]} tick={{ fill: '#94a3b8', fontSize: 10 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
              labelStyle={{ color: '#94a3b8', fontSize: 11 }}
              itemStyle={{ color: '#a78bfa' }}
            />
            <ReferenceLine y={70} stroke="#ef4444" strokeDasharray="4 4" label={{ value: 'High', fill: '#ef4444', fontSize: 10 }} />
            <ReferenceLine y={40} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: 'Med', fill: '#f59e0b', fontSize: 10 }} />
            <Line
              type="monotone"
              dataKey="score"
              stroke="#818cf8"
              strokeWidth={2}
              dot={<CustomDot />}
              activeDot={{ r: 6 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
