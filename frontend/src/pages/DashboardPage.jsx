// DashboardPage.jsx — Main security dashboard
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import api from '../services/api';
import Navbar from '../components/Navbar';
import StatsCards from '../components/StatsCards';
import RiskGauge from '../components/RiskGauge';
import LoginHistoryTable from '../components/LoginHistoryTable';
import AlertsList from '../components/AlertsList';
import RiskTrendChart from '../components/RiskTrendChart';
import IdentityHealthBadge from '../components/IdentityHealthBadge';

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchData = async () => {
    try {
      const [statsRes, alertsRes] = await Promise.all([
        api.get('/dashboard/stats'),
        api.get('/risk/alerts'),
      ]);
      setStats(statsRes.data);
      setAlerts(alertsRes.data.alerts || []);
    } catch (err) {
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleResolveAlert = async (alertId) => {
    try {
      await api.patch(`/risk/alerts/${alertId}/resolve`);
      setAlerts((prev) => prev.map((a) => (a._id === alertId ? { ...a, resolved: true } : a)));
    } catch {
      /* ignore */
    }
  };

  const handleResetIdentity = async () => {
    try {
      await api.post('/risk/reset');
      fetchData();
    } catch {
      /* ignore */
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-sentinel-dark">
        <div className="text-slate-400 text-lg animate-pulse">Loading dashboard…</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-sentinel-dark">
      <Navbar user={user} onLogout={handleLogout} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg p-4">
            {error}
          </div>
        )}

        {/* Identity Health + Reset */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white">Identity Dashboard</h1>
            <p className="text-slate-400 text-sm mt-1">Real-time behavioral anomaly monitoring</p>
          </div>
          <div className="flex items-center gap-4">
            <IdentityHealthBadge status={stats?.identityStatus || 'normal'} />
            {stats?.identityStatus !== 'normal' && (
              <button
                onClick={handleResetIdentity}
                className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
              >
                Reset Identity Health
              </button>
            )}
          </div>
        </div>

        {/* Stats Cards */}
        <StatsCards stats={stats} />

        {/* Risk Gauge + Trend Chart */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <RiskGauge
            riskScore={stats?.recentEvents?.[0]?.riskScore || 0}
            riskLevel={stats?.recentEvents?.[0]?.riskLevel || 'low'}
          />
          <RiskTrendChart data={stats?.riskTrend || []} />
        </div>

        {/* Alerts */}
        <AlertsList alerts={alerts} onResolve={handleResolveAlert} />

        {/* Login History */}
        <LoginHistoryTable events={stats?.recentEvents || []} />
      </main>
    </div>
  );
}
