// Navbar.jsx — Top navigation bar
import React from 'react';
import { ShieldCheck, LogOut, Bell } from 'lucide-react';

export default function Navbar({ user, onLogout }) {
  return (
    <nav className="bg-sentinel-card border-b border-sentinel-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-indigo-500/20">
              <ShieldCheck className="w-5 h-5 text-indigo-400" />
            </div>
            <span className="text-white font-bold text-lg">Sentinel Zero</span>
          </div>

          {/* User info + logout */}
          <div className="flex items-center gap-4">
            <div className="text-right hidden sm:block">
              <div className="text-sm font-medium text-white">{user?.username}</div>
              <div className="text-xs text-slate-400">{user?.email}</div>
            </div>
            <button
              onClick={onLogout}
              className="flex items-center gap-2 text-slate-400 hover:text-red-400 transition-colors text-sm font-medium"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Sign out</span>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
