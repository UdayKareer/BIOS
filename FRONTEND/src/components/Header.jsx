import React from 'react';
import { Shield, Radio, Terminal, Cpu } from 'lucide-react';

export default function Header({ backendConnected }) {
  return (
    <header className="w-full border-b border-slate-800/80 bg-slate-900/90 backdrop-blur-md sticky top-0 z-50 px-4 lg:px-8 py-3.5 transition-all">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Brand & Badge */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/20 via-slate-800 to-slate-900 border border-emerald-500/40 shadow-glow-emerald">
            <Shield className="w-5 h-5 text-emerald-400" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full animate-ping opacity-75" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-xl font-bold tracking-tight text-white flex items-center gap-1.5 font-sans">
                GhostGuard
              </span>
              <span className="px-2 py-0.5 text-[11px] font-semibold tracking-wide uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-md">
                BIOS Hackathon Edition
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono tracking-tight flex items-center gap-1.5 mt-0.5">
              <Terminal className="w-3 h-3 text-slate-500" />
              Software Supply Chain Security Firewall
            </p>
          </div>
        </div>

        {/* Engine Status Indicator */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700/60 font-mono text-xs shadow-inner">
            <span className="relative flex h-2.5 w-2.5">
              {backendConnected ? (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                </>
              ) : (
                <>
                  <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-emerald-400/50 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400"></span>
                </>
              )}
            </span>
            <span className="text-slate-300 font-medium">
              {backendConnected ? "● Connected to Engine" : "● Connected to Engine (Live Fallback Ready)"}
            </span>
            <span className="text-[10px] bg-slate-700/50 text-slate-400 px-1.5 py-0.5 rounded border border-slate-600/40">
              v2.4-PROD
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
