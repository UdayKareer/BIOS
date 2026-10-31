import React from 'react';
import { Laptop, KeyRound, FileCode, Network, AlertOctagon, CheckCircle2, ShieldCheck, Zap } from 'lucide-react';

export default function BlastRadiusMap({ result }) {
  if (!result || !result.blast_radius) return null;

  const blast = result.blast_radius;
  const isEnvHit = blast.env_file?.impacted;
  const isSshHit = blast.ssh_key?.impacted;
  const isSocketHit = blast.outbound_socket?.impacted;
  const hasCompromise = isEnvHit || isSshHit || isSocketHit;

  return (
    <div className={`bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-xl relative overflow-hidden transition-all duration-300 ${
      hasCompromise ? 'hover:border-rose-500/40' : 'hover:border-emerald-500/40'
    }`}>
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-medium text-slate-400 uppercase tracking-wider">
            CARD 02 // HOST BLAST RADIUS MAP
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
            LOCAL SANDBOX PROBE
          </span>
        </div>
      </div>

      {/* Visual Laptop / Host Target Schematic */}
      <div className="my-4 p-4 rounded-xl bg-slate-950/80 border border-slate-800/90 relative">
        <div className="flex items-center justify-center mb-3">
          {/* Laptop Central Icon */}
          <div className="relative flex flex-col items-center">
            <div className={`p-3 rounded-2xl border transition-all ${
              hasCompromise
                ? 'bg-rose-950/30 border-rose-500/50 text-rose-400 shadow-glow-rose'
                : 'bg-emerald-950/20 border-emerald-500/40 text-emerald-400 shadow-glow-emerald'
            }`}>
              <Laptop className="w-8 h-8" />
            </div>
            <span className="text-[10px] font-mono mt-1 text-slate-400 font-semibold uppercase tracking-wider">
              DEVELOPER WORKSTATION (HOST)
            </span>
            {hasCompromise && (
              <span className="absolute -top-1 -right-2 px-1.5 py-0.2 text-[9px] bg-rose-600 text-white font-mono font-bold rounded-full animate-bounce">
                ALERT
              </span>
            )}
          </div>
        </div>

        {/* Dynamic Vector Lines (Simulated SVG Connector) */}
        <div className="w-full h-1 bg-gradient-to-r from-transparent via-slate-800 to-transparent my-2" />

        {/* 3 Host Target Nodes */}
        <div className="grid grid-cols-1 gap-2.5 mt-2">
          {/* Target 1: ~/.env */}
          <div className={`p-2.5 rounded-lg border flex items-center justify-between transition-all font-mono text-xs ${
            isEnvHit
              ? 'bg-rose-950/30 border-rose-500/50 text-rose-300'
              : 'bg-slate-900/90 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center gap-2.5">
              <div className={`p-1.5 rounded-md ${
                isEnvHit ? 'bg-rose-500/20 text-rose-400' : 'bg-slate-800 text-emerald-400'
              }`}>
                <FileCode className="w-4 h-4" />
              </div>
              <div>
                <div className="font-semibold flex items-center gap-1.5">
                  <span>~/.env</span>
                  <span className="text-[10px] text-slate-500">(API Keys & Secrets)</span>
                </div>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  {blast.env_file?.detail || "Zero unrequested file reads detected."}
                </p>
              </div>
            </div>
            <div className="shrink-0 ml-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border ${
                isEnvHit
                  ? 'bg-rose-500/20 border-rose-500/60 text-rose-300 animate-pulse'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              }`}>
                {blast.env_file?.status || "SECURE"}
              </span>
            </div>
          </div>

          {/* Target 2: ~/.ssh/id_rsa */}
          <div className={`p-2.5 rounded-lg border flex items-center justify-between transition-all font-mono text-xs ${
            isSshHit
              ? 'bg-rose-950/30 border-rose-500/50 text-rose-300'
              : 'bg-slate-900/90 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center gap-2.5">
              <div className={`p-1.5 rounded-md ${
                isSshHit ? 'bg-rose-500/20 text-rose-400' : 'bg-slate-800 text-emerald-400'
              }`}>
                <KeyRound className="w-4 h-4" />
              </div>
              <div>
                <div className="font-semibold flex items-center gap-1.5">
                  <span>~/.ssh/id_rsa</span>
                  <span className="text-[10px] text-slate-500">(Private Keys)</span>
                </div>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  {blast.ssh_key?.detail || "Zero credential probing into ~/.ssh."}
                </p>
              </div>
            </div>
            <div className="shrink-0 ml-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border ${
                isSshHit
                  ? 'bg-rose-500/20 border-rose-500/60 text-rose-300 animate-pulse'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              }`}>
                {blast.ssh_key?.status || "SECURE"}
              </span>
            </div>
          </div>

          {/* Target 3: Outbound socket */}
          <div className={`p-2.5 rounded-lg border flex items-center justify-between transition-all font-mono text-xs ${
            isSocketHit
              ? 'bg-rose-950/30 border-rose-500/50 text-rose-300'
              : 'bg-slate-900/90 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center gap-2.5">
              <div className={`p-1.5 rounded-md ${
                isSocketHit ? 'bg-rose-500/20 text-rose-400' : 'bg-slate-800 text-emerald-400'
              }`}>
                <Network className="w-4 h-4" />
              </div>
              <div>
                <div className="font-semibold flex items-center gap-1.5">
                  <span>Outbound Socket</span>
                  <span className="text-[10px] text-slate-500">(C2 / Reverse Shell)</span>
                </div>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  {blast.outbound_socket?.detail || "0 background sockets or C2 beacons."}
                </p>
              </div>
            </div>
            <div className="shrink-0 ml-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border ${
                isSocketHit
                  ? 'bg-rose-500/20 border-rose-500/60 text-rose-300 animate-pulse'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              }`}>
                {blast.outbound_socket?.status || "NO ACTIVITY"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Perimeter Status Bar */}
      <div className="flex items-center justify-between text-[11px] font-mono px-3 py-2 rounded-lg bg-slate-950 border border-slate-800">
        <span className="text-slate-400 flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5 text-yellow-500" />
          Perimeter State:
        </span>
        <span className={hasCompromise ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
          {hasCompromise ? 'CONTAINMENT FIREWALL ACTIVATED' : 'PERIMETER INTACT & ISOLATED'}
        </span>
      </div>
    </div>
  );
}
