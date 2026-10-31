import React from 'react';
import { ShieldCheck, Cpu, Clock, DollarSign, Receipt, Sparkles } from 'lucide-react';

export default function AuditFooter({ audit }) {
  const defaultAudit = {
    provider: "Prune AI Gateway",
    model: "gpt-4o-mini",
    latency: "138ms",
    cost: "$0.0003",
    savings: "96.4%",
    receipt: "#PRUNE-SEALED"
  };

  const data = audit || defaultAudit;

  return (
    <div className="w-full mt-6 bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 hover:border-slate-700/80 rounded-xl p-4 shadow-xl relative overflow-hidden transition-all">
      {/* Subtle glowing accent line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-emerald-500/0 via-emerald-500/60 to-cyan-500/0" />

      <div className="flex flex-col md:flex-row items-center justify-between gap-3 text-xs font-mono">
        {/* Left: Verified Badge */}
        <div className="flex items-center gap-2.5 text-slate-200">
          <div className="w-6 h-6 rounded-md bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <ShieldCheck className="w-3.5 h-3.5" />
          </div>
          <div>
            <span className="font-semibold text-white tracking-wide">
              🛡️ Audit Verified by {data.provider}
            </span>
            <span className="text-slate-400 ml-2 hidden sm:inline">
              | Cryptographically Signed Telemetry
            </span>
          </div>
        </div>

        {/* Center / Right: Telemetry metrics */}
        <div className="flex flex-wrap items-center justify-center md:justify-end gap-x-4 gap-y-1.5 text-slate-400">
          {/* Routed Model */}
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Routed:</span>
            <span className="text-slate-200 font-semibold">{data.model}</span>
          </div>

          <span className="text-slate-700 hidden sm:inline">|</span>

          {/* Latency */}
          <div className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-yellow-400" />
            <span>Latency:</span>
            <span className="text-emerald-400 font-semibold">{data.latency}</span>
          </div>

          <span className="text-slate-700 hidden sm:inline">|</span>

          {/* Cost & Savings */}
          <div className="flex items-center gap-1.5">
            <DollarSign className="w-3.5 h-3.5 text-emerald-400" />
            <span>Cost:</span>
            <span className="text-white font-semibold">{data.cost}</span>
            <span className="text-emerald-400 text-[11px] font-bold">
              (Saved {data.savings})
            </span>
          </div>

          <span className="text-slate-700 hidden sm:inline">|</span>

          {/* Cryptographic Receipt */}
          <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded border border-slate-800 text-slate-300">
            <Receipt className="w-3.5 h-3.5 text-emerald-400" />
            <span>Receipt:</span>
            <span className="text-emerald-400 font-bold tracking-wider">
              {data.receipt}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
