import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, Crosshair, Hash } from 'lucide-react';

export default function ScoreCard({ result }) {
  if (!result) return null;

  const isSafe = result.score >= 80;
  const strokeColor = isSafe ? '#10b981' : '#f43f5e';
  const glowShadow = isSafe ? 'shadow-glow-emerald' : 'shadow-glow-rose';

  // SVG circular dial parameters
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (result.score / 100) * circumference;

  return (
    <div className={`bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-xl relative overflow-hidden transition-all duration-300 ${
      isSafe ? 'hover:border-emerald-500/40' : 'hover:border-rose-500/40'
    }`}>
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-medium text-slate-400 uppercase tracking-wider">
            CARD 01 // RISK EVALUATION
          </span>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/60">
          ID: {result.package_name}@{result.version || 'latest'}
        </span>
      </div>

      {/* Main Dial & Metric */}
      <div className="my-5 flex flex-col items-center justify-center relative">
        <div className="relative flex items-center justify-center">
          <svg className="w-36 h-36 transform -rotate-90">
            {/* Background Circle */}
            <circle
              cx="72"
              cy="72"
              r={radius}
              stroke="#1e293b"
              strokeWidth="10"
              fill="transparent"
            />
            {/* Foreground Progress Circle */}
            <circle
              cx="72"
              cy="72"
              r={radius}
              stroke={strokeColor}
              strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
              style={{
                filter: isSafe 
                  ? 'drop-shadow(0px 0px 8px rgba(16, 185, 129, 0.7))' 
                  : 'drop-shadow(0px 0px 8px rgba(244, 63, 94, 0.7))'
              }}
            />
          </svg>

          {/* Centered Score */}
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className={`text-4xl font-extrabold font-mono tracking-tight ${
              isSafe ? 'text-emerald-400' : 'text-rose-500'
            }`}>
              {result.score}
            </span>
            <span className="text-[10px] uppercase font-mono tracking-widest text-slate-400">
              SAFETY / 100
            </span>
          </div>
        </div>

        {/* Threat Level Badge */}
        <div className="mt-4">
          {isSafe ? (
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/40 text-emerald-400 text-xs font-semibold tracking-wide uppercase shadow-glow-emerald">
              <ShieldCheck className="w-4 h-4" />
              <span>{result.status_label || "SAFE / VERIFIED INTEGRITY"}</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/50 text-rose-400 text-xs font-semibold tracking-wide uppercase shadow-glow-rose animate-pulse">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>{result.status_label || "CRITICAL THREAT (BLOCKED)"}</span>
            </div>
          )}
        </div>
      </div>

      {/* Typosquat Percentage Alert */}
      <div className={`mt-auto p-3.5 rounded-lg border font-mono transition-all ${
        isSafe
          ? 'bg-slate-950/60 border-slate-800 text-slate-300'
          : 'bg-rose-950/20 border-rose-500/30 text-rose-200'
      }`}>
        <div className="flex items-center justify-between text-xs mb-1.5">
          <span className="flex items-center gap-1.5 font-medium text-slate-300">
            <Crosshair className={`w-3.5 h-3.5 ${isSafe ? 'text-emerald-400' : 'text-rose-400'}`} />
            Typosquat Similarity Index:
          </span>
          <span className={`font-bold px-1.5 py-0.5 rounded text-xs ${
            isSafe
              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
              : 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-mono'
          }`}>
            {result.typosquat_risk}
          </span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          {result.typosquat_detail}
        </p>
      </div>
    </div>
  );
}
