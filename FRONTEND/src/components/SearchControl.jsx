import React from 'react';
import { Search, Loader2, Sparkles, Layers, ArrowRight } from 'lucide-react';
import { DEMO_PILLS } from '../mockData';

export default function SearchControl({
  packageName,
  setPackageName,
  ecosystem,
  setEcosystem,
  onScan,
  isScanning,
  onSelectPill,
  activePill
}) {
  const handleSubmit = (e) => {
    e.preventDefault();
    if (packageName.trim()) {
      onScan(packageName.trim(), ecosystem);
    }
  };

  return (
    <div className="w-full bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl relative overflow-hidden">
      {/* Subtle background grid pattern */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />

      <div className="relative z-10 flex flex-col gap-4">
        {/* Search Bar & Controls */}
        <form onSubmit={handleSubmit} className="flex flex-col md:flex-row items-center gap-3">
          {/* Ecosystem Toggle */}
          <div className="flex items-center p-1 bg-slate-950 border border-slate-800 rounded-lg shrink-0 w-full md:w-auto">
            <button
              type="button"
              onClick={() => setEcosystem('npm')}
              className={`flex-1 md:flex-none px-3.5 py-2 rounded-md text-xs font-mono font-medium transition-all flex items-center justify-center gap-1.5 ${
                ecosystem === 'npm'
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-red-500/80"></span>
              npm
            </button>
            <button
              type="button"
              onClick={() => setEcosystem('pypi')}
              className={`flex-1 md:flex-none px-3.5 py-2 rounded-md text-xs font-mono font-medium transition-all flex items-center justify-center gap-1.5 ${
                ecosystem === 'pypi'
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-blue-500/80"></span>
              PyPI
            </button>
          </div>

          {/* Package Input Box */}
          <div className="relative flex-1 w-full">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Search className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
              placeholder="Enter package name (e.g. lodash, requests, reqeusts)..."
              className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/50 rounded-lg text-sm font-mono text-slate-100 placeholder-slate-500 outline-none transition-all shadow-inner"
            />
          </div>

          {/* Glowing Scan Package Button */}
          <button
            type="submit"
            disabled={isScanning || !packageName.trim()}
            className={`w-full md:w-auto px-6 py-2.5 rounded-lg text-sm font-medium tracking-wide font-sans transition-all flex items-center justify-center gap-2 cursor-pointer shadow-lg shrink-0 ${
              isScanning
                ? 'bg-slate-800 text-slate-400 border border-slate-700 cursor-wait'
                : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold shadow-glow-emerald hover:shadow-emerald-500/50 active:scale-[0.98]'
            }`}
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
                <span>Deep Scanning...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-slate-950" />
                <span>Scan Package</span>
              </>
            )}
          </button>
        </form>

        {/* 4 Instant Demo Pills */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 pt-1 border-t border-slate-800/60">
          <span className="text-xs font-mono text-slate-400 shrink-0 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-slate-500" />
            Instant Demos:
          </span>
          <div className="flex flex-wrap items-center gap-2 w-full">
            {DEMO_PILLS.map((pill) => {
              const isSelected = activePill === pill.pkg;
              return (
                <button
                  key={pill.pkg}
                  type="button"
                  onClick={() => onSelectPill(pill)}
                  className={`px-3 py-1.5 rounded-md text-xs font-mono transition-all border flex items-center gap-1.5 cursor-pointer ${
                    isSelected
                      ? pill.isMalicious
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/60 shadow-glow-rose font-semibold'
                        : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/60 shadow-glow-emerald font-semibold'
                      : pill.isMalicious
                      ? 'bg-slate-950/80 text-rose-400/90 border-rose-500/30 hover:border-rose-500/60 hover:bg-rose-950/20'
                      : 'bg-slate-950/80 text-emerald-400/90 border-emerald-500/30 hover:border-emerald-500/60 hover:bg-emerald-950/20'
                  }`}
                >
                  <span>{pill.label}</span>
                  {isSelected && <ArrowRight className="w-3 h-3 animate-pulse" />}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
