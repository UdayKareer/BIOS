import React, { useState } from 'react';
import { Code2, BrainCircuit, Check, Copy, AlertTriangle, FileWarning, Sparkles } from 'lucide-react';

export default function DeobfuscatorCard({ result }) {
  if (!result || !result.deobfuscation) return null;

  const { obfuscated_code, clean_code, explanation } = result.deobfuscation;
  const isMalicious = result.score < 80;
  const [copiedSide, setCopiedSide] = useState(null);

  const handleCopy = (text, side) => {
    navigator.clipboard.writeText(text);
    setCopiedSide(side);
    setTimeout(() => setCopiedSide(null), 2000);
  };

  return (
    <div className={`col-span-1 lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-xl relative overflow-hidden transition-all duration-300 ${
      isMalicious ? 'hover:border-rose-500/40' : 'hover:border-emerald-500/40'
    }`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between border-b border-slate-800/80 pb-3 gap-2">
        <div className="flex items-center gap-2">
          <BrainCircuit className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-mono font-medium text-slate-400 uppercase tracking-wider">
            CARD 03 // AI DE-OBFUSCATOR & AST RECONSTRUCTION
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700/60 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
            Prune Static + Dynamic Unpacker
          </span>
        </div>
      </div>

      {/* Side-by-Side Diff Windows */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
        {/* Left Window: Obfuscated Base64 / Raw in Red */}
        <div className="flex flex-col rounded-xl overflow-hidden border border-rose-500/40 bg-slate-950 shadow-inner">
          <div className="bg-rose-950/40 px-3.5 py-2 border-b border-rose-500/30 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-rose-400 font-semibold">
              <FileWarning className="w-3.5 h-3.5 text-rose-500" />
              <span>[RAW / OBFUSCATED PAYLOAD]</span>
            </div>
            <button
              onClick={() => handleCopy(obfuscated_code, 'left')}
              className="text-slate-400 hover:text-rose-300 p-1 rounded hover:bg-rose-900/30 transition-all text-[11px] flex items-center gap-1 cursor-pointer"
            >
              {copiedSide === 'left' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedSide === 'left' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="p-3.5 font-mono text-[11px] text-rose-300/90 overflow-x-auto max-h-56 leading-relaxed bg-[#0a0508]/80 selection:bg-rose-900/50">
            <pre className="whitespace-pre-wrap break-all font-mono">
              {obfuscated_code}
            </pre>
          </div>
        </div>

        {/* Right Window: Clean De-obfuscated Python/JS in Green */}
        <div className="flex flex-col rounded-xl overflow-hidden border border-emerald-500/40 bg-slate-950 shadow-inner">
          <div className="bg-emerald-950/40 px-3.5 py-2 border-b border-emerald-500/30 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold">
              <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
              <span>[CLEAN DE-OBFUSCATED CODE]</span>
            </div>
            <button
              onClick={() => handleCopy(clean_code, 'right')}
              className="text-slate-400 hover:text-emerald-300 p-1 rounded hover:bg-emerald-900/30 transition-all text-[11px] flex items-center gap-1 cursor-pointer"
            >
              {copiedSide === 'right' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedSide === 'right' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="p-3.5 font-mono text-[11px] text-emerald-300/90 overflow-x-auto max-h-56 leading-relaxed bg-[#050d0a]/80 selection:bg-emerald-900/50">
            <pre className="whitespace-pre-wrap font-mono">
              {clean_code}
            </pre>
          </div>
        </div>
      </div>

      {/* AI Explanation Box */}
      <div className={`p-4 rounded-xl border transition-all ${
        isMalicious
          ? 'bg-rose-950/20 border-rose-500/30 text-rose-200'
          : 'bg-emerald-950/20 border-emerald-500/30 text-emerald-200'
      }`}>
        <div className="flex items-start gap-2.5">
          <div className={`p-1.5 rounded-lg shrink-0 mt-0.5 ${
            isMalicious ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
          }`}>
            <BrainCircuit className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold uppercase tracking-wider">
                AI Analysis & Attribution Breakdown
              </span>
              <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                isMalicious 
                  ? 'bg-rose-500/20 border-rose-500/40 text-rose-300' 
                  : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
              }`}>
                {isMalicious ? 'MALICIOUS FINDING' : 'CLEAN INTEGRITY'}
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
              {explanation}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
