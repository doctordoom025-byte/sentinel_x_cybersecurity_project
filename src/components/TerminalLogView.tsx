import React, { useState } from 'react';
import { Terminal, Copy, Check, Trash2, ShieldCheck, Activity } from 'lucide-react';

interface TerminalLogViewProps {
  logs: string[];
  isScanning: boolean;
}

export const TerminalLogView: React.FC<TerminalLogViewProps> = ({ logs, isScanning }) => {
  const [copied, setCopied] = useState(false);

  const handleCopyLogs = () => {
    navigator.clipboard.writeText(logs.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#050811] border border-cyan-900/40 rounded-xl p-4 font-mono shadow-2xl relative mb-8 scanlines">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-3 text-xs">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          </div>
          <span className="text-slate-400 font-semibold ml-2 flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            SENTINEL-X RECON TACTICAL CONSOLE // CHAIN-OF-THOUGHT
          </span>
        </div>

        <div className="flex items-center gap-2">
          {isScanning && (
            <span className="text-[10px] text-amber-400 font-bold flex items-center gap-1 animate-pulse">
              <Activity className="w-3 h-3 animate-spin" />
              ANALYZING VECTORS...
            </span>
          )}

          <button
            onClick={handleCopyLogs}
            className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 px-2 py-0.5 rounded bg-slate-900 border border-slate-800 transition-all cursor-pointer"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Terminal Output */}
      <div className="space-y-1.5 text-xs text-slate-300 max-h-72 overflow-y-auto pr-2">
        {logs.map((log, idx) => {
          const isPhase = log.startsWith('[PHASE');
          const isMod = log.startsWith('[MODULE');
          const isCritical = log.includes('CRITICAL');

          let colorClass = 'text-slate-300';
          if (isCritical) colorClass = 'text-rose-400 font-bold';
          else if (isPhase) colorClass = 'text-cyan-400 font-semibold';
          else if (isMod) colorClass = 'text-amber-300';

          return (
            <div key={idx} className="flex items-start gap-2">
              <span className="text-slate-600 select-none text-[10px] pt-0.5">
                {String(idx + 1).padStart(2, '0')}
              </span>
              <span className="text-emerald-500 select-none">&gt;</span>
              <span className={`${colorClass} leading-relaxed`}>{log}</span>
            </div>
          );
        })}

        {isScanning && (
          <div className="flex items-center gap-2 text-cyan-400 animate-pulse">
            <span className="text-slate-600 text-[10px]">--</span>
            <span>&gt; Intercepting dynamic payload structures...</span>
          </div>
        )}
      </div>
    </div>
  );
};
