import React from 'react';
import { ShieldAlert, ShieldCheck, Terminal, Cpu, Radio, Activity, Lock } from 'lucide-react';

interface HeaderProps {
  isScanning: boolean;
  threatCount: number;
  serverOnline: boolean;
  aiReady: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  isScanning,
  threatCount,
  serverOnline,
  aiReady,
}) => {
  return (
    <header className="border-b border-cyan-900/30 bg-[#070b12]/90 backdrop-blur-md sticky top-0 z-40 px-4 lg:px-8 py-3">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${isScanning ? 'bg-rose-400 opacity-75' : 'bg-cyan-400 opacity-75'}`}></span>
              <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${isScanning ? 'bg-rose-500' : 'bg-cyan-500'}`}></span>
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-black tracking-wider font-mono text-white">SENTINEL<span className="text-cyan-400">-X</span></span>
              <span className="px-1.5 py-0.5 text-[10px] font-mono font-semibold tracking-widest uppercase bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 rounded">
                v2.4 SEC-OPS
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
              <span>Cyber Reconnaissance AI Agent</span>
              <span className="text-slate-600">•</span>
              <span className="text-emerald-400">Passive Threat Analysis</span>
            </p>
          </div>
        </div>

        {/* Tactical status telemetry chips */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-slate-900/80 border border-slate-800 text-slate-300">
            <Radio className={`w-3.5 h-3.5 ${isScanning ? 'text-amber-400 animate-pulse' : 'text-emerald-400'}`} />
            <span>RADAR:</span>
            <span className={isScanning ? 'text-amber-300 font-semibold' : 'text-emerald-400 font-semibold'}>
              {isScanning ? 'INTERCEPTING' : 'PASSIVE STANDBY'}
            </span>
          </div>

          <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-slate-900/80 border border-slate-800 text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>NEURAL CORE:</span>
            <span className={aiReady ? 'text-cyan-300 font-semibold' : 'text-slate-400'}>
              {aiReady ? 'GEMINI 3.8 FLASH' : 'DETERMINISTIC HEURISTICS'}
            </span>
          </div>

          <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-slate-900/80 border border-slate-800 text-slate-300">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>MODULES:</span>
            <span className="text-white font-semibold">5/5 ARMED</span>
          </div>
        </div>
      </div>
    </header>
  );
};
