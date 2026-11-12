import React, { useState } from 'react';
import { Globe, Code2, Network, Sparkles, Play, RotateCcw, AlertTriangle, ShieldCheck, Flame } from 'lucide-react';
import { SAMPLE_TARGETS, SampleTarget } from '../data/sampleThreats';

interface TargetInputPanelProps {
  onScan: (type: 'url' | 'code' | 'network', input: string, useAi: boolean, label?: string) => void;
  isScanning: boolean;
  aiAvailable: boolean;
}

export const TargetInputPanel: React.FC<TargetInputPanelProps> = ({
  onScan,
  isScanning,
  aiAvailable,
}) => {
  const [activeTab, setActiveTab] = useState<'url' | 'code' | 'network'>('code');
  const [urlInput, setUrlInput] = useState<string>('https://secure-recovery-chase.crypto-verify.top/auth');
  const [codeInput, setCodeInput] = useState<string>(SAMPLE_TARGETS[0].payload);
  const [networkInput, setNetworkInput] = useState<string>(
    JSON.stringify(
      {
        timestamp: "2026-11-11T13:00:00Z",
        method: "POST",
        target: "https://exfil-gaway.ru/api/v1/stats",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
          "Content-Type": "application/json",
          "Referer": "https://boutique-store-checkout.com/cart"
        },
        payload: {
          victim_origin: "https://boutique-store-checkout.com",
          captured_inputs: {
            cc_number: "4111-2222-3333-4444",
            cvv: "789",
            expiry: "11/28"
          }
        }
      },
      null,
      2
    )
  );
  const [useAi, setUseAi] = useState<boolean>(true);
  const [selectedPresetId, setSelectedPresetId] = useState<string>('phishing-trap');

  const handleSelectPreset = (preset: SampleTarget) => {
    setSelectedPresetId(preset.id);
    if (preset.type === 'url' && preset.targetUrl) {
      setActiveTab('url');
      setUrlInput(preset.targetUrl);
      setCodeInput(preset.payload);
    } else {
      setActiveTab('code');
      setCodeInput(preset.payload);
      if (preset.targetUrl) setUrlInput(preset.targetUrl);
    }
  };

  const handleRunAudit = () => {
    if (activeTab === 'url') {
      onScan('url', urlInput.trim(), useAi, urlInput.trim());
    } else if (activeTab === 'code') {
      const activePreset = SAMPLE_TARGETS.find(s => s.id === selectedPresetId);
      const label = activePreset ? activePreset.name : 'Custom Source Code';
      onScan('code', codeInput, useAi, label);
    } else {
      onScan('network', networkInput, useAi, 'Captured Network Request Log');
    }
  };

  return (
    <div className="bg-[#0b101b] border border-cyan-900/40 rounded-xl shadow-2xl p-4 lg:p-6 mb-8 relative overflow-hidden">
      {/* Decorative ambient background */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header bar of panel */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80 mb-5">
        <div>
          <h2 className="text-base font-bold font-mono tracking-wide text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
            TARGET RECONNAISSANCE CONSOLE
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Ingest live website endpoints, raw HTML/JS scripts, or telemetry packets for multi-layer forensic analysis.
          </p>
        </div>

        {/* Input Mode Selector Tabs */}
        <div className="flex items-center bg-slate-900/90 border border-slate-800 p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('code')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
              activeTab === 'code'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Raw Code / HTML</span>
          </button>

          <button
            onClick={() => setActiveTab('url')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
              activeTab === 'url'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Live URL Probe</span>
          </button>

          <button
            onClick={() => setActiveTab('network')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
              activeTab === 'network'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Network Log</span>
          </button>
        </div>
      </div>

      {/* Preset Targets Selector Bar */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Flame className="w-3 h-3 text-amber-400" />
            Forensic Preset Targets (1-Click Load):
          </span>
          <span className="text-[11px] font-mono text-cyan-400/80">Simulating Real-World Hostile Vectors</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
          {SAMPLE_TARGETS.map(preset => {
            const isSelected = selectedPresetId === preset.id;
            const badgeColor =
              preset.expectedThreatLevel === 'CRITICAL'
                ? 'border-rose-500/40 text-rose-400 bg-rose-950/20'
                : preset.expectedThreatLevel === 'HIGH'
                ? 'border-amber-500/40 text-amber-400 bg-amber-950/20'
                : 'border-emerald-500/40 text-emerald-400 bg-emerald-950/20';

            return (
              <button
                key={preset.id}
                onClick={() => handleSelectPreset(preset)}
                className={`text-left p-2.5 rounded-lg border transition-all text-xs font-mono group relative ${
                  isSelected
                    ? 'border-cyan-500/80 bg-cyan-950/30 ring-1 ring-cyan-500/50'
                    : 'border-slate-800 bg-slate-900/50 hover:border-slate-700 hover:bg-slate-900/80 text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="font-semibold text-white truncate text-[11px]">{preset.name}</span>
                  <span className={`text-[9px] px-1 py-0.2 rounded border font-mono ${badgeColor}`}>
                    {preset.expectedThreatLevel}
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 line-clamp-2 leading-relaxed">{preset.shortDesc}</p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Target Content Input Area */}
      <div className="space-y-3">
        {activeTab === 'url' && (
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5">
              TARGET URL / DOMAIN (Passive Headers & Remote Markup Interceptor):
            </label>
            <div className="relative">
              <input
                type="url"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
                placeholder="https://example.com/login"
                className="w-full bg-[#070b13] border border-cyan-800/40 rounded-lg px-4 py-3 text-sm font-mono text-cyan-300 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 pl-10"
              />
              <Globe className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3.5" />
            </div>
            <p className="text-[11px] font-mono text-slate-400 mt-1">
              Sentinel-X server will passively issue a HEAD & GET request, inspect TLS/HSTS/CSP/CORS headers, and ingest response payload without executing client-side scripts.
            </p>
          </div>
        )}

        {activeTab === 'code' && (
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-mono text-slate-300">
                SOURCE CODE / HTML / JAVASCRIPT PAYLOAD:
              </label>
              <span className="text-[11px] font-mono text-slate-500">
                {codeInput.split('\n').length} lines • {codeInput.length} characters
              </span>
            </div>
            <textarea
              rows={8}
              value={codeInput}
              onChange={e => setCodeInput(e.target.value)}
              placeholder="Paste raw HTML, JavaScript, inline trackers, or obfuscated payloads..."
              className="w-full bg-[#070b13] border border-slate-800 focus:border-cyan-500 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500/40 font-mono leading-relaxed"
              spellCheck={false}
            />
          </div>
        )}

        {activeTab === 'network' && (
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-mono text-slate-300">
                NETWORK HAR / BEACON TELEMETRY LOG (JSON FORMAT):
              </label>
              <span className="text-[11px] font-mono text-slate-500">
                {networkInput.split('\n').length} lines
              </span>
            </div>
            <textarea
              rows={8}
              value={networkInput}
              onChange={e => setNetworkInput(e.target.value)}
              placeholder="Paste network request traces, cURL output, or telemetry logs..."
              className="w-full bg-[#070b13] border border-slate-800 focus:border-cyan-500 rounded-lg p-3 text-xs font-mono text-emerald-300/90 focus:outline-none focus:ring-1 focus:ring-cyan-500/40 font-mono leading-relaxed"
              spellCheck={false}
            />
          </div>
        )}
      </div>

      {/* Control bar: AI toggle + Launch Audit */}
      <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* AI Recon toggle */}
        <div className="flex items-center gap-3">
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={useAi}
              onChange={e => setUseAi(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
            <span className="ml-3 text-xs font-mono font-medium text-slate-200 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Gemini 3.8 Flash Neural Reconnaissance</span>
            </span>
          </label>
          <span className="text-[10px] font-mono text-slate-500 hidden md:inline">
            (Combines deterministic AST engine + LLM forensic reasoning)
          </span>
        </div>

        {/* Action Button */}
        <button
          onClick={handleRunAudit}
          disabled={isScanning}
          className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(6,182,212,0.35)] transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
        >
          {isScanning ? (
            <>
              <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
              <span>INTERCEPTING & DECONSTRUCTING...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-slate-950" />
              <span>INITIALIZE FORENSIC AUDIT</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
