import React, { useState } from 'react';
import { AnalysisReport, RiskLevel } from '../types/threat';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  ShieldX, 
  Copy, 
  Check, 
  FileCode, 
  Download, 
  Sparkles,
  ExternalLink,
  Sliders,
  TerminalSquare
} from 'lucide-react';

interface ThreatOverviewCardProps {
  report: AnalysisReport;
  onOpenReportModal: () => void;
  onSelectTab: (tab: 'overview' | 'findings' | 'remediation' | 'terminal') => void;
}

export const ThreatOverviewCard: React.FC<ThreatOverviewCardProps> = ({
  report,
  onOpenReportModal,
  onSelectTab,
}) => {
  const [copied, setCopied] = useState(false);

  const getRiskStyles = (level: RiskLevel) => {
    switch (level) {
      case 'CRITICAL':
        return {
          border: 'border-rose-500/60 shadow-[0_0_35px_rgba(244,63,94,0.25)]',
          bg: 'bg-rose-950/20',
          badgeBg: 'bg-rose-500/20 border-rose-500/40 text-rose-300',
          text: 'text-rose-400',
          gaugeColor: '#f43f5e',
          icon: ShieldAlert,
          label: 'CRITICAL THREAT',
        };
      case 'HIGH':
        return {
          border: 'border-amber-500/60 shadow-[0_0_35px_rgba(245,158,11,0.25)]',
          bg: 'bg-amber-950/20',
          badgeBg: 'bg-amber-500/20 border-amber-500/40 text-amber-300',
          text: 'text-amber-400',
          gaugeColor: '#f59e0b',
          icon: AlertTriangle,
          label: 'HIGH RISK',
        };
      case 'MEDIUM':
        return {
          border: 'border-yellow-500/60 shadow-[0_0_30px_rgba(234,179,8,0.2)]',
          bg: 'bg-yellow-950/20',
          badgeBg: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300',
          text: 'text-yellow-400',
          gaugeColor: '#eab308',
          icon: AlertTriangle,
          label: 'MEDIUM RISK',
        };
      case 'LOW':
        return {
          border: 'border-cyan-500/60 shadow-[0_0_30px_rgba(6,182,212,0.2)]',
          bg: 'bg-cyan-950/20',
          badgeBg: 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300',
          text: 'text-cyan-400',
          gaugeColor: '#06b6d4',
          icon: ShieldCheck,
          label: 'LOW EXPOSURE',
        };
      case 'SAFE':
      default:
        return {
          border: 'border-emerald-500/60 shadow-[0_0_35px_rgba(16,185,129,0.25)]',
          bg: 'bg-emerald-950/20',
          badgeBg: 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300',
          text: 'text-emerald-400',
          gaugeColor: '#10b981',
          icon: ShieldCheck,
          label: 'MATHEMATICALLY SECURE',
        };
    }
  };

  const style = getRiskStyles(report.overallRiskLevel);
  const IconComponent = style.icon;

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(report.rawMarkdownReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sentinel-x-audit-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // SVG Gauge Calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (report.threatIndexScore / 100) * circumference;

  return (
    <div className={`rounded-xl border ${style.border} ${style.bg} p-6 mb-8 transition-all relative overflow-hidden backdrop-blur-md`}>
      {/* Background cyber accent */}
      <div className="absolute top-0 right-0 w-80 h-80 rounded-full opacity-10 pointer-events-none" style={{ backgroundColor: style.gaugeColor }} />

      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
        {/* Left: Gauge and Threat Score */}
        <div className="flex items-center gap-6">
          <div className="relative flex items-center justify-center w-32 h-32 flex-shrink-0">
            <svg className="w-32 h-32 -rotate-90 transform">
              <circle
                cx="64"
                cy="64"
                r={radius}
                className="stroke-slate-800"
                strokeWidth="10"
                fill="transparent"
              />
              <circle
                cx="64"
                cy="64"
                r={radius}
                stroke={style.gaugeColor}
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-1000 ease-out"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-black font-mono tracking-tight text-white">
                {report.threatIndexScore}
              </span>
              <span className="text-[10px] font-mono tracking-widest text-slate-400 uppercase">
                / 100
              </span>
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold tracking-wider uppercase border ${style.badgeBg}`}>
                <IconComponent className="w-3.5 h-3.5" />
                {report.overallRiskLevel}
              </span>

              {report.isAiEnhanced && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-950/80 border border-cyan-500/40 text-cyan-300">
                  <Sparkles className="w-3 h-3 text-cyan-400" />
                  NEURAL VERIFIED
                </span>
              )}
            </div>

            <h3 className="text-xl font-bold font-mono tracking-tight text-white mb-1">
              {style.label}
            </h3>

            <p className="text-xs font-mono text-slate-300 max-w-xl leading-relaxed">
              <strong className="text-white">Primary Verdict:</strong> {report.primaryVerdict}
            </p>

            <div className="flex flex-wrap items-center gap-3 mt-3 text-xs font-mono text-slate-400">
              <span className="flex items-center gap-1 text-slate-300">
                <span className="text-slate-500">Asset:</span>
                <span className="truncate max-w-[240px] text-cyan-300 font-semibold" title={report.target}>
                  {report.target}
                </span>
              </span>
              <span>•</span>
              <span>Findings: <strong className="text-white">{report.detailedFindings.length}</strong></span>
              <span>•</span>
              <span>Timestamp: <strong className="text-slate-300">{new Date(report.timestamp).toLocaleTimeString()}</strong></span>
            </div>
          </div>
        </div>

        {/* Right: Quick Action Buttons */}
        <div className="flex flex-wrap lg:flex-col gap-2 w-full lg:w-auto flex-shrink-0">
          <button
            onClick={onOpenReportModal}
            className="flex-1 lg:flex-none flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-semibold transition-all shadow-sm cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Full Structured Report</span>
          </button>

          <button
            onClick={() => onSelectTab('remediation')}
            className="flex-1 lg:flex-none flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-semibold transition-all shadow-sm cursor-pointer"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Remediation & CSP (Module 5)</span>
          </button>

          <button
            onClick={handleCopyMarkdown}
            className="flex-1 lg:flex-none flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono font-medium transition-all cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied Markdown' : 'Copy Schema Markdown'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="flex-1 lg:flex-none flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 text-xs font-mono transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON Audit</span>
          </button>
        </div>
      </div>
    </div>
  );
};
