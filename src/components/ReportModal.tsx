import React, { useState } from 'react';
import { AnalysisReport } from '../types/threat';
import { X, Copy, Check, Download, FileText } from 'lucide-react';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: AnalysisReport;
}

export const ReportModal: React.FC<ReportModalProps> = ({ isOpen, onClose, report }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(report.rawMarkdownReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const element = document.createElement('a');
    const file = new Blob([report.rawMarkdownReport], { type: 'text/markdown' });
    element.href = URL.createObjectURL(file);
    element.download = `sentinel-x-audit-report-${Date.now()}.md`;
    document.body.appendChild(element);
    element.click();
    element.remove();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#080d1a] border border-cyan-800/60 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col font-mono relative overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#060913]">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              SENTINEL-X STRUCTURED FORENSIC REPORT
            </h3>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-900/80 text-xs font-semibold transition-all cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied Markdown' : 'Copy Report'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white text-xs transition-all cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .md</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all cursor-pointer ml-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs leading-relaxed text-slate-300 bg-[#050810]">
          <pre className="font-mono text-xs whitespace-pre-wrap select-all text-slate-200">
            {report.rawMarkdownReport}
          </pre>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-[#060913] flex items-center justify-between text-[11px] text-slate-500">
          <span>Schema format: Sentinel-X Standard Reconnaissance Blueprint</span>
          <span className="text-cyan-400">Threat Index: {report.threatIndexScore}/100 [{report.overallRiskLevel}]</span>
        </div>
      </div>
    </div>
  );
};
