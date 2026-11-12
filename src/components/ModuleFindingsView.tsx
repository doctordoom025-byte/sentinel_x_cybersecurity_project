import React, { useState } from 'react';
import { AnalysisReport, RiskLevel, ThreatFinding } from '../types/threat';
import { 
  Bot, 
  Fingerprint, 
  FileWarning, 
  Radio, 
  ShieldCheck, 
  ChevronDown, 
  ChevronUp, 
  AlertCircle,
  Code,
  Filter,
  CheckCircle2,
  Bug
} from 'lucide-react';

interface ModuleFindingsViewProps {
  report: AnalysisReport;
}

export const ModuleFindingsView: React.FC<ModuleFindingsViewProps> = ({ report }) => {
  const [activeModuleFilter, setActiveModuleFilter] = useState<number | 'all'>('all');
  const [severityFilter, setSeverityFilter] = useState<RiskLevel | 'all'>('all');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  const toggleFinding = (id: string) => {
    setExpandedFindings(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredFindings = report.detailedFindings.filter(f => {
    if (activeModuleFilter !== 'all' && f.module !== activeModuleFilter) return false;
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    return true;
  });

  const getSeverityBadge = (severity: RiskLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      case 'LOW':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    }
  };

  return (
    <div className="space-y-6 mb-8">
      {/* Module Overview Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Module 1 */}
        <button
          onClick={() => setActiveModuleFilter(activeModuleFilter === 1 ? 'all' : 1)}
          className={`p-4 rounded-xl border text-left transition-all relative overflow-hidden font-mono cursor-pointer ${
            activeModuleFilter === 1
              ? 'border-cyan-400 bg-cyan-950/40 ring-1 ring-cyan-400'
              : 'border-slate-800 bg-[#090e18] hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-cyan-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
              <Bot className="w-3.5 h-3.5" /> MODULE 1
            </span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
              report.moduleBreakdown.module1_botScam.score > 40 ? 'bg-rose-950/40 text-rose-400 border-rose-800' : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}>
              Score: {report.moduleBreakdown.module1_botScam.score}
            </span>
          </div>
          <h4 className="text-xs font-bold text-white mb-1">Bot & Scam Signatures</h4>
          <p className="text-[11px] text-slate-400 line-clamp-2">
            Templates, SEO keyword cloaking, static fake proof seals, free host heuristics.
          </p>
        </button>

        {/* Module 2 */}
        <button
          onClick={() => setActiveModuleFilter(activeModuleFilter === 2 ? 'all' : 2)}
          className={`p-4 rounded-xl border text-left transition-all relative overflow-hidden font-mono cursor-pointer ${
            activeModuleFilter === 2
              ? 'border-cyan-400 bg-cyan-950/40 ring-1 ring-cyan-400'
              : 'border-slate-800 bg-[#090e18] hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-cyan-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
              <Fingerprint className="w-3.5 h-3.5" /> MODULE 2
            </span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
              report.moduleBreakdown.module2_trackers.score > 40 ? 'bg-rose-950/40 text-rose-400 border-rose-800' : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}>
              Score: {report.moduleBreakdown.module2_trackers.score}
            </span>
          </div>
          <h4 className="text-xs font-bold text-white mb-1">Trackers & Telemetry</h4>
          <p className="text-[11px] text-slate-400 line-clamp-2">
            Canvas/WebGL/Audio profiling, session replay (Hotjar/FullStory), 1x1 pixels.
          </p>
        </button>

        {/* Module 3 */}
        <button
          onClick={() => setActiveModuleFilter(activeModuleFilter === 3 ? 'all' : 3)}
          className={`p-4 rounded-xl border text-left transition-all relative overflow-hidden font-mono cursor-pointer ${
            activeModuleFilter === 3
              ? 'border-cyan-400 bg-cyan-950/40 ring-1 ring-cyan-400'
              : 'border-slate-800 bg-[#090e18] hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-cyan-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
              <FileWarning className="w-3.5 h-3.5" /> MODULE 3
            </span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
              report.moduleBreakdown.module3_codeSecurity.score > 40 ? 'bg-rose-950/40 text-rose-400 border-rose-800' : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}>
              Score: {report.moduleBreakdown.module3_codeSecurity.score}
            </span>
          </div>
          <h4 className="text-xs font-bold text-white mb-1">Code & Payloads</h4>
          <p className="text-[11px] text-slate-400 line-clamp-2">
            Packed eval scripts, atob decoders, DOM XSS sinks, clipjacking, Wasm cryptominers.
          </p>
        </button>

        {/* Module 4 */}
        <button
          onClick={() => setActiveModuleFilter(activeModuleFilter === 4 ? 'all' : 4)}
          className={`p-4 rounded-xl border text-left transition-all relative overflow-hidden font-mono cursor-pointer ${
            activeModuleFilter === 4
              ? 'border-cyan-400 bg-cyan-950/40 ring-1 ring-cyan-400'
              : 'border-slate-800 bg-[#090e18] hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-cyan-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5" /> MODULE 4
            </span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
              report.moduleBreakdown.module4_network.score > 40 ? 'bg-rose-950/40 text-rose-400 border-rose-800' : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}>
              Score: {report.moduleBreakdown.module4_network.score}
            </span>
          </div>
          <h4 className="text-xs font-bold text-white mb-1">Network & Requests</h4>
          <p className="text-[11px] text-slate-400 line-clamp-2">
            Data exfiltration, sendBeacon hooks, Magecart credit card skimmers, CSP/CORS.
          </p>
        </button>
      </div>

      {/* Filter and Findings Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-[#0a0f1c] border border-slate-800 p-3 rounded-lg font-mono text-xs">
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-400">Severity Filter:</span>
          <div className="flex flex-wrap gap-1.5">
            {(['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-all cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-cyan-500/30 text-cyan-200 border border-cyan-500/50'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {sev.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="text-slate-400 text-[11px]">
          Showing <span className="text-white font-bold">{filteredFindings.length}</span> of {report.detailedFindings.length} findings
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="p-8 text-center border border-slate-800/80 rounded-xl bg-[#090d18] font-mono">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <h4 className="text-sm font-semibold text-white">No Threat Vectors in Current Filter</h4>
          <p className="text-xs text-slate-400 mt-1">
            Zero anomalies matched the selected module and severity filters.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map(finding => {
            const isExpanded = expandedFindings[finding.id] ?? true;
            return (
              <div
                key={finding.id}
                className="bg-[#090e19] border border-slate-800 rounded-xl p-4 font-mono transition-all hover:border-slate-700"
              >
                <div
                  onClick={() => toggleFinding(finding.id)}
                  className="flex items-start justify-between gap-4 cursor-pointer"
                >
                  <div className="flex items-start gap-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border tracking-wider flex-shrink-0 ${getSeverityBadge(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold text-white">{finding.title}</span>
                        <span className="text-[10px] text-slate-500">[{finding.id}]</span>
                        <span className="text-[10px] px-1.5 py-0.2 bg-slate-900 text-cyan-400 border border-slate-800 rounded">
                          {finding.category}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                        {finding.description}
                      </p>
                    </div>
                  </div>

                  <button className="text-slate-500 hover:text-slate-300 p-1 flex-shrink-0">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                </div>

                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-2.5 text-xs">
                    {finding.evidence && (
                      <div className="bg-[#05080e] p-2.5 rounded border border-slate-800/80">
                        <span className="text-[10px] text-amber-400/90 font-semibold block mb-1">
                          DETECTED SYNTAX EVIDENCE:
                        </span>
                        <code className="text-rose-300/90 text-[11px] block overflow-x-auto whitespace-pre-wrap">
                          {finding.evidence}
                        </code>
                      </div>
                    )}

                    {finding.lineNumbers && finding.lineNumbers.length > 0 && (
                      <div className="text-[11px] text-slate-400">
                        <span className="text-slate-500">Trigger Lines: </span>
                        {finding.lineNumbers.map(l => (
                          <span key={l} className="inline-block px-1.5 py-0.2 bg-slate-800 text-cyan-300 rounded mr-1">
                            L{l}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="bg-emerald-950/20 border border-emerald-500/20 p-2.5 rounded">
                      <span className="text-[10px] text-emerald-400 font-semibold uppercase tracking-wider block mb-0.5">
                        Defensive Neutralization Recommendation:
                      </span>
                      <p className="text-slate-300 text-[11px]">
                        {finding.recommendation}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
