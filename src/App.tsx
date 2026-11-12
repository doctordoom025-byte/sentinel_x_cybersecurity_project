import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { TargetInputPanel } from './components/TargetInputPanel';
import { ThreatOverviewCard } from './components/ThreatOverviewCard';
import { ModuleFindingsView } from './components/ModuleFindingsView';
import { RemediationWorkbench } from './components/RemediationWorkbench';
import { TerminalLogView } from './components/TerminalLogView';
import { ReportModal } from './components/ReportModal';
import { runStaticReconnaissance } from './services/heuristicsEngine';
import { SAMPLE_TARGETS } from './data/sampleThreats';
import { AnalysisReport } from './types/threat';
import { 
  ShieldAlert, 
  Layers, 
  ShieldCheck, 
  TerminalSquare, 
  Sliders, 
  Radar, 
  FileCode,
  Lock,
  Cpu
} from 'lucide-react';

export default function App() {
  // Initialize with the Phishing Trap scenario
  const [report, setReport] = useState<AnalysisReport>(() => {
    return runStaticReconnaissance(
      SAMPLE_TARGETS[0].payload,
      'code',
      undefined,
      SAMPLE_TARGETS[0].name
    );
  });

  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'remediation' | 'terminal'>('overview');
  const [isScanning, setIsScanning] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [serverOnline, setServerOnline] = useState(false);
  const [aiAvailable, setAiAvailable] = useState(false);
  const [logs, setLogs] = useState<string[]>([
    '[INIT] Sentinel-X Cyber Reconnaissance Engine initialized.',
    '[MODULE 1-5] Heuristic signature banks loaded: 42 rule sets active.',
    '[SCAN] Initialized baseline audit on Phishing Trap & AI Scraper Portal preset.',
    '[VERDICT] Assigned Threat Index Score: 92/100 [CRITICAL]. Hostile markers confirmed.',
  ]);

  // Ping backend on mount to check server and Gemini status
  useEffect(() => {
    const checkServer = async () => {
      try {
        const res = await fetch('/api/health');
        if (res.ok) {
          const data = await res.json();
          setServerOnline(true);
          setAiAvailable(!!data.geminiAiReady);
          setLogs(prev => [
            ...prev,
            `[SYS] Server connected: ${data.agent}. Gemini Core: ${data.geminiAiReady ? 'ONLINE' : 'HEURISTICS ONLY'}`
          ]);
        }
      } catch {
        setServerOnline(false);
      }
    };
    checkServer();
  }, []);

  const handleRunAudit = async (
    type: 'url' | 'code' | 'network',
    input: string,
    useAi: boolean,
    label?: string
  ) => {
    setIsScanning(true);
    const targetLabel = label || (type === 'url' ? input : 'Custom Source Code');

    setLogs(prev => [
      `\n------------------------------------------------------------`,
      `[TASK] New Recon Task Dispatched: Target=${targetLabel} [Type=${type.toUpperCase()}]`,
      `[STEP 1] Initializing Passive Reconnaissance Matrix & AST tokenizers...`,
    ]);

    try {
      let finalReport: AnalysisReport;

      if (type === 'url') {
        setLogs(prev => [...prev, `[STEP 2] Dispatching passive HTTP/TLS probe to ${input}...`]);
        try {
          const urlRes = await fetch('/api/audit/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: input }),
          });

          if (urlRes.ok) {
            const data = await urlRes.json();
            setLogs(prev => [
              ...prev,
              `[STEP 3] Response received: HTTP ${data.statusCode}. Captured ${Object.keys(data.headers).length} response headers.`,
              `[STEP 4] Executing static AST & behavioral heuristics across 5 engines...`
            ]);
            finalReport = data.report;
          } else {
            setLogs(prev => [
              ...prev,
              `[WARN] Remote fetch returned status error; executing client-side URL & syntactic audit...`
            ]);
            finalReport = runStaticReconnaissance(input, 'url', undefined, targetLabel);
          }
        } catch {
          setLogs(prev => [
            ...prev,
            `[WARN] Server unreachable; executing client-side URL & syntactic audit...`
          ]);
          finalReport = runStaticReconnaissance(input, 'url', undefined, targetLabel);
        }
      } else {
        setLogs(prev => [
          ...prev,
          `[STEP 2] Running deterministic AST, regex, and behavioral heuristics across Modules 1-5...`
        ]);
        finalReport = runStaticReconnaissance(input, type, undefined, targetLabel);
      }

      // If AI reasoning is requested, query Gemini 3.8 Flash endpoint
      if (useAi) {
        setLogs(prev => [
          ...prev,
          `[STEP 3] Querying Gemini 3.8 Flash Neural Reconnaissance Engine for deep threat reasoning...`
        ]);

        try {
          const aiRes = await fetch('/api/audit/gemini', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              input,
              targetType: type,
              targetLabel,
            }),
          });

          if (aiRes.ok) {
            const aiData = await aiRes.json();
            if (aiData.report) {
              finalReport = aiData.report;
              setLogs(prev => [
                ...prev,
                `[STEP 4] Neural analysis synthesized. Threat verdict refined by Gemini 3.8 Flash.`
              ]);
            }
          }
        } catch (e) {
          console.warn('AI endpoint fallback', e);
          setLogs(prev => [
            ...prev,
            `[NOTE] AI connection timed out; deterministic heuristic report utilized.`
          ]);
        }
      }

      setLogs(prev => [
        ...prev,
        `[AUDIT COMPLETE] Threat Index: ${finalReport.threatIndexScore}/100 [${finalReport.overallRiskLevel}]`,
        `[MODULE 5] Strict Content Security Policy & uBlock rules generated.`,
      ]);

      setReport(finalReport);
    } catch (err: unknown) {
      const errStr = err instanceof Error ? err.message : 'Unknown error';
      setLogs(prev => [...prev, `[ERROR] Forensic scan encountered exception: ${errStr}`]);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#06090e] text-slate-100 cyber-grid flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Cyber Telemetry Header */}
      <Header
        isScanning={isScanning}
        threatCount={report.detailedFindings.length}
        serverOnline={serverOnline}
        aiReady={aiAvailable}
      />

      {/* Main Body Container */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 lg:px-8 py-6">
        {/* Target Ingestion & Scan Console */}
        <TargetInputPanel
          onScan={handleRunAudit}
          isScanning={isScanning}
          aiAvailable={aiAvailable}
        />

        {/* Threat Assessment Overview Banner */}
        <ThreatOverviewCard
          report={report}
          onOpenReportModal={() => setIsModalOpen(true)}
          onSelectTab={tab => setActiveTab(tab)}
        />

        {/* Navigation Tabs for Analysis View */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2 mb-6 font-mono text-xs overflow-x-auto">
          <button
            onClick={() => setActiveTab('overview')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg font-bold transition-all cursor-pointer ${
              activeTab === 'overview'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <Radar className="w-3.5 h-3.5" />
            <span>Overview & Breakdown</span>
          </button>

          <button
            onClick={() => setActiveTab('findings')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg font-bold transition-all cursor-pointer ${
              activeTab === 'findings'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Detailed Module Findings ({report.detailedFindings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('remediation')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg font-bold transition-all cursor-pointer ${
              activeTab === 'remediation'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <Sliders className="w-3.5 h-3.5 text-emerald-400" />
            <span>Remediation & CSP (Module 5)</span>
          </button>

          <button
            onClick={() => setActiveTab('terminal')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg font-bold transition-all cursor-pointer ${
              activeTab === 'terminal'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <TerminalSquare className="w-3.5 h-3.5" />
            <span>Terminal & Chain-of-Thought</span>
          </button>
        </div>

        {/* Tab View Contents */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <ModuleFindingsView report={report} />
            <RemediationWorkbench report={report} />
            <TerminalLogView logs={logs} isScanning={isScanning} />
          </div>
        )}

        {activeTab === 'findings' && (
          <ModuleFindingsView report={report} />
        )}

        {activeTab === 'remediation' && (
          <RemediationWorkbench report={report} />
        )}

        {activeTab === 'terminal' && (
          <TerminalLogView logs={logs} isScanning={isScanning} />
        )}
      </main>

      {/* Full Structured Markdown Report Modal */}
      <ReportModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        report={report}
      />

      {/* Tactical Footer */}
      <footer className="border-t border-slate-900 bg-[#050810] px-4 py-4 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>Sentinel-X Passive Reconnaissance Engine</span>
            <span>•</span>
            <span>Zero Offensive Weaponry • Defensive Hardening Standard</span>
          </div>
          <div>
            Built with Google GenAI SDK (`gemini-3.8-flash`) & Deterministic AST Heuristics
          </div>
        </div>
      </footer>
    </div>
  );
}
