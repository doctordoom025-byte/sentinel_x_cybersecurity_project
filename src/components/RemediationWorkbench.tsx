import React, { useState } from 'react';
import { AnalysisReport } from '../types/threat';
import { 
  ShieldCheck, 
  Copy, 
  Check, 
  FileCode, 
  Terminal, 
  ExternalLink, 
  Sliders, 
  Sparkles,
  Layers,
  Code2
} from 'lucide-react';

interface RemediationWorkbenchProps {
  report: AnalysisReport;
}

export const RemediationWorkbench: React.FC<RemediationWorkbenchProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'csp' | 'adblock' | 'hosts' | 'code'>('csp');
  const [copiedType, setCopiedType] = useState<string | null>(null);

  const remediation = report.moduleBreakdown.module5_remediation;

  const handleCopy = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const cspDirectives = [
    { directive: "default-src 'self'", description: "Restricts all unclassified resource fetches strictly to the first-party origin." },
    { directive: "script-src 'self' 'strict-dynamic'", description: "Prohibits unauthorized third-party scripts, unsafe-inline injections, and raw string evals." },
    { directive: "style-src 'self' 'unsafe-inline'", description: "Constrains stylesheet resources while permitting vetted UI rendering." },
    { directive: "connect-src 'self'", description: "Crucial Magecart defense: immediately aborts unauthorized fetch(), XHR, and sendBeacon() data exfiltration channels." },
    { directive: "frame-ancestors 'none'", description: "Renders the web page immune to iframe clickjacking and UI redressing attacks." },
    { directive: "base-uri 'self'", description: "Prevents <base> tag injection attacks that redirect relative script and asset resolutions." },
    { directive: "form-action 'self'", description: "Guarantees form inputs cannot be submitted to external harvest gates or phishing drop endpoints." },
    { directive: "upgrade-insecure-requests", description: "Instructs client browsers to transparently upgrade all legacy HTTP asset requests to secure HTTPS." },
  ];

  return (
    <div className="bg-[#0b101b] border border-emerald-500/30 rounded-xl p-5 mb-8 font-mono shadow-2xl relative overflow-hidden">
      {/* Decorative accent */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800 mb-5">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              MODULE 5: DEFENSIVE HARDENING & NEUTRALIZATION ENGINE
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Actionable counter-measures, cryptographic CSP headers, browser filter rules, and code sanitization blueprints.
          </p>
        </div>

        {/* Tab switcher */}
        <div className="flex flex-wrap items-center bg-slate-900 border border-slate-800 p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('csp')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'csp' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Strict CSP
          </button>
          <button
            onClick={() => setActiveTab('adblock')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'adblock' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            uBlock / AdGuard Rules
          </button>
          <button
            onClick={() => setActiveTab('hosts')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'hosts' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            /etc/hosts Quarantine
          </button>
          <button
            onClick={() => setActiveTab('code')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'code' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Sanitized Code
          </button>
        </div>
      </div>

      {/* Content Panes */}

      {/* TAB 1: STRICT CSP */}
      {activeTab === 'csp' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-300 font-semibold">
              RECOMMENDED PRODUCTION HTTP RESPONSE HEADER:
            </span>
            <button
              onClick={() => handleCopy(remediation.recommendedCsp, 'csp')}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:text-white text-xs transition-all cursor-pointer"
            >
              {copiedType === 'csp' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedType === 'csp' ? 'Copied CSP' : 'Copy Header'}</span>
            </button>
          </div>

          <div className="bg-[#060910] border border-slate-800 p-4 rounded-lg overflow-x-auto text-emerald-300 text-xs leading-relaxed select-all">
            {remediation.recommendedCsp}
          </div>

          <div>
            <h4 className="text-xs font-bold text-white mb-2 uppercase tracking-wider text-slate-400">
              Directive Defensive Threat Mapping:
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
              {cspDirectives.map((d, i) => (
                <div key={i} className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80">
                  <code className="text-cyan-300 text-[11px] block font-bold mb-1">{d.directive}</code>
                  <p className="text-slate-400 text-[11px] leading-relaxed">{d.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: UBLOCK / ADGUARD RULES */}
      {activeTab === 'adblock' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-300 font-semibold block">
                BROWSER EXTENSION BLOCKING RULES (uBlock Origin / AdGuard Syntax):
              </span>
              <span className="text-[11px] text-slate-500">
                Paste these rules into your browser extension's "My Filters" panel.
              </span>
            </div>
            <button
              onClick={() => handleCopy(remediation.uBlockFilterRules.join('\n'), 'adblock')}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:text-white text-xs transition-all cursor-pointer"
            >
              {copiedType === 'adblock' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedType === 'adblock' ? 'Copied Rules' : 'Copy Filter List'}</span>
            </button>
          </div>

          <div className="bg-[#060910] border border-slate-800 p-4 rounded-lg overflow-x-auto font-mono text-cyan-300 text-xs leading-relaxed whitespace-pre select-all max-h-72">
{remediation.uBlockFilterRules.join('\n')}
          </div>

          <div className="p-3 rounded bg-slate-900/70 border border-slate-800 text-xs text-slate-400">
            <strong className="text-white block mb-1">Installation Guide:</strong>
            1. Open uBlock Origin Dashboard &rarr; 2. Navigate to "My Filters" tab &rarr; 3. Paste the rules above &rarr; 4. Click "Apply Changes".
          </div>
        </div>
      )}

      {/* TAB 3: HOSTS BLOCKLIST */}
      {activeTab === 'hosts' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-300 font-semibold block">
                SYSTEM HOSTS NULL-ROUTING BLOCKLIST (/etc/hosts or C:\Windows\System32\drivers\etc\hosts):
              </span>
              <span className="text-[11px] text-slate-500">
                Routes malicious exfiltration servers directly to 0.0.0.0 at the operating system network stack.
              </span>
            </div>
            <button
              onClick={() => handleCopy(remediation.hostsBlocklist.join('\n'), 'hosts')}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:text-white text-xs transition-all cursor-pointer"
            >
              {copiedType === 'hosts' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedType === 'hosts' ? 'Copied Hosts' : 'Copy Blocklist'}</span>
            </button>
          </div>

          <div className="bg-[#060910] border border-slate-800 p-4 rounded-lg overflow-x-auto font-mono text-amber-300 text-xs leading-relaxed whitespace-pre select-all max-h-72">
{`# Sentinel-X Hostile Domain Quarantine
# Generated at: ${report.timestamp}
${remediation.hostsBlocklist.join('\n')}`}
          </div>
        </div>
      )}

      {/* TAB 4: SANITIZED CODE STUDIO */}
      {activeTab === 'code' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-300 font-semibold block">
                SENTINEL-X SANITIZED CODE BLUEPRINT:
              </span>
              <span className="text-[11px] text-slate-500">
                Harmful sinks, eval packers, canvas fingerprints, and beacon exfiltrators neutralized with safe stubs.
              </span>
            </div>
            <button
              onClick={() => handleCopy(remediation.sanitizedCode || '', 'code')}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:text-white text-xs transition-all cursor-pointer"
            >
              {copiedType === 'code' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedType === 'code' ? 'Copied Clean Code' : 'Copy Sanitized Code'}</span>
            </button>
          </div>

          <div className="bg-[#060910] border border-slate-800 p-4 rounded-lg overflow-x-auto font-mono text-slate-300 text-xs leading-relaxed whitespace-pre select-all max-h-96">
            {remediation.sanitizedCode || '// No code payload provided to sanitize.'}
          </div>

          {/* Hardening checklist */}
          <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2">
              Actionable Code Remediation Steps:
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-300">
              {remediation.cleanInstructions.map((instruction, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-emerald-400 font-bold">•</span>
                  <span>{instruction}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
