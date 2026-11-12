export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

export interface ThreatFinding {
  id: string;
  module: 1 | 2 | 3 | 4 | 5;
  moduleName: string;
  category: string;
  title: string;
  description: string;
  severity: RiskLevel;
  evidence?: string;
  lineNumbers?: number[];
  recommendation: string;
}

export interface ModuleFindings {
  module1_botScam: {
    templateArtifacts: string[];
    hiddenSeoKeywords: string[];
    domainTrustVerification: string[];
    score: number;
  };
  module2_trackers: {
    activeFingerprinting: string[];
    sessionRecorders: string[];
    invisiblePixelsAndCloaking: string[];
    score: number;
  };
  module3_codeSecurity: {
    obfuscatedScripts: string[];
    dataExfiltration: string[];
    exploitInjectionRisks: string[];
    score: number;
  };
  module4_network: {
    exfiltrationEndpoints: string[];
    securityHeadersFindings: string[];
    resourceAnomalies: string[];
    score: number;
  };
  module5_remediation: {
    recommendedCsp: string;
    uBlockFilterRules: string[];
    hostsBlocklist: string[];
    sanitizedCode?: string;
    cleanInstructions: string[];
  };
}

export interface AnalysisReport {
  target: string;
  targetType: 'url' | 'code' | 'network';
  timestamp: string;
  overallRiskLevel: RiskLevel;
  threatIndexScore: number; // 0 - 100
  primaryVerdict: string;
  chainOfThought: string[];
  detailedFindings: ThreatFinding[];
  moduleBreakdown: ModuleFindings;
  rawMarkdownReport: string;
  httpHeaders?: Record<string, string>;
  isAiEnhanced?: boolean;
}
