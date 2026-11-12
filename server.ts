import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { runStaticReconnaissance } from './src/services/heuristicsEngine.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const portArgIndex = process.argv.indexOf('--port');
const PORT = (portArgIndex !== -1 && process.argv[portArgIndex + 1])
  ? Number(process.argv[portArgIndex + 1])
  : 3000;

app.use(express.json({ limit: '10mb' }));

// Initialize Google GenAI client if GEMINI_API_KEY is present
let aiClient: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  aiClient = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// Health check endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'online',
    agent: 'Sentinel-X Recon Core',
    geminiAiReady: !!aiClient,
    timestamp: new Date().toISOString(),
  });
});

// Passive Remote URL Inspection API
app.post('/api/audit/url', async (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Valid URL is required.' });
    return;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
  } catch {
    res.status(400).json({ error: 'Malformed URL provided.' });
    return;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);

    const response = await fetch(parsedUrl.toString(), {
      method: 'GET',
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Sentinel-X/2.4 (Security Recon Bot)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
    });
    clearTimeout(timeout);

    // Extract relevant security headers
    const headersMap: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headersMap[key.toLowerCase()] = value;
    });

    const contentType = response.headers.get('content-type') || '';
    let bodyText = '';
    if (contentType.includes('text') || contentType.includes('json') || contentType.includes('javascript') || contentType.includes('html')) {
      const rawText = await response.text();
      bodyText = rawText.slice(0, 500000); // 500kb slice for safety
    } else {
      bodyText = `<!-- Non-text asset: Content-Type=${contentType}, HTTP Status=${response.status} -->`;
    }

    // Run deterministic multi-module analysis
    const staticReport = runStaticReconnaissance(bodyText, 'url', headersMap, parsedUrl.toString());

    res.json({
      success: true,
      statusCode: response.status,
      finalUrl: response.url,
      headers: headersMap,
      rawContentPreview: bodyText.slice(0, 40000),
      report: staticReport,
    });
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Failed to fetch target URL';
    res.status(502).json({
      error: `Passive URL probe encountered error: ${errorMsg}`,
      fallbackAnalysis: runStaticReconnaissance(url, 'url', undefined, parsedUrl.toString()),
    });
  }
});

// Deep AI Reconnaissance API using Gemini 3.8 Flash
app.post('/api/audit/gemini', async (req: Request, res: Response) => {
  const { input, targetType, targetLabel } = req.body;

  if (!input || typeof input !== 'string') {
    res.status(400).json({ error: 'Target payload is required.' });
    return;
  }

  // First generate deterministic baseline
  const baselineReport = runStaticReconnaissance(input, targetType || 'code', undefined, targetLabel);

  if (!aiClient) {
    // If no GEMINI_API_KEY configured, gracefully return the high-fidelity baseline
    res.json({
      success: true,
      report: {
        ...baselineReport,
        isAiEnhanced: false,
      },
      note: 'Analyzed using Sentinel-X Local Deterministic Reconnaissance Engine.',
    });
    return;
  }

  try {
    const systemPrompt = `You are "Sentinel-X", an elite Cybersecurity Reconnaissance AI Agent specializing in passive threat analysis, bot-generated fraud detection, fingerprinting, and tracker neutralization.
Your objective is to perform comprehensive, multi-layer security assessments on user-provided website links, raw HTML/JS code, or network request logs.

Operating Principle: Assume all untrusted web inputs are hostile, obfuscated, or evasion-oriented until mathematically and structurally proven secure.

Execute analysis systematically through the 5 detection engines:
1. BOT-GENERATED & SCAM SITE DETECTION ENGINE (Template artifacts, SEO keyword manipulation, fake static proof elements, domain/host heuristics)
2. ADVANCED TRACKER & TELEMETRY IDENTIFICATION ENGINE (Canvas, WebGL, AudioContext, Battery status, Screen parameters, Full-session replays, Keystroke hooks, 1x1 pixels, CNAME cloaking)
3. MALICIOUS CODE & OBFUSCATION ENGINE (Packed scripts, atob/eval, DOM-XSS vectors, clipjacking, cryptominers, dynamic script injections)
4. NETWORK & REQUEST AUDITING ENGINE (Data exfiltration, sendBeacon, Magecart skimmers, missing CSP/HSTS/CORS issues)
5. DEFENSIVE HARDENING & NEUTRALIZATION ENGINE (Strict CSP header, uBlock Origin filter rules, /etc/hosts blocklist, code sanitization plan)

You MUST structure your response strictly following this format:

### 🎯 THREAT ASSESSMENT OVERVIEW
- **Target URL / Asset:** [Target Link or Code Snippet]
- **Overall Risk Level:** [CRITICAL / HIGH / MEDIUM / LOW / SAFE]
- **Threat Index Score:** [0 - 100]
- **Primary Verdict:** [Concise summary of findings]

---

### 🔍 DETAILED MODULE FINDINGS

#### 1. Bot & Scam Signatures
- **Template & AI Artifacts:** [Findings]
- **Hidden SEO / Keyword Stuffing:** [Findings]
- **Domain & Trust Verification:** [Findings]

#### 2. Trackers & Telemetry
- **Active Fingerprinting:** [Findings]
- **Session Recorders & Analytics:** [Findings]
- **Invisible Pixels / CNAME Cloaking:** [Findings]

#### 3. Code Security & Malicious Payloads
- **Obfuscated / Packed Scripts:** [Findings]
- **Data Exfiltration & Keylogging:** [Findings]
- **Exploit & Injection Risks:** [Findings]

#### 4. Network & Request Auditing
- **Exfiltration & Skimmers:** [Findings]
- **Security Headers & CORS:** [Findings]

---

### 🛡️ REMEDIATION & NEUTRALIZATION PLAN

#### Recommended Content Security Policy (CSP) Header
\`\`\`http
[Content Security Policy here]
\`\`\`

#### Browser Extension Neutralization Rules (uBlock Origin / AdGuard)
\`\`\`adblock
[Adblock rules here]
\`\`\`

#### Host-Level Network Blocklist (/etc/hosts)
\`\`\`hosts
[Hosts blocking rules here]
\`\`\`

#### Actionable Hardening Checklist
[Bullet list of concrete remediations]
`;

    const userPrompt = `Perform an aggressive, comprehensive Sentinel-X forensic audit on the following target (${targetType || 'code'}):
Target Identifier: ${targetLabel || 'User Input'}

Input Payload:
\`\`\`
${input.slice(0, 15000)}
\`\`\`

Baseline Static Signatures Detected:
- Overall Score: ${baselineReport.threatIndexScore}/100 [${baselineReport.overallRiskLevel}]
- Findings count: ${baselineReport.detailedFindings.length}
- Primary heuristic triggers: ${baselineReport.detailedFindings.map(f => f.title).join(', ') || 'None'}

Produce the complete forensic report according to the Sentinel-X Output Schema.`;

    const aiResponse = await aiClient.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: userPrompt,
      config: {
        systemInstruction: systemPrompt,
      },
    });

    const markdownText = aiResponse.text || baselineReport.rawMarkdownReport;

    // Parse Risk Level and Score from AI output if available
    let aiRiskLevel = baselineReport.overallRiskLevel;
    let aiScore = baselineReport.threatIndexScore;
    let aiVerdict = baselineReport.primaryVerdict;

    const riskMatch = markdownText.match(/\*\*Overall Risk Level:\*\*\s*(CRITICAL|HIGH|MEDIUM|LOW|SAFE)/i);
    if (riskMatch) {
      aiRiskLevel = riskMatch[1].toUpperCase() as any;
    }
    const scoreMatch = markdownText.match(/\*\*Threat Index Score:\*\*\s*(\d{1,3})/i);
    if (scoreMatch) {
      aiScore = parseInt(scoreMatch[1], 10);
    }
    const verdictMatch = markdownText.match(/\*\*Primary Verdict:\*\*\s*(.+)/i);
    if (verdictMatch) {
      aiVerdict = verdictMatch[1].trim();
    }

    res.json({
      success: true,
      report: {
        ...baselineReport,
        overallRiskLevel: aiRiskLevel,
        threatIndexScore: aiScore,
        primaryVerdict: aiVerdict,
        rawMarkdownReport: markdownText,
        isAiEnhanced: true,
      },
    });
  } catch (err: unknown) {
    console.error('Gemini AI Recon error:', err);
    // Graceful fallback to static report
    res.json({
      success: true,
      report: {
        ...baselineReport,
        isAiEnhanced: false,
      },
      warning: 'AI Recon experienced latency; provided full deterministic analysis.',
    });
  }
});

// Setup Vite in Dev mode or Static in Production
async function startServer() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  VITE v8.3.0  ready in 150 ms\n`);
    console.log(`  ➜  Local:   http://localhost:${PORT}/`);
    console.log(`  ➜  Network: http://0.0.0.0:${PORT}/`);
    console.log(`[SENTINEL-X] Recon Core Server online on port ${PORT}\n`);
  });
}

startServer().catch(err => {
  console.error('[SENTINEL-X] Server initialization failed:', err);
});
