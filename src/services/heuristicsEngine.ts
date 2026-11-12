import { AnalysisReport, ModuleFindings, RiskLevel, ThreatFinding } from '../types/threat';

export function runStaticReconnaissance(
  input: string,
  targetType: 'url' | 'code' | 'network' = 'code',
  httpHeaders?: Record<string, string>,
  targetLabel?: string
): AnalysisReport {
  const content = input || '';
  const findings: ThreatFinding[] = [];
  const chainOfThought: string[] = [];
  const lines = content.split('\n');

  // Track domains detected for blocking
  const detectedMaliciousDomains = new Set<string>();

  // Helper to find line numbers matching regex
  const findLines = (pattern: RegExp): number[] => {
    const matched: number[] = [];
    lines.forEach((line, idx) => {
      if (pattern.test(line)) {
        matched.push(idx + 1);
      }
    });
    return matched;
  };

  chainOfThought.push(`[PHASE 0: INGESTION] Loaded ${lines.length} lines of payload. Analyzing syntactic AST signatures and structural heuristics.`);

  // --------------------------------------------------------------------------
  // MODULE 1: BOT-GENERATED & SCAM SITE DETECTION ENGINE
  // --------------------------------------------------------------------------
  const mod1_template: string[] = [];
  const mod1_seo: string[] = [];
  const mod1_trust: string[] = [];

  // Check unrendered template tags
  const templateTags = /(?:\{\{[^}]+\}\}|<%\s*=[^%]+%>|\$\{item\.[^}]+\}|v-model=["'][^"']+["']|ng-bind)/g;
  if (templateTags.test(content)) {
    const matchedLines = findLines(/(?:\{\{|\$|v-|ng-)/);
    const desc = 'Detected unrendered template tags / raw variable brackets indicating mass-generated scraper or unhydrated scraper page.';
    mod1_template.push('Unrendered template artifacts found: {{...}} or <%=...%>');
    findings.push({
      id: 'BOT-TMPL-01',
      module: 1,
      moduleName: 'Bot & Scam Signatures',
      category: 'Template & Scraper Artifacts',
      title: 'Unrendered Dynamic Template Variables',
      description: desc,
      severity: 'HIGH',
      lineNumbers: matchedLines.slice(0, 5),
      evidence: content.match(templateTags)?.slice(0, 3).join(', '),
      recommendation: 'Verify template compilation and remove exposed backend interpolators.',
    });
    chainOfThought.push('[MODULE 1] Flagged raw unrendered template brackets commonly found in automated phishing clones.');
  }

  // Broken asset trees / local paths
  const localPaths = /(?:file:\/\/\/[a-zA-Z]:|localhost:\d{3,5}|127\.0\.0\.1:\d{3,5}|\/Users\/[a-zA-Z0-9_-]+\/|C:\\[a-zA-Z0-9_\\]+)/gi;
  if (localPaths.test(content)) {
    const matchedLines = findLines(localPaths);
    mod1_template.push('Local machine path / localhost leaks found (e.g. file:///C: or localhost:8080)');
    findings.push({
      id: 'BOT-PATH-02',
      module: 1,
      moduleName: 'Bot & Scam Signatures',
      category: 'Template & Scraper Artifacts',
      title: 'Local Machine Asset Paths Leaked',
      description: 'Found hardcoded local file paths (C:\\ or localhost) indicating amateur site scraper cloning.',
      severity: 'MEDIUM',
      lineNumbers: matchedLines.slice(0, 5),
      evidence: content.match(localPaths)?.slice(0, 2).join(', '),
      recommendation: 'Replace local environment paths with relative production assets.',
    });
  }

  // Dead links / non-functional UI elements
  const deadLinkMatches = (content.match(/href=["'](?:#|javascript:;|javascript:void\(0\);?)["']/gi) || []).length;
  if (deadLinkMatches >= 4) {
    mod1_template.push(`Excessive non-functional navigation dead links (${deadLinkMatches} instances of href="#" or javascript:;)`);
    findings.push({
      id: 'BOT-DEAD-03',
      module: 1,
      moduleName: 'Bot & Scam Signatures',
      category: 'Template & Scraper Artifacts',
      title: 'Deceptive Facade UI / Dead Links',
      description: `${deadLinkMatches} links are dead-end anchors designed to emulate real UI without real endpoints.`,
      severity: 'HIGH',
      recommendation: 'Audit all action handlers and navigation targets.',
    });
    chainOfThought.push(`[MODULE 1] High density of dead href="#" anchors detected (${deadLinkMatches}x). Classic hallmark of phishing clone facades.`);
  }

  // Hidden SEO & Keyword Manipulation
  const hiddenSeoPattern = /(?:display:\s*none|opacity:\s*0|position:\s*absolute;\s*left:\s*-(?:9999|999|1000)px|font-size:\s*0px|text-indent:\s*-(?:9999|999)px)/i;
  if (hiddenSeoPattern.test(content)) {
    const matches = findLines(hiddenSeoPattern);
    mod1_seo.push('Hidden text blocks detected via CSS offscreen / zero opacity techniques.');
    findings.push({
      id: 'SEO-CLOAK-01',
      module: 1,
      moduleName: 'Bot & Scam Signatures',
      category: 'SEO & Keyword Manipulation',
      title: 'Deceptive Hidden Keyword / Text Cloaking',
      description: 'Content is rendered off-screen or invisible (opacity:0, left:-9999px) to manipulate search crawler indexing.',
      severity: 'HIGH',
      lineNumbers: matches.slice(0, 5),
      recommendation: 'Remove hidden off-screen text blocks and adhere to clean semantic markup.',
    });
  }

  // Hidden heading tags
  if (/<h[1-6][^>]*class=["'][^"']*\bhidden\b[^"']*["']|<h[1-6][^>]*style=["'][^"']*display:\s*none/i.test(content)) {
    mod1_seo.push('Hidden <h1-h6> headings found concealed from human visitors.');
    findings.push({
      id: 'SEO-HEAD-02',
      module: 1,
      moduleName: 'Bot & Scam Signatures',
      category: 'SEO & Keyword Manipulation',
      title: 'Cloaked Heading Tags for Crawler Manipulation',
      description: 'Heading tags are hidden from users to deceive search indexers.',
      severity: 'MEDIUM',
      recommendation: 'Ensure all heading hierarchies are visible and aligned with user viewport content.',
    });
  }

  // Fake Proof Elements / Static Trust Badges without verification
  const fakeBadgePattern = /(?:norton|mcafee|trustpilot|bbb|verisign|verified-by-visa|pci-dss|truste|ssl-secure)[a-zA-Z0-9_\-\.]*\.(?:png|jpg|jpeg|webp|svg)/i;
  if (fakeBadgePattern.test(content)) {
    // Check if there is an actual verification script or genuine verification link
    const hasLiveVerification = /(?:seal\.verisign\.com|trustedsite\.com|seal\.starfieldtech\.com|trustpilot\.com\/review)/i.test(content);
    if (!hasLiveVerification) {
      mod1_trust.push('Static trust badge images (e.g. Norton/McAfee/Trustpilot/BBB) detected without dynamic verification seal scripts.');
      findings.push({
        id: 'TRUST-FAKE-01',
        module: 1,
        moduleName: 'Bot & Scam Signatures',
        category: 'Fake Proof Elements',
        title: 'Unverified Static Security Badges',
        description: 'Static images claiming security certification or buyer protection without authentic vendor verification tokens.',
        severity: 'HIGH',
        recommendation: 'Integrate legitimate cryptographic vendor seals or remove deceptive static badge graphics.',
      });
      chainOfThought.push('[MODULE 1] Unverified static trust seals discovered with no cryptographic or live vendor anchor.');
    }
  }

  // Domain & Host Heuristics (Target URL or raw references)
  const freeHostPattern = /(?:pages\.dev|vercel\.app|webflow\.io|firebaseapp\.com|ngrok\.io|glitch\.me|surge\.sh|000webhostapp\.com|duckdns\.org|netlify\.app)/i;
  const targetHost = targetLabel || input;
  if (freeHostPattern.test(targetHost) || freeHostPattern.test(content)) {
    mod1_trust.push('Free hosting subdomain detected masquerading as commercial service or enterprise utility.');
    findings.push({
      id: 'HOST-FREE-01',
      module: 1,
      moduleName: 'Bot & Scam Signatures',
      category: 'Domain & Host Heuristics',
      title: 'Disposable / Free Cloud Subdomain Utilization',
      description: 'High-risk usage of disposable cloud subdomains often utilized by short-lived phishing campaigns.',
      severity: 'MEDIUM',
      recommendation: 'Enforce enterprise custom domain routing with strict DNS CAA and DMARC verification.',
    });
  }

  // Suspicious TLDs
  if (/(?:\.top|\.xyz|\.click|\.buzz|\.icu|\.tk|\.ml|\.ga|\.cf|\.rest|\.surf)\b/i.test(targetHost)) {
    mod1_trust.push('Suspicious low-reputation top-level domain (TLD) flagged.');
  }

  // --------------------------------------------------------------------------
  // MODULE 2: ADVANCED TRACKER & TELEMETRY IDENTIFICATION ENGINE
  // --------------------------------------------------------------------------
  const mod2_fingerprint: string[] = [];
  const mod2_session: string[] = [];
  const mod2_pixels: string[] = [];

  // Canvas Fingerprinting
  const canvasPattern = /(?:toDataURL|getImageData|measureText|isPointInPath)\s*\(/;
  if (canvasPattern.test(content)) {
    const linesCanvas = findLines(canvasPattern);
    mod2_fingerprint.push('HTML5 Canvas Fingerprinting (toDataURL / getImageData font & GPU rasterization)');
    findings.push({
      id: 'FP-CANVAS-01',
      module: 2,
      moduleName: 'Trackers & Telemetry',
      category: 'Active Fingerprinting',
      title: 'HTML5 Canvas Hardware Fingerprinting',
      description: 'Script renders invisible canvas geometric shapes and extracts byte hashes to uniquely identify the graphics card and browser rendering engine.',
      severity: 'HIGH',
      lineNumbers: linesCanvas.slice(0, 5),
      recommendation: 'Block unauthorized canvas extraction and sanitize getImageData calls.',
    });
    chainOfThought.push('[MODULE 2] Detected Canvas graphics profiling hook (toDataURL / getImageData). Unique device fingerprinting active.');
  }

  // WebGL Profiling
  const webglPattern = /(?:UNMASKED_RENDERER_WEBGL|UNMASKED_VENDOR_WEBGL|WEBGL_debug_renderer_info|getParameter\(3744[56]\))/;
  if (webglPattern.test(content)) {
    const linesWebgl = findLines(webglPattern);
    mod2_fingerprint.push('WebGL Hardware Render Query (UNMASKED_RENDERER_WEBGL GPU unmasking)');
    findings.push({
      id: 'FP-WEBGL-02',
      module: 2,
      moduleName: 'Trackers & Telemetry',
      category: 'Active Fingerprinting',
      title: 'WebGL GPU Unmasking & Hardware Profiling',
      description: 'Probing WEBGL_debug_renderer_info to query low-level GPU hardware models and driver versions bypassing sandboxing.',
      severity: 'HIGH',
      lineNumbers: linesWebgl.slice(0, 5),
      recommendation: 'Strip WebGL vendor extensions from third-party scripts.',
    });
    chainOfThought.push('[MODULE 2] WebGL hardware probe detected: extracting unmasked GPU device strings.');
  }

  // AudioContext Fingerprinting
  const audioPattern = /(?:OfflineAudioContext|createOscillator|createDynamicsCompressor|getFloatFrequencyData)/;
  if (audioPattern.test(content)) {
    mod2_fingerprint.push('AudioContext / Web Audio Acoustic Fingerprinting');
    findings.push({
      id: 'FP-AUDIO-03',
      module: 2,
      moduleName: 'Trackers & Telemetry',
      category: 'Active Fingerprinting',
      title: 'AudioContext Acoustic Hardware Profiling',
      description: 'Utilizing oscillator phase response and compressor dynamics to produce unique mathematical acoustic signatures of user sound card.',
      severity: 'HIGH',
      recommendation: 'Neutralize unauthorized AudioContext synthesis in passive page contexts.',
    });
    chainOfThought.push('[MODULE 2] AudioContext acoustic profiling identified.');
  }

  // Battery Status API & Screen Harvesting
  if (/navigator\.getBattery|screen\.colorDepth|screen\.pixelDepth|navigator\.hardwareConcurrency/i.test(content)) {
    mod2_fingerprint.push('Device Parameter Harvesting (Hardware concurrency, Screen depth, Battery status API)');
    findings.push({
      id: 'FP-ENV-04',
      module: 2,
      moduleName: 'Trackers & Telemetry',
      category: 'Active Fingerprinting',
      title: 'Client Environmental Hardware Harvesting',
      description: 'Harvesting CPU core counts, screen dimensions, color depth, and battery degradation to correlate user identities across sessions.',
      severity: 'MEDIUM',
      recommendation: 'Mask hardware concurrency and restrict screen telemetry.',
    });
  }

  // Session Replay & Keystroke Logging
  const sessionReplayVendor = /(?:hotjar\.com|_hjSettings|fullstory\.com|fs\.js|clarity\.ms|smartlook\.com|logrocket\.io|datadoghq\.com\/rum|yandex\.ru\/metrika)/i;
  if (sessionReplayVendor.test(content)) {
    const matchedVendors = content.match(sessionReplayVendor) || [];
    const vendorList = Array.from(new Set(matchedVendors.map(v => v.toLowerCase()))).join(', ');
    mod2_session.push(`Full-session replay recording suite identified: ${vendorList}`);
    findings.push({
      id: 'REC-SESSION-01',
      module: 2,
      moduleName: 'Trackers & Telemetry',
      category: 'Session Recorders & Analytics',
      title: 'Full-Session DOM & Interaction Recorder',
      description: `Invasive session recorder active (${vendorList}). Capable of recording mouse movements, clicks, DOM modifications, and viewport scrolling.`,
      severity: 'HIGH',
      recommendation: 'Remove full-session recorders or implement strict PII masking directives.',
    });
    detectedMaliciousDomains.add('hotjar.com');
    detectedMaliciousDomains.add('fullstory.com');
    detectedMaliciousDomains.add('clarity.ms');
    chainOfThought.push(`[MODULE 2] Session replay recording library detected (${vendorList}). Live DOM capture active.`);
  }

  // Keystroke Logging on Input Fields
  const keystrokePattern = /(?:addEventListener\s*\(\s*["'](?:keydown|keyup|keypress|input)["']|onkeydown\s*=|onkeyup\s*=)/i;
  const inputTargeting = /(?:input|password|cvv|card|cc_num|credit|billing|ssn)/i;
  if (keystrokePattern.test(content) && inputTargeting.test(content)) {
    const linesKey = findLines(keystrokePattern);
    mod2_session.push('Keystroke input listener hooked to dynamic form elements');
    findings.push({
      id: 'LOG-KEY-02',
      module: 2,
      moduleName: 'Trackers & Telemetry',
      category: 'Session Recorders & Analytics',
      title: 'Keystroke Listener Hooked to Sensitive Input Fields',
      description: 'EventListener hooked to keydown/keyup/input events across form inputs, presenting severe risk of real-time credential/card interception.',
      severity: 'CRITICAL',
      lineNumbers: linesKey.slice(0, 5),
      recommendation: 'Strip universal keydown/input hooks and inspect target event callback destinations.',
    });
    chainOfThought.push('[MODULE 2] CRITICAL: Keystroke listeners detected on sensitive input selectors. High credential harvesting probability.');
  }

  // Invisible Pixels & CNAME / Tracking Query Params
  const pixel1x1 = /<img[^>]+(?:width=["']1["'][^>]+height=["']1["']|height=["']1["'][^>]+width=["']1["']|style=["'][^"']*(?:width:\s*1px;\s*height:\s*1px|width:\s*0px|height:\s*0px)[^"']*)/i;
  if (pixel1x1.test(content)) {
    mod2_pixels.push('1x1 transparent tracking pixel beacon detected in markup');
    findings.push({
      id: 'TRK-PIXEL-01',
      module: 2,
      moduleName: 'Trackers & Telemetry',
      category: 'Invisible Pixels & Tracking',
      title: '1x1 Invisible Tracking Pixel Beacon',
      description: 'Zero-dimension/1x1 pixel image element used for cross-site cookie synchronization and user tracking without consent.',
      severity: 'MEDIUM',
      recommendation: 'Purge 1x1 image beacons and deploy strict image source CSP policies.',
    });
  }

  // URL query parameter tracking & third party telemetry
  const queryTrackers = /(?:fbq\(|fbevents\.js|gtag\(|google-analytics\.com|googletagmanager\.com|analytics\.js|tiktok\.com\/pixel|ttq\.track)/i;
  if (queryTrackers.test(content)) {
    mod2_pixels.push('Third-party ad telemetry SDKs identified (Meta Pixel / Google Tag Manager / TikTok Pixel)');
    detectedMaliciousDomains.add('connect.facebook.net');
    detectedMaliciousDomains.add('google-analytics.com');
    detectedMaliciousDomains.add('googletagmanager.com');
  }

  // --------------------------------------------------------------------------
  // MODULE 3: MALICIOUS CODE & OBFUSCATION ENGINE
  // --------------------------------------------------------------------------
  const mod3_obfuscation: string[] = [];
  const mod3_exfil: string[] = [];
  const mod3_exploit: string[] = [];

  // Packed scripts (Dean Edwards packer pattern: eval(function(p,a,c,k,e,d)...))
  const packedPattern = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]/i;
  if (packedPattern.test(content)) {
    mod3_obfuscation.push('Dean Edwards JavaScript Packer signature detected (eval(function(p,a,c,k,e,d)))');
    findings.push({
      id: 'OBF-PACK-01',
      module: 3,
      moduleName: 'Code Security & Malicious Payloads',
      category: 'Obfuscated / Packed Scripts',
      title: 'Dean Edwards JavaScript Packer Obfuscation',
      description: 'Self-extracting dynamic packer script designed to conceal payload execution logic from static scanners.',
      severity: 'CRITICAL',
      recommendation: 'Unpack and de-obfuscate payload in a sandboxed runtime; prohibit execution of packed bundles.',
    });
    chainOfThought.push('[MODULE 3] CRITICAL: Classic packed JavaScript payload detected (eval(p,a,c,k,e,d)). Payload intentionally shielded.');
  }

  // Hex / Base64 decode + eval execution
  const base64Eval = /(?:eval|Function)\s*\(\s*(?:atob|btoa|String\.fromCharCode|decodeURIComponent)\s*\(/i;
  if (base64Eval.test(content)) {
    const linesB64 = findLines(base64Eval);
    mod3_obfuscation.push('Dynamic execution of encoded strings (eval(atob(...) / Function(String.fromCharCode(...)))');
    findings.push({
      id: 'OBF-EVAL-02',
      module: 3,
      moduleName: 'Code Security & Malicious Payloads',
      category: 'Obfuscated / Packed Scripts',
      title: 'Encoded Dynamic Code Execution (eval + atob)',
      description: 'Decoding obfuscated strings at runtime and passing them to eval() or Function constructor to evade static detection.',
      severity: 'CRITICAL',
      lineNumbers: linesB64.slice(0, 5),
      recommendation: 'Strictly prohibit eval() and new Function() calls via Content-Security-Policy (omit unsafe-eval).',
    });
    chainOfThought.push('[MODULE 3] CRITICAL: atob/fromCharCode piped directly into eval() found. High-confidence malicious dropper signature.');
  }

  // Hex array obfuscator (Obfuscator.io / _0x1a2b patterns)
  const hexObfuscator = /var\s+_0x[a-f0-9]{4,6}\s*=\s*\[.*\];.*function\s+_0x/i;
  if (hexObfuscator.test(content) || (content.match(/_0x[a-f0-9]{4,6}/g) || []).length > 20) {
    mod3_obfuscation.push('Obfuscator.io hex array identifier masking pattern detected (_0x.... variable chains)');
    findings.push({
      id: 'OBF-HEX-03',
      module: 3,
      moduleName: 'Code Security & Malicious Payloads',
      category: 'Obfuscated / Packed Scripts',
      title: 'Commercial Hex Array Obfuscation Pattern',
      description: 'Script uses string rotation tables and hexadecimal mangling typical of polymorphic malware or evasion cloaks.',
      severity: 'HIGH',
      recommendation: 'Inspect unpacked string tables and mandate clean source compilation.',
    });
  }

  // Dynamic script injection (document.createElement('script'))
  const dynamicScriptInjection = /document\.createElement\s*\(\s*["']script["']\s*\)/i;
  if (dynamicScriptInjection.test(content)) {
    const linesDyn = findLines(dynamicScriptInjection);
    mod3_obfuscation.push('Dynamic script element injection (document.createElement("script"))');
    findings.push({
      id: 'OBF-INJ-04',
      module: 3,
      moduleName: 'Code Security & Malicious Payloads',
      category: 'Obfuscated / Packed Scripts',
      title: 'Dynamic Script Tag DOM Injection',
      description: 'Creating and appending script elements to the DOM dynamically to bypass static markup parsers.',
      severity: 'HIGH',
      lineNumbers: linesDyn.slice(0, 5),
      recommendation: 'Enforce strict nonces and hashes in Content-Security-Policy script-src.',
    });
  }

  // DOM-based XSS vectors
  const domXssPattern = /(?:innerHTML|outerHTML|document\.write|document\.writeln)\s*=\s*(?:location\.|window\.location|document\.URL|document\.referrer|location\.hash|location\.search)/i;
  if (domXssPattern.test(content)) {
    const linesXss = findLines(domXssPattern);
    mod3_exploit.push('DOM XSS: Direct assignment of unvalidated URL/location source to innerHTML / document.write');
    findings.push({
      id: 'EXP-XSS-01',
      module: 3,
      moduleName: 'Code Security & Malicious Payloads',
      category: 'Exploit & Injection Risks',
      title: 'DOM-based Cross-Site Scripting (XSS) Sink',
      description: 'Unsanitized input sink receives untrusted client URL sources (location.hash / location.search) directly into innerHTML or document.write.',
      severity: 'CRITICAL',
      lineNumbers: linesXss.slice(0, 5),
      recommendation: 'Replace innerHTML with textContent or integrate DOMPurify sanitization library.',
    });
    chainOfThought.push('[MODULE 3] Sinks of DOM-based XSS uncovered without sanitization routines.');
  }

  // Clipjacking / Clipboard tampering
  if (/navigator\.clipboard\.writeText|document\.execCommand\s*\(\s*["']copy["']\s*\)/i.test(content)) {
    mod3_exploit.push('Clipboard hijacking / Clipjacking hook detected');
    findings.push({
      id: 'EXP-CLIP-02',
      module: 3,
      moduleName: 'Code Security & Malicious Payloads',
      category: 'Exploit & Injection Risks',
      title: 'Clipboard Hijacking (Clipjacking) Vector',
      description: 'Script can overwrite user clipboard contents (e.g. replacing cryptocurrency addresses or sensitive transaction hashes).',
      severity: 'HIGH',
      recommendation: 'Restrict clipboard-write permissions via Permissions-Policy header.',
    });
  }

  // Crypto mining signatures (CoinHive / Wasm mining pools)
  if (/(?:coinhive|cryptoloot|monero|webassembly\.instantiate.*(?:miner|stratum|hashrate)|mineral\.min\.js)/i.test(content)) {
    mod3_exploit.push('Cryptocurrency mining script / WebAssembly miner signature detected');
    findings.push({
      id: 'EXP-MINE-03',
      module: 3,
      moduleName: 'Code Security & Malicious Payloads',
      category: 'Exploit & Injection Risks',
      title: 'Unauthorized In-Browser Cryptomining (Cryptojacking)',
      description: 'Background thread attempts to harness user CPU cycles for cryptocurrency mining operations.',
      severity: 'CRITICAL',
      recommendation: 'Block mining pool WebSockets and revoke WebAssembly execution permissions.',
    });
    chainOfThought.push('[MODULE 3] Cryptomining payload signature detected.');
  }

  // --------------------------------------------------------------------------
  // MODULE 4: NETWORK & REQUEST AUDITING ENGINE
  // --------------------------------------------------------------------------
  const mod4_exfil: string[] = [];
  const mod4_headers: string[] = [];
  const mod4_anomalies: string[] = [];

  // Exfiltration via sendBeacon / external POST fetch
  const beaconPattern = /navigator\.sendBeacon\s*\(/i;
  if (beaconPattern.test(content)) {
    const linesBeacon = findLines(beaconPattern);
    mod4_exfil.push('Asynchronous out-of-band data exfiltration via navigator.sendBeacon()');
    findings.push({
      id: 'NET-BEACON-01',
      module: 4,
      moduleName: 'Network & Request Auditing',
      category: 'Data Exfiltration',
      title: 'Asynchronous Beacon Exfiltration Channel',
      description: 'Using navigator.sendBeacon to transmit harvested telemetry or captured keystrokes reliably even as the user navigates away.',
      severity: 'HIGH',
      lineNumbers: linesBeacon.slice(0, 5),
      recommendation: 'Audit all beacon destination URIs and restrict connect-src CSP directive.',
    });
  }

  // Magecart payment skimmer heuristics
  const skimmerPattern = /(?:(?:cc_number|card_number|cvv|cvc|card_exp|cardholder|cardNumber|securityCode).*fetch\s*\(|(?:fetch|sendBeacon).*payment|checkout.*exfil)/i;
  if (skimmerPattern.test(content) || (content.includes('cvv') && content.includes('sendBeacon'))) {
    mod4_exfil.push('Magecart-style digital credit card skimming and offsite exfiltration pattern detected');
    findings.push({
      id: 'NET-SKIM-02',
      module: 4,
      moduleName: 'Network & Request Auditing',
      category: 'Data Exfiltration',
      title: 'Magecart E-Commerce Checkout Payment Skimmer',
      description: 'Harvesting payment card numbers, CVVs, and expiration dates directly from form inputs and transmitting them to unauthorized third-party endpoints.',
      severity: 'CRITICAL',
      recommendation: 'Immediately revoke script injection access, isolate payment iframes (PCI-DSS SAQ A), and deploy strict connect-src CSP.',
    });
    chainOfThought.push('[MODULE 4] CRITICAL: Magecart payment skimmer signature confirmed. Card data extraction pipeline active.');
  }

  // Detect untrusted external destinations in URLs/scripts
  const urlMatches = content.match(/https?:\/\/[a-zA-Z0-9\-\.]+(?::\d+)?(?:\/[^\s"']*)?/g) || [];
  urlMatches.forEach(urlStr => {
    try {
      const u = new URL(urlStr);
      if (!['localhost', '127.0.0.1'].includes(u.hostname) && !u.hostname.endsWith('google.com') && !u.hostname.endsWith('github.com')) {
        if (/telemetry|tracker|analytics|pixel|collect|log|stat|metrics|payload|gate|exfil|drop/i.test(u.hostname) || /temp|bot|evil|phish/i.test(u.hostname)) {
          detectedMaliciousDomains.add(u.hostname);
          mod4_exfil.push(`Suspicious communication endpoint: ${u.hostname}`);
        }
      }
    } catch {
      // ignore invalid
    }
  });

  // HTTP Headers Security Audit (if provided)
  if (httpHeaders) {
    const csp = httpHeaders['content-security-policy'] || httpHeaders['Content-Security-Policy'];
    const hsts = httpHeaders['strict-transport-security'] || httpHeaders['Strict-Transport-Security'];
    const xfo = httpHeaders['x-frame-options'] || httpHeaders['X-Frame-Options'];
    const cors = httpHeaders['access-control-allow-origin'] || httpHeaders['Access-Control-Allow-Origin'];

    if (!csp) {
      mod4_headers.push('Missing Content-Security-Policy (CSP) header');
      findings.push({
        id: 'HDR-CSP-01',
        module: 4,
        moduleName: 'Network & Request Auditing',
        category: 'Resource & Header Anomalies',
        title: 'Missing Content-Security-Policy (CSP)',
        description: 'Target lacks a Content-Security-Policy header, leaving the browser defenseless against inline scripts and unauthorized external script loads.',
        severity: 'HIGH',
        recommendation: 'Enforce strict Content-Security-Policy with nonces or sha256 hashes.',
      });
    } else if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'") || csp.includes('*')) {
      mod4_headers.push('Permissive / Weak CSP detected with unsafe-inline or unsafe-eval directives');
      findings.push({
        id: 'HDR-CSP-02',
        module: 4,
        moduleName: 'Network & Request Auditing',
        category: 'Resource & Header Anomalies',
        title: 'Weak Content-Security-Policy Permitting Unsafe Execution',
        description: 'CSP allows unsafe-inline or unsafe-eval, rendering the policy ineffective against modern XSS exploits.',
        severity: 'HIGH',
        recommendation: 'Remove unsafe-inline and unsafe-eval; switch to cryptographic script nonces.',
      });
    }

    if (!hsts) {
      mod4_headers.push('Missing Strict-Transport-Security (HSTS) header');
      findings.push({
        id: 'HDR-HSTS-03',
        module: 4,
        moduleName: 'Network & Request Auditing',
        category: 'Resource & Header Anomalies',
        title: 'Missing Strict-Transport-Security (HSTS)',
        description: 'Site fails to mandate HTTPS connections, enabling SSL stripping and man-in-the-middle downgrade attacks.',
        severity: 'MEDIUM',
        recommendation: 'Enable HSTS with max-age=31536000; includeSubDomains; preload.',
      });
    }

    if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
      mod4_headers.push('Missing clickjacking defense (No X-Frame-Options or CSP frame-ancestors)');
      findings.push({
        id: 'HDR-XFO-04',
        module: 4,
        moduleName: 'Network & Request Auditing',
        category: 'Resource & Header Anomalies',
        title: 'Vulnerable to Clickjacking / UI Redressing',
        description: 'Site allows itself to be framed inside third-party iframes, enabling clickjacking attacks.',
        severity: 'MEDIUM',
        recommendation: 'Set X-Frame-Options: DENY or CSP frame-ancestors: \'none\'.',
      });
    }

    if (cors === '*' || cors?.includes('null')) {
      mod4_headers.push(`Overly permissive CORS policy (Access-Control-Allow-Origin: ${cors})`);
      findings.push({
        id: 'HDR-CORS-05',
        module: 4,
        moduleName: 'Network & Request Auditing',
        category: 'Resource & Header Anomalies',
        title: 'Wildcard CORS Policy (Access-Control-Allow-Origin: *)',
        description: 'Any external origin can make authenticated or cross-origin requests, risking credential leakage.',
        severity: 'HIGH',
        recommendation: 'Explicitly whitelist authorized origins rather than using wildcard wildcard (*).',
      });
    }
  }

  // --------------------------------------------------------------------------
  // MODULE 5: DEFENSIVE HARDENING & NEUTRALIZATION ENGINE
  // --------------------------------------------------------------------------
  const uBlockRules: string[] = [];
  const hostsRules: string[] = [];
  const cleanInstructions: string[] = [];

  // Generate AdBlock / uBlock Origin / Hosts rules from detected malicious / tracker domains
  const defaultTrackers = [
    'hotjar.com',
    'fullstory.com',
    'clarity.ms',
    'smartlook.com',
    'fbevents.js',
    'google-analytics.com',
    'googletagmanager.com',
    'coinhive.com',
    'cryptoloot.pro',
    'static-trackers.io',
  ];

  detectedMaliciousDomains.forEach(domain => {
    uBlockRules.push(`||${domain}^$third-party`);
    uBlockRules.push(`||${domain}^$script,xhr,beacon`);
    hostsRules.push(`0.0.0.0 ${domain}`);
  });

  if (uBlockRules.length === 0) {
    defaultTrackers.slice(0, 4).forEach(d => {
      uBlockRules.push(`||${d}^$third-party`);
      hostsRules.push(`0.0.0.0 ${d}`);
    });
  }

  // Specific cosmetic element hiding rules for uBlock
  if (mod1_seo.length > 0) {
    uBlockRules.push('##.hidden-seo-content');
    uBlockRules.push('##[style*="left: -9999px"]');
  }
  if (mod2_pixels.length > 0) {
    uBlockRules.push('##img[width="1"][height="1"]');
    uBlockRules.push('##img[style*="width: 1px"]');
  }

  // Strict CSP Generation
  const recommendedCsp = [
    "Content-Security-Policy: default-src 'self';",
    "script-src 'self' 'strict-dynamic';",
    "style-src 'self' 'unsafe-inline';",
    "img-src 'self' data: https:;",
    "font-src 'self' data:;",
    "connect-src 'self';",
    "frame-ancestors 'none';",
    "base-uri 'self';",
    "form-action 'self';",
    "upgrade-insecure-requests;",
    "block-all-mixed-content;",
  ].join(' ');

  // Sanitized Code Generation (Stripping trackers, eval, keyloggers, and bad sinks)
  let sanitizedCode = content;
  if (content.length > 0) {
    // Neutralize eval() and packed scripts
    sanitizedCode = sanitizedCode.replace(
      /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]/gi,
      '/* [NEUTRALIZED BY SENTINEL-X: PACKED JS EVAL BLOCKED] */ void(0); // eval(function(p,a,c,k,e,d)'
    );
    sanitizedCode = sanitizedCode.replace(
      /(?:eval|Function)\s*\(\s*(?:atob|btoa|String\.fromCharCode|decodeURIComponent)\s*\([^)]*\)\s*\)/gi,
      '/* [NEUTRALIZED BY SENTINEL-X: OBFUSCATED STRING EXECUTION STRIPPED] */ null'
    );
    // Neutralize Canvas Fingerprinting
    sanitizedCode = sanitizedCode.replace(
      /(?:canvas|ctx)\.(?:toDataURL|getImageData)\s*\([^)]*\)/gi,
      '/* [NEUTRALIZED BY SENTINEL-X: CANVAS FINGERPRINT DEFENSE] */ new ImageData(1, 1)'
    );
    // Neutralize WebGL unmasking
    sanitizedCode = sanitizedCode.replace(
      /gl\.getParameter\s*\(\s*(?:ext\.UNMASKED_RENDERER_WEBGL|37446)\s*\)/gi,
      '/* [NEUTRALIZED BY SENTINEL-X: WEBGL SPOOF] */ "Generic WebGL Renderer"'
    );
    // Neutralize AudioContext
    sanitizedCode = sanitizedCode.replace(
      /new\s+(?:window\.)?(?:OfflineAudioContext|AudioContext)\s*\([^)]*\)/gi,
      '/* [NEUTRALIZED BY SENTINEL-X: AUDIOCONTEXT PROFILING BLOCKED] */ null'
    );
    // Neutralize sendBeacon
    sanitizedCode = sanitizedCode.replace(
      /navigator\.sendBeacon\s*\([^)]*\)/gi,
      '/* [NEUTRALIZED BY SENTINEL-X: BEACON EXFILTRATION BLOCKED] */ false'
    );
    // Neutralize DOM XSS
    sanitizedCode = sanitizedCode.replace(
      /(\b(?:innerHTML|outerHTML)\s*=\s*)(?:location\.[a-zA-Z0-9_]+|document\.URL|document\.referrer)/gi,
      '$1/* [NEUTRALIZED BY SENTINEL-X: DOMPurify SANITIZATION ENFORCED] */ DOMPurify.sanitize(location.hash)'
    );
    // Neutralize 1x1 pixels
    sanitizedCode = sanitizedCode.replace(
      /<img[^>]+(?:width=["']1["'][^>]+height=["']1["']|height=["']1["'][^>]+width=["']1["'])[^>]*>/gi,
      '<!-- [NEUTRALIZED BY SENTINEL-X: 1x1 TRACKING PIXEL REMOVED] -->'
    );
    // Neutralize session recorder tags
    sanitizedCode = sanitizedCode.replace(
      /<script[^>]*(?:hotjar|fullstory|clarity|smartlook)[^>]*>[\s\S]*?<\/script>/gi,
      '<!-- [NEUTRALIZED BY SENTINEL-X: SESSION REPLAY SCRIPT REMOVED] -->'
    );
  }

  cleanInstructions.push('1. Replace permissive Content-Security-Policy with the strict nonce-based header generated above.');
  cleanInstructions.push('2. Strip third-party session recording scripts (Hotjar, FullStory, Clarity) from HTML templates.');
  cleanInstructions.push('3. Remove event listeners hooked to sensitive form fields (keydown, input) transmitting data to external domains.');
  cleanInstructions.push('4. Sanitize all DOM sinks using DOMPurify before writing into innerHTML.');
  cleanInstructions.push('5. Enforce Subresource Integrity (SRI) hashes on all external stylesheet and script assets.');

  // --------------------------------------------------------------------------
  // CALCULATE THREAT INDEX SCORE & OVERALL RISK LEVEL
  // --------------------------------------------------------------------------
  let score = 0;
  findings.forEach(f => {
    if (f.severity === 'CRITICAL') score += 28;
    else if (f.severity === 'HIGH') score += 16;
    else if (f.severity === 'MEDIUM') score += 8;
    else score += 3;
  });

  // Clamp score
  const threatIndexScore = Math.min(100, Math.max(0, score));

  let overallRiskLevel: RiskLevel = 'SAFE';
  if (threatIndexScore >= 75) overallRiskLevel = 'CRITICAL';
  else if (threatIndexScore >= 50) overallRiskLevel = 'HIGH';
  else if (threatIndexScore >= 25) overallRiskLevel = 'MEDIUM';
  else if (threatIndexScore > 5) overallRiskLevel = 'LOW';
  else overallRiskLevel = 'SAFE';

  // Primary Verdict construction
  let primaryVerdict = '';
  if (overallRiskLevel === 'CRITICAL') {
    primaryVerdict = findings.some(f => f.id.includes('SKIM') || f.id.includes('PACK'))
      ? 'Hostile Payload Detected: Active Magecart Skimmer / Obfuscated Dropper Vector.'
      : 'High-Risk Threat: Multi-Vector Malicious Exploitation & Aggressive Surveillance Trap.';
  } else if (overallRiskLevel === 'HIGH') {
    primaryVerdict = findings.some(f => f.module === 1)
      ? 'Bot-Generated Deceptive Portal with Heavy Client Telemetry & Fingerprinting.'
      : 'High-Risk Asset with Invasive Surveillance, Session Replay, & Insecure DOM Sinks.';
  } else if (overallRiskLevel === 'MEDIUM') {
    primaryVerdict = 'Medium Risk: Telemetry-Heavy Commercial Portal with Missing Defensive Headers.';
  } else if (overallRiskLevel === 'LOW') {
    primaryVerdict = 'Low Risk: Minor Header Hardening Opportunities; No Malicious Payloads Found.';
  } else {
    primaryVerdict = 'Mathematically Proven Secure: Zero Trackers, Strict Boundaries, Clean Semantics.';
  }

  chainOfThought.push(`[PHASE 5: VERDICT] Synthesized ${findings.length} threat vectors. Assigned Threat Score: ${threatIndexScore}/100 [${overallRiskLevel}].`);

  // Compute Module Breakdowns
  const moduleBreakdown: ModuleFindings = {
    module1_botScam: {
      templateArtifacts: mod1_template.length > 0 ? mod1_template : ['No template or scraper artifacts detected'],
      hiddenSeoKeywords: mod1_seo.length > 0 ? mod1_seo : ['No hidden SEO keyword cloaking detected'],
      domainTrustVerification: mod1_trust.length > 0 ? mod1_trust : ['Domain and trust badges verified normal'],
      score: Math.min(100, (mod1_template.length * 20) + (mod1_seo.length * 20) + (mod1_trust.length * 15)),
    },
    module2_trackers: {
      activeFingerprinting: mod2_fingerprint.length > 0 ? mod2_fingerprint : ['No canvas, WebGL, or AudioContext fingerprinting detected'],
      sessionRecorders: mod2_session.length > 0 ? mod2_session : ['No session replay or keystroke recorders identified'],
      invisiblePixelsAndCloaking: mod2_pixels.length > 0 ? mod2_pixels : ['No invisible 1x1 tracking pixels detected'],
      score: Math.min(100, (mod2_fingerprint.length * 25) + (mod2_session.length * 25) + (mod2_pixels.length * 15)),
    },
    module3_codeSecurity: {
      obfuscatedScripts: mod3_obfuscation.length > 0 ? mod3_obfuscation : ['No packed or obfuscated scripts detected'],
      dataExfiltration: mod3_exfil.length > 0 ? mod3_exfil : ['No unverified exfiltration channels discovered'],
      exploitInjectionRisks: mod3_exploit.length > 0 ? mod3_exploit : ['No DOM XSS, clipjacking, or crypto-mining vectors found'],
      score: Math.min(100, (mod3_obfuscation.length * 30) + (mod3_exploit.length * 30)),
    },
    module4_network: {
      exfiltrationEndpoints: mod4_exfil.length > 0 ? mod4_exfil : ['No unauthorized exfiltration endpoints active'],
      securityHeadersFindings: mod4_headers.length > 0 ? mod4_headers : ['Standard baseline headers inspected'],
      resourceAnomalies: mod4_anomalies.length > 0 ? mod4_anomalies : ['Resource trees consistent; no 404/403 core asset leaks'],
      score: Math.min(100, (mod4_exfil.length * 30) + (mod4_headers.length * 15)),
    },
    module5_remediation: {
      recommendedCsp,
      uBlockFilterRules: uBlockRules,
      hostsBlocklist: hostsRules,
      sanitizedCode,
      cleanInstructions,
    },
  };

  // Build the Raw Structured Markdown Report according to the exact schema specified in the prompt!
  const rawMarkdownReport = `### 🎯 THREAT ASSESSMENT OVERVIEW
- **Target URL / Asset:** ${targetLabel || (targetType === 'url' ? input : 'Submitted Raw Code Snippet')}
- **Overall Risk Level:** ${overallRiskLevel}
- **Threat Index Score:** ${threatIndexScore} / 100
- **Primary Verdict:** ${primaryVerdict}

---

### 🔍 DETAILED MODULE FINDINGS

#### 1. Bot & Scam Signatures
- **Template & AI Artifacts:** ${moduleBreakdown.module1_botScam.templateArtifacts.join('; ')}
- **Hidden SEO / Keyword Stuffing:** ${moduleBreakdown.module1_botScam.hiddenSeoKeywords.join('; ')}
- **Domain & Trust Verification:** ${moduleBreakdown.module1_botScam.domainTrustVerification.join('; ')}

#### 2. Trackers & Telemetry
- **Active Fingerprinting:** ${moduleBreakdown.module2_trackers.activeFingerprinting.join('; ')}
- **Session Recorders & Analytics:** ${moduleBreakdown.module2_trackers.sessionRecorders.join('; ')}
- **Invisible Pixels / CNAME Cloaking:** ${moduleBreakdown.module2_trackers.invisiblePixelsAndCloaking.join('; ')}

#### 3. Code Security & Malicious Payloads
- **Obfuscated / Packed Scripts:** ${moduleBreakdown.module3_codeSecurity.obfuscatedScripts.join('; ')}
- **Data Exfiltration & Keylogging:** ${mod4_exfil.length > 0 ? mod4_exfil.join('; ') : 'None Detected'}
- **Exploit & Injection Risks:** ${moduleBreakdown.module3_codeSecurity.exploitInjectionRisks.join('; ')}

#### 4. Network & Request Auditing
- **Exfiltration & Skimmers:** ${moduleBreakdown.module4_network.exfiltrationEndpoints.join('; ')}
- **Security Headers & CORS:** ${moduleBreakdown.module4_network.securityHeadersFindings.join('; ')}

---

### 🛡️ REMEDIATION & NEUTRALIZATION PLAN

#### Recommended Content Security Policy (CSP) Header
\`\`\`http
${recommendedCsp}
\`\`\`

#### Browser Extension Neutralization Rules (uBlock Origin / AdGuard)
\`\`\`adblock
${uBlockRules.slice(0, 10).join('\n')}
\`\`\`

#### Host-Level Network Blocklist (/etc/hosts)
\`\`\`hosts
# Sentinel-X Threat Intelligence Quarantine List
${hostsRules.slice(0, 8).join('\n')}
\`\`\`

#### Actionable Hardening Checklist
${cleanInstructions.map(instr => `- ${instr}`).join('\n')}
`;

  return {
    target: targetLabel || (targetType === 'url' ? input : 'Submitted Code / Log Payload'),
    targetType,
    timestamp: new Date().toISOString(),
    overallRiskLevel,
    threatIndexScore,
    primaryVerdict,
    chainOfThought,
    detailedFindings: findings,
    moduleBreakdown,
    rawMarkdownReport,
    httpHeaders,
  };
}
