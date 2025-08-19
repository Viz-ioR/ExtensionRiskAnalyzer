# Extension Risk Analyzer

## Files & What They Do

- **manifest.json** — MV3 config. Declares the side panel (`app/index.html`), background service worker (`background/sw.js`), and host permissions for CRX downloads + OpenAI. No tab/active-page access.
- **background/sw.js** — Service worker. Opens the side panel when the toolbar icon is clicked and proxies OpenAI requests using a baked api key.
- **app/index.html** — Side panel UI shell. Contains the input (`#query`), button (`#analyzeBtn`), status (`#status`), and results (`#result`). Loads `vendor/jszip.min.js` then `app/app.js`.
- **app/app.js** — Main client logic. Validates input (32-char ID or Chrome Web Store detail URL), downloads the CRX, extracts `manifest.json` with JSZip, resolves the extension name from `_locales` if needed, runs risk analysis via `analysis.js`, calls OpenAI via the background, and renders the score, risks, safeties, and technical evidence.
- **app/analysis.js** — Pluggable heuristics module exporting `Analysis.analyzeRisk({ manifest, metadata })`
- **vendor/jszip.min.js** — Local minified JSZip library used to read the ZIP payload inside CRX files (required in MV3; remote scripts aren’t allowed).

---

## Risk Assessment Methodology

**Inputs (from `manifest.json`):**
- `permissions`
- `host_permissions`
- `content_scripts[].matches`
- `manifest_version`

**Signals & Weights:**
- **Broad host access** — `<all_urls>` or `*://*/*` in host permissions or in content-script matches  
  → **+35** (High). Rationale: can read/change data on any site.
- **Sensitive APIs** — any of: `webRequest`, `webRequestBlocking`, `history`, `downloads`, `cookies`, `clipboardRead`, `clipboardWrite`, `tabs`, `scripting`, `nativeMessaging`  
  → **+5 each** (Medium). Rationale: privileged capabilities.
- **Positive indicators** *(reported, not scored)* — MV3, ≤3 total permissions, no sensitive permissions, and narrow host access.

**Score → Category:**
- **0–34** → Low  
- **35–69** → Medium  
- **70–100** → High

**Outputs shown to the user:**
- **Risk score** (0–100) & **category**
- **Why risky** — factors with severity + brief rationale
- **Why safe** — positives/mitigations
- **Technical evidence** — counts + raw lists of permissions, host permissions, and content scripts
- **AI summary** — compact JSON from the model parsed into simple bullets (falls back to plain text if not JSON)


## Installation

1. **Download & extract** the ZIP of this repository.
2. Open Chrome and go to `chrome://extensions/`.
3. Toggle **Developer mode** (top-right).
4. Click **Load unpacked** and select the folder that contains `manifest.json` (e.g., `ExtensionRiskAnalyzer/`).
5. (Optional) Pin the extension from the puzzle-piece icon.

## Usage

1. Click the **Extension Risk Analyzer** icon (opens in the side panel or a new tab).
2. Enter a Chrome Web Store extension **ID or URL** and click **Analyze**.

## Remove

- **Uninstall:** `chrome://extensions/` → **Remove**.


