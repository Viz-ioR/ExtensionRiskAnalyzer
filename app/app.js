// This script analyzes Chrome extension manifests for potential risks based on permissions and host access.
  

// ----- tiny helpers -----
const $ = s => document.querySelector(s);
const isId = s => /^[a-p]{32}$/i.test((s || '').trim());
const storeUrl = id => `https://chromewebstore.google.com/detail/${id}`;
const log = (...a) => false && console.log('[ERA]', ...a); // flip to true to debug
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// Chrome Web Store URL → id
function idFromUrl(s) {
  try {
    const u = new URL(String(s));
    const ok = u.hostname === 'chromewebstore.google.com' ||
               (u.hostname === 'chrome.google.com' && u.pathname.startsWith('/webstore/'));
    if (!ok) return null;
    return u.pathname.split('/').find(p => /^[a-p]{32}$/i.test(p))?.toLowerCase() || null;
  } catch { return null; }
}

// ----- CRX download -----
function chromeVersion() {
  const m = navigator.userAgent.match(/Chrome\/(\d+\.\d+\.\d+\.\d+)/);
  return m ? m[1] : '120.0.0.0';
}
function crxUrls(id) {
  const pv = chromeVersion();
  const base = 'https://clients2.google.com/service/update2/crx';
  return [
    `${base}?response=redirect&prodversion=${encodeURIComponent(pv)}&acceptformat=crx3&x=id%3D${id}%26uc`,
    `${base}?response=redirect&prodversion=200&acceptformat=crx3&x=id%3D${id}%26uc`,
    `${base}?response=redirect&prod=chrome&prodchannel=stable&prodversion=${encodeURIComponent(pv)}&acceptformat=crx3,crx2&x=id%3D${id}%26installsource%3Dondemand%26uc`
  ];
}
function xhrBuf(url) {
  return new Promise(r => {
    const x = new XMLHttpRequest();
    x.open('GET', url, true);
    x.responseType = 'arraybuffer';
    x.onload = () => r(x.status >= 200 && x.status < 300 ? x.response : null);
    x.onerror = () => r(null);
    x.send();
  });
}
async function downloadCrx(id) {
  for (const url of crxUrls(id)) {
    const body = await xhrBuf(url);
    if (body && body.byteLength) return body;
  }
  throw new Error('Download failed');
}

// ----- CRX → ZIP → manifest + display name -----
async function zipFromCrx(buf) {
  if (typeof JSZip === 'undefined') throw new Error('JSZip missing');
  const u8 = new Uint8Array(buf);
  for (let i = 0; i < u8.length - 3; i++) {
    if (u8[i]===0x50 && u8[i+1]===0x4B && u8[i+2]===0x03 && u8[i+3]===0x04) {
      return JSZip.loadAsync(buf.slice(i));
    }
  }
  throw new Error('Bad CRX');
}
async function manifestFrom(zip) {
  const f = zip.file('manifest.json');
  if (!f) throw new Error('No manifest');
  return JSON.parse(await f.async('string'));
}
async function displayName(manifest, zip) {
  const raw = manifest?.name;
  if (!raw || !/^__MSG_/.test(raw)) return raw || '(unknown)';
  const key = raw.replace(/^__MSG_/, '').replace(/__$/, '');
  const nav = (navigator.language || 'en').toLowerCase();
  const tries = [
    manifest.default_locale?.toLowerCase(),
    nav.replace('-', '_'),
    nav.split('-')[0],
    'en_us', 'en'
  ].filter(Boolean);
  for (const loc of tries) {
    const f = zip.file(`_locales/${loc}/messages.json`);
    if (!f) continue;
    try {
      const msg = JSON.parse(await f.async('string'))?.[key]?.message;
      if (msg) return String(msg);
    } catch {}
  }
  for (const f of zip.file(/^_locales\/[^/]+\/messages\.json$/i)) {
    try {
      const msg = JSON.parse(await f.async('string'))?.[key]?.message;
      if (msg) return String(msg);
    } catch {}
  }
  return raw;
}

// ----- Signals for AI -----
function deriveSignals(manifest, zip) {
  const perms = new Set(manifest.permissions || []);
  const hosts = new Set(manifest.host_permissions || []);
  const optPerms = new Set(manifest.optional_permissions || []);
  const optHosts = new Set(manifest.optional_host_permissions || []);
  const cs = manifest.content_scripts || [];

  const broad = new Set(['<all_urls>', '*://*/*']);
  const hasBroadHosts =
    [...hosts].some(h => broad.has(h)) ||
    cs.some(s => (s.matches || []).some(m => broad.has(m)));

  const sensList = ['webRequest','webRequestBlocking','history','downloads','cookies','clipboardRead','clipboardWrite','tabs','scripting','nativeMessaging'];
  const sensitive = [...perms].filter(p => sensList.includes(p));

  const usesDNR = perms.has('declarativeNetRequest') || perms.has('declarativeNetRequestWithHostAccess') || perms.has('declarativeNetRequestFeedback');
  const usesWR = perms.has('webRequest') || perms.has('webRequestBlocking');
  const hasExternallyConnectable = !!manifest.externally_connectable;
  const hasOAuth2 = !!manifest.oauth2;
  const updateUrl = manifest.update_url || null;

  const csp = manifest.content_security_policy || {};
  const cspStr = typeof csp === 'string' ? csp : (csp.extension_pages || '');
  const cspUnsafeEval = /\bunsafe-eval\b/.test(cspStr);

  const files = zip.file(/.*/).filter(f => !f.dir).map(f => f.name);
  const jsFiles = files.filter(n => /\.js$/i.test(n));
  const minJs = jsFiles.filter(n => /\.min\.js$/i.test(n) || /bundle/i.test(n));
  const wasm = files.filter(n => /\.wasm$/i.test(n));
  const suspiciousNames = files.filter(n =>
    /(keylog|inject|payload|steal|wallet|mnemonic|seed|tracker|beacon|adserver)/i.test(n)
  ).slice(0, 50);

  return {
    mv: manifest.manifest_version,
    permissionCount: manifest.permissions?.length || 0,
    hostPermissionCount: manifest.host_permissions?.length || 0,
    contentScriptCount: cs.length,

    hasBroadHosts,
    sensitivePermissions: sensitive,
    optionalPermissions: [...optPerms],
    optionalHostPermissions: [...optHosts],
    usesWebRequest: usesWR,
    usesDeclarativeNetRequest: usesDNR,
    hasExternallyConnectable,
    hasOAuth2,
    updateUrl,
    cspUnsafeEval,

    fileStats: {
      totalFiles: files.length,
      jsFiles: jsFiles.length,
      minJsFiles: minJs.length,
      wasmFiles: wasm.length,
      suspiciousNames
    }
  };
}

// ----- AI helpers -----
function parseAiJson(maybe) {
  if (!maybe) return null;
  const s = String(maybe).trim();
  try { return JSON.parse(s); } catch {}
  const fenced = s.replace(/^```json\s*/i, '').replace(/```$/i, '').trim();
  try { return JSON.parse(fenced); } catch {}
  const a = s.indexOf('{'), b = s.lastIndexOf('}');
  if (a !== -1 && b > a) { try { return JSON.parse(s.slice(a, b + 1)); } catch {} }
  return null;
}
function simpleAiSection(aiText) {
  const ai = parseAiJson(aiText);
  if (!ai) return `<h3>AI summary</h3><p>${esc(String(aiText || '').trim())}</p>`;
  const rows = [];
  if (typeof ai.score === 'number') rows.push(`<p><strong>AI score:</strong> ${Math.max(0, Math.min(100, ai.score|0))}</p>`);
  if (ai.summary) rows.push(`<p>${esc(ai.summary)}</p>`);
  if (ai.subscores && typeof ai.subscores === 'object') {
    const items = Object.entries(ai.subscores).map(([k,v]) => `<li><code>${esc(k)}</code>: ${Number(v)}</li>`).join('');
    rows.push(`<h4>AI subscores</h4><ul>${items}</ul>`);
  }
  if (Array.isArray(ai.factors) && ai.factors.length) {
    rows.push(`<h4>Risks</h4><ul>${
      ai.factors.map(f => `<li>${f?.severity ? `[${esc(String(f.severity).toUpperCase())}] ` : ''}${esc(f?.label || '')}${f?.detail ? ` — ${esc(f.detail)}` : ''}</li>`).join('')
    }</ul>`);
  }
  if (Array.isArray(ai.positives) && ai.positives.length) {
    rows.push(`<h4>Safeties</h4><ul>${
      ai.positives.map(p => `<li>${esc(p?.label || '')}${p?.detail ? ` — ${esc(p.detail)}` : ''}</li>`).join('')
    }</ul>`);
  }
  return `<h3>AI summary</h3>${rows.join('')}`;
}
function askOpenAI(payload) {
  return new Promise((resolve, reject) => {
    const body = {
      model: 'gpt-4o-mini',
      temperature: 0.2,
      messages: [
        { role: 'system', content:
'Review a Chrome extension’s risk. Compute your OWN subscores and final score. Return JSON only.' },
        { role: 'user', content:
`Inputs:

${JSON.stringify(payload)}

Rules:
1) Score these (0-100, higher = riskier): permissionsRisk, hostScopeRisk, contentScriptsRisk, backgroundCspRisk, messagingRisk, networkRisk, artifactRisk.
2) Pick a reasonable weighting and compute a final "score" (0-100). Mention the weighting briefly in "summary".
3) List concrete "factors" (label,severity,detail) and "positives".
Return EXACT JSON:
{
  "score": <0-100>,
  "subscores": {
    "permissionsRisk": <0-100>,
    "hostScopeRisk": <0-100>,
    "contentScriptsRisk": <0-100>,
    "backgroundCspRisk": <0-100>,
    "messagingRisk": <0-100>,
    "networkRisk": <0-100>,
    "artifactRisk": <0-100>
  },
  "summary": "<one or two sentences>",
  "factors": [{"label":"", "severity":"low|medium|high", "detail":""}],
  "positives": [{"label":"", "detail":""}]
}` }
      ]
    };
    chrome.runtime.sendMessage({ type: 'OPENAI_CHAT', body }, (res) => {
      if (chrome.runtime.lastError) return reject(new Error('No SW'));
      if (!res?.ok) return reject(new Error(res?.error || 'AI error'));
      resolve(res.content || '');
    });
  });
}

// ----- Results UI -----
function colorFor(cat){ return cat === 'high' ? '#dc2626' : cat === 'medium' ? '#f59e0b' : '#16a34a'; }

function renderResults({ id, name, heuristic, manifest, aiText }) {
  const r = document.createElement('div');

  const cat = (heuristic.category || 'low').toLowerCase();
  const score = Math.max(0, Math.min(100, Number(heuristic.score) || 0));
  const ring = colorFor(cat);
  const b = heuristic.breakdown || {};
  const sens = (b.sensitiveUsed || []).join(', ') || 'None';

  const perms = manifest.permissions || [];
  const hosts = manifest.host_permissions || [];
  const scripts = manifest.content_scripts || [];

  const header = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
      <div>
        <h2 style="margin:0;">${esc(name || '(unknown extension)')}</h2>
        <div class="muted" style="margin-top:2px;">ID: ${esc(id)} ·
          <a class="link" href="${storeUrl(id)}" target="_blank" rel="noopener">Open in Chrome Web Store</a>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:14px;">
        <div style="--pct:${score}%;--ring:${ring};width:72px;height:72px;border-radius:9999px;background:conic-gradient(var(--ring) var(--pct), #e5e7eb 0);position:relative;">
          <div style="position:absolute;inset:8px;background:#fff;border-radius:9999px;"></div>
          <div style="position:absolute;inset:0;display:grid;place-items:center;font-weight:800;font-size:18px;">${score}</div>
        </div>
        <div>
          <div style="font-weight:700;color:${ring};">${cat.toUpperCase()} RISK</div>
          <div class="muted">${esc(heuristic.summary || '')}</div>
        </div>
      </div>
    </div>
  `;

  const risky = (heuristic.factors || [])
    .map(f => `<li>${f?.severity ? `[${esc(String(f.severity).toUpperCase())}] ` : ''}${esc(f?.label || '')}${f?.detail ? ` — ${esc(f.detail)}` : ''}</li>`)
    .join('');

  const safe = (heuristic.positives || [])
    .map(p => `<li>${esc(p?.label || '')}${p?.detail ? ` — ${esc(p.detail)}` : ''}</li>`)
    .join('');

  const evidence = `
    <h3>Technical evidence</h3>
    <ul style="margin:6px 0;">
      <li>Manifest v${b.manifestVersion ?? '?'}</li>
      <li>Permissions: ${b.permissionCount ?? (perms.length || 0)}</li>
      <li>Host permissions: ${b.hostPermissionCount ?? (hosts.length || 0)}</li>
      <li>Content scripts: ${b.contentScriptCount ?? (scripts.length || 0)}</li>
      <li>Sensitive: ${sens}</li>
    </ul>
    <details><summary>Permissions</summary><pre>${esc(JSON.stringify(perms, null, 2))}</pre></details>
    <details><summary>Host permissions</summary><pre>${esc(JSON.stringify(hosts, null, 2))}</pre></details>
    <details><summary>Content scripts</summary><pre>${esc(JSON.stringify(scripts, null, 2))}</pre></details>
    <details><summary>Raw manifest.json</summary><pre>${esc(JSON.stringify(manifest, null, 2))}</pre></details>
  `;

  const ai = aiText ? simpleAiSection(aiText) : '';

  r.innerHTML = `
    ${header}
    ${risky ? `<h3>Why it might be risky</h3><ul>${risky}</ul>` : ''}
    ${safe  ? `<h3>Why it might be safe</h3><ul>${safe}</ul>`   : ''}
    ${evidence}
    ${ai}
  `;

  $('#result').innerHTML = '';
  $('#result').appendChild(r);
}

// ----- Main flow -----
let runId = null;

async function analyzeById(id) {
  if (id === chrome.runtime.id) { $('#status').textContent = 'That ID is this unpacked extension.'; return; }
  if (typeof Analysis === 'undefined' || typeof Analysis.analyzeRisk !== 'function') {
    $('#status').textContent = 'Analysis module missing.'; return;
  }

  runId = id;
  $('#result').innerHTML = '';
  $('#status').textContent = 'Downloading…';

  try {
    const crx = await downloadCrx(id);
    if (runId !== id) return;

    $('#status').textContent = 'Parsing…';
    const zip = await zipFromCrx(crx);
    const manifest = await manifestFrom(zip);
    const name = await displayName(manifest, zip);

    const heuristic = Analysis.analyzeRisk({ manifest, metadata: { id, name } });

    // AI payload
    const signals = deriveSignals(manifest, zip);
    $('#status').textContent = 'Asking AI…';
    let aiText = null;
    try { aiText = await askOpenAI({ manifest, metadata: { id, name }, heuristic, signals }); }
    catch (e) { log('AI error', e); }

    if (runId !== id) return;
    $('#status').textContent = '';
    renderResults({ id, name, manifest, heuristic, aiText });

  } catch (e) {
    if (runId !== id) return;
    $('#status').textContent = String(e?.message || e);
  }
}

// ----- UI wiring -----
function onSubmit(e) {
  e?.preventDefault();
  const q = ($('#query')?.value || '').trim();
  const id = isId(q) ? q.toLowerCase() : idFromUrl(q);
  if (!id) { $('#status').textContent = 'Not an ID or Store URL.'; return; }
  analyzeById(id);
}
$('#q')?.addEventListener('submit', onSubmit);
$('#analyzeBtn')?.addEventListener('click', onSubmit);
