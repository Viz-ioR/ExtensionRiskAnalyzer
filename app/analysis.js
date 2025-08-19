//analyzes extension risk based on permissions and hosts

(function (w) {
  // Rules: +30 broad hosts; +7 per sensitive API. Positives are informational.
  function analyzeRisk({ manifest }) {
    const perms = new Set(manifest?.permissions || []);
    const hosts = new Set(manifest?.host_permissions || []);
    const cs = manifest?.content_scripts || [];
    const factors = [], positives = [];
    let score = 0;

    const broad = new Set(['<all_urls>', '*://*/*']);
    const hasBroad =
      [...hosts].some(h => broad.has(h)) ||
      cs.some(s => (s.matches || []).some(m => broad.has(m)));
    if (hasBroad) { factors.push({ label: 'Broad host access', severity: 'high', detail: 'All sites' }); score += 30; }

    const sens = ['webRequest','webRequestBlocking','history','downloads','cookies','clipboardRead','clipboardWrite','tabs','scripting','nativeMessaging'];
    const used = [...perms].filter(p => sens.includes(p));
    used.forEach(p => { factors.push({ label: 'Sensitive API', severity: 'medium', detail: p }); score += 7; });

    if (!hasBroad && hosts.size) positives.push({ label: 'Narrow hosts', detail: 'Specific origins' });
    if (!used.length) positives.push({ label: 'No sensitive APIs', detail: '' });
    if ((manifest.permissions?.length || 0) + (manifest.host_permissions?.length || 0) <= 3)
      positives.push({ label: 'Few permissions', detail: '' });
    if (manifest.manifest_version === 3)
      positives.push({ label: 'MV3', detail: 'Event-driven' });

    score = Math.min(100, score);
    const category = score >= 70 ? 'high' : score >= 35 ? 'medium' : 'low';
    const summary = category === 'high' ? 'High: broad access / sensitive APIs.'
                   : category === 'medium' ? 'Medium: some elevated permissions.'
                   : 'Low: limited access.';

    return {
      score, category, summary, factors, positives,
      breakdown: {
        manifestVersion: manifest.manifest_version,
        permissionCount: manifest.permissions?.length || 0,
        hostPermissionCount: manifest.host_permissions?.length || 0,
        contentScriptCount: cs.length,
        sensitiveUsed: used
      }
    };
  }

  // make it globally available
  w.Analysis = { analyzeRisk };
})(window);
