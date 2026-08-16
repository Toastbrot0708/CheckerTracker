/* ============================================================================
   MODULE: CT.engines.web — HTTP security header & cookie evaluation
   Header parsing and scoring are fully real; they run identically on captured
   scan data and on a raw response block pasted into the Header Analyzer.
   ========================================================================= */
CT.engines.web = (function () {
  'use strict';

  function ev(label, value) { return { label, value: String(value) }; }

  const CHECKS = [
    { key: 'strict-transport-security', rule: 'CT-WEB-001', label: 'Strict-Transport-Security', httpsOnly: true },
    { key: 'content-security-policy', rule: 'CT-WEB-002', label: 'Content-Security-Policy' },
    { key: 'x-content-type-options', rule: 'CT-WEB-003', label: 'X-Content-Type-Options' },
    { key: 'referrer-policy', rule: 'CT-WEB-004', label: 'Referrer-Policy' },
    { key: 'permissions-policy', rule: 'CT-WEB-005', label: 'Permissions-Policy' }
  ];

  const VERSION_BANNER = /\d+\.\d+(\.\d+)?/;

  /** Parse a raw HTTP response head (status line + headers) into a structure. */
  function parseRawHeaders(text) {
    const lines = String(text).replace(/\r\n/g, '\n').split('\n');
    let status = null, statusText = null, httpVersion = null;
    const headers = {};
    const cookies = [];
    let started = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) { if (started) break; else continue; }
      const statusMatch = /^HTTP\/([\d.]+)\s+(\d{3})\s*(.*)$/i.exec(line.trim());
      if (statusMatch && !started) {
        httpVersion = statusMatch[1];
        status = parseInt(statusMatch[2], 10);
        statusText = statusMatch[3] || null;
        started = true;
        continue;
      }
      const idx = line.indexOf(':');
      if (idx <= 0) continue;
      started = true;
      const name = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();
      if (name === 'set-cookie') {
        cookies.push(parseCookie(value));
      } else if (headers[name]) {
        headers[name] += ', ' + value;
      } else {
        headers[name] = value;
      }
    }
    if (!started) throw new Error('No HTTP headers recognised. Paste a full response head, for example "HTTP/1.1 200 OK" followed by header lines.');
    return { status, statusText, httpVersion, headers, cookies,
             server: headers['server'] || null,
             redirect: headers['location'] || null };
  }

  function parseCookie(value) {
    const parts = value.split(';').map((p) => p.trim());
    const nv = parts[0] || '';
    const eq = nv.indexOf('=');
    const c = {
      name: eq > -1 ? nv.slice(0, eq) : nv,
      secure: false, httpOnly: false, sameSite: null, path: null, domain: null, maxAge: null
    };
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i], lower = p.toLowerCase();
      if (lower === 'secure') c.secure = true;
      else if (lower === 'httponly') c.httpOnly = true;
      else if (lower.startsWith('samesite=')) c.sameSite = p.slice(9);
      else if (lower.startsWith('path=')) c.path = p.slice(5);
      else if (lower.startsWith('domain=')) c.domain = p.slice(7);
      else if (lower.startsWith('max-age=')) c.maxAge = p.slice(8);
    }
    return c;
  }

  /**
   * @param {object} res { scheme, status, headers{}, cookies[], redirect, plaintextPort80 }
   * @returns {Array} issues
   */
  function evaluate(res) {
    const out = [];
    if (!res) return out;
    const headers = res.headers || {};
    const scheme = res.scheme || (res.port === 443 ? 'https' : 'http');
    const isHttps = scheme === 'https';

    CHECKS.forEach((chk) => {
      if (chk.httpsOnly && !isHttps) return;
      if (!headers[chk.key]) {
        out.push({
          ruleId: chk.rule, confidence: 'high',
          detail: chk.label + ' was not present in the response.',
          evidence: [ev('Header', chk.label), ev('Observed', 'absent'),
                     ev('Response', (res.status || '?') + ' over ' + scheme.toUpperCase())]
        });
      }
    });

    // HSTS present but weak
    const hsts = headers['strict-transport-security'];
    if (isHttps && hsts) {
      const m = /max-age\s*=\s*(\d+)/i.exec(hsts);
      const maxAge = m ? parseInt(m[1], 10) : 0;
      if (maxAge < 15552000) {
        out.push({
          ruleId: 'CT-WEB-001', severity: 'low', confidence: 'high',
          detail: 'Strict-Transport-Security is present but max-age is below the recommended 180 days.',
          evidence: [ev('Header value', hsts), ev('max-age', maxAge + ' s'), ev('Recommended', '15552000 s (180 days)')]
        });
      }
    }

    // Cookie attributes
    const badCookies = (res.cookies || []).filter((c) =>
      (isHttps && !c.secure) || !c.httpOnly || !c.sameSite);
    if (badCookies.length) {
      out.push({
        ruleId: 'CT-WEB-006', confidence: 'high',
        detail: CT.util.plural(badCookies.length, 'cookie') + ' missing one or more protective attributes.',
        evidence: badCookies.slice(0, 6).map((c) => ev(c.name, [
          c.secure ? 'Secure' : 'no Secure',
          c.httpOnly ? 'HttpOnly' : 'no HttpOnly',
          c.sameSite ? 'SameSite=' + c.sameSite : 'no SameSite'
        ].join(' · ')))
      });
    }

    // Version disclosure
    const banners = [];
    if (headers['server'] && VERSION_BANNER.test(headers['server'])) banners.push(ev('Server', headers['server']));
    if (headers['x-powered-by']) banners.push(ev('X-Powered-By', headers['x-powered-by']));
    if (headers['x-aspnet-version']) banners.push(ev('X-AspNet-Version', headers['x-aspnet-version']));
    if (banners.length) {
      out.push({
        ruleId: 'CT-WEB-007', confidence: 'high',
        detail: 'Response headers disclose specific product versions.',
        evidence: banners
      });
    }

    // Cleartext HTTP without redirect
    const plain = res.plaintextPort80;
    if (plain && plain.redirects === false) {
      out.push({
        ruleId: 'CT-WEB-008', confidence: 'high',
        detail: 'Port 80 answered ' + plain.status + ' without redirecting to HTTPS.',
        evidence: [ev('Port 80 status', plain.status), ev('Location header', 'absent')]
      });
    } else if (!isHttps && !res.redirect && res.status && res.status < 300) {
      out.push({
        ruleId: 'CT-WEB-008', confidence: 'medium',
        detail: 'Cleartext HTTP returned ' + res.status + ' with no redirect to HTTPS.',
        evidence: [ev('Scheme', 'http'), ev('Status', res.status), ev('Location header', 'absent')]
      });
    }

    return out;
  }

  /** Per-header verdict table used by the Header Analyzer tool. */
  function headerReport(res) {
    const headers = res.headers || {};
    const isHttps = (res.scheme || 'http') === 'https';
    const rows = CHECKS.map((chk) => {
      const val = headers[chk.key] || null;
      let state = val ? 'ok' : 'missing';
      let note = val || 'Not set';
      if (chk.key === 'strict-transport-security') {
        if (!isHttps) { state = 'na'; note = 'Only meaningful over HTTPS'; }
        else if (val) {
          const m = /max-age\s*=\s*(\d+)/i.exec(val);
          const age = m ? parseInt(m[1], 10) : 0;
          if (age < 15552000) { state = 'weak'; note = val + '  (max-age below 180 days)'; }
        }
      }
      if (chk.key === 'x-content-type-options' && val && val.toLowerCase() !== 'nosniff') {
        state = 'weak'; note = val + '  (expected "nosniff")';
      }
      if (chk.key === 'content-security-policy' && val && /unsafe-inline|unsafe-eval/i.test(val)) {
        state = 'weak'; note = val;
      }
      return { label: chk.label, key: chk.key, state, note };
    });
    const extras = ['x-frame-options', 'cross-origin-opener-policy', 'cross-origin-resource-policy',
                    'cache-control', 'server', 'x-powered-by'];
    extras.forEach((k) => {
      if (headers[k]) rows.push({ label: k.replace(/(^|-)([a-z])/g, (m0, a, b) => a + b.toUpperCase()), key: k, state: 'info', note: headers[k] });
    });
    return rows;
  }

  return { parseRawHeaders, parseCookie, evaluate, headerReport, CHECKS };
})();
