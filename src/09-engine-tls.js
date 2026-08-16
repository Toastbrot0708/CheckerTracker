/* ============================================================================
   MODULE: CT.engines.tls — certificate and protocol evaluation
   Operates on a normalised TLS observation. The same evaluator serves the
   simulated scan pipeline and the (fully real) offline TLS Inspector.
   ========================================================================= */
CT.engines.tls = (function () {
  'use strict';

  const DAY = 86400000;
  const EXPIRY_WARN_DAYS = 30;
  const DEPRECATED = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'];
  const WEAK_SIG = /^(sha1|md5)/i;

  function ev(label, value) { return { label, value: String(value) }; }

  /**
   * @param {object} tls  { protocols[], minProtocol, cipher, cert{} }
   * @param {string} hostname  name the service was reached by (for SAN matching)
   * @returns {Array} issues -> { ruleId, severity?, confidence, evidence[], detail }
   */
  function evaluate(tls, hostname) {
    const out = [];
    if (!tls) return out;
    const c = tls.cert || null;
    const now = Date.now();

    if (c) {
      const daysLeft = Math.floor((c.notAfter - now) / DAY);

      if (now > c.notAfter) {
        out.push({
          ruleId: 'CT-TLS-001', confidence: 'high',
          detail: 'Certificate expired ' + Math.abs(daysLeft) + ' day(s) ago.',
          evidence: [
            ev('Subject', c.subjectCN || '(none)'),
            ev('Issuer', c.issuerCN || '(none)'),
            ev('Not after', new Date(c.notAfter).toISOString()),
            ev('Days past expiry', Math.abs(daysLeft))
          ]
        });
      } else if (daysLeft <= EXPIRY_WARN_DAYS) {
        out.push({
          ruleId: 'CT-TLS-002', confidence: 'high',
          severity: daysLeft <= 7 ? 'high' : 'medium',
          detail: 'Certificate expires in ' + daysLeft + ' day(s).',
          evidence: [
            ev('Subject', c.subjectCN || '(none)'),
            ev('Not after', new Date(c.notAfter).toISOString()),
            ev('Days remaining', daysLeft)
          ]
        });
      }

      if (c.notBefore && now < c.notBefore) {
        out.push({
          ruleId: 'CT-TLS-001', confidence: 'high',
          detail: 'Certificate is not yet valid (notBefore is in the future).',
          evidence: [ev('Not before', new Date(c.notBefore).toISOString())]
        });
      }

      if (c.selfSigned) {
        out.push({
          ruleId: 'CT-TLS-005', confidence: 'high',
          detail: 'Issuer and subject are identical.',
          evidence: [ev('Subject', c.subjectCN || '(none)'), ev('Issuer', c.issuerCN || '(none)')]
        });
      }

      if (c.sigAlg && WEAK_SIG.test(c.sigAlg)) {
        out.push({
          ruleId: 'CT-TLS-006', confidence: 'high',
          detail: 'Signature algorithm ' + c.sigAlg + ' is no longer collision resistant.',
          evidence: [ev('Signature algorithm', c.sigAlg)]
        });
      }

      const weakRsa = c.keyAlg === 'RSA' && c.keyBits && c.keyBits < 2048;
      const weakEc = c.keyAlg === 'EC' && c.keyBits && c.keyBits < 256;
      if (weakRsa || weakEc) {
        out.push({
          ruleId: 'CT-TLS-007', confidence: 'high',
          detail: (c.keyAlg || 'Key') + ' ' + c.keyBits + '-bit is below the recommended minimum.',
          evidence: [ev('Key algorithm', c.keyAlg || 'unknown'), ev('Key size', c.keyBits + ' bit'),
                     ev('Recommended minimum', c.keyAlg === 'EC' ? '256 bit (P-256)' : '2048 bit')]
        });
      }

      if (hostname) {
        const names = (c.san && c.san.length) ? c.san.slice() : (c.subjectCN ? [c.subjectCN] : []);
        if (names.length && !CT.crypto.hostnameMatches(hostname, names)) {
          out.push({
            ruleId: 'CT-TLS-004', confidence: names.length > 0 ? 'high' : 'medium',
            detail: '"' + hostname + '" does not match any name in the certificate.',
            evidence: [ev('Requested host', hostname), ev('Certificate names', names.join(', '))]
          });
        }
      }
    }

    const protos = tls.protocols || [];
    const deprecated = protos.filter((p) => DEPRECATED.indexOf(p) !== -1);
    if (deprecated.length) {
      out.push({
        ruleId: 'CT-TLS-003', confidence: 'high',
        severity: deprecated.some((p) => p.indexOf('SSL') === 0) ? 'critical' : 'high',
        detail: deprecated.join(' and ') + ' still enabled.',
        evidence: [ev('Enabled protocols', protos.join(', ')),
                   ev('Deprecated', deprecated.join(', ')),
                   ev('Required minimum', 'TLS 1.2')]
      });
    }

    return out;
  }

  /** Summary used by asset detail and the TLS Inspector. */
  function summarise(tls, hostname) {
    if (!tls) return { state: 'none', label: 'No TLS service observed', kind: 'info' };
    const issues = evaluate(tls, hostname);
    const worst = issues.reduce((acc, i) => {
      const sev = i.severity || CT.data.rule(i.ruleId).severity;
      return CT.data.SEV_RANK[sev] < CT.data.SEV_RANK[acc] ? sev : acc;
    }, 'informational');
    if (!issues.length) return { state: 'ok', label: 'Valid configuration', kind: 'ok', issues };
    return {
      state: 'issues', kind: worst === 'critical' || worst === 'high' ? 'bad' : 'warn',
      label: CT.util.plural(issues.length, 'issue') + ' · worst ' + CT.data.SEV_LABEL[worst],
      worst, issues
    };
  }

  return { evaluate, summarise, EXPIRY_WARN_DAYS, DEPRECATED };
})();
