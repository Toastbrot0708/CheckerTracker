/* ============================================================================
   MODULE: CT.util — primitives, deterministic RNG, formatting
   ========================================================================= */
window.CT = window.CT || {};
CT.util = (function () {
  'use strict';

  let idSeq = 0;
  const uid = (p) => (p || 'id') + '_' + (++idSeq).toString(36) + Math.floor(performance.now() % 1000).toString(36);

  const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));
  const sum = (arr, f) => arr.reduce((a, x) => a + (f ? f(x) : x), 0);

  function groupBy(arr, keyFn) {
    const out = new Map();
    for (const x of arr) {
      const k = keyFn(x);
      if (!out.has(k)) out.set(k, []);
      out.get(k).push(x);
    }
    return out;
  }

  function sortBy(arr, keyFn, dir) {
    const d = dir === 'desc' ? -1 : 1;
    return arr.slice().sort((a, b) => {
      const ka = keyFn(a), kb = keyFn(b);
      if (ka === kb) return 0;
      if (ka === null || ka === undefined) return 1;
      if (kb === null || kb === undefined) return -1;
      return (ka > kb ? 1 : -1) * d;
    });
  }

  function debounce(fn, ms) {
    let t = null;
    return function () {
      const args = arguments, self = this;
      clearTimeout(t);
      t = setTimeout(() => fn.apply(self, args), ms);
    };
  }

  /* -- Deterministic PRNG ---------------------------------------------------
     Every simulated value in this app is derived from a seeded generator so
     that a given scope + profile + run always produces identical output. This
     is what makes "simulated" reproducible and auditable rather than random
     noise dressed up as a result.                                          */
  function seedFrom(str) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h >>> 0;
  }

  function rng(seed) {
    let a = (typeof seed === 'string' ? seedFrom(seed) : seed >>> 0) || 1;
    const next = function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    next.int = (lo, hi) => lo + Math.floor(next() * (hi - lo + 1));
    next.pick = (arr) => arr[Math.floor(next() * arr.length)];
    next.chance = (p) => next() < p;
    next.shuffle = (arr) => {
      const a2 = arr.slice();
      for (let i = a2.length - 1; i > 0; i--) {
        const j = Math.floor(next() * (i + 1));
        const tmp = a2[i]; a2[i] = a2[j]; a2[j] = tmp;
      }
      return a2;
    };
    next.sample = (arr, n) => next.shuffle(arr).slice(0, n);
    return next;
  }

  /* -- Formatting ---------------------------------------------------------- */
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  function pad2(n) { return n < 10 ? '0' + n : '' + n; }

  function fmtDate(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + d.getFullYear();
  }
  function fmtDateTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return fmtDate(ts) + ', ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
  }
  function fmtTime(ts) {
    const d = new Date(ts);
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }
  function fmtClock(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const m = Math.floor(s / 60), h = Math.floor(m / 60);
    if (h > 0) return h + ':' + pad2(m % 60) + ':' + pad2(s % 60);
    return pad2(m) + ':' + pad2(s % 60);
  }
  function fmtDuration(ms) {
    const s = Math.floor(ms / 1000);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + (s % 60) + 's';
    return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
  }
  function fmtRelative(ts) {
    if (!ts) return 'never';
    const diff = Date.now() - ts;
    if (diff < 0) return 'in ' + fmtDuration(-diff);
    if (diff < 45000) return 'just now';
    const m = Math.floor(diff / 60000);
    if (m < 60) return m + ' min ago';
    const h = Math.floor(m / 60);
    if (h < 24) return h + (h === 1 ? ' hour ago' : ' hours ago');
    const d = Math.floor(h / 24);
    if (d < 30) return d + (d === 1 ? ' day ago' : ' days ago');
    return fmtDate(ts);
  }
  function fmtNum(n) {
    if (n === null || n === undefined || Number.isNaN(n)) return '—';
    return n.toLocaleString('en-US');
  }
  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function plural(n, one, many) {
    return n + ' ' + (n === 1 ? one : (many || one + 's'));
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }
  function escapeCsv(v) {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function titleCase(s) {
    return String(s).replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(() => true).catch(() => fallbackCopy(text));
    }
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:-1000px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e) { return false; }
  }

  return {
    uid, clamp, sum, groupBy, sortBy, debounce,
    rng, seedFrom,
    fmtDate, fmtDateTime, fmtTime, fmtClock, fmtDuration, fmtRelative,
    fmtNum, fmtBytes, plural, pad2, MONTHS,
    escapeHtml, escapeCsv, titleCase, copyText
  };
})();
