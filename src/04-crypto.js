/* ============================================================================
   MODULE: CT.crypto — real cryptographic utilities
     - SHA-256 / SHA-1 via WebCrypto (genuine)
     - MD5 implemented locally (genuine; WebCrypto does not expose MD5)
     - AES-GCM vault with PBKDF2 key derivation for at-rest encryption
     - DER / X.509 certificate parser (genuine offline certificate analysis)

   This module intentionally contains NO password recovery, NO hash reversal
   and NO key extraction capability. Hashing is one-way by construction.
   ========================================================================= */
CT.crypto = (function () {
  'use strict';

  const enc = new TextEncoder();
  const subtle = (window.crypto && window.crypto.subtle) ? window.crypto.subtle : null;

  function toHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }
  function fromHex(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const out = new Uint8Array(clean.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }
  function b64encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function b64decode(str) {
    const bin = atob(str.replace(/\s+/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* -- MD5 (RFC 1321) ------------------------------------------------------ */
  const MD5_K = new Int32Array(64);
  for (let i = 0; i < 64; i++) MD5_K[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0;
  const MD5_S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];

  function md5Bytes(input) {
    const len = input.length;
    const total = (((len + 8) >> 6) + 1) << 6;
    const msg = new Uint8Array(total);
    msg.set(input);
    msg[len] = 0x80;
    const dv = new DataView(msg.buffer);
    dv.setUint32(total - 8, (len << 3) >>> 0, true);
    dv.setUint32(total - 4, Math.floor(len / 536870912) >>> 0, true);

    let a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
    const M = new Int32Array(16);
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true) | 0;
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * i) & 15; }
        F = (F + A + MD5_K[i] + M[g]) | 0;
        A = D; D = C; C = B;
        const s = MD5_S[i];
        B = (B + ((F << s) | (F >>> (32 - s)))) | 0;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, a0 >>> 0, true); odv.setUint32(4, b0 >>> 0, true);
    odv.setUint32(8, c0 >>> 0, true); odv.setUint32(12, d0 >>> 0, true);
    return out;
  }

  function md5(text) { return toHex(md5Bytes(enc.encode(text))); }

  async function digest(algo, data) {
    const bytes = typeof data === 'string' ? enc.encode(data) : data;
    if (algo === 'MD5') return toHex(md5Bytes(bytes));
    if (!subtle) throw new Error('WebCrypto unavailable in this context (requires a secure origin).');
    const buf = await subtle.digest(algo, bytes);
    return toHex(new Uint8Array(buf));
  }

  const sha256 = (d) => digest('SHA-256', d);
  const sha1 = (d) => digest('SHA-1', d);
  const sha384 = (d) => digest('SHA-384', d);
  const sha512 = (d) => digest('SHA-512', d);

  /* -- At-rest vault (AES-GCM + PBKDF2) ------------------------------------
     Used when the user enables an app passcode. Scan data is serialised,
     encrypted and only then written to local storage.                      */
  async function deriveKey(passphrase, salt, iterations) {
    if (!subtle) throw new Error('WebCrypto unavailable');
    const base = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iterations || 210000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function seal(passphrase, plaintextObj) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    const data = enc.encode(JSON.stringify(plaintextObj));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { v: 1, kdf: 'PBKDF2-SHA256', iter: 210000, alg: 'AES-GCM-256',
             salt: b64encode(salt), iv: b64encode(iv), ct: b64encode(new Uint8Array(ct)) };
  }

  async function open(passphrase, envelope) {
    const salt = b64decode(envelope.salt);
    const iv = b64decode(envelope.iv);
    const key = await deriveKey(passphrase, salt, envelope.iter);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, b64decode(envelope.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  /* -- ASN.1 / DER parser --------------------------------------------------- */
  function parseDER(bytes, offset, end) {
    const nodes = [];
    let p = offset;
    while (p < end) {
      const start = p;
      const tag = bytes[p++];
      if (p >= end) break;
      let len = bytes[p++];
      if (len & 0x80) {
        const nBytes = len & 0x7f;
        if (nBytes === 0 || nBytes > 4) throw new Error('Unsupported DER length encoding');
        len = 0;
        for (let i = 0; i < nBytes; i++) len = (len << 8) | bytes[p++];
      }
      const contentStart = p;
      const contentEnd = p + len;
      if (contentEnd > end) throw new Error('DER length exceeds buffer');
      const constructed = (tag & 0x20) !== 0;
      const node = {
        tag, cls: (tag & 0xc0) >> 6, constructed, tagNo: tag & 0x1f,
        start, contentStart, contentEnd,
        bytes: bytes.subarray(contentStart, contentEnd),
        children: constructed ? parseDER(bytes, contentStart, contentEnd) : null
      };
      nodes.push(node);
      p = contentEnd;
    }
    return nodes;
  }

  function oidToString(bytes) {
    if (!bytes.length) return '';
    const first = bytes[0];
    const parts = [Math.floor(first / 40), first % 40];
    let val = 0;
    for (let i = 1; i < bytes.length; i++) {
      val = val * 128 + (bytes[i] & 0x7f);
      if (!(bytes[i] & 0x80)) { parts.push(val); val = 0; }
    }
    return parts.join('.');
  }

  const OIDS = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.5': 'sha1WithRSA',
    '1.2.840.113549.1.1.11': 'sha256WithRSA', '1.2.840.113549.1.1.12': 'sha384WithRSA',
    '1.2.840.113549.1.1.13': 'sha512WithRSA', '1.2.840.113549.1.1.4': 'md5WithRSA',
    '1.2.840.10045.2.1': 'EC', '1.2.840.10045.4.3.2': 'ecdsaWithSHA256',
    '1.2.840.10045.4.3.3': 'ecdsaWithSHA384', '1.2.840.10045.4.3.1': 'ecdsaWithSHA1',
    '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
    '1.3.101.112': 'Ed25519',
    '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.15': 'keyUsage',
    '2.5.29.17': 'subjectAltName', '2.5.29.19': 'basicConstraints',
    '2.5.29.31': 'cRLDistributionPoints', '2.5.29.32': 'certificatePolicies',
    '2.5.29.35': 'authorityKeyIdentifier', '2.5.29.37': 'extKeyUsage',
    '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
    '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth'
  };
  const oidName = (o) => OIDS[o] || o;

  function derTime(node) {
    const s = new TextDecoder().decode(node.bytes);
    let y, mo, d, h, mi, sec;
    if (node.tagNo === 23) { // UTCTime YYMMDDhhmmssZ
      const yy = parseInt(s.slice(0, 2), 10);
      y = yy >= 50 ? 1900 + yy : 2000 + yy;
      mo = +s.slice(2, 4); d = +s.slice(4, 6); h = +s.slice(6, 8); mi = +s.slice(8, 10); sec = +s.slice(10, 12) || 0;
    } else { // GeneralizedTime YYYYMMDDhhmmssZ
      y = +s.slice(0, 4); mo = +s.slice(4, 6); d = +s.slice(6, 8);
      h = +s.slice(8, 10); mi = +s.slice(10, 12); sec = +s.slice(12, 14) || 0;
    }
    return Date.UTC(y, mo - 1, d, h, mi, sec);
  }

  function rdnToString(nameNode) {
    const out = [];
    (nameNode.children || []).forEach((rdnSet) => {
      (rdnSet.children || []).forEach((atv) => {
        const kids = atv.children || [];
        if (kids.length < 2) return;
        const key = oidName(oidToString(kids[0].bytes));
        const val = new TextDecoder().decode(kids[1].bytes);
        out.push(key + '=' + val);
      });
    });
    return out.join(', ');
  }
  function rdnField(str, key) {
    const m = new RegExp('(?:^|, )' + key + '=([^,]*)').exec(str);
    return m ? m[1] : null;
  }

  function parseSAN(bytes) {
    const names = [];
    try {
      const seq = parseDER(bytes, 0, bytes.length)[0];
      (seq.children || []).forEach((n) => {
        if (n.tagNo === 2) names.push(new TextDecoder().decode(n.bytes));           // dNSName
        else if (n.tagNo === 7) {                                                     // iPAddress
          if (n.bytes.length === 4) names.push(Array.from(n.bytes).join('.'));
        } else if (n.tagNo === 1) names.push(new TextDecoder().decode(n.bytes));    // rfc822Name
        else if (n.tagNo === 6) names.push(new TextDecoder().decode(n.bytes));      // URI
      });
    } catch (e) { /* malformed extension — reported by caller as unparsed */ }
    return names;
  }

  const KEY_USAGE_BITS = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
                          'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];

  function parseKeyUsage(bytes) {
    try {
      const bs = parseDER(bytes, 0, bytes.length)[0];
      const unused = bs.bytes[0];
      const data = bs.bytes.subarray(1);
      const bits = [];
      const totalBits = data.length * 8 - unused;
      for (let i = 0; i < totalBits && i < KEY_USAGE_BITS.length; i++) {
        if (data[i >> 3] & (0x80 >> (i & 7))) bits.push(KEY_USAGE_BITS[i]);
      }
      return bits;
    } catch (e) { return []; }
  }

  function pemToDer(pem) {
    const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
    const body = m ? m[1] : pem;
    if (!/^[A-Za-z0-9+/=\s]+$/.test(body.trim())) throw new Error('Input is not valid PEM/base64 certificate data.');
    return b64decode(body);
  }

  /**
   * Parse an X.509 certificate from PEM or DER. Fully local — nothing leaves
   * the device. Returns structured fields plus derived validity state.
   */
  function parseCertificate(pemOrDer) {
    const der = typeof pemOrDer === 'string' ? pemToDer(pemOrDer) : pemOrDer;
    const root = parseDER(der, 0, der.length)[0];
    if (!root || !root.constructed) throw new Error('Not a DER SEQUENCE — unrecognised certificate structure.');
    const tbs = root.children[0];
    const sigAlgNode = root.children[1];

    let i = 0;
    let version = 1;
    if (tbs.children[0].cls === 2 && tbs.children[0].tagNo === 0) {
      version = (tbs.children[0].children[0].bytes[0] || 0) + 1;
      i = 1;
    }
    const serialNode = tbs.children[i++];
    tbs.children[i++]; // inner signature algorithm (must match outer)
    const issuerNode = tbs.children[i++];
    const validityNode = tbs.children[i++];
    const subjectNode = tbs.children[i++];
    const spkiNode = tbs.children[i++];

    const notBefore = derTime(validityNode.children[0]);
    const notAfter = derTime(validityNode.children[1]);

    // Public key details
    let keyAlg = 'unknown', keyBits = null, curve = null;
    try {
      const algSeq = spkiNode.children[0];
      keyAlg = oidName(oidToString(algSeq.children[0].bytes));
      if (keyAlg === 'RSA') {
        const bitStr = spkiNode.children[1];
        const inner = parseDER(bitStr.bytes, 1, bitStr.bytes.length)[0];
        let mod = inner.children[0].bytes;
        if (mod[0] === 0x00) mod = mod.subarray(1);
        keyBits = mod.length * 8;
      } else if (keyAlg === 'EC') {
        curve = oidName(oidToString(algSeq.children[1].bytes));
        keyBits = curve === 'P-256' ? 256 : curve === 'P-384' ? 384 : curve === 'P-521' ? 521 : null;
      }
    } catch (e) { /* key details are best-effort */ }

    // Extensions
    const ext = { san: [], basicConstraints: null, keyUsage: [], extKeyUsage: [], all: [] };
    for (let k = i; k < tbs.children.length; k++) {
      const n = tbs.children[k];
      if (n.cls === 2 && n.tagNo === 3) {
        const extSeq = n.children[0];
        (extSeq.children || []).forEach((e) => {
          const kids = e.children || [];
          if (!kids.length) return;
          const oid = oidToString(kids[0].bytes);
          const critical = kids.length > 2 || (kids[1] && kids[1].tagNo === 1 && kids[1].bytes[0] === 0xff);
          const valNode = kids[kids.length - 1];
          ext.all.push({ oid, name: oidName(oid), critical: !!critical });
          if (oid === '2.5.29.17') ext.san = parseSAN(valNode.bytes);
          else if (oid === '2.5.29.15') ext.keyUsage = parseKeyUsage(valNode.bytes);
          else if (oid === '2.5.29.19') {
            try {
              const bc = parseDER(valNode.bytes, 0, valNode.bytes.length)[0];
              const isCa = bc.children && bc.children.length && bc.children[0].tagNo === 1 && bc.children[0].bytes[0] === 0xff;
              ext.basicConstraints = { ca: !!isCa };
            } catch (e2) { /* ignore */ }
          } else if (oid === '2.5.29.37') {
            try {
              const eku = parseDER(valNode.bytes, 0, valNode.bytes.length)[0];
              ext.extKeyUsage = (eku.children || []).map((c) => oidName(oidToString(c.bytes)));
            } catch (e2) { /* ignore */ }
          }
        });
      }
    }

    const issuer = rdnToString(issuerNode);
    const subject = rdnToString(subjectNode);
    const sigAlg = oidName(oidToString(sigAlgNode.children[0].bytes));
    const now = Date.now();

    return {
      version,
      serial: toHex(serialNode.bytes).replace(/^00/, ''),
      issuer, subject,
      issuerCN: rdnField(issuer, 'CN'), issuerO: rdnField(issuer, 'O'),
      subjectCN: rdnField(subject, 'CN'), subjectO: rdnField(subject, 'O'),
      notBefore, notAfter,
      selfSigned: issuer === subject,
      expired: now > notAfter,
      notYetValid: now < notBefore,
      daysRemaining: Math.floor((notAfter - now) / 86400000),
      validityDays: Math.round((notAfter - notBefore) / 86400000),
      sigAlg, keyAlg, keyBits, curve,
      san: ext.san,
      keyUsage: ext.keyUsage,
      extKeyUsage: ext.extKeyUsage,
      basicConstraints: ext.basicConstraints,
      extensions: ext.all,
      der
    };
  }

  /** RFC 6125-style wildcard hostname match against CN/SAN entries. */
  function hostnameMatches(host, names) {
    const h = String(host).toLowerCase().replace(/\.$/, '');
    return names.some((n) => {
      const p = String(n).toLowerCase().replace(/\.$/, '');
      if (p === h) return true;
      if (p.startsWith('*.')) {
        const suffix = p.slice(1);                 // ".example.com"
        if (!h.endsWith(suffix)) return false;
        const left = h.slice(0, h.length - suffix.length);
        return left.length > 0 && left.indexOf('.') === -1;
      }
      return false;
    });
  }

  return {
    toHex, fromHex, b64encode, b64decode,
    md5, md5Bytes, sha1, sha256, sha384, sha512, digest,
    seal, open, available: !!subtle,
    parseDER, oidToString, oidName, parseCertificate, pemToDer, hostnameMatches
  };
})();
