/* ============================================================================
   MODULE: CT.engines.analyzer — rule evaluation over observed assets
   Turns observations into findings. Purely defensive: every rule describes a
   configuration state and how to correct it. No rule attempts, encourages or
   automates exploitation, authentication or access of any kind.
   ========================================================================= */
CT.engines.analyzer = (function () {
  'use strict';

  const REMOTE_DESKTOP = [3389, 5900];
  const CLEARTEXT_MGMT = [23, 21, 5985, 2375, 69, 1080];
  const ADMIN_EXTRA = [22, 5986, 623, 6443, 8006, 9090, 10000, 2376, 5555, 902, 5601];
  const DATABASE = [1433, 1521, 3306, 5432, 6379, 9200, 27017, 11211];
  const DISCOVERY = [1900, 5353, 137];
  const IOT_OPEN = [1883, 554, 5000, 49152];
  const NONSTANDARD_ON_CLIENT = [3128, 1080, 32400, 5000, 8080];

  function ev(label, value) { return { label, value: String(value) }; }
  function svcLabel(s) {
    const ref = CT.data.portInfo(s.port);
    return s.port + '/' + s.proto + '  ' + (ref ? ref.name : (s.name || 'unknown')) +
           (s.product ? '  (' + s.product + (s.version ? ' ' + s.version : '') + ')' : '');
  }

  function mkFinding(asset, issue, ctx) {
    const rule = CT.data.rule(issue.ruleId);
    const severity = issue.severity || rule.severity;
    const disc = issue.key || '';
    return {
      id: issue.ruleId + '|' + (asset ? asset.id : 'env') + (disc ? '|' + disc : ''),
      ruleId: issue.ruleId,
      title: rule.title,
      severity,
      category: rule.category,
      assetId: asset ? asset.id : null,
      assetLabel: asset ? (asset.hostname || asset.ip) : (ctx && ctx.envName) || 'Environment',
      assetIp: asset ? asset.ip : null,
      service: issue.service || null,
      confidence: issue.confidence || 'medium',
      detail: issue.detail || null,
      // Rule prose (description, impact, remediation, references) is NOT
      // copied onto each finding — it is resolved from the catalog via
      // CT.data.rule(ruleId) at display time. Duplicating it here would
      // multiply the stored payload several-fold on a large estate.
      evidence: issue.evidence || [],
      discoveredAt: (ctx && ctx.at) || Date.now(),
      status: 'open',
      assignee: null,
      notes: [],
      simulated: !!(ctx && ctx.simulated)
    };
  }

  /**
   * @param {Array}  assets
   * @param {object} opts { network, at, simulated, baseline (previous assets) }
   * @returns {Array} findings
   */
  function analyze(assets, opts) {
    const o = opts || {};
    const ctx = { at: o.at || Date.now(), simulated: !!o.simulated, envName: o.network ? o.network.name : 'Environment' };
    const findings = [];
    const push = (asset, issue) => findings.push(mkFinding(asset, issue, ctx));

    const baselineMap = new Map();
    if (o.baseline) o.baseline.forEach((a) => baselineMap.set(a.id, a));

    const hasWorkstations = assets.some((a) => CT.data.DEVICE_GROUP[a.deviceType] === 'workstations');

    assets.forEach((asset) => {
      const services = asset.services || [];
      const portsOpen = services.map((s) => s.port);
      const has = (p) => portsOpen.indexOf(p) !== -1;

      /* --- TLS -------------------------------------------------------- */
      if (asset.tls) {
        // The name a client would use: the asset hostname qualified with the
        // segment's search domain, unless it is already fully qualified.
        const domain = o.network && o.network.domain;
        const hostForMatch = asset.hostname
          ? (asset.hostname.indexOf('.') !== -1
            ? asset.hostname.toLowerCase()
            : (domain ? asset.hostname.toLowerCase() + '.' + domain : asset.hostname.toLowerCase()))
          : null;
        CT.engines.tls.evaluate(asset.tls, hostForMatch).forEach((i) => {
          i.service = asset.tls.port + '/tcp TLS';
          i.key = 'tls' + asset.tls.port + (i.detail ? '' : '');
          push(asset, i);
        });
      }

      /* --- Web -------------------------------------------------------- */
      if (asset.http) {
        CT.engines.web.evaluate(asset.http).forEach((i) => {
          i.service = asset.http.port + '/tcp ' + (asset.http.scheme || 'http').toUpperCase();
          i.key = 'http' + asset.http.port;
          push(asset, i);
        });
      }

      /* --- Remote desktop --------------------------------------------- */
      const rdp = services.filter((s) => REMOTE_DESKTOP.indexOf(s.port) !== -1);
      rdp.forEach((s) => {
        push(asset, {
          ruleId: 'CT-CFG-003', confidence: 'high', key: 'p' + s.port,
          service: s.port + '/' + s.proto,
          severity: s.port === 5900 ? 'high' : 'high',
          detail: (CT.data.portInfo(s.port) || {}).name + ' is reachable on ' + asset.ip + '.',
          evidence: [ev('Service', svcLabel(s)), ev('Host', asset.ip),
                     ev('Device type', asset.deviceType),
                     ev('Transport encryption', s.port === 5900 ? 'Not guaranteed by the protocol' : 'TLS (RDP security layer)')]
        });
      });

      /* --- Cleartext management --------------------------------------- */
      const clear = services.filter((s) => CLEARTEXT_MGMT.indexOf(s.port) !== -1);
      if (clear.length) {
        push(asset, {
          ruleId: 'CT-NET-002', confidence: 'high', key: 'clear',
          service: clear.map((s) => s.port + '/' + s.proto).join(', '),
          detail: clear.length + ' cleartext management service(s) reachable.',
          evidence: clear.map((s) => ev('Service', svcLabel(s)))
            .concat([ev('Encrypted alternative', 'SSH (22), HTTPS (443), SNMPv3, WinRM over HTTPS (5986)')])
        });
      }
      // SNMP v1/v2c is cleartext by construction.
      const snmp = services.find((s) => s.port === 161);
      if (snmp && (!snmp.version || /^v?[12]/.test(String(snmp.version)))) {
        push(asset, {
          ruleId: 'CT-NET-002', confidence: snmp.version ? 'high' : 'medium', key: 'snmp',
          service: '161/udp SNMP',
          severity: 'medium',
          detail: 'SNMP ' + (snmp.version || 'version not determined') + ' transmits community strings without encryption.',
          evidence: [ev('Service', svcLabel(snmp)),
                     ev('Version indicator', snmp.version || 'not determined'),
                     ev('Recommended', 'SNMPv3 with authPriv')]
        });
      }

      /* --- Other administrative services ------------------------------- */
      const admin = services.filter((s) => ADMIN_EXTRA.indexOf(s.port) !== -1);
      if (admin.length) {
        const unauthRisk = admin.some((s) => [2375, 5555, 623, 10000, 5601].indexOf(s.port) !== -1);
        push(asset, {
          ruleId: 'CT-NET-001',
          severity: unauthRisk ? 'high' : (asset.deviceType === 'Server' || asset.deviceType === 'Router' ||
                    asset.deviceType === 'Switch' || asset.deviceType === 'NAS') ? 'medium' : 'high',
          confidence: 'high', key: 'admin',
          service: admin.map((s) => s.port + '/' + s.proto).join(', '),
          detail: CT.util.plural(admin.length, 'administrative service') + ' reachable within the authorized scope.',
          evidence: admin.map((s) => ev('Service', svcLabel(s))).concat([
            ev('Host', asset.ip + (asset.hostname ? ' (' + asset.hostname + ')' : '')),
            ev('Device role', asset.deviceType),
            ev('Reachable from', 'Scan origin inside the authorized scope')
          ])
        });
      }

      /* --- Legacy SMB -------------------------------------------------- */
      if (has(445)) {
        const smb = services.find((s) => s.port === 445);
        // A dialect below 3 is the actual defect. Port 139 alongside 445 is a
        // supporting indicator, not a finding on its own — modern Windows
        // hosts commonly still listen on 139.
        const dialect = smb && smb.version ? parseFloat(smb.version) : null;
        const legacyDialect = dialect !== null && !Number.isNaN(dialect) && dialect < 3;
        const unknownWithNetbios = dialect === null && has(139);
        if (legacyDialect || unknownWithNetbios) {
          push(asset, {
            ruleId: 'CT-NET-003', confidence: legacyDialect ? 'high' : 'low', key: 'smb',
            severity: legacyDialect ? 'high' : 'medium',
            service: '445/tcp SMB',
            detail: legacyDialect
              ? 'Reported SMB dialect ' + smb.version + ' predates SMB 3.'
              : 'SMB dialect could not be determined and the legacy NetBIOS session service is also present.',
            evidence: [
              ev('SMB service', svcLabel(smb)),
              ev('Dialect indicator', smb && smb.version ? smb.version : 'not determined'),
              ev('NetBIOS session service', has(139) ? '139/tcp present' : 'not observed'),
              ev('Recommended', 'SMB 3.1.1 with signing and encryption required')
            ]
          });
        }
      }

      /* --- Databases on a client-bearing segment ----------------------- */
      const dbs = services.filter((s) => DATABASE.indexOf(s.port) !== -1);
      if (dbs.length && hasWorkstations) {
        push(asset, {
          ruleId: 'CT-NET-004', confidence: 'high', key: 'db',
          service: dbs.map((s) => s.port + '/' + s.proto).join(', '),
          detail: CT.util.plural(dbs.length, 'database listener') + ' reachable from a segment that also contains workstations.',
          evidence: dbs.map((s) => ev('Listener', svcLabel(s))).concat([
            ev('Segment', (o.network && o.network.subnet) || 'authorized scope'),
            ev('Workstations in segment', String(assets.filter((x) => CT.data.DEVICE_GROUP[x.deviceType] === 'workstations').length))
          ])
        });
      }

      /* --- Printers ---------------------------------------------------- */
      if (asset.deviceType === 'Printer') {
        const printerAdmin = services.filter((s) => [80, 443, 9100, 515, 631].indexOf(s.port) !== -1);
        if (printerAdmin.length) {
          push(asset, {
            ruleId: 'CT-NET-007', confidence: 'high', key: 'prn',
            service: printerAdmin.map((s) => s.port + '/' + s.proto).join(', '),
            detail: 'Printer management and raw print services are reachable from the general network.',
            evidence: printerAdmin.map((s) => ev('Service', svcLabel(s))).concat([
              ev('Raw print port', has(9100) ? '9100/tcp open — accepts unauthenticated jobs' : 'not observed')
            ])
          });
        }
      }

      /* --- IoT --------------------------------------------------------- */
      if (asset.deviceType === 'IoT' || asset.deviceType === 'Camera') {
        const iot = services.filter((s) => IOT_OPEN.indexOf(s.port) !== -1);
        if (iot.length) {
          push(asset, {
            ruleId: 'CT-NET-008', confidence: 'medium', key: 'iot',
            service: iot.map((s) => s.port + '/' + s.proto).join(', '),
            detail: 'IoT-class device exposes control services that commonly ship without authentication.',
            evidence: iot.map((s) => ev('Service', svcLabel(s))).concat([
              ev('Device type', asset.deviceType),
              ev('In inventory', asset.inInventory ? 'yes' : 'no'),
              ev('Note', 'No authentication was attempted. Verify manually within the authorized environment.')
            ])
          });
        }
      }

      /* --- Discovery protocols ----------------------------------------- */
      const disc = services.filter((s) => DISCOVERY.indexOf(s.port) !== -1);
      if (disc.length) {
        push(asset, {
          ruleId: 'CT-NET-009', confidence: 'high', key: 'disc',
          service: disc.map((s) => s.port + '/' + s.proto).join(', '),
          detail: CT.util.plural(disc.length, 'discovery service') + ' responding on the segment.',
          evidence: disc.map((s) => ev('Service', svcLabel(s)))
        });
      }

      /* --- Unnecessary services on client devices ----------------------- */
      const grp = CT.data.DEVICE_GROUP[asset.deviceType];
      if (grp === 'workstations' || grp === 'mobile') {
        const odd = services.filter((s) => NONSTANDARD_ON_CLIENT.indexOf(s.port) !== -1);
        if (odd.length) {
          push(asset, {
            ruleId: 'CT-NET-005', confidence: 'medium', key: 'extra',
            service: odd.map((s) => s.port + '/' + s.proto).join(', '),
            detail: 'Service(s) listening that are not typical for a ' + asset.deviceType.toLowerCase() + '.',
            evidence: odd.map((s) => ev('Service', svcLabel(s))).concat([ev('Device role', asset.deviceType)])
          });
        }
      }

      /* --- Inventory ---------------------------------------------------- */
      if (asset.inInventory === false) {
        push(asset, {
          ruleId: 'CT-INV-001', confidence: 'high', key: 'inv',
          detail: 'Device responded within the scope but is not recorded in the expected inventory.',
          evidence: [
            ev('IP address', asset.ip),
            ev('MAC address', asset.mac || 'not observed'),
            ev('Vendor (from OUI)', asset.vendor || 'not determined'),
            ev('Hostname', asset.hostname || 'not resolved'),
            ev('Device type', asset.deviceType),
            ev('First seen', new Date(asset.firstSeen).toISOString()),
            ev('Open services', services.length ? services.map((s) => s.port + '/' + s.proto).join(', ') : 'none observed')
          ]
        });
      }

      /* --- Default configuration ---------------------------------------- */
      const defaultHostname = asset.hostname && /^(esp[-_]|npi|hp[a-f0-9]{6}|android-|localhost|raspberrypi|new-host|printer|setup)/i.test(asset.hostname);
      const defaultIdentity = asset.http && asset.http.defaultIdentity;
      const defaultCertCN = asset.tls && asset.tls.cert && asset.tls.cert.selfSigned &&
                            asset.tls.cert.subjectCN && /^[0-9A-F]{10,14}$|^NPI|^root-bridge$/i.test(asset.tls.cert.subjectCN);
      if (defaultHostname || defaultIdentity || defaultCertCN) {
        const evd = [];
        if (defaultHostname) evd.push(ev('Hostname', asset.hostname + '  (matches a factory naming pattern)'));
        if (defaultIdentity) evd.push(ev('Web interface', (asset.http.title || 'default landing page') + '  (unmodified vendor page)'));
        if (defaultCertCN) evd.push(ev('Certificate subject', asset.tls.cert.subjectCN + '  (factory self-signed identity)'));
        evd.push(ev('Note', 'Configuration state only. No credentials were submitted or tested.'));
        push(asset, {
          ruleId: 'CT-CFG-001', confidence: (defaultHostname && defaultIdentity) ? 'high' : 'medium', key: 'default',
          detail: 'Indicators consistent with an unmodified factory configuration.',
          evidence: evd
        });
      }

      /* --- Outdated software indicators ---------------------------------- */
      const outdatedSvc = services.filter((s) => isOutdated(s));
      if (asset.outdatedIndicator || outdatedSvc.length || isOutdatedOs(asset.os)) {
        const evd = [];
        if (isOutdatedOs(asset.os)) evd.push(ev('Operating system banner', asset.os));
        outdatedSvc.forEach((s) => evd.push(ev('Service banner', svcLabel(s))));
        if (!evd.length) evd.push(ev('Indicator', 'Version metadata older than the current supported branch'));
        evd.push(ev('Confidence note', 'Derived from self-reported banners. Backported patches are not visible this way.'));
        push(asset, {
          ruleId: 'CT-CFG-002', confidence: 'low', key: 'outdated',
          detail: 'Version banners indicate a release older than the current supported branch.',
          evidence: evd
        });
      }

      /* --- Service drift vs baseline -------------------------------------- */
      if (baselineMap.size) {
        const prev = baselineMap.get(asset.id);
        if (prev) {
          const prevPorts = new Set((prev.services || []).map((s) => s.port + '/' + s.proto));
          const added = services.filter((s) => !prevPorts.has(s.port + '/' + s.proto));
          if (added.length) {
            push(asset, {
              ruleId: 'CT-NET-006', confidence: 'high', key: 'drift',
              service: added.map((s) => s.port + '/' + s.proto).join(', '),
              detail: CT.util.plural(added.length, 'service') + ' present now that was not observed in the previous assessment.',
              evidence: added.map((s) => ev('New service', svcLabel(s))).concat([
                ev('Previous assessment', new Date(o.baselineAt || Date.now()).toISOString()),
                ev('Previously observed', (prev.services || []).map((s) => s.port + '/' + s.proto).join(', ') || 'none')
              ])
            });
          }
        }
      }
    });

    /* --- Environment-level: segmentation --------------------------------- */
    const groups = new Set(assets.map((a) => CT.data.DEVICE_GROUP[a.deviceType]));
    if (groups.has('servers') && groups.has('workstations') && (groups.has('iot') || groups.has('network'))) {
      const counts = {};
      assets.forEach((a) => {
        const g = CT.data.DEVICE_GROUP[a.deviceType];
        counts[g] = (counts[g] || 0) + 1;
      });
      findings.push(mkFinding(null, {
        ruleId: 'CT-CFG-004', confidence: 'medium', key: 'seg',
        detail: 'Server, client and IoT-class devices share one broadcast domain.',
        evidence: [
          ev('Segment', (o.network && o.network.subnet) || 'authorized scope'),
          ev('Servers / NAS', String(counts.servers || 0)),
          ev('Workstations', String(counts.workstations || 0)),
          ev('Mobile', String(counts.mobile || 0)),
          ev('IoT / printers / cameras', String(counts.iot || 0)),
          ev('Network devices', String(counts.network || 0)),
          ev('Observation basis', 'All responding hosts fall inside a single IPv4 prefix with a shared gateway.')
        ]
      }, ctx));
    }

    findings.sort((a, b) => {
      const d = CT.data.SEV_RANK[a.severity] - CT.data.SEV_RANK[b.severity];
      return d !== 0 ? d : String(a.assetLabel).localeCompare(String(b.assetLabel));
    });
    return findings;
  }

  const OUTDATED_OS = [/Windows 10 Pro 21H2/i, /Windows 7/i, /Windows Server 2012/i,
                       /Ubuntu 18\.04/i, /Ubuntu 20\.04/i, /CentOS 7/i, /Debian 10/i];
  function isOutdatedOs(os) { return !!os && OUTDATED_OS.some((re) => re.test(os)); }

  const OUTDATED_SVC = [
    { product: /nginx/i, below: '1.22.0' },
    { product: /OpenSSH/i, below: '8.5' },
    { product: /Apache/i, below: '2.4.54' },
    { product: /Samba/i, below: '4.17' }
  ];
  function cmpVersion(a, b) {
    const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
    const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0);
      if (d !== 0) return d;
    }
    return 0;
  }
  function isOutdated(s) {
    if (!s.product || !s.version) return false;
    const m = OUTDATED_SVC.find((x) => x.product.test(s.product));
    if (!m) return false;
    const clean = String(s.version).replace(/[^0-9.].*$/, '');
    return cmpVersion(clean, m.below) < 0;
  }

  return { analyze, isOutdated, isOutdatedOs, cmpVersion };
})();
