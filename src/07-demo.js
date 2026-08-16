/* ============================================================================
   MODULE: CT.demo — simulated environments
   ---------------------------------------------------------------------------
   These datasets describe FICTIONAL systems inside RFC 1918 private address
   space with non-resolvable .internal hostnames. They do not represent, and
   cannot reach, any real system.

   Demo data supplies OBSERVATIONS only (hosts, services, banners, headers,
   certificate fields). Every finding, risk value and score shown in the app is
   computed from these observations by the analysis engines — exactly the same
   code path a real or imported dataset would take.
   ========================================================================= */
CT.demo = (function () {
  'use strict';

  const DAY = 86400000, HOUR = 3600000, MIN = 60000;

  function svc(port, proto, extra) {
    const ref = CT.data.portInfo(port);
    return Object.assign({
      port, proto: proto || 'tcp',
      name: ref ? ref.name : 'unknown',
      service: ref ? ref.service : 'Unidentified service',
      product: null, version: null, versionConfidence: null, banner: null
    }, extra || {});
  }

  function cert(o) {
    const now = Date.now();
    return Object.assign({
      subjectCN: null, subjectO: 'CheckerTracker Demo Lab (fictional)',
      issuerCN: 'CORP-LAB Internal Issuing CA', issuerO: 'CheckerTracker Demo Lab (fictional)',
      notBefore: now - 200 * DAY, notAfter: now + 165 * DAY,
      sigAlg: 'sha256WithRSA', keyAlg: 'RSA', keyBits: 2048,
      san: [], selfSigned: false, serial: '0a1b2c3d4e5f6071'
    }, o);
  }

  /* -- CORP-LAB: 18 assets ------------------------------------------------- */
  function corpLab() {
    const now = Date.now();
    const seen = (mins) => now - mins * MIN;
    const born = (days) => now - days * DAY;

    const network = {
      id: 'corp-lab',
      name: 'CORP-LAB',
      ssid: 'CORP-LAB-WIFI',
      security: 'WPA2-Enterprise (802.1X)',
      type: 'Wi-Fi 6 · 802.11ax',
      band: '5 GHz · channel 44 · 80 MHz',
      signal: -52,
      interface: 'en0 (Wi-Fi)',
      localIp: '192.168.1.57',
      localMac: 'AC:DE:48:11:9F:20',
      subnet: '192.168.1.0/24',
      netmask: '255.255.255.0',
      gateway: '192.168.1.1',
      dns: ['192.168.1.1', '9.9.9.9'],
      dhcp: '192.168.1.1',
      ipv4: '192.168.1.57/24',
      ipv6: 'fd7a:9c2e:41b0::57',
      ipv6Mode: 'ULA · fd00::/8 (no global IPv6)',
      vpn: 'Not connected',
      domain: 'corp-lab.internal',
      range: '192.168.1.1 – 192.168.1.254',
      mtu: 1500
    };

    const A = [];
    const add = (a) => { A.push(Object.assign({ inInventory: true, status: 'reachable', criticality: 'standard' }, a)); };

    add({
      id: 'a-gw-01', hostname: 'GW-EDGE-01', ip: '192.168.1.1',
      ipv6: 'fd7a:9c2e:41b0::1', mac: '74:AC:B9:2E:11:04', deviceType: 'Router',
      os: 'EdgeOS 2.0.9', osConfidence: 'high', owner: 'Network Operations', criticality: 'critical',
      firstSeen: born(412), lastSeen: seen(2),
      services: [
        svc(22, 'tcp', { product: 'OpenSSH', version: '8.2p1', versionConfidence: 'high', banner: 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5' }),
        svc(53, 'udp', { product: 'dnsmasq', version: '2.80', versionConfidence: 'medium' }),
        svc(80, 'tcp', { product: 'lighttpd', version: '1.4.55', versionConfidence: 'medium' }),
        svc(443, 'tcp', { product: 'lighttpd', version: '1.4.55', versionConfidence: 'medium' }),
        svc(1900, 'udp', {})
      ],
      http: {
        port: 80, scheme: 'http', status: 200, redirect: null, server: 'lighttpd/1.4.55',
        headers: { 'server': 'lighttpd/1.4.55', 'content-type': 'text/html' },
        cookies: [{ name: 'X-CSRF-TOKEN', secure: false, httpOnly: false, sameSite: null }],
        title: 'EdgeRouter — Login'
      },
      tls: {
        port: 443, protocols: ['TLSv1.2'], minProtocol: 'TLSv1.2',
        cipher: 'ECDHE-RSA-AES128-GCM-SHA256',
        cert: cert({ subjectCN: 'GW-EDGE-01.corp-lab.internal', issuerCN: 'GW-EDGE-01.corp-lab.internal',
                     selfSigned: true, keyBits: 2048, notAfter: now + 640 * DAY, san: ['GW-EDGE-01.corp-lab.internal'] })
      },
      tags: ['gateway', 'managed']
    });

    add({
      id: 'a-web-01', hostname: 'WEB-SERVER-01', ip: '192.168.1.20',
      ipv6: 'fd7a:9c2e:41b0::14', mac: '00:50:56:9A:3C:71', deviceType: 'Server',
      os: 'Ubuntu 22.04.3 LTS', osConfidence: 'high', owner: 'Platform Engineering', criticality: 'high',
      firstSeen: born(298), lastSeen: seen(1),
      services: [
        svc(22, 'tcp', { product: 'OpenSSH', version: '8.9p1', versionConfidence: 'high', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4' }),
        svc(80, 'tcp', { product: 'nginx', version: '1.18.0', versionConfidence: 'high' }),
        svc(443, 'tcp', { product: 'nginx', version: '1.18.0', versionConfidence: 'high' })
      ],
      http: {
        port: 443, scheme: 'https', status: 200, redirect: null, server: 'nginx/1.18.0 (Ubuntu)',
        headers: {
          'server': 'nginx/1.18.0 (Ubuntu)', 'x-powered-by': 'PHP/8.1.2',
          'x-frame-options': 'SAMEORIGIN', 'content-type': 'text/html; charset=UTF-8'
        },
        cookies: [{ name: 'PHPSESSID', secure: true, httpOnly: false, sameSite: null }],
        title: 'CORP-LAB Intranet Portal',
        plaintextPort80: { status: 200, redirects: false }
      },
      tls: {
        port: 443, protocols: ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'], minProtocol: 'TLSv1.0',
        cipher: 'ECDHE-RSA-AES256-GCM-SHA384',
        cert: cert({ subjectCN: 'web-server-01.corp-lab.internal', keyBits: 2048,
                     notAfter: now + 47 * DAY, san: ['web-server-01.corp-lab.internal', 'intranet.corp-lab.internal'] })
      },
      tags: ['web', 'production']
    });

    add({
      id: 'a-db-01', hostname: 'DB-SERVER-01', ip: '192.168.1.21',
      ipv6: 'fd7a:9c2e:41b0::15', mac: '0C:C4:7A:18:BB:2E', deviceType: 'Server',
      os: 'Debian 12 (bookworm)', osConfidence: 'high', owner: 'Platform Engineering', criticality: 'critical',
      firstSeen: born(298), lastSeen: seen(1),
      services: [
        svc(22, 'tcp', { product: 'OpenSSH', version: '9.2p1', versionConfidence: 'high', banner: 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2' }),
        svc(5432, 'tcp', { product: 'PostgreSQL', version: '15.4', versionConfidence: 'medium' }),
        svc(9090, 'tcp', { product: 'Cockpit', version: '287', versionConfidence: 'low' })
      ],
      tls: null, http: null,
      tags: ['database', 'production']
    });

    add({
      id: 'a-nas-01', hostname: 'NAS-ARCHIVE-01', ip: '192.168.1.30',
      ipv6: 'fd7a:9c2e:41b0::1e', mac: '00:11:32:6D:04:A9', deviceType: 'NAS',
      os: 'Synology DSM 7.1', osConfidence: 'medium', owner: 'IT Operations', criticality: 'high',
      firstSeen: born(365), lastSeen: seen(4),
      services: [
        svc(22, 'tcp', { product: 'OpenSSH', version: '8.2p1', versionConfidence: 'medium' }),
        svc(139, 'tcp', {}),
        svc(445, 'tcp', { product: 'Samba', version: '4.15.13', versionConfidence: 'medium' }),
        svc(443, 'tcp', { product: 'nginx', version: '1.20.1', versionConfidence: 'medium' }),
        svc(2049, 'tcp', {}),
        svc(5000, 'tcp', { product: 'Synology DSM', version: null, versionConfidence: null })
      ],
      http: {
        port: 443, scheme: 'https', status: 200, redirect: null, server: 'nginx',
        headers: { 'server': 'nginx', 'x-content-type-options': 'nosniff', 'content-type': 'text/html' },
        cookies: [{ name: 'id', secure: false, httpOnly: true, sameSite: null }],
        title: 'DiskStation Manager'
      },
      tls: {
        port: 443, protocols: ['TLSv1.2', 'TLSv1.3'], minProtocol: 'TLSv1.2',
        cipher: 'TLS_AES_256_GCM_SHA384',
        cert: cert({ subjectCN: 'nas-archive-01.corp-lab.internal', keyBits: 2048,
                     notBefore: now - 430 * DAY, notAfter: now - 12 * DAY,
                     san: ['nas-archive-01.corp-lab.internal'] })
      },
      tags: ['storage', 'backup']
    });

    add({
      id: 'a-prn-01', hostname: 'PRN-FLOOR2-01', ip: '192.168.1.40',
      ipv6: null, mac: 'F0:92:1C:55:3D:80', deviceType: 'Printer',
      os: 'HP FutureSmart 5', osConfidence: 'medium', owner: 'Facilities', criticality: 'low',
      firstSeen: born(365), lastSeen: seen(18),
      services: [
        svc(80, 'tcp', { product: 'HP Embedded Web Server', version: null }),
        svc(161, 'udp', { product: 'SNMP', version: 'v2c', versionConfidence: 'medium' }),
        svc(443, 'tcp', { product: 'HP Embedded Web Server', version: null }),
        svc(515, 'tcp', {}),
        svc(631, 'tcp', {}),
        svc(9100, 'tcp', {})
      ],
      http: {
        port: 80, scheme: 'http', status: 200, redirect: null, server: 'HP HTTP Server; HP LaserJet',
        headers: { 'server': 'HP HTTP Server; HP LaserJet M507 - 2.4.5' },
        cookies: [], title: 'HP LaserJet M507 — Home', defaultIdentity: true
      },
      tls: {
        port: 443, protocols: ['TLSv1.0', 'TLSv1.2'], minProtocol: 'TLSv1.0',
        cipher: 'AES128-SHA',
        cert: cert({ subjectCN: 'NPI553D80', issuerCN: 'NPI553D80', selfSigned: true,
                     keyBits: 1024, sigAlg: 'sha1WithRSA', notAfter: now + 1200 * DAY, san: [] })
      },
      tags: ['printer']
    });

    add({
      id: 'a-iot-01', hostname: 'esp-hvac-ctrl', ip: '192.168.1.60',
      ipv6: null, mac: '24:0A:C4:7B:E1:0C', deviceType: 'IoT',
      os: null, osConfidence: null, owner: null, criticality: 'low',
      inInventory: false,
      firstSeen: born(6), lastSeen: seen(9),
      services: [
        svc(80, 'tcp', { product: 'ESP-IDF httpd', version: null }),
        svc(1883, 'tcp', {}),
        svc(5353, 'udp', {})
      ],
      http: {
        port: 80, scheme: 'http', status: 200, redirect: null, server: null,
        headers: { 'content-type': 'text/html' }, cookies: [], title: 'HVAC Controller', defaultIdentity: true
      },
      tls: null,
      tags: ['iot', 'unmanaged']
    });

    add({
      id: 'a-iot-02', hostname: 'HUE-BRIDGE-01', ip: '192.168.1.61',
      ipv6: null, mac: '00:17:88:41:9C:33', deviceType: 'IoT',
      os: 'Hue Bridge BSB002', osConfidence: 'medium', owner: 'Facilities', criticality: 'low',
      firstSeen: born(210), lastSeen: seen(7),
      services: [
        svc(80, 'tcp', { product: 'nginx', version: null }),
        svc(443, 'tcp', { product: 'nginx', version: null }),
        svc(1900, 'udp', {}),
        svc(5353, 'udp', {})
      ],
      http: {
        port: 80, scheme: 'http', status: 200, redirect: null, server: 'nginx',
        headers: { 'server': 'nginx' }, cookies: [], title: 'Hue personal wireless lighting'
      },
      tls: {
        port: 443, protocols: ['TLSv1.2'], minProtocol: 'TLSv1.2', cipher: 'ECDHE-RSA-AES128-GCM-SHA256',
        cert: cert({ subjectCN: '001788419C33', issuerCN: 'root-bridge', selfSigned: true, keyBits: 2048,
                     notAfter: now + 900 * DAY, san: [] })
      },
      tags: ['iot']
    });

    /* Workstations */
    const WKS = [
      { id: 'a-wks-01', hostname: 'LT-ENG-014', ip: '192.168.1.100', mac: '18:03:73:2A:5F:11', type: 'Laptop',
        vendorOs: 'Windows 11 Pro 23H2', owner: 'Engineering', ports: [135, 139, 445, 3389], first: 240, last: 3 },
      { id: 'a-wks-02', hostname: 'LT-ENG-021', ip: '192.168.1.101', mac: 'A8:66:7F:31:C2:48', type: 'Laptop',
        vendorOs: 'macOS 14.5', owner: 'Engineering', ports: [22], first: 190, last: 5 },
      { id: 'a-wks-03', hostname: 'WS-FIN-007', ip: '192.168.1.102', mac: '54:EE:75:09:B3:2C', type: 'Desktop',
        vendorOs: 'Windows 11 Pro 23H2', owner: 'Finance', ports: [135, 139, 445], first: 330, last: 6 },
      { id: 'a-wks-04', hostname: 'WS-FIN-009', ip: '192.168.1.103', mac: '54:EE:75:09:B3:71', type: 'Desktop',
        vendorOs: 'Windows 10 Pro 21H2', owner: 'Finance', ports: [135, 139, 445, 5985], first: 330, last: 6, outdated: true },
      { id: 'a-wks-05', hostname: 'LT-MKT-003', ip: '192.168.1.104', mac: '40:B3:95:7D:1E:90', type: 'Laptop',
        vendorOs: 'macOS 14.5', owner: 'Marketing', ports: [], first: 150, last: 22 },
      { id: 'a-wks-06', hostname: 'LT-OPS-011', ip: '192.168.1.105', mac: 'B8:2A:72:44:0A:6D', type: 'Laptop',
        vendorOs: 'Ubuntu 24.04 LTS', owner: 'IT Operations', ports: [22], first: 120, last: 2 },
      { id: 'a-wks-07', hostname: 'WS-LAB-002', ip: '192.168.1.106', mac: 'AC:22:0B:66:12:F4', type: 'Desktop',
        vendorOs: 'Windows 11 Pro 23H2', owner: 'Engineering', ports: [135, 139, 445, 5900], first: 280, last: 4 },
      { id: 'a-wks-08', hostname: 'LT-SUP-018', ip: '192.168.1.107', mac: '80:C1:6E:2D:77:A1', type: 'Laptop',
        vendorOs: 'Windows 11 Pro 23H2', owner: 'Support', ports: [135, 139, 445], first: 95, last: 11 }
    ];
    WKS.forEach((w) => {
      add({
        id: w.id, hostname: w.hostname, ip: w.ip, ipv6: null, mac: w.mac, deviceType: w.type,
        os: w.vendorOs, osConfidence: 'medium', owner: w.owner, criticality: 'standard',
        firstSeen: born(w.first), lastSeen: seen(w.last),
        services: w.ports.map((p) => svc(p, 'tcp', p === 3389 ? { product: 'Microsoft Terminal Services', version: null }
          : p === 5900 ? { product: 'RealVNC', version: '6.7.2', versionConfidence: 'low' }
          : p === 445 ? { product: 'Microsoft SMB', version: w.outdated ? '2.1' : '3.1.1', versionConfidence: 'medium' }
          : p === 22 ? { product: 'OpenSSH', version: '9.6p1', versionConfidence: 'medium' } : {})),
        tls: null, http: null,
        outdatedIndicator: !!w.outdated,
        tags: ['workstation']
      });
    });

    /* Mobile devices */
    add({
      id: 'a-mob-01', hostname: 'MOB-IOS-004', ip: '192.168.1.120', ipv6: null,
      mac: '84:38:35:0C:2B:19', deviceType: 'Smartphone', os: 'iOS 18.1', osConfidence: 'low',
      owner: 'Engineering', firstSeen: born(140), lastSeen: seen(14), services: [], tls: null, http: null,
      tags: ['mobile', 'managed']
    });
    add({
      id: 'a-mob-02', hostname: 'android-8f21c4', ip: '192.168.1.121', ipv6: null,
      mac: '78:BD:BC:4E:71:02', deviceType: 'Smartphone', os: 'Android 14', osConfidence: 'low',
      owner: null, inInventory: false, firstSeen: born(2), lastSeen: seen(26),
      services: [svc(5555, 'tcp', { product: 'Android Debug Bridge', version: null })],
      tls: null, http: null, tags: ['mobile', 'byod']
    });
    add({
      id: 'a-mob-03', hostname: null, ip: '192.168.1.122', ipv6: null,
      mac: 'B2:41:9E:03:7C:5A', deviceType: 'Smartphone', os: null, osConfidence: null,
      owner: null, firstSeen: born(48), lastSeen: seen(41), services: [], tls: null, http: null,
      tags: ['mobile']
    });

    A.forEach((a) => {
      a.vendor = CT.data.lookupVendor(a.mac);
      a.services.sort((x, y) => x.port - y.port);
    });

    return { network, assets: A };
  }

  /* -- Derive the previous assessment snapshot -----------------------------
     Produces a coherent "one week ago" view so Comparison Mode diffs two real
     snapshots rather than displaying hardcoded deltas.                     */
  const PREV_REMOVED_ASSETS = ['a-iot-01', 'a-mob-02', 'a-wks-08'];   // appear as NEW today
  const PREV_EXTRA_ASSET_ID = 'a-legacy-01';                           // existed then, gone today
  const PREV_REMOVED_SERVICES = [                                      // appear as NEW today
    { assetId: 'a-web-01', port: 80 },
    { assetId: 'a-wks-01', port: 3389 },
    { assetId: 'a-wks-07', port: 5900 },
    { assetId: 'a-nas-01', port: 2049 }
  ];

  function previousSnapshot(current) {
    const now = Date.now();
    const at = now - 7 * DAY;
    const isCorpLab = current.network && current.network.id === 'corp-lab';

    // For CORP-LAB the deltas are hand-authored so the demo tells a coherent
    // story. Any other environment gets an equivalent set derived
    // deterministically from its own contents.
    let removedIds = PREV_REMOVED_ASSETS;
    let removedServices = PREV_REMOVED_SERVICES;
    if (!isCorpLab) {
      const r = CT.util.rng('prev-' + ((current.network && current.network.id) || 'env'));
      const withServices = current.assets.filter((a) => (a.services || []).length > 1);
      removedIds = r.sample(current.assets.map((a) => a.id), Math.min(3, current.assets.length));
      removedServices = r.sample(withServices, Math.min(4, withServices.length)).map((a) => ({
        assetId: a.id, port: a.services[a.services.length - 1].port
      }));
    }

    const assets = current.assets
      .filter((a) => removedIds.indexOf(a.id) === -1)
      .map((a) => {
        const copy = JSON.parse(JSON.stringify(a));
        copy.lastSeen = at - (now - a.lastSeen);
        copy.services = copy.services.filter((s) =>
          !removedServices.some((r) => r.assetId === a.id && r.port === s.port));
        // A week ago the NAS certificate had not yet expired and the printer
        // had not yet been re-enrolled with a SHA-1 certificate.
        if (copy.id === 'a-nas-01' && copy.tls) copy.tls.cert.notAfter = at + 5 * DAY;
        if (copy.id === 'a-prn-01' && copy.tls) { copy.tls.cert.sigAlg = 'sha256WithRSA'; copy.tls.cert.keyBits = 2048; }
        if (copy.id === 'a-web-01' && copy.http) { delete copy.http.plaintextPort80; }
        if (copy.id === 'a-wks-04') copy.outdatedIndicator = false;
        return copy;
      });

    // One device that existed a week ago and has since left the network.
    const retiredIp = freeAddress(current.network, current.assets.map((a) => a.ip));
    if (retiredIp) {
      assets.push({
        id: PREV_EXTRA_ASSET_ID, hostname: 'LT-CONTRACT-002', ip: retiredIp,
        ipv6: null, mac: '00:21:CC:7E:44:B0', vendor: 'Lenovo', deviceType: 'Laptop',
        os: 'Windows 11 Pro 23H2', osConfidence: 'medium', owner: 'Contractor', criticality: 'standard',
        inInventory: false, status: 'reachable',
        firstSeen: at - 20 * DAY, lastSeen: at - 2 * HOUR,
        services: [svc(135, 'tcp'), svc(139, 'tcp'), svc(445, 'tcp', { product: 'Microsoft SMB', version: '2.1', versionConfidence: 'medium' })],
        tls: null, http: null, tags: ['workstation', 'contractor']
      });
    }

    const network = Object.assign({}, current.network);
    return { network, assets, at };
  }

  /** Highest unused host address inside the network, or null if none is free. */
  function freeAddress(network, taken) {
    if (!network || !network.subnet) return null;
    try {
      const info = CT.net.cidrInfo(network.subnet);
      const used = new Set(taken);
      for (let n = info.broadcastInt - 1; n > info.networkInt; n--) {
        const ip = CT.net.intToIp(n);
        if (!used.has(ip)) return ip;
      }
    } catch (e) { /* unparseable subnet — no retired asset */ }
    return null;
  }

  /* -- Large lab: 520 assets for list-virtualisation and map density ------- */
  function largeLab() {
    const r = CT.util.rng('CORP-LAB-LARGE-v1');
    const now = Date.now();
    const network = {
      id: 'corp-lab-large', name: 'CORP-LAB-DC', ssid: null,
      security: 'Wired · 802.1X', type: 'Ethernet · 1 GbE',
      band: null, signal: null, interface: 'eth0',
      localIp: '10.20.0.9', localMac: 'AC:DE:48:11:9F:20',
      subnet: '10.20.0.0/22', netmask: '255.255.252.0', gateway: '10.20.0.1',
      dns: ['10.20.0.2', '10.20.0.3'], dhcp: '10.20.0.2',
      ipv4: '10.20.0.9/22', ipv6: 'fd7a:9c2e:41b0:20::9',
      ipv6Mode: 'ULA · fd00::/8', vpn: 'Not connected',
      domain: 'dc.corp-lab.internal', range: '10.20.0.1 – 10.20.3.254', mtu: 1500
    };

    const MIX = [
      { type: 'Desktop', n: 210, prefix: 'WS', ports: [[135, 139, 445], [135, 139, 445], [135, 139, 445, 5985]] },
      { type: 'Laptop', n: 130, prefix: 'LT', ports: [[], [22], [135, 139, 445]] },
      { type: 'Smartphone', n: 60, prefix: 'MOB', ports: [[], [], [5555]] },
      { type: 'Server', n: 48, prefix: 'SRV', ports: [[22, 443], [22, 80, 443], [22, 3306], [22, 5432], [22, 445, 139]] },
      { type: 'Printer', n: 22, prefix: 'PRN', ports: [[80, 161, 515, 631, 9100]] },
      { type: 'IoT', n: 20, prefix: 'IOT', ports: [[80, 1883], [80, 1900, 5353]] },
      { type: 'Camera', n: 12, prefix: 'CAM', ports: [[80, 554], [80, 443, 554]] },
      { type: 'NAS', n: 6, prefix: 'NAS', ports: [[22, 139, 445, 443, 2049]] },
      { type: 'Switch', n: 6, prefix: 'SW', ports: [[22, 161, 443]] },
      { type: 'Tablet', n: 4, prefix: 'TAB', ports: [[]] },
      { type: 'Unknown', n: 2, prefix: null, ports: [[80], [23, 80]] }
    ];

    const VENDOR_BY_TYPE = {
      Desktop: ['00:21:CC', '54:EE:75', '18:03:73', '80:C1:6E'],
      Laptop: ['A8:66:7F', '40:B3:95', 'B8:2A:72', 'E4:54:E8'],
      Smartphone: ['84:38:35', '78:BD:BC', '64:09:80', '94:65:2D'],
      Server: ['00:50:56', '0C:C4:7A', 'AC:1F:6B', '3C:EC:EF'],
      Printer: ['F0:92:1C', '00:80:77', '00:1E:8F', '00:26:AB'],
      IoT: ['24:0A:C4', '30:AE:A4', '00:17:88', '5C:AA:FD'],
      Camera: ['00:40:8C', '44:19:B6', 'AC:CC:8E'],
      NAS: ['00:11:32', '00:08:9B', '00:90:A9'],
      Switch: ['00:1B:0C', '18:E8:29', '4C:5E:0C'],
      Tablet: ['A8:66:7F', '00:26:73'],
      Unknown: ['B6:22:41', 'AE:19:03']
    };
    const OS_BY_TYPE = {
      Desktop: ['Windows 11 Pro 23H2', 'Windows 11 Pro 22H2', 'Windows 10 Pro 21H2'],
      Laptop: ['macOS 14.5', 'Windows 11 Pro 23H2', 'Ubuntu 24.04 LTS'],
      Smartphone: ['iOS 18.1', 'Android 14', 'Android 13'],
      Server: ['Ubuntu 22.04.3 LTS', 'Debian 12 (bookworm)', 'Windows Server 2022', 'RHEL 9.3'],
      Printer: ['HP FutureSmart 5', 'Brother Firmware R', null],
      IoT: [null, 'ESP-IDF 4.4'], Camera: ['Axis OS 11.6', null],
      NAS: ['Synology DSM 7.2', 'QTS 5.1'], Switch: ['EdgeSwitch 1.9', 'IOS-XE 17.9'],
      Tablet: ['iPadOS 17.6', 'Android 13'], Unknown: [null]
    };

    // Allocate unique host offsets inside 10.20.0.0/22 so every generated
    // address genuinely falls within the declared scope.
    const TOTAL = MIX.reduce((acc, m) => acc + m.n, 0);
    const baseInt = CT.net.ipToInt('10.20.0.0');
    const pool = [];
    for (let o = 5; o <= 1020; o++) pool.push(o);
    const slots = r.shuffle(pool).slice(0, TOTAL).sort((x, y) => x - y);

    const assets = [];
    let n = 0;
    MIX.forEach((m) => {
      for (let i = 0; i < m.n; i++) {
        n++;
        const ip = CT.net.intToIp(baseInt + slots[n - 1]);
        const macPfx = r.pick(VENDOR_BY_TYPE[m.type]);
        const mac = macPfx + ':' + [r.int(0, 255), r.int(0, 255), r.int(0, 255)]
          .map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
        const ports = r.pick(m.ports);
        const seq = String(i + 1).padStart(3, '0');
        const inInv = m.type === 'Unknown' ? false : r.chance(0.955);
        const a = {
          id: 'lg-' + n,
          hostname: m.prefix ? m.prefix + '-DC' + seq : null,
          ip: ip,
          ipv6: null, mac, deviceType: m.type,
          os: r.pick(OS_BY_TYPE[m.type]), osConfidence: r.pick(['low', 'medium', 'high']),
          owner: inInv ? r.pick(['IT Operations', 'Engineering', 'Finance', 'Facilities', 'Support']) : null,
          criticality: m.type === 'Server' ? r.pick(['high', 'critical', 'standard']) : 'standard',
          inInventory: inInv, status: r.chance(0.94) ? 'reachable' : 'unreachable',
          firstSeen: now - r.int(3, 400) * DAY, lastSeen: now - r.int(1, 240) * MIN,
          services: ports.map((p) => svc(p, p === 161 || p === 1900 || p === 5353 ? 'udp' : 'tcp')),
          tls: null, http: null,
          outdatedIndicator: r.chance(0.08),
          tags: [m.type.toLowerCase()]
        };
        if (ports.indexOf(443) !== -1) {
          const expired = r.chance(0.07);
          const soon = !expired && r.chance(0.12);
          a.tls = {
            port: 443,
            protocols: r.chance(0.18) ? ['TLSv1.0', 'TLSv1.2'] : ['TLSv1.2', 'TLSv1.3'],
            minProtocol: r.chance(0.18) ? 'TLSv1.0' : 'TLSv1.2',
            cipher: 'ECDHE-RSA-AES256-GCM-SHA384',
            cert: cert({
              subjectCN: (a.hostname || a.ip).toLowerCase() + '.dc.corp-lab.internal',
              selfSigned: r.chance(0.22),
              keyBits: r.chance(0.05) ? 1024 : 2048,
              sigAlg: r.chance(0.04) ? 'sha1WithRSA' : 'sha256WithRSA',
              notAfter: now + (expired ? -r.int(1, 60) : soon ? r.int(1, 25) : r.int(60, 500)) * DAY,
              san: [(a.hostname || a.ip).toLowerCase() + '.dc.corp-lab.internal']
            })
          };
        }
        if (ports.indexOf(80) !== -1) {
          const hdr = { 'content-type': 'text/html' };
          if (r.chance(0.6)) hdr['server'] = r.pick(['nginx/1.24.0', 'Apache/2.4.52 (Ubuntu)', 'lighttpd/1.4.55', 'Microsoft-IIS/10.0']);
          if (r.chance(0.35)) hdr['x-content-type-options'] = 'nosniff';
          if (r.chance(0.2)) hdr['strict-transport-security'] = 'max-age=31536000';
          if (r.chance(0.12)) hdr['content-security-policy'] = "default-src 'self'";
          a.http = {
            port: 80, scheme: 'http', status: 200,
            redirect: r.chance(0.4) ? 'https://' + (a.hostname || a.ip) + '/' : null,
            server: hdr['server'] || null, headers: hdr,
            cookies: r.chance(0.4) ? [{ name: 'session', secure: r.chance(0.5), httpOnly: r.chance(0.6), sameSite: r.chance(0.4) ? 'Lax' : null }] : [],
            title: null,
            defaultIdentity: m.type === 'Printer' || m.type === 'IoT' ? r.chance(0.5) : false
          };
        }
        assets.push(a);
      }
    });
    assets.forEach((a) => { a.vendor = CT.data.lookupVendor(a.mac); });
    return { network, assets };
  }

  const ENVIRONMENTS = [
    { id: 'corp-lab', name: 'CORP-LAB', desc: '18 assets · single /24 office segment', build: corpLab },
    { id: 'corp-lab-large', name: 'CORP-LAB-DC', desc: '520 assets · /22 datacentre segment', build: largeLab }
  ];

  function build(id) {
    const e = ENVIRONMENTS.find((x) => x.id === id) || ENVIRONMENTS[0];
    return e.build();
  }

  return { ENVIRONMENTS, build, previousSnapshot, corpLab, largeLab, svc, cert };
})();
