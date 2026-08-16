/* ============================================================================
   MODULE: CT.data — reference databases
     - OUI → vendor lookup
     - TCP/UDP port & service reference
     - Defensive finding catalog (descriptions, impact, remediation)
   ========================================================================= */
CT.data = (function () {
  'use strict';

  /* -- OUI prefixes (first three octets) ----------------------------------- */
  const OUI = {
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:1C:14': 'VMware',
    '08:00:27': 'Oracle VirtualBox', '00:15:5D': 'Microsoft (Hyper-V)',
    '52:54:00': 'QEMU/KVM',
    '00:1B:63': 'Apple', 'F0:18:98': 'Apple', 'A8:66:7F': 'Apple', '40:B3:95': 'Apple',
    '84:38:35': 'Apple', 'C8:2A:14': 'Apple', '98:01:A7': 'Apple', '00:1E:C2': 'Apple',
    '3C:5A:B4': 'Google', '54:60:09': 'Google', 'F4:F5:D8': 'Google', '1C:F2:9A': 'Google',
    '18:B4:30': 'Google Nest',
    'B8:27:EB': 'Raspberry Pi Foundation', 'DC:A6:32': 'Raspberry Pi Trading',
    'E4:5F:01': 'Raspberry Pi Trading', 'D8:3A:DD': 'Raspberry Pi Trading',
    '24:0A:C4': 'Espressif', '30:AE:A4': 'Espressif', 'A4:CF:12': 'Espressif', '7C:9E:BD': 'Espressif',
    '00:17:88': 'Signify (Philips Hue)', 'EC:B5:FA': 'Signify (Philips Hue)',
    '00:0E:58': 'Sonos', '5C:AA:FD': 'Sonos',
    '44:65:0D': 'Amazon Technologies', 'F0:D2:F1': 'Amazon Technologies', '68:37:E9': 'Amazon Technologies',
    '00:11:32': 'Synology', '00:08:9B': 'QNAP', '00:90:A9': 'Western Digital', '00:14:EE': 'Western Digital',
    '00:1D:7E': 'Cisco-Linksys', '00:1B:0C': 'Cisco Systems', '00:0A:41': 'Cisco Systems',
    'E0:D1:73': 'Cisco Systems', '70:1F:53': 'Cisco Systems', '00:18:0A': 'Cisco Meraki',
    '88:15:44': 'Cisco Meraki', 'E0:CB:BC': 'Cisco Meraki',
    '18:E8:29': 'Ubiquiti', '74:AC:B9': 'Ubiquiti', 'F4:92:BF': 'Ubiquiti', '44:D9:E7': 'Ubiquiti',
    'FC:EC:DA': 'Ubiquiti', '78:8A:20': 'Ubiquiti', '24:5A:4C': 'Ubiquiti', '68:D7:9A': 'Ubiquiti',
    '4C:5E:0C': 'MikroTik', '48:8F:5A': 'MikroTik', 'DC:2C:6E': 'MikroTik', '2C:C8:1B': 'MikroTik',
    '00:09:0F': 'Fortinet', '08:5B:0E': 'Fortinet', '70:4C:A5': 'Fortinet',
    '00:0B:86': 'Aruba Networks', '24:DE:C6': 'Aruba Networks', '6C:F3:7F': 'Aruba Networks',
    'B0:7F:B9': 'Netgear', 'A0:63:91': 'Netgear', '9C:3D:CF': 'Netgear', '00:0F:B5': 'Netgear',
    '50:C7:BF': 'TP-Link', 'A4:2B:B0': 'TP-Link', 'C4:6E:1F': 'TP-Link',
    '00:1A:A0': 'Dell', '18:03:73': 'Dell', 'B8:2A:72': 'Dell', '00:26:B9': 'Dell',
    '48:4D:7E': 'Dell', '54:BF:64': 'Dell', 'D0:67:E5': 'Dell', 'F8:BC:12': 'Dell', '14:18:77': 'Dell',
    '00:1B:78': 'Hewlett Packard', '3C:D9:2B': 'Hewlett Packard', '2C:59:E5': 'Hewlett Packard',
    '80:C1:6E': 'Hewlett Packard', 'B4:99:BA': 'Hewlett Packard', 'EC:9A:74': 'Hewlett Packard',
    'F0:92:1C': 'HP (Imaging)', '9C:8E:99': 'HP (Imaging)', '00:21:5A': 'HP (Imaging)',
    '00:25:90': 'Super Micro', '0C:C4:7A': 'Super Micro', 'AC:1F:6B': 'Super Micro', '3C:EC:EF': 'Super Micro',
    '00:1F:3B': 'Intel', 'A4:BB:6D': 'Intel', '34:13:E8': 'Intel', '8C:16:45': 'Intel',
    '5C:51:4F': 'Intel', '7C:7A:91': 'Intel', 'C4:D9:87': 'Intel', 'E4:A7:A0': 'Intel',
    '00:21:CC': 'Lenovo', '54:EE:75': 'Lenovo', 'E4:54:E8': 'Lenovo', 'F0:DE:F1': 'Lenovo',
    '28:18:78': 'Microsoft', '50:1A:C5': 'Microsoft',
    '50:EB:F6': 'ASUSTek', '1C:87:2C': 'ASUSTek', 'AC:22:0B': 'ASUSTek', 'F4:6D:04': 'ASUSTek',
    '00:26:73': 'Samsung', '78:BD:BC': 'Samsung', '5C:0A:5B': 'Samsung',
    '64:09:80': 'Xiaomi', '28:6C:07': 'Xiaomi', '94:65:2D': 'OnePlus', 'C0:EE:FB': 'OnePlus',
    '00:80:77': 'Brother Industries', '30:05:5C': 'Brother Industries',
    '00:1E:8F': 'Canon', '88:87:17': 'Canon', '00:26:AB': 'Seiko Epson', 'A4:EE:57': 'Seiko Epson',
    '00:17:C8': 'Kyocera', '00:00:74': 'Ricoh', '00:04:00': 'Lexmark', '00:07:4D': 'Zebra Technologies',
    '00:40:8C': 'Axis Communications', 'AC:CC:8E': 'Axis Communications',
    '44:19:B6': 'Hangzhou Hikvision', 'C0:56:E3': 'Hangzhou Hikvision',
    '00:0E:8C': 'Siemens', '00:1B:1B': 'Siemens', '00:80:F4': 'Schneider Electric',
    '00:D0:2D': 'Honeywell', '00:04:F2': 'Polycom'
  };

  function lookupVendor(mac) {
    if (!mac) return null;
    const pfx = String(mac).toUpperCase().replace(/-/g, ':').split(':').slice(0, 3).join(':');
    if (OUI[pfx]) return OUI[pfx];
    // Locally administered addresses (bit 1 of first octet) indicate randomisation.
    const first = parseInt(String(mac).slice(0, 2), 16);
    if (!Number.isNaN(first) && (first & 0x02)) return 'Randomised (locally administered)';
    return null;
  }

  /* -- Port / service reference -------------------------------------------- */
  const PORTS = [
    { port: 20, proto: 'tcp', name: 'FTP-DATA', service: 'File Transfer', category: 'File', encrypted: false, admin: false, note: 'Legacy data channel for FTP. Transmits file contents in cleartext.' },
    { port: 21, proto: 'tcp', name: 'FTP', service: 'File Transfer', category: 'File', encrypted: false, admin: false, note: 'Credentials and data travel unencrypted. Prefer SFTP or FTPS.' },
    { port: 22, proto: 'tcp', name: 'SSH', service: 'Remote Administration', category: 'Admin', encrypted: true, admin: true, note: 'Encrypted remote shell. Restrict to management networks and prefer key-based authentication.' },
    { port: 23, proto: 'tcp', name: 'Telnet', service: 'Remote Administration', category: 'Admin', encrypted: false, admin: true, note: 'Cleartext remote shell. Should be disabled on all modern equipment.' },
    { port: 25, proto: 'tcp', name: 'SMTP', service: 'Mail Transfer', category: 'Mail', encrypted: false, admin: false, note: 'Mail transfer. Verify STARTTLS is offered and relaying is restricted.' },
    { port: 53, proto: 'tcp/udp', name: 'DNS', service: 'Name Resolution', category: 'Infrastructure', encrypted: false, admin: false, note: 'Name resolution. Open resolvers can be abused for amplification.' },
    { port: 67, proto: 'udp', name: 'DHCP', service: 'Address Assignment', category: 'Infrastructure', encrypted: false, admin: false, note: 'Server side of DHCP. Unexpected DHCP servers indicate rogue devices.' },
    { port: 69, proto: 'udp', name: 'TFTP', service: 'File Transfer', category: 'File', encrypted: false, admin: false, note: 'Unauthenticated file transfer, often used for device firmware.' },
    { port: 80, proto: 'tcp', name: 'HTTP', service: 'Web Server', category: 'Web', encrypted: false, admin: false, note: 'Cleartext web. Should redirect to HTTPS.' },
    { port: 88, proto: 'tcp/udp', name: 'Kerberos', service: 'Authentication', category: 'Directory', encrypted: true, admin: false, note: 'Kerberos KDC — indicates a domain controller.' },
    { port: 110, proto: 'tcp', name: 'POP3', service: 'Mail Retrieval', category: 'Mail', encrypted: false, admin: false, note: 'Cleartext mail retrieval. Prefer POP3S/993 IMAPS.' },
    { port: 111, proto: 'tcp/udp', name: 'rpcbind', service: 'RPC Portmapper', category: 'Infrastructure', encrypted: false, admin: false, note: 'Enumerates RPC services. Rarely needed outside NFS deployments.' },
    { port: 123, proto: 'udp', name: 'NTP', service: 'Time Sync', category: 'Infrastructure', encrypted: false, admin: false, note: 'Time synchronisation. Restrict monlist/mode 6 queries.' },
    { port: 135, proto: 'tcp', name: 'MSRPC', service: 'Windows RPC', category: 'Windows', encrypted: false, admin: false, note: 'Windows endpoint mapper. Should never be internet reachable.' },
    { port: 137, proto: 'udp', name: 'NetBIOS-NS', service: 'Name Service', category: 'Windows', encrypted: false, admin: false, note: 'Legacy Windows name service. Disable where not required.' },
    { port: 139, proto: 'tcp', name: 'NetBIOS-SSN', service: 'Session Service', category: 'Windows', encrypted: false, admin: false, note: 'Legacy SMB transport. Indicates older SMB configuration.' },
    { port: 143, proto: 'tcp', name: 'IMAP', service: 'Mail Retrieval', category: 'Mail', encrypted: false, admin: false, note: 'Cleartext unless STARTTLS is enforced.' },
    { port: 161, proto: 'udp', name: 'SNMP', service: 'Monitoring', category: 'Admin', encrypted: false, admin: true, note: 'SNMP v1/v2c uses cleartext community strings. Prefer SNMPv3.' },
    { port: 162, proto: 'udp', name: 'SNMP-TRAP', service: 'Monitoring', category: 'Admin', encrypted: false, admin: true, note: 'Trap receiver for SNMP notifications.' },
    { port: 389, proto: 'tcp', name: 'LDAP', service: 'Directory', category: 'Directory', encrypted: false, admin: false, note: 'Directory access. Enforce LDAPS or StartTLS for binds.' },
    { port: 443, proto: 'tcp', name: 'HTTPS', service: 'Web Server', category: 'Web', encrypted: true, admin: false, note: 'TLS-protected web service. Review certificate and protocol configuration.' },
    { port: 445, proto: 'tcp', name: 'SMB', service: 'File Sharing', category: 'File', encrypted: false, admin: false, note: 'Windows file sharing. Require SMBv3 with signing; never expose externally.' },
    { port: 465, proto: 'tcp', name: 'SMTPS', service: 'Mail Submission', category: 'Mail', encrypted: true, admin: false, note: 'Implicit TLS mail submission.' },
    { port: 500, proto: 'udp', name: 'ISAKMP', service: 'VPN', category: 'VPN', encrypted: true, admin: false, note: 'IKE key exchange for IPsec VPN.' },
    { port: 514, proto: 'udp', name: 'syslog', service: 'Logging', category: 'Infrastructure', encrypted: false, admin: false, note: 'Cleartext log transport. Consider TLS syslog (6514).' },
    { port: 515, proto: 'tcp', name: 'LPD', service: 'Printing', category: 'Print', encrypted: false, admin: false, note: 'Legacy line printer daemon.' },
    { port: 548, proto: 'tcp', name: 'AFP', service: 'File Sharing', category: 'File', encrypted: false, admin: false, note: 'Apple Filing Protocol, deprecated in favour of SMB.' },
    { port: 554, proto: 'tcp', name: 'RTSP', service: 'Media Streaming', category: 'IoT', encrypted: false, admin: false, note: 'Camera/video stream control. Frequently unauthenticated by default.' },
    { port: 587, proto: 'tcp', name: 'Submission', service: 'Mail Submission', category: 'Mail', encrypted: true, admin: false, note: 'Authenticated mail submission with STARTTLS.' },
    { port: 623, proto: 'udp', name: 'IPMI', service: 'Out-of-band Management', category: 'Admin', encrypted: false, admin: true, note: 'Baseboard management controller. Isolate on a dedicated management VLAN.' },
    { port: 631, proto: 'tcp', name: 'IPP', service: 'Printing', category: 'Print', encrypted: false, admin: false, note: 'Internet Printing Protocol; often exposes an administrative web UI.' },
    { port: 636, proto: 'tcp', name: 'LDAPS', service: 'Directory', category: 'Directory', encrypted: true, admin: false, note: 'TLS-protected directory access.' },
    { port: 873, proto: 'tcp', name: 'rsync', service: 'File Sync', category: 'File', encrypted: false, admin: false, note: 'Often configured without authentication.' },
    { port: 902, proto: 'tcp', name: 'VMware', service: 'Hypervisor Agent', category: 'Admin', encrypted: false, admin: true, note: 'ESXi/host agent channel.' },
    { port: 993, proto: 'tcp', name: 'IMAPS', service: 'Mail Retrieval', category: 'Mail', encrypted: true, admin: false, note: 'TLS-protected IMAP.' },
    { port: 995, proto: 'tcp', name: 'POP3S', service: 'Mail Retrieval', category: 'Mail', encrypted: true, admin: false, note: 'TLS-protected POP3.' },
    { port: 1080, proto: 'tcp', name: 'SOCKS', service: 'Proxy', category: 'Proxy', encrypted: false, admin: false, note: 'Open proxies allow traffic laundering through the network.' },
    { port: 1194, proto: 'udp', name: 'OpenVPN', service: 'VPN', category: 'VPN', encrypted: true, admin: false, note: 'VPN endpoint.' },
    { port: 1433, proto: 'tcp', name: 'MSSQL', service: 'Database', category: 'Database', encrypted: false, admin: false, note: 'Microsoft SQL Server. Databases should not be reachable from user subnets.' },
    { port: 1521, proto: 'tcp', name: 'Oracle', service: 'Database', category: 'Database', encrypted: false, admin: false, note: 'Oracle TNS listener.' },
    { port: 1723, proto: 'tcp', name: 'PPTP', service: 'VPN', category: 'VPN', encrypted: false, admin: false, note: 'Obsolete VPN protocol with known cryptographic weaknesses.' },
    { port: 1883, proto: 'tcp', name: 'MQTT', service: 'IoT Messaging', category: 'IoT', encrypted: false, admin: false, note: 'Cleartext IoT broker. Prefer MQTTS (8883) with authentication.' },
    { port: 1900, proto: 'udp', name: 'SSDP', service: 'Service Discovery', category: 'IoT', encrypted: false, admin: false, note: 'UPnP discovery. Can be abused for reflection attacks.' },
    { port: 2049, proto: 'tcp', name: 'NFS', service: 'File Sharing', category: 'File', encrypted: false, admin: false, note: 'Network file system. Verify export lists and root squashing.' },
    { port: 2375, proto: 'tcp', name: 'Docker', service: 'Container API', category: 'Admin', encrypted: false, admin: true, note: 'Unauthenticated Docker daemon API. Must never be exposed.' },
    { port: 2376, proto: 'tcp', name: 'Docker-TLS', service: 'Container API', category: 'Admin', encrypted: true, admin: true, note: 'TLS Docker daemon API; still an administrative endpoint.' },
    { port: 3128, proto: 'tcp', name: 'Squid', service: 'Proxy', category: 'Proxy', encrypted: false, admin: false, note: 'HTTP proxy. Confirm access control lists.' },
    { port: 3268, proto: 'tcp', name: 'GC', service: 'Global Catalog', category: 'Directory', encrypted: false, admin: false, note: 'Active Directory global catalog.' },
    { port: 3306, proto: 'tcp', name: 'MySQL', service: 'Database', category: 'Database', encrypted: false, admin: false, note: 'MySQL/MariaDB. Bind to localhost or a database VLAN.' },
    { port: 3389, proto: 'tcp', name: 'RDP', service: 'Remote Desktop', category: 'Admin', encrypted: true, admin: true, note: 'Remote Desktop. Require NLA and restrict source networks.' },
    { port: 5000, proto: 'tcp', name: 'UPnP/HTTP-alt', service: 'Application', category: 'Web', encrypted: false, admin: false, note: 'Commonly a device UI or development server.' },
    { port: 5060, proto: 'tcp/udp', name: 'SIP', service: 'VoIP Signalling', category: 'VoIP', encrypted: false, admin: false, note: 'Cleartext VoIP signalling; a frequent brute-force target.' },
    { port: 5353, proto: 'udp', name: 'mDNS', service: 'Service Discovery', category: 'Infrastructure', encrypted: false, admin: false, note: 'Multicast DNS. Leaks hostnames and service inventory on the local segment.' },
    { port: 5432, proto: 'tcp', name: 'PostgreSQL', service: 'Database', category: 'Database', encrypted: false, admin: false, note: 'PostgreSQL. Review pg_hba.conf and network binding.' },
    { port: 5555, proto: 'tcp', name: 'ADB', service: 'Debug Bridge', category: 'Admin', encrypted: false, admin: true, note: 'Android Debug Bridge. Should never be enabled on production devices.' },
    { port: 5601, proto: 'tcp', name: 'Kibana', service: 'Analytics UI', category: 'Web', encrypted: false, admin: true, note: 'Analytics console; often deployed without authentication.' },
    { port: 5900, proto: 'tcp', name: 'VNC', service: 'Remote Desktop', category: 'Admin', encrypted: false, admin: true, note: 'Remote framebuffer. Weak or absent authentication is common.' },
    { port: 5985, proto: 'tcp', name: 'WinRM', service: 'Remote Administration', category: 'Admin', encrypted: false, admin: true, note: 'Windows Remote Management over HTTP.' },
    { port: 5986, proto: 'tcp', name: 'WinRM-TLS', service: 'Remote Administration', category: 'Admin', encrypted: true, admin: true, note: 'Windows Remote Management over HTTPS.' },
    { port: 6379, proto: 'tcp', name: 'Redis', service: 'Key-Value Store', category: 'Database', encrypted: false, admin: false, note: 'Historically unauthenticated by default. Enable AUTH and bind locally.' },
    { port: 6443, proto: 'tcp', name: 'Kubernetes', service: 'Cluster API', category: 'Admin', encrypted: true, admin: true, note: 'Kubernetes API server — a high-value administrative endpoint.' },
    { port: 8006, proto: 'tcp', name: 'Proxmox', service: 'Hypervisor UI', category: 'Admin', encrypted: true, admin: true, note: 'Virtualisation management console.' },
    { port: 8080, proto: 'tcp', name: 'HTTP-alt', service: 'Web Server', category: 'Web', encrypted: false, admin: false, note: 'Alternate HTTP port, frequently an application or admin UI.' },
    { port: 8443, proto: 'tcp', name: 'HTTPS-alt', service: 'Web Server', category: 'Web', encrypted: true, admin: false, note: 'Alternate HTTPS port, frequently a management interface.' },
    { port: 8883, proto: 'tcp', name: 'MQTTS', service: 'IoT Messaging', category: 'IoT', encrypted: true, admin: false, note: 'TLS-protected MQTT broker.' },
    { port: 9000, proto: 'tcp', name: 'HTTP-alt', service: 'Application', category: 'Web', encrypted: false, admin: false, note: 'Common application or management port (Portainer, SonarQube, PHP-FPM).' },
    { port: 9090, proto: 'tcp', name: 'Cockpit/Prometheus', service: 'Admin UI', category: 'Admin', encrypted: false, admin: true, note: 'Server management or metrics UI.' },
    { port: 9100, proto: 'tcp', name: 'JetDirect', service: 'Raw Printing', category: 'Print', encrypted: false, admin: false, note: 'Raw print data port. Accepts unauthenticated print jobs.' },
    { port: 9200, proto: 'tcp', name: 'Elasticsearch', service: 'Search API', category: 'Database', encrypted: false, admin: false, note: 'Search cluster API; historically shipped without authentication.' },
    { port: 10000, proto: 'tcp', name: 'Webmin', service: 'Admin UI', category: 'Admin', encrypted: false, admin: true, note: 'Server administration interface.' },
    { port: 11211, proto: 'tcp/udp', name: 'memcached', service: 'Cache', category: 'Database', encrypted: false, admin: false, note: 'Unauthenticated cache; UDP mode enables large amplification attacks.' },
    { port: 27017, proto: 'tcp', name: 'MongoDB', service: 'Database', category: 'Database', encrypted: false, admin: false, note: 'Document database. Verify authentication is enabled.' },
    { port: 32400, proto: 'tcp', name: 'Plex', service: 'Media Server', category: 'Media', encrypted: false, admin: false, note: 'Media server web interface.' },
    { port: 49152, proto: 'tcp', name: 'UPnP', service: 'Device Control', category: 'IoT', encrypted: false, admin: false, note: 'Dynamic UPnP control endpoint on consumer devices.' }
  ];

  const PORT_MAP = new Map();
  PORTS.forEach((p) => { if (!PORT_MAP.has(p.port)) PORT_MAP.set(p.port, p); });
  const portInfo = (port) => PORT_MAP.get(Number(port)) || null;

  const DEVICE_TYPES = ['Laptop', 'Desktop', 'Smartphone', 'Tablet', 'Server', 'Router',
                        'Switch', 'Printer', 'IoT', 'NAS', 'Camera', 'Unknown'];

  const DEVICE_GROUP = {
    Server: 'servers', NAS: 'servers',
    Laptop: 'workstations', Desktop: 'workstations',
    Smartphone: 'mobile', Tablet: 'mobile',
    IoT: 'iot', Camera: 'iot', Printer: 'iot',
    Router: 'network', Switch: 'network',
    Unknown: 'unknown'
  };

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational' };
  /* Severity is never conveyed by colour alone — each level carries a glyph. */
  const SEV_GLYPH = { critical: '▲', high: '▲', medium: '◆', low: '●', informational: '○' };
  const SEV_WEIGHT = { critical: 40, high: 18, medium: 7, low: 2.5, informational: 0 };

  /* -- Finding catalog ------------------------------------------------------
     Every rule is observational. None of them instruct or automate an attack;
     each states what was observed, why it matters, and how to remediate.   */
  const RULES = {
    'CT-TLS-001': {
      title: 'Expired TLS certificate', severity: 'critical', category: 'TLS',
      description: 'The certificate presented by this service is past its notAfter date. Clients will either refuse the connection or prompt users to bypass the warning.',
      impact: 'Expired certificates break the trust chain. Users conditioned to click through warnings cannot distinguish a genuine expiry from an interception attempt.',
      remediation: ['Renew and deploy a valid certificate', 'Automate renewal (ACME or an internal CA workflow)', 'Add certificate expiry to monitoring with a 30-day alert threshold'],
      references: ['NIST SP 800-52r2 §3.3', 'CIS Controls v8 – 3.10']
    },
    'CT-TLS-002': {
      title: 'TLS certificate approaching expiry', severity: 'medium', category: 'TLS',
      description: 'The certificate for this service expires soon. No action has failed yet, but the renewal window is closing.',
      impact: 'Unrenewed certificates cause abrupt service outages and erode trust in browser warnings.',
      remediation: ['Schedule renewal before the expiry date', 'Enable automated renewal', 'Verify the renewal process covers all SAN entries'],
      references: ['CIS Controls v8 – 3.10']
    },
    'CT-TLS-003': {
      title: 'Deprecated TLS protocol version enabled', severity: 'high', category: 'TLS',
      description: 'The service negotiated or advertised a TLS version that is formally deprecated (TLS 1.0 or TLS 1.1).',
      impact: 'Deprecated versions lack modern cipher constructions and are no longer supported by major browsers and compliance regimes.',
      remediation: ['Disable TLS 1.0 and TLS 1.1', 'Require TLS 1.2 as a minimum; prefer TLS 1.3', 'Re-test after the change to confirm client compatibility'],
      references: ['RFC 8996', 'NIST SP 800-52r2 §3.1', 'PCI DSS v4.0 – 4.2.1']
    },
    'CT-TLS-004': {
      title: 'Certificate hostname mismatch', severity: 'high', category: 'TLS',
      description: 'The hostname used to reach the service does not appear in the certificate Common Name or Subject Alternative Name entries.',
      impact: 'Hostname validation is the control that binds a certificate to an identity. A mismatch means clients cannot verify they are talking to the intended system.',
      remediation: ['Reissue the certificate with the correct SAN entries', 'Ensure every published name is covered', 'Verify virtual host and SNI configuration'],
      references: ['RFC 6125 §6', 'NIST SP 800-52r2 §3.3']
    },
    'CT-TLS-005': {
      title: 'Self-signed certificate in use', severity: 'medium', category: 'TLS',
      description: 'The certificate is self-signed rather than issued by a certificate authority trusted by the environment.',
      impact: 'Self-signed certificates provide encryption but no verifiable identity, so interception cannot be distinguished from normal operation.',
      remediation: ['Issue certificates from an internal or public CA', 'Distribute the internal CA root to managed endpoints', 'Reserve self-signed certificates for isolated lab systems'],
      references: ['NIST SP 800-52r2 §3.3']
    },
    'CT-TLS-006': {
      title: 'Weak certificate signature algorithm', severity: 'high', category: 'TLS',
      description: 'The certificate is signed with an algorithm no longer considered collision resistant (SHA-1 or MD5).',
      impact: 'Weak signature algorithms undermine the integrity guarantee of the certificate chain.',
      remediation: ['Reissue with SHA-256 or stronger', 'Audit the issuing CA configuration', 'Reject weak algorithms at the trust store level'],
      references: ['RFC 9155', 'NIST SP 800-131A Rev.2']
    },
    'CT-TLS-007': {
      title: 'Insufficient certificate key size', severity: 'high', category: 'TLS',
      description: 'The certificate public key is below the currently recommended minimum strength.',
      impact: 'Undersized keys reduce the work factor required to compromise the private key over the certificate lifetime.',
      remediation: ['Reissue with RSA 2048-bit minimum, or an ECDSA P-256 key', 'Shorten certificate lifetimes', 'Review CA issuance policy'],
      references: ['NIST SP 800-57 Part 1 Rev.5']
    },
    'CT-WEB-001': {
      title: 'Missing HTTP Strict-Transport-Security header', severity: 'medium', category: 'Web',
      description: 'The HTTPS response does not include a Strict-Transport-Security header.',
      impact: 'Without HSTS, a client\'s first request can be downgraded to cleartext before the redirect to HTTPS takes effect.',
      remediation: ['Add Strict-Transport-Security with a max-age of at least 15552000', 'Include subdomains once all of them serve HTTPS', 'Consider preload submission after validating coverage'],
      references: ['RFC 6797', 'OWASP Secure Headers Project']
    },
    'CT-WEB-002': {
      title: 'Missing Content-Security-Policy header', severity: 'medium', category: 'Web',
      description: 'No Content-Security-Policy header was returned by this web service.',
      impact: 'CSP is the primary defence-in-depth control limiting the impact of content injection. Without it, injected script executes with full page privileges.',
      remediation: ['Deploy a policy in report-only mode first', 'Remove inline script and eliminate unsafe-inline', 'Move to an enforcing policy once reports are clean'],
      references: ['OWASP Secure Headers Project', 'W3C CSP Level 3']
    },
    'CT-WEB-003': {
      title: 'Missing X-Content-Type-Options header', severity: 'low', category: 'Web',
      description: 'Responses do not set X-Content-Type-Options: nosniff.',
      impact: 'Browsers may infer a content type different from the one declared, which can turn an uploaded file into executable content.',
      remediation: ['Set X-Content-Type-Options: nosniff on all responses', 'Ensure Content-Type headers are accurate'],
      references: ['OWASP Secure Headers Project']
    },
    'CT-WEB-004': {
      title: 'Missing Referrer-Policy header', severity: 'low', category: 'Web',
      description: 'No Referrer-Policy header was returned.',
      impact: 'Full URLs — potentially including identifiers in paths or query strings — may be disclosed to third-party destinations.',
      remediation: ['Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer', 'Avoid placing sensitive values in URLs'],
      references: ['W3C Referrer Policy']
    },
    'CT-WEB-005': {
      title: 'Missing Permissions-Policy header', severity: 'informational', category: 'Web',
      description: 'No Permissions-Policy header was returned to constrain powerful browser features.',
      impact: 'Embedded content can request access to features such as camera, microphone or geolocation that the application does not need.',
      remediation: ['Declare a Permissions-Policy disabling unused features', 'Review third-party iframe requirements'],
      references: ['W3C Permissions Policy']
    },
    'CT-WEB-006': {
      title: 'Insecure cookie configuration', severity: 'medium', category: 'Web',
      description: 'One or more cookies were issued without the Secure, HttpOnly or SameSite attributes.',
      impact: 'Cookies missing Secure can leak over cleartext channels; missing HttpOnly exposes them to script access; missing SameSite widens cross-site request exposure.',
      remediation: ['Set Secure and HttpOnly on all session cookies', 'Set SameSite=Lax or Strict where the flow allows', 'Scope cookies to the narrowest path and domain'],
      references: ['RFC 6265bis', 'OWASP Session Management Cheat Sheet']
    },
    'CT-WEB-007': {
      title: 'Software version disclosed in response headers', severity: 'low', category: 'Web',
      description: 'Server or framework banners disclose specific product versions.',
      impact: 'Version disclosure lets an observer determine applicable known vulnerabilities without any interaction with the service.',
      remediation: ['Suppress or genericise Server and X-Powered-By headers', 'Remove framework version banners', 'Treat this as hardening, not as a substitute for patching'],
      references: ['OWASP Secure Headers Project']
    },
    'CT-WEB-008': {
      title: 'Cleartext HTTP served without redirect', severity: 'medium', category: 'Web',
      description: 'The service answers on port 80 and does not redirect clients to the HTTPS equivalent.',
      impact: 'Content and any submitted data travel unprotected and can be observed or modified in transit.',
      remediation: ['Return a 301 redirect from HTTP to HTTPS', 'Enable HSTS once the redirect is in place', 'Verify no application path is reachable only over HTTP'],
      references: ['NIST SP 800-52r2', 'OWASP Transport Layer Security Cheat Sheet']
    },
    'CT-NET-001': {
      title: 'Exposed administrative service', severity: 'high', category: 'Network',
      description: 'An administrative service is reachable from within the authorized scope. Verify that access is restricted to intended management hosts and that strong authentication is enabled.',
      impact: 'Management interfaces increase the attack surface and should generally be restricted to trusted administration networks.',
      remediation: ['Restrict management access to a dedicated administration network', 'Use network segmentation and host firewall rules', 'Require multi-factor or key-based authentication', 'Review firewall rules covering this service', 'Monitor and alert on access to management endpoints'],
      references: ['CIS Controls v8 – 4.6, 12.8', 'NIST SP 800-53 AC-17']
    },
    'CT-NET-002': {
      title: 'Unencrypted management protocol reachable', severity: 'high', category: 'Network',
      description: 'A management protocol that transmits session data without encryption is reachable within the scope.',
      impact: 'Anyone positioned on the path can observe the session, including anything typed into it.',
      remediation: ['Disable the cleartext protocol', 'Migrate to the encrypted equivalent (SSH, HTTPS, SNMPv3)', 'Confirm no automation still depends on the legacy protocol'],
      references: ['CIS Controls v8 – 4.6', 'NIST SP 800-53 SC-8']
    },
    'CT-NET-003': {
      title: 'Legacy file-sharing configuration indicator', severity: 'high', category: 'Network',
      description: 'The observed file-sharing service exposes indicators consistent with a legacy SMB configuration (NetBIOS session service alongside SMB, or absent signing indicators).',
      impact: 'Legacy SMB dialects lack modern integrity protections and are a common lateral-movement path inside flat networks.',
      remediation: ['Disable SMBv1 across the estate', 'Require SMB signing and encryption', 'Restrict file sharing to the segments that need it'],
      references: ['CIS Controls v8 – 4.8', 'Microsoft SMBv1 deprecation guidance']
    },
    'CT-NET-004': {
      title: 'Database service reachable from a client segment', severity: 'high', category: 'Network',
      description: 'A database listener answered from a segment that also contains user workstations.',
      impact: 'Databases reachable from user networks turn any compromised endpoint into a direct path to stored data.',
      remediation: ['Bind the database to a dedicated data segment or to localhost', 'Place an application tier between clients and the database', 'Apply firewall rules restricting source addresses', 'Enable authentication and transport encryption'],
      references: ['CIS Controls v8 – 3.12, 12.2', 'NIST SP 800-53 SC-7']
    },
    'CT-NET-005': {
      title: 'Unnecessary network service exposed', severity: 'low', category: 'Network',
      description: 'A service is listening that is not typically required for this device role.',
      impact: 'Every listening service is additional attack surface and additional patching obligation.',
      remediation: ['Confirm whether the service is required', 'Disable it if unused', 'Where required, restrict the source networks permitted to reach it'],
      references: ['CIS Controls v8 – 4.8']
    },
    'CT-NET-006': {
      title: 'Unexpected exposed service', severity: 'medium', category: 'Network',
      description: 'A service was observed that was not present in the previous assessment of this asset.',
      impact: 'Unplanned service changes may indicate configuration drift, an unreviewed deployment, or an unauthorised change.',
      remediation: ['Confirm the change was intentional and approved', 'Record it in the asset baseline if legitimate', 'Investigate through change management if not recognised'],
      references: ['CIS Controls v8 – 4.2']
    },
    'CT-NET-007': {
      title: 'Printer administrative interface reachable', severity: 'medium', category: 'Network',
      description: 'A printing device exposes an administrative web interface and/or a raw print port to the general network.',
      impact: 'Printers frequently ship with default credentials and hold cached documents and directory credentials for scan-to-mail features.',
      remediation: ['Change default administrative credentials', 'Restrict the management interface to the administration network', 'Disable unused protocols such as raw port 9100, FTP and Telnet', 'Keep printer firmware current'],
      references: ['CIS Controls v8 – 4.6, 4.8']
    },
    'CT-NET-008': {
      title: 'IoT device exposing an unauthenticated service', severity: 'low', category: 'Network',
      description: 'An IoT-class device exposes a control or discovery service that commonly operates without authentication.',
      impact: 'IoT devices are rarely patched and are a common foothold on flat networks.',
      remediation: ['Place IoT devices on a dedicated VLAN', 'Block inter-VLAN traffic except where required', 'Disable UPnP and unused discovery protocols', 'Track firmware versions in the asset inventory'],
      references: ['CIS Controls v8 – 12.2', 'NIST IR 8259A']
    },
    'CT-NET-009': {
      title: 'Service discovery protocol broadly reachable', severity: 'low', category: 'Network',
      description: 'A discovery protocol (SSDP, mDNS or NetBIOS name service) responds across the scope.',
      impact: 'Discovery protocols disclose hostnames, device models and service inventories to any device on the segment, and some can be abused for traffic amplification.',
      remediation: ['Disable discovery protocols on server and infrastructure segments', 'Limit multicast forwarding between VLANs', 'Where discovery is needed, confine it to the client VLAN'],
      references: ['CIS Controls v8 – 4.8']
    },
    'CT-INV-001': {
      title: 'Unknown asset detected', severity: 'medium', category: 'Inventory',
      description: 'A device responded within the authorized scope that is not present in the expected inventory.',
      impact: 'Devices outside the inventory are outside patching, monitoring and ownership processes, and cannot be assessed for risk.',
      remediation: ['Identify the device owner and purpose', 'Add it to the asset inventory or remove it from the network', 'Review how it obtained network access (NAC, 802.1X, DHCP reservations)'],
      references: ['CIS Controls v8 – 1.1, 1.2']
    },
    'CT-INV-002': {
      title: 'Device outside expected inventory profile', severity: 'medium', category: 'Inventory',
      description: 'A known device presents a device class, vendor or service profile that differs from its recorded inventory entry.',
      impact: 'Profile drift can indicate a replaced device, a repurposed system, or address reuse that invalidates existing risk assumptions.',
      remediation: ['Reconcile the inventory record with the observed device', 'Confirm the change through change management', 'Update ownership and criticality metadata'],
      references: ['CIS Controls v8 – 1.1']
    },
    'CT-CFG-001': {
      title: 'Default configuration indicator', severity: 'medium', category: 'Configuration',
      description: 'The service presents identifiers consistent with a factory or installer default configuration, such as a default hostname, default banner or default service set.',
      impact: 'Default configurations frequently include documented default credentials and permissive settings. This is an observation of the configuration state only — no authentication was attempted.',
      remediation: ['Apply the vendor hardening guide', 'Replace default credentials and certificates', 'Change default hostnames and banners', 'Record the device as hardened in the inventory'],
      references: ['CIS Benchmarks', 'CIS Controls v8 – 4.1']
    },
    'CT-CFG-002': {
      title: 'Outdated software indicator', severity: 'medium', category: 'Configuration',
      description: 'A version banner indicates a release that is older than the current supported branch. This is an indicator derived from a self-reported banner, not a confirmed vulnerability.',
      impact: 'Older releases accumulate publicly documented defects. The actual exposure depends on the build, backported patches and configuration.',
      remediation: ['Verify the installed version against the vendor advisory list', 'Apply the current supported release', 'Where the banner is inaccurate, record the true version in the inventory'],
      references: ['CIS Controls v8 – 7.3, 7.4']
    },
    'CT-CFG-003': {
      title: 'Remote desktop service exposed', severity: 'high', category: 'Configuration',
      description: 'A remote desktop service is reachable within the scope.',
      impact: 'Remote desktop endpoints are a routine target for credential-guessing campaigns and should not be broadly reachable.',
      remediation: ['Restrict access to a management network or VPN', 'Require network level authentication and multi-factor authentication', 'Enable account lockout and monitor authentication logs', 'Review firewall rules'],
      references: ['CIS Controls v8 – 4.6, 6.4', 'NIST SP 800-53 AC-17']
    },
    'CT-CFG-004': {
      title: 'Limited network segmentation indicator', severity: 'medium', category: 'Configuration',
      description: 'Server, client and IoT-class devices were observed within a single broadcast domain with no evidence of segmentation.',
      impact: 'Flat networks allow a single compromised endpoint to reach every other system directly, with no internal control point.',
      remediation: ['Separate servers, clients, management and IoT into distinct VLANs', 'Apply inter-VLAN filtering with a default-deny posture', 'Move management interfaces onto a dedicated administration network'],
      references: ['CIS Controls v8 – 12.2', 'NIST SP 800-53 SC-7']
    }
  };

  function rule(id) {
    return RULES[id] || {
      title: id, severity: 'informational', category: 'Other',
      description: 'No catalog entry for this rule.', impact: '—', remediation: [], references: []
    };
  }

  return {
    OUI, lookupVendor, PORTS, PORT_MAP, portInfo,
    DEVICE_TYPES, DEVICE_GROUP,
    SEVERITIES, SEV_RANK, SEV_LABEL, SEV_GLYPH, SEV_WEIGHT,
    RULES, rule
  };
})();
