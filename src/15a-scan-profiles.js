/* ============================================================================
   MODULE: CT.scanProfiles
   `depth` reaches the scanner service and decides how much is actually sent
   to the network. `rules` limits which findings a profile may produce.
   ========================================================================= */
CT.scanProfiles = (function () {
  'use strict';

  const STAGE_LABEL = {
    authorize: 'Validating authorization and scope',
    discover: 'Discovering hosts',
    identify: 'Identifying services',
    metadata: 'Collecting metadata',
    tls: 'Checking TLS configuration',
    headers: 'Reviewing security headers',
    analyze: 'Analyzing findings',
    score: 'Generating risk score'
  };

  const ALL_STAGES = ['authorize', 'discover', 'identify', 'metadata', 'tls', 'headers', 'analyze', 'score'];

  const PROFILES = [
    { id: 'passive', name: 'Passive Discovery', icon: 'radar', intensity: 'Passive',
      description: 'Reads the neighbour cache this machine already holds. Nothing is sent to any host in scope.',
      stages: ['authorize', 'discover', 'metadata', 'analyze', 'score'],
      depth: 'passive', rules: ['CT-INV-', 'CT-NET-009'] },

    { id: 'discovery', name: 'Network Discovery', icon: 'crosshair', intensity: 'Light',
      description: 'Which hosts are reachable, their MAC addresses and their names.',
      stages: ['authorize', 'discover', 'metadata', 'analyze', 'score'],
      depth: 'hosts', rules: ['CT-INV-', 'CT-CFG-004'] },

    { id: 'services', name: 'Service Inventory', icon: 'layers', intensity: 'Moderate',
      description: 'Enumerates reachable services and reads the banners they volunteer.',
      stages: ['authorize', 'discover', 'identify', 'metadata', 'analyze', 'score'],
      depth: 'services', rules: ['CT-NET-', 'CT-INV-', 'CT-CFG-003', 'CT-CFG-004'] },

    { id: 'config', name: 'Configuration Audit', icon: 'shieldCheck', intensity: 'Moderate',
      description: 'Reviews defensively relevant misconfigurations across discovered services.',
      stages: ['authorize', 'discover', 'identify', 'metadata', 'analyze', 'score'],
      depth: 'services', rules: ['CT-CFG-', 'CT-NET-', 'CT-INV-'] },

    { id: 'tls', name: 'TLS / Certificate Audit', icon: 'certificate', intensity: 'Light',
      description: 'Validity, expiry, hostname match, chain, protocol versions and key strength.',
      stages: ['authorize', 'discover', 'identify', 'tls', 'analyze', 'score'],
      depth: 'services', rules: ['CT-TLS-'] },

    { id: 'web', name: 'Web Security Review', icon: 'globe', intensity: 'Moderate',
      description: 'Security headers, TLS, cookie attributes, redirects and server banners. No vulnerability is exercised.',
      stages: ['authorize', 'discover', 'identify', 'tls', 'headers', 'analyze', 'score'],
      depth: 'services', rules: ['CT-WEB-', 'CT-TLS-'] },

    { id: 'full', name: 'Full Assessment', icon: 'shield', intensity: 'Comprehensive',
      description: 'Every check above in one structured assessment.',
      stages: ['authorize', 'discover', 'identify', 'metadata', 'tls', 'headers', 'analyze', 'score'],
      depth: 'services', rules: null }
  ];

  const ERRORS = {
    unauthorized: { title: 'Authorization required',
      body: 'Active checks cannot start until you confirm that you are authorized to test the systems in scope.' },
    scope: { title: 'Scope invalid', body: null },
    capability: { title: 'Scanner service not reachable',
      body: 'Active scanning needs the local scanner service. Start it with "node server/checkertracker.js" on a machine in the network you want to assess, then open the URL it prints.' },
    empty: { title: 'No hosts responded',
      body: 'Nothing inside the declared scope answered. Check that the scope matches your subnet, and that the machine running the service is on that network.' },
    cancelled: { title: 'Scan cancelled', body: 'The assessment was stopped before completion. No partial results were saved.' }
  };

  const byId = (id) => PROFILES.find((p) => p.id === id) || PROFILES[PROFILES.length - 1];

  return { PROFILES, STAGE_LABEL, ALL_STAGES, ERRORS, byId };
})();
