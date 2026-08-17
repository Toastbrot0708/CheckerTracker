/* ============================================================================
   CheckerTracker service worker — offline application shell.

   Three rules matter more than the caching strategy:

   1. Only same-origin GET requests are intercepted. The DNS Inspector's
      DNS-over-HTTPS queries must always reach the network; a cached answer
      presented as a live lookup would make the app lie about what it saw.

   2. /api is never cached, ever. That is the scanner service. A stored
      response replayed as a fresh measurement would be the worst thing this
      application could do.

   3. skipWaiting() is never called. A new worker waits until every tab is
      closed, so files cannot be swapped underneath a running assessment.
      pwa.js shows a quiet "relaunch to apply" toast instead.
   ========================================================================= */
'use strict';

const VERSION = 'checkertracker-v2';

const SHELL = [
  './',
  './index.html',
  './styles.css',
  './manifest.webmanifest',
  './favicon.svg',
  './icon.svg',
  './pwa.js',
  './src/01-util.js',
  './src/02-icons.js',
  './src/03-dom.js',
  './src/04-crypto.js',
  './src/05-net.js',
  './src/06-data.js',
  './src/07-live.js',
  './src/08-engine-capabilities.js',
  './src/09-engine-tls.js',
  './src/10-engine-web.js',
  './src/11-engine-analyzer.js',
  './src/12-engine-risk.js',
  './src/13-engine-assetdb.js',
  './src/14-engine-dns.js',
  './src/15-engine-report.js',
  './src/15a-scan-profiles.js',
  './src/16b-scanner-live.js',
  './src/17-store.js',
  './src/18-ui-shell.js',
  './src/19-ui-dashboard.js',
  './src/20c-ui-scan-run.js',
  './src/20d-ui-scan-wizard.js',
  './src/21-ui-findings.js',
  './src/22-ui-assets.js',
  './src/23-ui-reports.js',
  './src/24-ui-tools.js',
  './src/25-ui-settings.js',
  './src/26b-ui-boot.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(VERSION).then((cache) => cache.addAll(SHELL)));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;              // rule 1
  if (url.pathname.indexOf('/api') !== -1) return;              // rule 2

  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(VERSION).then((c) => c.put('./index.html', copy));
          return res;
        })
        .catch(() => caches.match('./index.html').then((r) => r || caches.match('./')))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((hit) => {
      const network = fetch(req).then((res) => {
        if (res && res.ok && res.type === 'basic') {
          const copy = res.clone();
          caches.open(VERSION).then((c) => c.put(req, copy));
        }
        return res;
      }).catch(() => hit);
      return hit || network;
    })
  );
});
