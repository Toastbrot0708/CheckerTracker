/* ============================================================================
   CheckerTracker service worker — offline application shell.

   Two rules matter more than the caching strategy itself:

   1. Only same-origin GET requests are ever intercepted. The DNS Inspector's
      DNS-over-HTTPS queries and the HTTP Header Analyzer's URL fetch must
      always reach the network. A cached DoH answer presented as a live lookup
      would make the app lie about what it observed, and being honest about
      what is real is the entire point of the capability layer.

   2. skipWaiting() is never called. A newly installed worker stays in the
      waiting state until every tab is closed, so application files can never
      be swapped underneath a running assessment. pwa.js surfaces a quiet
      "relaunch to apply" toast instead of forcing a reload.
   ========================================================================= */
'use strict';

const VERSION = 'checkertracker-v1';

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
  './src/07-demo.js',
  './src/08-engine-capabilities.js',
  './src/09-engine-tls.js',
  './src/10-engine-web.js',
  './src/11-engine-analyzer.js',
  './src/12-engine-risk.js',
  './src/13-engine-assetdb.js',
  './src/14-engine-dns.js',
  './src/15-engine-report.js',
  './src/16-engine-scanner.js',
  './src/17-store.js',
  './src/18-ui-shell.js',
  './src/19-ui-dashboard.js',
  './src/20-ui-scan.js',
  './src/21-ui-findings.js',
  './src/22-ui-assets.js',
  './src/23-ui-reports.js',
  './src/24-ui-tools.js',
  './src/25-ui-settings.js',
  './src/26-ui-boot.js'
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

  // Rule 1. Not calling respondWith() lets the request proceed untouched.
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Navigations prefer the network so a redeploy is picked up straight away,
  // and fall back to the cached shell when there is no connection.
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

  // Everything else: serve from cache immediately, refresh in the background.
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
