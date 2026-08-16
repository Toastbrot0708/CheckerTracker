/* ============================================================================
   CheckerTracker — progressive web app glue.

   This is deployment plumbing, not a CT module. It registers the offline
   service worker and produces the iOS home-screen icon. The application runs
   identically without it; nothing in CT depends on anything here.
   ========================================================================= */
(function () {
  'use strict';

  /* Same brand mark as icon.svg: radar sweep, network nodes, checkmark. */
  const MARK =
    '<rect width="512" height="512" fill="#080B11"/>' +
    '<g transform="translate(106 106) scale(6.25)">' +
    '<circle cx="24" cy="24" r="21" fill="none" stroke="#4C8DFF" stroke-opacity=".22" stroke-width="2" stroke-dasharray="52 14" stroke-linecap="round"/>' +
    '<circle cx="24" cy="24" r="14.5" fill="none" stroke="#4C8DFF" stroke-opacity=".4" stroke-width="1.6"/>' +
    '<circle cx="24" cy="3" r="2.6" fill="#4C8DFF" fill-opacity=".85"/>' +
    '<circle cx="42.2" cy="34.5" r="2.6" fill="#4C8DFF" fill-opacity=".55"/>' +
    '<circle cx="5.8" cy="34.5" r="2.6" fill="#4C8DFF" fill-opacity=".55"/>' +
    '<path d="M16.5 24.6 21.6 29.8 32 18.4" fill="none" stroke="#4C8DFF" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</g>';

  /* -- iOS home-screen icon -------------------------------------------------
     iOS reads apple-touch-icon at add-to-home-screen time and accepts raster
     formats only. Rather than commit a binary that could silently drift from
     the vector, rasterise the same mark on device. If anything here fails the
     SVG favicon remains as the fallback. */
  function appleTouchIcon() {
    if (document.querySelector('link[rel="apple-touch-icon"]')) return;
    const size = 180;
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + size + '" height="' + size +
      '" viewBox="0 0 512 512">' + MARK + '</svg>';
    const img = new Image();
    img.onload = function () {
      try {
        const canvas = document.createElement('canvas');
        canvas.width = size;
        canvas.height = size;
        canvas.getContext('2d').drawImage(img, 0, 0, size, size);
        const link = document.createElement('link');
        link.rel = 'apple-touch-icon';
        link.setAttribute('sizes', size + 'x' + size);
        link.href = canvas.toDataURL('image/png');
        document.head.appendChild(link);
      } catch (e) { /* fallback: favicon.svg */ }
    };
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  }

  /* -- Offline shell -------------------------------------------------------- */
  function announceUpdate() {
    const S = window.CT && CT.ui && CT.ui.shell;
    if (S && S.toast) S.toast('Update downloaded — relaunch to apply', 'ok', 6000);
  }

  function registerWorker() {
    if (!('serviceWorker' in navigator)) return;
    const host = location.hostname;
    const secure = location.protocol === 'https:' || host === 'localhost' || host === '127.0.0.1';
    if (!secure) return;

    navigator.serviceWorker.register('sw.js').then((reg) => {
      reg.addEventListener('updatefound', () => {
        const worker = reg.installing;
        if (!worker) return;
        worker.addEventListener('statechange', () => {
          // Reaching "installed" while another worker still controls the page
          // means this is an update waiting for the next launch, not the
          // first install.
          if (worker.state === 'installed' && navigator.serviceWorker.controller) announceUpdate();
        });
      });
    }).catch(() => { /* offline support is optional; the app runs without it */ });
  }

  appleTouchIcon();
  if (document.readyState === 'complete') registerWorker();
  else window.addEventListener('load', registerWorker);
})();
