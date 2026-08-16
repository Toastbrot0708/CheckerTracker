/* ============================================================================
   MODULE: CT.icons — inline SVG registry (stroke style, no external assets)
   ========================================================================= */
CT.icons = (function () {
  'use strict';

  const P = {
    dashboard: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.6"/><path d="M12 12 19 6.6"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/>',
    crosshair: '<circle cx="12" cy="12" r="8.6"/><line x1="22" y1="12" x2="18.4" y2="12"/><line x1="5.6" y1="12" x2="2" y2="12"/><line x1="12" y1="5.6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18.4"/><circle cx="12" cy="12" r="2.4"/>',
    alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.4"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    server: '<rect x="2.5" y="2.5" width="19" height="8" rx="2"/><rect x="2.5" y="13.5" width="19" height="8" rx="2"/><line x1="6.5" y1="6.5" x2="6.51" y2="6.5"/><line x1="6.5" y1="17.5" x2="6.51" y2="17.5"/>',
    report: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13.5" x2="8" y2="13.5"/><line x1="16" y1="17.5" x2="8" y2="17.5"/>',
    tools: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1.5" y1="14" x2="6.5" y2="14"/><line x1="9.5" y1="8" x2="14.5" y2="8"/><line x1="17.5" y1="16" x2="22.5" y2="16"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    more: '<circle cx="12" cy="12" r="1.7" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1.7" fill="currentColor" stroke="none"/><circle cx="5" cy="12" r="1.7" fill="currentColor" stroke="none"/>',
    search: '<circle cx="11" cy="11" r="7.5"/><line x1="21" y1="21" x2="16.5" y2="16.5"/>',
    chevronRight: '<polyline points="9 18 15 12 9 6"/>',
    chevronLeft: '<polyline points="15 18 9 12 15 6"/>',
    chevronDown: '<polyline points="6 9.5 12 15.5 18 9.5"/>',
    close: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    check: '<polyline points="20 6.5 9 17.5 4 12.5"/>',
    bell: '<path d="M18 8.4A6 6 0 0 0 6 8.4c0 7-3 8.6-3 8.6h18s-3-1.6-3-8.6"/><path d="M13.7 20.5a2 2 0 0 1-3.4 0"/>',
    shield: '<path d="M12 22s8-3.8 8-10V5.2L12 2 4 5.2V12c0 6.2 8 10 8 10z"/>',
    shieldCheck: '<path d="M12 22s8-3.8 8-10V5.2L12 2 4 5.2V12c0 6.2 8 10 8 10z"/><polyline points="8.8 11.8 11 14 15.4 9.6"/>',
    lock: '<rect x="3.5" y="10.5" width="17" height="11" rx="2.5"/><path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5"/>',
    unlock: '<rect x="3.5" y="10.5" width="17" height="11" rx="2.5"/><path d="M7.5 10.5V7a4.5 4.5 0 0 1 8.6-1.8"/>',
    wifi: '<path d="M5 12.6a11 11 0 0 1 14 0"/><path d="M1.6 9a16 16 0 0 1 20.8 0"/><path d="M8.5 16.1a6 6 0 0 1 7 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    globe: '<circle cx="12" cy="12" r="9.5"/><line x1="2.5" y1="12" x2="21.5" y2="12"/><path d="M12 2.5a15 15 0 0 1 3.8 9.5A15 15 0 0 1 12 21.5 15 15 0 0 1 8.2 12 15 15 0 0 1 12 2.5z"/>',
    laptop: '<rect x="3.5" y="4.5" width="17" height="11" rx="2"/><line x1="1.8" y1="19.5" x2="22.2" y2="19.5"/>',
    desktop: '<rect x="2.5" y="3.5" width="19" height="13" rx="2"/><line x1="8" y1="20.5" x2="16" y2="20.5"/><line x1="12" y1="16.5" x2="12" y2="20.5"/>',
    smartphone: '<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><line x1="12" y1="18" x2="12.01" y2="18"/>',
    tablet: '<rect x="4.5" y="2.5" width="15" height="19" rx="2.5"/><line x1="12" y1="18" x2="12.01" y2="18"/>',
    printer: '<polyline points="6.5 9 6.5 2.5 17.5 2.5 17.5 9"/><path d="M6.5 17.5h-2a2 2 0 0 1-2-2V11a2 2 0 0 1 2-2h15a2 2 0 0 1 2 2v4.5a2 2 0 0 1-2 2h-2"/><rect x="6.5" y="14" width="11" height="7.5" rx="1"/>',
    camera: '<path d="M22.5 18.5a2 2 0 0 1-2 2h-17a2 2 0 0 1-2-2v-10a2 2 0 0 1 2-2h3.5l1.8-2.8h6.4l1.8 2.8h3.5a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="3.6"/>',
    nas: '<line x1="22" y1="12" x2="2" y2="12"/><path d="M5.4 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.4-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.8 1.1z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>',
    router: '<rect x="2.5" y="13.5" width="19" height="8" rx="2"/><line x1="6.5" y1="17.5" x2="6.51" y2="17.5"/><line x1="10.5" y1="17.5" x2="10.51" y2="17.5"/><path d="M12 10.5V8"/><path d="M9 7.6a4.2 4.2 0 0 1 6 0"/><path d="M6.6 5a7.6 7.6 0 0 1 10.8 0"/>',
    switch: '<rect x="16" y="16" width="6" height="5.5" rx="1.2"/><rect x="2" y="16" width="6" height="5.5" rx="1.2"/><rect x="9" y="2.5" width="6" height="5.5" rx="1.2"/><path d="M5 16v-2.6a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1V16"/><path d="M12 12.4V8"/>',
    iot: '<rect x="4.5" y="4.5" width="15" height="15" rx="2.5"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><line x1="9" y1="1.5" x2="9" y2="4.5"/><line x1="15" y1="1.5" x2="15" y2="4.5"/><line x1="9" y1="19.5" x2="9" y2="22.5"/><line x1="15" y1="19.5" x2="15" y2="22.5"/><line x1="19.5" y1="9" x2="22.5" y2="9"/><line x1="19.5" y1="15" x2="22.5" y2="15"/><line x1="1.5" y1="9" x2="4.5" y2="9"/><line x1="1.5" y1="15" x2="4.5" y2="15"/>',
    unknown: '<circle cx="12" cy="12" r="9.5"/><path d="M9.3 9.2a2.8 2.8 0 0 1 5.4.9c0 1.9-2.7 2.6-2.7 2.6"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    download: '<path d="M21 15.5V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3.5"/><polyline points="7.5 10.5 12 15 16.5 10.5"/><line x1="12" y1="15" x2="12" y2="3"/>',
    upload: '<path d="M21 15.5V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3.5"/><polyline points="7.5 7.5 12 3 16.5 7.5"/><line x1="12" y1="3" x2="12" y2="15"/>',
    copy: '<rect x="9" y="9" width="12.5" height="12.5" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4.5a2 2 0 0 1 2-2h8.5a2 2 0 0 1 2 2V5"/>',
    play: '<polygon points="6 3.5 20 12 6 20.5"/>',
    pause: '<rect x="6.5" y="4" width="3.8" height="16" rx="1"/><rect x="13.7" y="4" width="3.8" height="16" rx="1"/>',
    stop: '<rect x="5.5" y="5.5" width="13" height="13" rx="2"/>',
    refresh: '<polyline points="22.5 4 22.5 10 16.5 10"/><polyline points="1.5 20 1.5 14 7.5 14"/><path d="M4 9.5a8.5 8.5 0 0 1 14-3.2l4.5 3.7"/><path d="M1.5 14l4.5 3.7a8.5 8.5 0 0 0 14-3.2"/>',
    info: '<circle cx="12" cy="12" r="9.5"/><line x1="12" y1="16.5" x2="12" y2="11.5"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    alertCircle: '<circle cx="12" cy="12" r="9.5"/><line x1="12" y1="7.5" x2="12" y2="12.5"/><line x1="12" y1="16.5" x2="12.01" y2="16.5"/>',
    clock: '<circle cx="12" cy="12" r="9.5"/><polyline points="12 6.5 12 12 15.8 14"/>',
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    minus: '<line x1="5" y1="12" x2="19" y2="12"/>',
    filter: '<polygon points="21.5 3.5 2.5 3.5 10.2 12.6 10.2 19 13.8 20.8 13.8 12.6"/>',
    key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.8 12.2 20 3"/><path d="M17 6l2.5 2.5"/><path d="M14.5 8.5 17 11"/>',
    eye: '<path d="M1.8 12S6 4.8 12 4.8 22.2 12 22.2 12 18 19.2 12 19.2 1.8 12 1.8 12z"/><circle cx="12" cy="12" r="3.2"/>',
    trash: '<polyline points="3.5 6 20.5 6"/><path d="M18.5 6v13.5a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2V6"/><path d="M8.5 6V4.2a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2V6"/><line x1="10.2" y1="10.5" x2="10.2" y2="17"/><line x1="13.8" y1="10.5" x2="13.8" y2="17"/>',
    edit: '<path d="M11 4.5H4.5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h13a2 2 0 0 0 2-2V13"/><path d="M18.4 2.6a2.1 2.1 0 0 1 3 3L12 15l-4.2 1.2L9 12z"/>',
    database: '<ellipse cx="12" cy="5.5" rx="8.5" ry="3"/><path d="M20.5 11.8c0 1.66-3.8 3-8.5 3s-8.5-1.34-8.5-3"/><path d="M3.5 5.5v13c0 1.66 3.8 3 8.5 3s8.5-1.34 8.5-3v-13"/>',
    layers: '<polygon points="12 2.5 2.5 7 12 11.5 21.5 7"/><polyline points="2.5 16.8 12 21.3 21.5 16.8"/><polyline points="2.5 11.9 12 16.4 21.5 11.9"/>',
    list: '<line x1="8.5" y1="6" x2="21" y2="6"/><line x1="8.5" y1="12" x2="21" y2="12"/><line x1="8.5" y1="18" x2="21" y2="18"/><line x1="3.5" y1="6" x2="3.51" y2="6"/><line x1="3.5" y1="12" x2="3.51" y2="12"/><line x1="3.5" y1="18" x2="3.51" y2="18"/>',
    map: '<polygon points="1.8 6.2 1.8 21.5 8.4 17.8 15.6 21.5 22.2 17.8 22.2 2.5 15.6 6.2 8.4 2.5 1.8 6.2"/><line x1="8.4" y1="2.5" x2="8.4" y2="17.8"/><line x1="15.6" y1="6.2" x2="15.6" y2="21.5"/>',
    terminal: '<rect x="2.5" y="4" width="19" height="16" rx="2"/><polyline points="7 10 10 13 7 16"/><line x1="12.5" y1="16" x2="17" y2="16"/>',
    hash: '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10.5" y1="3.5" x2="8.5" y2="20.5"/><line x1="15.5" y1="3.5" x2="13.5" y2="20.5"/>',
    certificate: '<circle cx="12" cy="9" r="6"/><polyline points="8.4 14.4 7.2 22 12 19.3 16.8 22 15.6 14.4"/>',
    book: '<path d="M4 19.2A2.5 2.5 0 0 1 6.5 16.7H20"/><path d="M6.5 2.5H20v19H6.5A2.5 2.5 0 0 1 4 19V5a2.5 2.5 0 0 1 2.5-2.5z"/>',
    note: '<path d="M21 14.5a2 2 0 0 1-2 2H8l-4.5 4V4.5a2 2 0 0 1 2-2H19a2 2 0 0 1 2 2z"/><line x1="7.5" y1="8" x2="16.5" y2="8"/><line x1="7.5" y1="11.5" x2="13" y2="11.5"/>',
    compare: '<circle cx="6" cy="18" r="2.8"/><circle cx="18" cy="6" r="2.8"/><path d="M13 6H8.6a2 2 0 0 0-2 2v7.2"/><path d="M11 18h4.4a2 2 0 0 0 2-2V8.8"/>',
    calendar: '<rect x="3" y="4.5" width="18" height="17" rx="2"/><line x1="16" y1="2.5" x2="16" y2="6.5"/><line x1="8" y1="2.5" x2="8" y2="6.5"/><line x1="3" y1="10" x2="21" y2="10"/>',
    trendUp: '<polyline points="22.5 6.5 13.5 15.5 8.5 10.5 1.5 17.5"/><polyline points="17 6.5 22.5 6.5 22.5 12"/>',
    trendDown: '<polyline points="22.5 17.5 13.5 8.5 8.5 13.5 1.5 6.5"/><polyline points="17 17.5 22.5 17.5 22.5 12"/>',
    external: '<path d="M18 13.5V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5.5"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7.5" r="4"/>',
    arrowLeft: '<line x1="20" y1="12" x2="4" y2="12"/><polyline points="11 19 4 12 11 5"/>',
    arrowRight: '<line x1="4" y1="12" x2="20" y2="12"/><polyline points="13 5 20 12 13 19"/>',
    zap: '<polygon points="13 2 3.5 13.8 11.5 13.8 10.5 22 20.5 10.2 12.5 10.2"/>',
    inbox: '<polyline points="22 12.5 16 12.5 14 15.5 10 15.5 8 12.5 2 12.5"/><path d="M5.4 5.1 2 12.5V18a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-5.5l-3.4-7.4A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.8 1.1z"/>',
    activity: '<polyline points="22 12 17.5 12 14.5 20.5 9.5 3.5 6.5 12 2 12"/>',
    grid: '<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/>',
    sort: '<path d="M7 4v16"/><polyline points="3.5 7.5 7 4 10.5 7.5"/><path d="M17 20V4"/><polyline points="13.5 16.5 17 20 20.5 16.5"/>',
    share: '<path d="M4 12.5V19a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6.5"/><polyline points="16 6.5 12 2.5 8 6.5"/><line x1="12" y1="2.5" x2="12" y2="15"/>',
    scope: '<circle cx="12" cy="12" r="9.5"/><circle cx="12" cy="12" r="5.2" stroke-dasharray="2.4 2.4"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/>'
  };

  function svg(name, opts) {
    const o = opts || {};
    const body = P[name] || P.unknown;
    const el = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    el.setAttribute('viewBox', '0 0 24 24');
    el.setAttribute('fill', 'none');
    el.setAttribute('stroke', 'currentColor');
    el.setAttribute('stroke-width', o.weight || '1.7');
    el.setAttribute('stroke-linecap', 'round');
    el.setAttribute('stroke-linejoin', 'round');
    el.setAttribute('aria-hidden', 'true');
    el.setAttribute('focusable', 'false');
    if (o.cls) el.setAttribute('class', o.cls);
    el.innerHTML = body;
    return el;
  }

  /* Brand mark: radar sweep + network nodes + checkmark. Works as an app icon. */
  function logo(size) {
    const s = size || 44;
    const el = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    el.setAttribute('viewBox', '0 0 48 48');
    el.setAttribute('width', s);
    el.setAttribute('height', s);
    el.setAttribute('aria-hidden', 'true');
    el.setAttribute('focusable', 'false');
    el.innerHTML =
      '<circle cx="24" cy="24" r="21" fill="none" stroke="currentColor" stroke-opacity=".22" stroke-width="2" stroke-dasharray="52 14" stroke-linecap="round"/>' +
      '<circle cx="24" cy="24" r="14.5" fill="none" stroke="currentColor" stroke-opacity=".4" stroke-width="1.6"/>' +
      '<circle cx="24" cy="3" r="2.6" fill="currentColor" fill-opacity=".85"/>' +
      '<circle cx="42.2" cy="34.5" r="2.6" fill="currentColor" fill-opacity=".55"/>' +
      '<circle cx="5.8" cy="34.5" r="2.6" fill="currentColor" fill-opacity=".55"/>' +
      '<path d="M16.5 24.6 21.6 29.8 32 18.4" fill="none" stroke="currentColor" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round"/>';
    return el;
  }

  const DEVICE_ICON = {
    Laptop: 'laptop', Desktop: 'desktop', Smartphone: 'smartphone', Tablet: 'tablet',
    Server: 'server', Router: 'router', Switch: 'switch', Printer: 'printer',
    IoT: 'iot', NAS: 'nas', Camera: 'camera', Unknown: 'unknown'
  };

  return { svg, logo, DEVICE_ICON, has: (n) => !!P[n] };
})();
