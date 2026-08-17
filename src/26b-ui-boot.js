/* ============================================================================
   MODULE: CT.ui.boot — startup, onboarding, lock screen, auto-lock
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  const overlay = document.getElementById('ct-overlay-root');
  const root = document.getElementById('ct-root');
  const tabbar = document.getElementById('ct-tabbar');

  function showShell(visible) {
    root.style.display = visible ? '' : 'none';
    tabbar.style.display = visible ? '' : 'none';
  }

  function applySettings() {
    const st = CT.store.state.settings;
    document.body.dataset.textscale = st.textScale || 'm';
    document.body.dataset.reduceMotion = st.reduceMotion ? '1' : '0';
  }
  CT.ui.applySettings = applySettings;

  /* -- Onboarding ---------------------------------------------------------- */
  function showOnboarding() {
    showShell(false);
    const live = CT.live.online;

    CT.dom.mount(overlay, h('div.overlay-screen', h('div.overlay-inner.stack.gap16', [
      h('div.brand-mark', [
        h('span', { style: { color: 'var(--accent)', display: 'flex' } }, CT.icons.logo(52)),
        h('span', [h('div.bt', 'CheckerTracker'),
                   h('div.bs', 'Security visibility for authorized environments')])
      ]),
      h('div.mt16', [
        h('h2', { style: { 'font-size': '1.35em', 'line-height': '1.25' } }, 'Welcome to CheckerTracker'),
        h('p.mt8', { style: { color: 'var(--text-2)', 'font-size': '0.95em', 'line-height': '1.55' } },
          'Understand your network. Identify exposure. Fix what is weak.')
      ]),

      h('div.card.mt16', {
        style: live
          ? { 'border-color': 'var(--accent-line)', background: 'var(--accent-dim)' }
          : null
      }, [
        h('div.row.gap8', [
          h('span.status-dot.' + (live ? 'ok' : 'medium'), { 'aria-hidden': 'true' }),
          h('span.grow.small', { style: { 'font-weight': '650' } },
            live ? 'Scanner service connected' : 'Scanner service not detected')
        ]),
        h('p.tiny.muted.mt6', { style: { margin: '6px 0 0', 'line-height': '1.5' } }, live
          ? 'Live discovery, port scanning, TLS handshakes and header analysis are all available.'
          : 'The offline tools work now. For live scanning, run this on a machine in the network you want to assess:'),
        !live ? h('pre.code.mt8', { style: { margin: '8px 0 0' } }, 'node server/checkertracker.js') : null,
        !live ? h('p.tiny.muted.mt6', { style: { margin: '6px 0 0' } },
          'Then open the URL it prints — also from your phone, on the same network.') : null,
        !live ? h('button.btn.sm.mt8', { type: 'button',
          onClick: () => CT.live.probe().then(() => { CT.engines.capabilities.refresh(); showOnboarding(); }) },
          [icon('refresh'), 'Check again']) : null
      ]),

      h('div.stack.gap8.mt16', [
        h('button.profile-card', { type: 'button',
          onClick: () => { CT.store.startFresh(); start('#/scan'); } }, [
          h('span.pico', icon('crosshair')),
          h('span.grow', [
            h('span.ptitle', live ? 'Run an assessment' : 'Set up an assessment'),
            h('span.pdesc', 'Declare the scope you are authorized to test and sweep it.')
          ]),
          icon('chevronRight', { cls: 'chev' })
        ]),
        h('button.profile-card', { type: 'button',
          onClick: () => { CT.store.startFresh(); start('#/tools'); } }, [
          h('span.pico', icon('tools')),
          h('span.grow', [
            h('span.ptitle', 'Open the tools'),
            h('span.pdesc', 'Certificate parsing, DNS, header analysis, CIDR maths and hashing — all real, service or not.')
          ]),
          icon('chevronRight', { cls: 'chev' })
        ]),
        h('button.profile-card', { type: 'button',
          onClick: () => { CT.store.startFresh(); start('#/settings'); } }, [
          h('span.pico', icon('upload')),
          h('span.grow', [
            h('span.ptitle', 'Import an assessment'),
            h('span.pdesc', 'Load a CheckerTracker JSON export; findings and score are recomputed locally.')
          ]),
          icon('chevronRight', { cls: 'chev' })
        ])
      ]),

      h('div.notice.mt16', [icon('shield'), h('div.grow', [
        h('strong', 'Authorized networks only'),
        h('span', 'Active checks require you to confirm authorization for the systems in scope. CheckerTracker observes and reports; it contains no exploitation, credential-capture or evasion capability.')
      ])]),

      h('p.tiny.muted.center.mt12',
        'Everything stays on this device. No account, no telemetry, no upload.')
    ])));
  }

  /* -- Lock screen --------------------------------------------------------- */
  function showLock() {
    showShell(false);
    let value = '';
    const errBox = h('div');
    const input = h('input', {
      type: 'password', placeholder: 'Passcode', 'aria-label': 'Passcode',
      autocomplete: 'current-password',
      on: {
        input: function () { value = this.value; },
        keydown: function (e) { if (e.key === 'Enter') attempt(); }
      }
    });

    function attempt() {
      CT.dom.clear(errBox);
      CT.store.unlock(value)
        .then(() => { applySettings(); start(location.hash || '#/dashboard'); })
        .catch(() => {
          errBox.appendChild(CT.dom.notice('err', 'Incorrect passcode',
            'The stored data could not be decrypted with that passcode. There is no recovery mechanism by design.'));
          input.value = ''; value = '';
          input.focus();
        });
    }

    CT.dom.mount(overlay, h('div.overlay-screen', h('div.overlay-inner.stack.gap16', [
      h('div.center', [
        h('span', { style: { color: 'var(--accent)', display: 'inline-flex' } }, CT.icons.logo(52)),
        h('h2.mt12', { style: { 'font-size': '1.2em' } }, 'CheckerTracker is locked'),
        h('p.small.muted.mt6', 'Enter your passcode to decrypt the assessment store.')
      ]),
      h('div.card', [
        h('label.field', { style: { margin: 0 } }, [h('span.lbl', 'Passcode'), input]),
        h('button.btn.primary.block.mt12', { type: 'button', onClick: attempt }, [icon('unlock'), 'Unlock'])
      ]),
      errBox,
      h('div.notice', [icon('lock'), h('div.grow', [
        h('strong', 'AES-256-GCM'),
        h('span', 'The key is derived from your passcode with PBKDF2-SHA256 and exists only in memory while the app is unlocked.')
      ])]),
      h('button.btn.quiet.block', { type: 'button',
        onClick: () => S.confirm({
          title: 'Discard encrypted data?', danger: true, confirmLabel: 'Delete and start over',
          body: 'If the passcode is lost the data cannot be recovered. This deletes the encrypted store from this device.'
        }).then((ok) => { if (ok) { CT.store.reset(); CT.ui.boot(); } })
      }, 'Forgot passcode')
    ])));
    setTimeout(() => input.focus(), 60);
  }

  /* -- Auto-lock ----------------------------------------------------------- */
  let lastActivity = Date.now();
  function markActivity() { lastActivity = Date.now(); }
  function autoLockCheck() {
    const st = CT.store.state.settings;
    if (!st.passcodeEnabled || !st.autoLockMinutes || CT.store.locked) return;
    if (Date.now() - lastActivity > st.autoLockMinutes * 60000) {
      if (CT.store.lock()) showLock();
    }
  }

  /* -- Start --------------------------------------------------------------- */
  function start(route) {
    CT.dom.clear(overlay);
    showShell(true);
    applySettings();
    if (route) {
      if (location.hash === route) S.render();
      else location.hash = route;
    } else {
      S.render();
    }
  }

  async function boot() {
    if (!document.querySelector('meta[name="viewport"]')) {
      const m = document.createElement('meta');
      m.name = 'viewport';
      m.content = 'width=device-width, initial-scale=1, viewport-fit=cover';
      document.head.appendChild(m);
    }
    if (!document.title) document.title = 'CheckerTracker';

    // Settle the capability picture before anything renders, so no screen
    // has to guess whether live scanning is available.
    await CT.live.probe();
    CT.engines.capabilities.refresh();

    const res = CT.store.load();
    applySettings();

    if (res.locked) { showLock(); return; }
    if (!CT.store.state.onboarded) { showOnboarding(); return; }
    start(null);
  }
  CT.ui.boot = boot;

  window.addEventListener('hashchange', () => {
    if (CT.store.locked || !CT.store.state.onboarded) return;
    S.render();
  });

  CT.store.subscribe(CT.util.debounce(() => {
    if (CT.store.locked || !CT.store.state.onboarded) return;
    if (root.style.display === 'none') return;
    try { S.renderChrome(); } catch (e) { console.error('[CheckerTracker] chrome refresh', e); }
  }, 120));

  ['pointerdown', 'keydown', 'touchstart'].forEach((ev) =>
    window.addEventListener(ev, markActivity, { passive: true }));
  setInterval(autoLockCheck, 15000);

  window.addEventListener('error', (e) => console.error('[CheckerTracker]', e.error || e.message));

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
