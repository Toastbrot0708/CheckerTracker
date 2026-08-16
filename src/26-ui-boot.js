/* ============================================================================
   MODULE: CT.ui.boot — onboarding, lock screen, settings application, startup
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
    CT.dom.mount(overlay, h('div.overlay-screen', h('div.overlay-inner.stack.gap16', [
      h('div.brand-mark', [
        h('span', { style: { color: 'var(--accent)', display: 'flex' } }, CT.icons.logo(52)),
        h('span', [h('div.bt', 'CheckerTracker'), h('div.bs', 'Security visibility for authorized environments')])
      ]),
      h('div.mt16', [
        h('h2', { style: { 'font-size': '1.35em', 'line-height': '1.25' } }, 'Welcome to CheckerTracker'),
        h('p.mt8', { style: { color: 'var(--text-2)', 'font-size': '0.95em', 'line-height': '1.55' } },
          'Understand your environment. Identify exposure. Improve security.')
      ]),

      h('div.stack.gap8.mt16', [
        h('button.profile-card', { type: 'button', onClick: () => { CT.store.startFresh(); start('#/scan'); } }, [
          h('span.pico', icon('crosshair')),
          h('span.grow', [
            h('span.ptitle', 'Start assessment'),
            h('span.pdesc', 'Declare an authorized scope and run a scan against it.')
          ]),
          icon('chevronRight', { cls: 'chev' })
        ]),
        h('button.profile-card', { type: 'button', onClick: () => { CT.store.seedDemo('corp-lab'); start('#/dashboard'); } }, [
          h('span.pico', icon('database')),
          h('span.grow', [
            h('span.ptitle', 'Explore demo environment'),
            h('span.pdesc', 'A complete simulated estate — 18 assets, findings, history and reports — with no network access at all.')
          ]),
          icon('chevronRight', { cls: 'chev' })
        ]),
        h('button.profile-card', { type: 'button', onClick: () => { CT.store.startFresh(); start('#/settings'); } }, [
          h('span.pico', icon('upload')),
          h('span.grow', [
            h('span.ptitle', 'Import existing assessment'),
            h('span.pdesc', 'Load a CheckerTracker JSON export and recompute findings locally.')
          ]),
          icon('chevronRight', { cls: 'chev' })
        ])
      ]),

      h('div.notice.mt16', [icon('shield'), h('div.grow', [
        h('strong', 'Authorized environments only'),
        h('span', 'Active checks require you to confirm authorization for the systems in scope. CheckerTracker contains no exploitation, credential-capture or evasion capability.')
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
      h('button.btn.quiet.block', {
        type: 'button',
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
      if (CT.store.lock()) { showLock(); }
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

  function boot() {
    // The published-artifact wrapper supplies its own <head>; make sure the
    // viewport meta exists wherever this file is rendered.
    if (!document.querySelector('meta[name="viewport"]')) {
      const m = document.createElement('meta');
      m.name = 'viewport';
      m.content = 'width=device-width, initial-scale=1, viewport-fit=cover';
      document.head.appendChild(m);
    }
    if (!document.title) document.title = 'CheckerTracker';

    const res = CT.store.load();
    applySettings();

    if (res.locked) { showLock(); return; }
    if (!CT.store.state.onboarded) { showOnboarding(); return; }
    start(null);
  }
  CT.ui.boot = boot;

  /* -- Global wiring ------------------------------------------------------- */
  window.addEventListener('hashchange', () => {
    if (CT.store.locked || !CT.store.state.onboarded) return;
    S.render();
  });

  // Keep the app bar badge and tab indicators current without touching the
  // view, so focus and in-progress input in the current screen survive.
  CT.store.subscribe(CT.util.debounce(() => {
    if (CT.store.locked || !CT.store.state.onboarded) return;
    if (root.style.display === 'none') return;
    try { S.renderChrome(); } catch (e) { console.error('[CheckerTracker] chrome refresh', e); }
  }, 120));

  ['pointerdown', 'keydown', 'touchstart'].forEach((ev) =>
    window.addEventListener(ev, markActivity, { passive: true }));
  setInterval(autoLockCheck, 15000);

  window.addEventListener('error', (e) => {
    console.error('[CheckerTracker]', e.error || e.message);
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
