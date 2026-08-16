/* ============================================================================
   MODULE: CT.ui.routes.settings — settings, notifications, audit, about
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  function switchRow(label, desc, value, onToggle, disabled, disabledReason) {
    return h('button.switch-row', {
      type: 'button', role: 'switch', 'aria-checked': value ? 'true' : 'false',
      'aria-label': label, disabled: disabled ? true : null,
      style: disabled ? { opacity: '0.5', cursor: 'not-allowed' } : null,
      onClick: () => { if (!disabled) onToggle(!value); }
    }, [
      h('span.grow.stack', [
        h('span', { style: { 'font-size': '0.89em', 'font-weight': '600' } }, label),
        desc ? h('span.tiny.muted', { style: { 'line-height': '1.4' } }, disabled && disabledReason ? disabledReason : desc) : null
      ]),
      h('span.switch', { dataset: { on: value ? '1' : '0' }, 'aria-hidden': 'true' })
    ]);
  }

  CT.ui.routes.settings = {
    parent: '#/more', tab: 'more',
    title: () => 'Settings',
    render() {
      const st = CT.store.state.settings;
      const bioAvailable = !!(window.PublicKeyCredential);
      const notifSupported = 'Notification' in window;
      const notifPerm = notifSupported ? Notification.permission : 'unsupported';

      return h('div.stack.gap12', [
        h('div.card', { style: { 'border-color': 'var(--accent-line)', background: 'var(--accent-dim)' } }, [
          h('div.row.gap10', [
            h('span', { style: { color: 'var(--accent-2)', display: 'flex' } }, icon('shieldCheck')),
            h('span.grow', [
              h('div', { style: { 'font-weight': '650', 'font-size': '0.95em' } }, 'Privacy Mode'),
              h('div.small.mt4', { style: { color: 'var(--text-2)', 'line-height': '1.5' } },
                'Scan results remain on this device unless explicitly exported.')
            ])
          ]),
          h('dl.mt12', [
            CT.dom.kv('Storage', st.passcodeEnabled ? 'Encrypted (AES-256-GCM)' : 'Local storage, unencrypted'),
            CT.dom.kv('Telemetry', 'None — the app makes no analytics or reporting calls'),
            CT.dom.kv('Outbound requests', 'Only DNS Inspector and the header fetch tool, on explicit action')
          ])
        ]),

        card('Security', 'lock', [
          switchRow('App passcode', st.passcodeEnabled
            ? 'Enabled. Scan data is sealed with AES-256-GCM before it is written to storage.'
            : 'Encrypt all stored scan data with a passcode you set.',
            st.passcodeEnabled,
            (on) => {
              if (on) {
                S.prompt({
                  title: 'Set passcode', type: 'password', label: 'Passcode (6+ characters)',
                  body: 'The passcode derives an AES-256 key with PBKDF2-SHA256 at 210,000 iterations. It is never stored — if you forget it the data cannot be recovered.',
                  confirmLabel: 'Enable'
                }).then((v) => {
                  if (!v) return;
                  CT.store.enablePasscode(v)
                    .then(() => { S.toast('Encryption enabled', 'ok'); S.render(); })
                    .catch((e) => S.toast(e.message, 'err', 4500));
                });
              } else {
                S.confirm({ title: 'Disable encryption?', danger: true, confirmLabel: 'Disable',
                  body: 'Stored scan data will be written to local storage in plaintext.' })
                  .then((ok) => { if (ok) CT.store.disablePasscode().then(() => { S.toast('Encryption disabled', 'warn'); S.render(); }); });
              }
            },
            !CT.crypto.available, 'Requires a secure context (https:// or localhost).'),

          switchRow('Prefer biometric unlock', bioAvailable
            ? 'Use the platform authenticator to unlock when the device offers one.'
            : 'No platform authenticator is exposed to this runtime.',
            st.biometricPreferred, (on) => { CT.store.setSetting('biometricPreferred', on); S.render(); },
            !bioAvailable || !st.passcodeEnabled,
            !st.passcodeEnabled ? 'Enable the app passcode first.' : 'No platform authenticator is exposed to this runtime.'),

          h('label.field', { style: { margin: '10px 12px 12px' } }, [
            h('span.lbl', 'Automatic session lock'),
            h('select', {
              'aria-label': 'Auto-lock timeout',
              on: { change: function () { CT.store.setSetting('autoLockMinutes', Number(this.value)); S.render(); } }
            }, [0, 1, 5, 15, 30].map((m) => h('option', { value: String(m), selected: st.autoLockMinutes === m ? true : null },
              m === 0 ? 'Never' : m + ' minute' + (m === 1 ? '' : 's') + ' of inactivity'))),
            h('span.hint', st.passcodeEnabled ? 'Locks the app and clears the decryption key from memory.'
              : 'Takes effect once the app passcode is enabled.')
          ])
        ]),

        card('Notifications', 'bell', [
          h('div', { style: { padding: '0 12px 10px' } }, [
            h('div.row.gap8', [
              h('span.status-dot.' + (notifPerm === 'granted' ? 'ok' : notifPerm === 'denied' ? 'critical' : 'medium'), { 'aria-hidden': 'true' }),
              h('span.small.grow', notifSupported
                ? 'System permission: ' + notifPerm
                : 'System notifications are not available in this runtime'),
              notifSupported && notifPerm === 'default'
                ? h('button.btn.sm', { type: 'button', onClick: () => Notification.requestPermission().then(() => S.render()) }, 'Allow')
                : null
            ]),
            h('p.tiny.muted.mt6', { style: { margin: '6px 0 0' } },
              'In-app notifications work regardless of the system permission. Permission is requested only when you turn it on here.')
          ]),
          [['newAsset', 'New or unknown device', 'A device responded that was not present in the previous assessment.'],
           ['newFinding', 'New finding', 'A critical or high severity finding appeared.'],
           ['criticalChange', 'Critical change', 'A change that materially alters the risk picture.'],
           ['certExpiry', 'Certificate expiring', 'A certificate in the inventory expires within 30 days.'],
           ['newService', 'New service detected', 'A port started responding that was previously closed.'],
           ['scoreChange', 'Security score change', 'The environment score moved between assessments.']]
            .map(([k, label, desc]) => switchRow(label, desc, st.notifications[k],
              (on) => { CT.store.setSetting('notifications.' + k, on); S.render(); }))
        ]),

        card('Accessibility', 'eye', [
          h('label.field', { style: { margin: '2px 12px 12px' } }, [
            h('span.lbl', 'Text size'),
            h('div.segmented', { role: 'group', 'aria-label': 'Text size' },
              [['s', 'Small'], ['m', 'Default'], ['l', 'Large'], ['xl', 'Largest']].map(([id, label]) =>
                h('button', {
                  type: 'button', 'aria-pressed': st.textScale === id ? 'true' : 'false',
                  onClick: () => { CT.store.setSetting('textScale', id); CT.ui.applySettings(); S.render(); }
                }, label))),
            h('span.hint', 'Scales the entire interface. Layouts reflow rather than clip.')
          ]),
          switchRow('Reduce motion', 'Removes transitions and the scan progress pulse. Also honoured automatically when the system requests reduced motion.',
            st.reduceMotion, (on) => { CT.store.setSetting('reduceMotion', on); CT.ui.applySettings(); S.render(); })
        ]),

        card('Data & export', 'database', [
          switchRow('Confirm before export', 'Ask for confirmation before any report or dataset leaves the app.',
            st.exportRequiresConfirm, (on) => { CT.store.setSetting('exportRequiresConfirm', on); S.render(); }),
          switchRow('Show demo watermark', 'Keep the DEMO DATA marker visible while simulated results are loaded. Strongly recommended.',
            st.showDemoWatermark, (on) => { CT.store.setSetting('showDemoWatermark', on); S.render(); }),
          h('div', { style: { padding: '4px 12px 12px' } }, [
            h('div.btn-grid', [
              h('button.btn.sm', { type: 'button', onClick: () => importSheet() }, [icon('upload'), 'Import']),
              h('button.btn.sm', {
                type: 'button',
                onClick: () => {
                  const cur = CT.store.currentAssessment();
                  if (!cur) { S.toast('No assessment to export', 'warn'); return; }
                  S.navigate('#/reports');
                }
              }, [icon('download'), 'Export'])
            ]),
            h('button.btn.sm.danger.block.mt8', {
              type: 'button',
              onClick: () => S.confirm({
                title: 'Clear all local data?', danger: true, confirmLabel: 'Delete everything',
                body: 'Removes every assessment, finding state, note, notification and audit entry from this device. This cannot be undone.'
              }).then((ok) => { if (ok) { CT.store.reset(); S.toast('All local data cleared', 'ok'); location.hash = '#/dashboard'; CT.ui.boot(); } })
            }, [icon('trash'), 'Clear all local data'])
          ])
        ]),

        card('Permissions', 'key', [
          h('div.list', [
            permRow('Local network access', 'unavailable',
              'Required for real host discovery. Web runtimes are not granted raw network access, so discovery runs simulated.'),
            permRow('Wi-Fi information', 'unavailable',
              'SSID, BSSID and signal strength are not exposed to web content. Environment values come from the demo dataset.'),
            permRow('Notifications', notifPerm === 'granted' ? 'granted' : notifPerm === 'denied' ? 'denied' : 'not requested',
              'Requested only when you enable a notification category.'),
            permRow('Local storage', 'granted',
              'Used for the encrypted assessment store. Never leaves the device.'),
            permRow('Camera', 'not requested',
              'Not used. Would only be requested if QR-based asset import is added later.')
          ]),
          h('p.tiny.muted', { style: { padding: '0 12px 12px', margin: 0 } },
            'CheckerTracker requests nothing it does not currently need.')
        ]),

        card('Runtime capabilities', 'info', [
          h('div.list', CT.engines.capabilities.CAPS.map((c) => h('div.list-item.static', { style: { display: 'block' } }, [
            h('div.row.gap8', [
              h('span.grow.small', { style: { 'font-weight': '600' } }, c.name),
              h('span.pill.' + (c.mode === 'real' ? 'ok' : c.mode === 'simulated' ? 'medium' : 'neutral'),
                c.mode === 'real' ? 'Real' : c.mode === 'simulated' ? 'Simulated' : 'Unavailable')
            ]),
            h('p.tiny.muted.mt4', { style: { margin: '4px 0 0', 'line-height': '1.45' } }, c.reason)
          ])))
        ]),

        h('div.card.flush', h('div.list', [
          h('button.list-item', { type: 'button', onClick: () => S.navigate('#/audit') },
            [icon('list'), h('span.grow.small', 'Audit log'), h('span.tag', String(CT.store.state.audit.length)), icon('chevronRight', { cls: 'chev' })]),
          h('button.list-item', { type: 'button', onClick: () => S.navigate('#/about') },
            [icon('info'), h('span.grow.small', 'About & scope policy'), icon('chevronRight', { cls: 'chev' })])
        ])),

        h('p.tiny.muted.center', 'CheckerTracker · single-file prototype · no build, no dependencies, no telemetry')
      ]);
    }
  };

  function card(title, iconName, children) {
    return h('div.card.flush', [
      h('div', { style: { padding: '12px 12px 6px' } }, h('div.card-head', { style: { margin: 0 } }, [icon(iconName), h('h3', title)])),
      h('div', children)
    ]);
  }

  function permRow(label, state, why) {
    const kind = state === 'granted' ? 'ok' : state === 'denied' ? 'critical' : state === 'unavailable' ? 'info' : 'medium';
    return h('div.list-item.static', { style: { display: 'block' } }, [
      h('div.row.gap8', [
        h('span.status-dot.' + kind, { 'aria-hidden': 'true' }),
        h('span.grow.small', { style: { 'font-weight': '600' } }, label),
        h('span.tiny.muted', state)
      ]),
      h('p.tiny.muted.mt4', { style: { margin: '4px 0 0 16px', 'line-height': '1.45' } }, why)
    ]);
  }

  function importSheet() {
    let text = '';
    const s = S.sheet({
      title: 'Import assessment',
      body: h('div.stack.gap12', [
        CT.dom.notice(null, 'CheckerTracker JSON', 'Paste a previously exported assessment (schema checkertracker.report/1). Findings and the score are recomputed locally from the imported inventory.'),
        h('label.field', { style: { margin: 0 } }, [
          h('span.lbl', 'JSON payload'),
          h('textarea', {
            placeholder: '{ "tool": "CheckerTracker", "schema": "checkertracker.report/1", … }',
            spellcheck: 'false', style: { 'font-family': 'var(--mono)', 'font-size': '0.72em', 'min-height': '160px' },
            on: { input: function () { text = this.value; } }
          })
        ]),
        h('input', {
          type: 'file', accept: '.json,application/json', 'aria-label': 'Import file',
          on: {
            change: function () {
              const f = this.files && this.files[0];
              if (!f) return;
              const r = new FileReader();
              r.onload = () => { text = String(r.result); doImport(); };
              r.readAsText(f);
            }
          }
        })
      ]),
      footer: h('button.btn.primary.block', { type: 'button', onClick: () => doImport() }, [icon('upload'), 'Import'])
    });

    function doImport() {
      try {
        const rec = CT.store.importAssessment(text);
        s.close();
        S.toast('Imported ' + rec.assets.length + ' assets', 'ok');
        S.navigate('#/dashboard');
      } catch (e) {
        S.toast(e.message, 'err', 5000);
      }
    }
  }

  /* ==========================================================================
     NOTIFICATIONS
     ======================================================================= */
  CT.ui.routes.notifications = {
    parent: '#/more', tab: 'more',
    title: () => 'Notifications',
    subtitle: () => { const n = CT.store.unreadCount(); return n ? n + ' unread' : 'All caught up'; },
    actions: () => CT.store.state.notifications.length
      ? h('button.btn.sm.quiet', { type: 'button', onClick: () => { CT.store.markAllRead(); S.render(); } }, 'Mark all read')
      : null,
    render() {
      const list = CT.store.state.notifications;
      if (!list.length) {
        return CT.dom.empty({
          icon: 'bell', title: 'No notifications',
          body: 'Changes between assessments appear here: unknown devices, new findings, expiring certificates and score movement.',
          action: { label: 'Run an assessment', icon: 'crosshair', onClick: () => S.navigate('#/scan') }
        });
      }
      return h('div.card.flush', h('div.list', list.map((n) => h('button.list-item', {
        type: 'button',
        style: n.read ? { opacity: '0.62' } : null,
        onClick: () => { n.read = true; CT.store.commit(); if (n.route) S.navigate(n.route); else S.render(); }
      }, [
        h('span.status-dot.' + (n.kind === 'crit' ? 'critical' : n.kind === 'warn' ? 'medium' : n.kind === 'ok' ? 'ok' : 'info'), { 'aria-hidden': 'true' }),
        h('span.grow.stack', { style: { 'min-width': '0' } }, [
          h('span.row.gap6', [
            h('span.small', { style: { 'font-weight': n.read ? '500' : '650' } }, n.title),
            !n.read ? h('span.pill.accent', 'new') : null
          ]),
          h('span.tiny.muted', { style: { 'line-height': '1.4' } }, n.body),
          h('span.tiny.muted.mt4', [n.meta ? n.meta + ' · ' : '', CT.util.fmtRelative(n.ts)])
        ]),
        n.route ? icon('chevronRight', { cls: 'chev' }) : null
      ]))));
    }
  };

  /* ==========================================================================
     AUDIT LOG
     ======================================================================= */
  CT.ui.routes.audit = {
    parent: '#/settings', tab: 'more',
    title: () => 'Audit log',
    subtitle: () => CT.util.plural(CT.store.state.audit.length, 'entry', 'entries'),
    actions: () => h('button.icon-btn', {
      type: 'button', 'aria-label': 'Export audit log',
      onClick: () => S.guardedExport({
        filename: 'checkertracker-audit.json', mime: 'application/json', title: 'Export audit log',
        summary: CT.store.state.audit.length + ' entries',
        content: JSON.stringify({
          tool: 'CheckerTracker', schema: 'checkertracker.audit/1',
          exportedAt: new Date().toISOString(),
          entries: CT.store.state.audit.map((a) => ({
            timestamp: new Date(a.ts).toISOString(), actor: a.actor, action: a.action, detail: a.detail
          }))
        }, null, 2)
      })
    }, icon('download')),
    render() {
      const list = CT.store.state.audit;
      if (!list.length) {
        return CT.dom.empty({ icon: 'list', title: 'Audit log is empty', body: 'Actions taken in the app are recorded here as they happen.' });
      }
      return h('div.stack.gap12', [
        CT.dom.notice(null, 'Local record',
          'Every authorization confirmation, scan, finding decision and export is recorded with a timestamp. The log lives on this device and is never transmitted.'),
        h('div.card.flush', h('div.list', list.slice(0, 200).map((a) => h('div.list-item.static', { style: { display: 'block' } }, [
          h('div.row.gap8', [
            h('span.tag', a.action),
            h('span.grow'),
            h('span.tiny.muted', CT.util.fmtDateTime(a.ts))
          ]),
          h('div.small.mt4', { style: { color: 'var(--text-2)', 'line-height': '1.45' } }, a.detail),
          a.mode ? h('div.mt4', h('span.demo-chip', a.mode)) : null
        ]))))
      ]);
    }
  };

  /* ==========================================================================
     ABOUT / SCOPE POLICY
     ======================================================================= */
  CT.ui.routes.about = {
    parent: '#/more', tab: 'more',
    title: () => 'About',
    subtitle: () => 'Purpose and boundaries',
    render() {
      return h('div.stack.gap12', [
        h('div.card', [
          h('div.brand-mark', [
            h('span', { style: { color: 'var(--accent)', display: 'flex' } }, CT.icons.logo(46)),
            h('span', [h('div.bt', 'CheckerTracker'), h('div.bs', 'Security visibility for authorized environments')])
          ]),
          h('p.small.dim.mt12', 'A mobile security toolkit for engineers, administrators and testers working inside environments they own or have written permission to assess. It builds an inventory, evaluates configuration against a defensive rule catalog, explains the resulting risk score, and tracks how the picture changes over time.')
        ]),

        h('div.card', [
          h('div.card-head', [icon('shieldCheck'), h('h3', 'What it does')]),
          h('ul', { style: { margin: 0, 'padding-left': '20px', 'font-size': '0.85em', color: 'var(--text-2)', 'line-height': '1.75' } }, [
            h('li', 'Records an inventory of devices and reachable services inside a declared scope'),
            h('li', 'Evaluates certificates, protocol versions, security headers and cookie attributes'),
            h('li', 'Flags configuration states that commonly precede an incident'),
            h('li', 'Produces an explainable score and reports you can hand to someone else'),
            h('li', 'Diffs assessments so drift is visible')
          ])
        ]),

        h('div.card', { style: { 'border-color': 'rgba(255,90,99,0.3)' } }, [
          h('div.card-head', [icon('shield'), h('h3', 'What it will never do')]),
          h('p.small.dim.mb8', 'These are architectural boundaries, not settings. No part of the codebase implements them.'),
          h('div.row.wrap.gap6', [
            'Credential theft', 'Password recovery', 'Keylogging', 'Malware delivery', 'Ransomware',
            'Persistence', 'Privilege escalation', 'Exploit deployment', 'Account takeover', 'Phishing',
            'Authentication bypass', 'Security control evasion', 'Covert surveillance', 'Data exfiltration'
          ].map((t) => h('span.tag', { style: { 'border-color': 'rgba(255,90,99,0.3)', color: 'var(--sev-critical)' } }, t))),
          h('p.small.mt12', { style: { color: 'var(--text-2)', 'line-height': '1.55' } },
            'Where a check could only be completed by exploiting something, CheckerTracker reports the observation instead — "potential issue detected, verify manually within the authorized environment" — and tells you how to confirm it safely.')
        ]),

        h('div.card', [
          h('div.card-head', [icon('scope'), h('h3', 'Scope policy')]),
          h('ul', { style: { margin: 0, 'padding-left': '20px', 'font-size': '0.85em', color: 'var(--text-2)', 'line-height': '1.75' } }, [
            h('li', 'Every active operation is bound to an explicitly declared scope'),
            h('li', 'Authorization must be confirmed before an active scan can start'),
            h('li', 'Confirmation is recorded in the audit log with scope and timestamp'),
            h('li', 'Authorization windows expire automatically after 24 hours'),
            h('li', 'Scopes broader than /16 are rejected'),
            h('li', 'Nothing outside the declared scope is contacted')
          ])
        ]),

        h('div.card', [
          h('div.card-head', [icon('info'), h('h3', 'Real versus simulated')]),
          h('p.small.dim.mb12', 'This build runs in a web runtime, which cannot open raw sockets. Rather than pretend otherwise, each capability declares itself:'),
          h('div.list', CT.engines.capabilities.CAPS.map((c) => h('div.list-item.static', [
            h('span.pill.' + (c.mode === 'real' ? 'ok' : c.mode === 'simulated' ? 'medium' : 'neutral'),
              c.mode === 'real' ? 'Real' : c.mode === 'simulated' ? 'Sim' : 'N/A'),
            h('span.grow.small', c.name)
          ]))),
          h('p.tiny.muted.mt12', 'Simulated results are stamped at the point of creation and stay marked through history, comparison, reports and exports.')
        ]),

        h('div.card', [
          h('div.card-head', [icon('user'), h('h3', 'Legal')]),
          h('p.small', { style: { color: 'var(--text-2)', 'line-height': '1.6' } },
            'Active security testing without the system owner\'s permission is a criminal offence in most jurisdictions. Obtain written authorization before assessing anything you do not own. You are responsible for how you use this tool.')
        ])
      ]);
    }
  };
})();
