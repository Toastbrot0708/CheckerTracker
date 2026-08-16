# Architecture

No build step and no runtime dependency. `index.html` is a document shell that
loads `styles.css` and the modules in `src/` as classic scripts, in dependency
order, onto a single global `CT` namespace.

Classic scripts rather than ES modules is a deliberate choice: it keeps the
app working when served from any static host with no bundler, and preserves
the original single-file execution order exactly.

## Layers

```
                    +------------------------------+
  presentation      |  CT.ui.shell   CT.ui.routes  |
                    +---------------+--------------+
                                    |
                    +---------------+--------------+
  state             |  CT.store  (+ audit log)     |
                    +---------------+--------------+
                                    |
   +--------------------------------+-------------------------------+
   |                        CT.engines                              |
   |  capabilities  scanner  analyzer  tls  web  dns  risk          |
   |  assetdb  report                                               |
   +--------------------------------+-------------------------------+
                                    |
   +--------------------------------+-------------------------------+
   |  CT.util   CT.dom   CT.icons   CT.crypto   CT.net              |
   |  CT.data (reference DBs)   CT.demo (simulated environments)    |
   +----------------------------------------------------------------+
```

Data flows one way: observations enter at the bottom, engines derive findings
and scores, the store persists them, the UI renders. Nothing in the UI computes
risk of its own accord.

## Module reference

### Foundation

| File | Module | Responsibility |
| --- | --- | --- |
| `01-util.js` | `CT.util` | Formatting, collection helpers, and a seeded PRNG (mulberry32). Every simulated value derives from a seed, so a given scope + profile + run reproduces exactly. |
| `02-icons.js` | `CT.icons` | Inline SVG registry plus the brand mark. No external assets. |
| `03-dom.js` | `CT.dom` | Hyperscript render layer, shared primitives, and a virtualized list. |
| `04-crypto.js` | `CT.crypto` | WebCrypto SHA family, bundled RFC 1321 MD5, the AES-GCM + PBKDF2 vault, and a full ASN.1/DER and X.509 parser. |
| `05-net.js` | `CT.net` | IPv4 and CIDR mathematics, IPv6 compression, hostname validation, scope parsing. |

### Reference data

| File | Module | Contents |
| --- | --- | --- |
| `06-data.js` | `CT.data` | OUI vendor table (locally-administered MACs reported as randomised), a 75-entry port/service reference, device taxonomy, severity ranks/glyphs/weights, and the finding rule catalog. |
| `07-demo.js` | `CT.demo` | Two fictional environments in RFC 1918 space with `.internal` hostnames: CORP-LAB (18 assets, hand-authored) and CORP-LAB-DC (520 assets, deterministically generated). Also derives the "one week ago" snapshot that makes comparison mode real. |

Demo data supplies **observations only** — hosts, services, banners, headers,
certificate fields. It contains no findings, no risk values and no scores.
Those are always computed by the engines, through the same code path a real or
imported dataset would take.

### Engines

**`08-engine-capabilities.js`** — declares what this runtime can actually do.
Each entry is `real`, `simulated` or `unavailable` with a stated reason and,
where relevant, a fallback. Everything else consults it before claiming a
result. This module is what keeps the app honest.

**`16-engine-scanner.js`** — orchestration. Enforces the authorization gate,
builds a stage plan from the selected profile, drives it on a timer, emits
progress/stage/log events, supports pause and cancel, produces an assessment.

Two listener channels: `listeners` belong to whoever started the run and
survive the progress screen being rebuilt; `viewListeners` belong to the
current rendering and are discarded when it is rebuilt. This is why navigating
away from a running scan and back neither duplicates handlers nor loses the
handler that persists the result.

Tick rate adapts to plan size so an 18-asset run takes about nine seconds and a
520-asset run about fifteen.

**`11-engine-analyzer.js`** — the rule engine. Takes assets plus optional
baseline and network context, returns findings. Finding IDs are stable
(`ruleId|assetId|discriminator`) so status decisions survive re-scans and
snapshot diffs are meaningful.

Rule prose (description, impact, remediation, references) is **not** copied
onto each finding. It is resolved from `CT.data.rule(ruleId)` at display time;
duplicating it per instance would multiply the stored payload several-fold on
a large estate.

**`09-engine-tls.js`** — certificate and protocol evaluation over a normalised
TLS observation, so the same evaluator serves the simulated scan pipeline and
the fully real offline TLS Inspector.

**`10-engine-web.js`** — header checks, cookie attribute analysis,
version-disclosure detection, redirect behaviour, and a raw-response parser so
the header analyzer can work on pasted `curl -I` output.

**`14-engine-dns.js`** — DNS over HTTPS against Cloudflare with a Google
fallback. Read-only resolution; no zone transfer, no name enumeration.

**`12-engine-risk.js`** — explainable scoring. Returns the score plus a full
derivation: every dimension's percentage, weight, points cost and the
arithmetic behind it. `scoreAll()` indexes findings by asset once so a
500-asset list scores in linear rather than quadratic time.

**`13-engine-assetdb.js`** — snapshot diffing and per-asset change history,
computed on demand; no diff is ever stored.

**`15-engine-report.js`** — five report models, each declaring its own section
list, plus JSON, CSV and print exporters. Recommendations are deduplicated
across findings and ranked by highest contributing severity.

### State

**`17-store.js`** — a single state object with subscribe/notify, debounced
persistence, the audit log, notification generation, and demo seeding.

Persistence rules:

- Without a passcode: JSON in `localStorage`.
- With a passcode: the whole payload sealed with AES-256-GCM before writing.
- Locked with no key in memory: **no write at all**, rather than a silent
  plaintext fallback that would strip the encryption the user asked for.
- A failed write (typically the storage quota on the 520-asset environment)
  sets a flag the dashboard surfaces, instead of failing silently.

Finding status (`resolved`, `accepted`, assignee, notes) lives in a separate
`findingState` map keyed by stable finding ID, so decisions persist across
re-scans and are merged in by the `findings()` selector.

### Presentation

**`18-ui-shell.js`** — hash router, app bar, tab bar, bottom sheets, confirm
and prompt dialogs, toasts, the export flow, and shared components.

`render()` rebuilds the view; `renderChrome()` refreshes only the app bar and
tab bar. Store changes trigger the latter, so badges stay current without
dropping focus or discarding in-progress input in a form.

**`19-ui-dashboard.js`** through **`25-ui-settings.js`** — one entry per screen
in `CT.ui.routes`, each declaring `title`, `subtitle`, `tab`, optional `parent`
(which produces the back button) and `render()`.

**`26-ui-boot.js`** — onboarding, lock screen, settings application, auto-lock
timer and startup. Must load last.

## Data model

```js
Asset {
  id, hostname, ip, ipv6, mac, vendor, deviceType, os, osConfidence,
  owner, criticality, inInventory, status, firstSeen, lastSeen, tags[],
  services: [{ port, proto, name, service, product, version, versionConfidence, banner }],
  tls:  { port, protocols[], minProtocol, cipher, cert{...} } | null,
  http: { port, scheme, status, redirect, server, headers{}, cookies[], title } | null
}

Finding {
  id, ruleId, title, severity, category,
  assetId, assetLabel, assetIp, service,
  confidence, detail, evidence: [{ label, value }],
  discoveredAt, status, assignee, notes[], simulated
}

Assessment {
  id, number, startedAt, endedAt, durationMs,
  scopeLabel, scopeRaw, profileId, profileName,
  environmentId, environmentName, network,
  mode, simulated, authorization,
  assets[], findings[], score, stats, log[]
}
```

`mode` and `simulated` are set at creation and never mutated. They propagate
into history, comparisons, notifications, reports and the `dataOrigin` field of
every JSON export.

## Adding a rule

1. Add the entry to `CT.data.RULES` with `title`, `severity`, `category`,
   `description`, `impact`, `remediation[]` and `references[]`.
2. Map it to a score dimension in `CT.engines.risk.RULE_DIMENSION`.
3. Emit it from `CT.engines.analyzer.analyze()` with a stable `key`
   discriminator and structured `evidence`.
4. If it should only run under certain profiles, add its prefix to those
   profiles' `rules` array in `CT.engines.scanner.PROFILES`.

The rule must describe an observed configuration state and how to correct it.
It must not instruct, automate or assist an attack. See
[SECURITY.md](../SECURITY.md).

## Porting to native

The layering is designed so a React Native or native port replaces one layer
only. `CT.engines.capabilities` becomes the platform abstraction: on a native
target `hostDiscovery`, `portScan`, `interfaceInfo` and `tlsHandshake` flip to
`real`, backed by platform network APIs. `CT.engines.scanner` then drives real
probes instead of a demo environment, and stops stamping runs as simulated.
Everything below (`analyzer`, `tls`, `web`, `risk`, `assetdb`, `report`) is
pure logic over the data model and ports unchanged.
