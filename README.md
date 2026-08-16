# CheckerTracker

**Security visibility for authorized environments.**

A mobile-first security assessment toolkit for engineers, administrators and
testers working inside environments they own or have written permission to
assess. It builds an asset inventory, evaluates configuration against a
defensive rule catalog, explains the resulting risk score, and tracks how the
picture changes between assessments.

CheckerTracker is an *observation and analysis* tool. It contains no
exploitation, credential-capture, persistence or evasion capability of any
kind. See [SECURITY.md](SECURITY.md).

---

## Status

Complete. Every module `index.html` loads is present in `src/`, and the app
installs to a phone home screen as a progressive web app.

One caveat worth stating plainly: **it has never been loaded in a browser.**
The session that wrote it had no Node, no bundler and no browser, so the code
was reviewed by reading rather than by running. Roughly fifteen defects were
found and fixed that way — listener leaks, a persistence path that would have
silently dropped encryption, generated addresses falling outside the declared
scope, a score that saturated at zero — but expect to find something on first
load.

---

## Running it

Serve the directory over HTTP. A secure context is required for WebCrypto, so
`http://localhost` qualifies:

```
python3 -m http.server 8080
# then visit http://localhost:8080/
```

No build step, no package manager, no dependencies. Modules load as classic
scripts in dependency order onto a single `CT` namespace.

Opening `index.html` straight from disk works too, except for at-rest
encryption and SHA-family hashing — `file://` is not a secure context, so
WebCrypto is unavailable there.

### On a phone

CheckerTracker installs to the home screen, runs full-screen without browser
chrome, and works offline once loaded.

First publish it with **GitHub Pages** — *Settings → Pages*, source branch
`claude/checkertracker-security-app-x37epz` (or merge the branch to `main`
first). The app is then served at:

```
https://toastbrot0708.github.io/CheckerTracker/
```

Pages on a **private** repository requires a paid plan. On the free plan, make
the repository public first (*Settings → General → Change visibility*). There
is nothing sensitive in it: no credentials, no telemetry endpoint, no backend,
and the demo estate is fictional.

Then, on the phone:

| Platform | Steps |
| --- | --- |
| **iOS / iPadOS** | Open the URL in **Safari** — Chrome on iOS cannot install web apps — then Share → *Add to Home Screen* |
| **Android** | Open in Chrome → menu → *Install app* / *Add to Home screen* |

After the first load the service worker keeps the whole application cached, so
it launches without a connection. It deliberately never caches cross-origin
requests: the DNS Inspector's DoH queries and the header analyzer's fetch
always hit the network, because a cached answer presented as a live lookup
would make the app lie about what it observed.

Updates never interrupt you. A new version installs in the background and
waits; you get a quiet "relaunch to apply" toast rather than a reload in the
middle of an assessment.

### First run

| Option | What happens |
| --- | --- |
| **Start assessment** | Empty environment; declare a scope and run a scan. |
| **Explore demo environment** | Seeds two complete assessments over a simulated 18-asset estate, so findings, history, comparison, the map and reports are populated immediately. |
| **Import existing assessment** | Load a CheckerTracker JSON export; findings and score are recomputed locally. |

---

## What is real and what is simulated

This is the part that matters most, and the app is explicit about it on every
screen rather than in a footnote.

A web runtime cannot open raw TCP/UDP sockets, send ICMP or ARP, read the
local interface configuration, or inspect a TLS peer certificate. Rather than
fake those and present the output as observed fact, CheckerTracker declares
each capability and behaves accordingly.

**Genuinely real:**

- **IP / CIDR mathematics** — exact integer arithmetic.
- **X.509 certificate parsing** — a complete ASN.1/DER decoder is built in.
  Paste a PEM certificate and it is parsed on device: validity window, issuer
  and subject RDNs, SANs, key algorithm and size, signature algorithm, key
  usage, extended key usage, basic constraints and every extension OID.
- **RFC 6125 hostname matching**, including wildcard rules.
- **HTTP security header and cookie analysis** — CSP, HSTS (including
  `max-age` adequacy), `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, cookie `Secure`/`HttpOnly`/`SameSite`, redirect
  behaviour and version-disclosure banners.
- **DNS over HTTPS** — real queries against Cloudflare and Google resolvers.
- **Hashing** — SHA-256/384/512 and SHA-1 via WebCrypto, MD5 via a bundled
  RFC 1321 implementation. Works over text or a local file.
- **The entire analysis layer** — rule engine, risk scoring, snapshot diffing,
  report generation and every export run for real over whatever inventory they
  are given.

**Simulated, and permanently labelled as such:**

- Host discovery and service enumeration. A scan runs against a declared demo
  environment, and the assessment is stamped `mode: simulated` at creation.
  That stamp travels into history, comparisons, notifications, reports and the
  `dataOrigin` field of every JSON export.
- Local interface, Wi-Fi and DHCP details shown under Discover.

The distinction is visible in the app bar (a persistent **DEMO DATA** chip), at
the top of every screen showing simulated results (**SIMULATED ASSESSMENT**),
on each tool (Real / Limited), and in Settings → Runtime capabilities.

Findings computed *from* simulated observations go through exactly the same
engine a real dataset would. The observations are synthetic; the analysis is
not.

---

## Feature map

**Dashboard** — security score with grade, device/host/service/network counts,
severity breakdown, last-assessment summary, network overview, and an activity
timeline derived from the assessment record and the audit log.

**Discover** — current-environment detail plus discovered assets, with search
across IP, hostname, MAC, vendor, OS and service, and filters for servers,
workstations, mobile, IoT, network devices, unknown and high-risk.

**Scan Center** — a three-step wizard:
1. *Scope* — current network, custom CIDR, single host, asset group or saved
   scope, with live validation of network, host range and usable host count.
   Scopes broader than /16 are rejected.
2. *Scan type* — Passive Discovery, Network Discovery, Service Inventory,
   Configuration Audit, TLS/Certificate Audit, Web Security Review, or Full
   Assessment. Each profile defines its own stage pipeline and rule subset.
3. *Authorize* — explicit confirmation, without which no active scan can
   start. Scope and timestamp go into the audit log; the window expires after
   24 hours.

During a run: stage-by-stage progress, elapsed time, hosts processed, services
identified, findings detected, a technical live log, and pause/cancel.

**Findings** — severity and status filters, search, three sort orders. Each
finding carries title, severity, asset, service, confidence, timestamp,
structured evidence, description, impact, ranked remediation, references and
status. Actions: resolve, accept risk with justification, assign, add note,
create report. Resolving or accepting removes the finding's weight from the
score immediately.

**Assets** — inventory with search, filters and five sort orders, virtualized
for large estates. Asset detail covers identity, a services table with exposure
and risk per port, a security section (TLS state, certificate detail,
security-header table, authentication exposure, pass/review configuration
checks), that asset's findings, and a change history.

**Network map** — interactive SVG topology, gateway at the centre, devices
grouped by class on concentric rings. Pan, zoom, tap to open. Risk is encoded
by colour *and* by ring weight and stroke pattern, never colour alone. Ring
geometry adapts to density; 500+ nodes stay usable.

**Reports** — Executive Summary, Technical Assessment, Asset Inventory,
Findings Report, Network Overview. Each includes scope, methodology (with an
explicit list of what was *not* done), assets, findings by severity,
deduplicated recommendations, timeline and the authorization disclaimer.
Export as PDF (print dialog), JSON or CSV.

**Scan history & comparison** — every assessment retained, with a score
trajectory chart. Comparison mode diffs any two: new and removed assets,
service drift on hosts present in both, new and resolved findings, and
per-dimension score movement. Computed on demand, never stored.

**Tools** — CIDR calculator, DNS inspector, TLS inspector, HTTP header
analyzer, port/service reference (75+ entries), hash utility, notes.

**Settings** — privacy posture, app passcode and auto-lock, notification
categories, text size and reduced motion, export control, permissions
overview, runtime capability matrix, audit log, and a full local-data wipe.

---

## Security score

A weighted sum of five measured dimensions. Deterministic — the same inventory
and findings always produce the same number — and every point deducted is
attributable.

| Dimension | Weight | Measures |
| --- | --- | --- |
| Asset visibility | 15% | Identity completeness: hostname, vendor, OS, owner |
| Network exposure | 30% | Administrative, remote-access, database and cleartext services |
| TLS posture | 20% | Certificate validity and protocol configuration |
| Configuration | 25% | Headers, cookies, defaults, version currency, segmentation |
| Unknown assets | 10% | Share of devices present in the expected inventory |

Severity weights: critical 40, high 18, medium 7, low 2.5, informational 0.
Each finding-driven dimension compares its severity-weighted penalty against a
capacity that scales with the size of the estate, so the score discriminates
instead of saturating at zero on a busy network.

The CORP-LAB demo lands at 67/100 ("Fair") — an expired NAS certificate,
exposed RDP and VNC, an unmanaged IoT device and a printer with a SHA-1,
1024-bit certificate. The Security Score screen shows the full derivation:
each dimension's percentage, weight, points cost, the arithmetic behind it,
and the individual findings contributing most.

---

## Privacy and data handling

- Everything stays in local storage. No account, no backend, no telemetry.
- The only outbound requests are the DNS Inspector's DoH queries and the header
  analyzer's URL fetch — both on explicit user action, both labelled.
- An app passcode seals the store with AES-256-GCM under a PBKDF2-SHA256 key
  (210,000 iterations). The key exists only in memory while unlocked. There is
  no recovery path by design.
- Passwords, private keys, session tokens and cookie *values* are never stored.
  The header analyzer reads cookie *attributes* only.
- Exports are generated on device and require confirmation by default.

---

## Accessibility

Four text sizes scaling the whole interface; reduced-motion support (system
preference and in-app override); ≥44px touch targets; visible focus rings;
semantic controls with ARIA labels, `role="switch"` toggles and live regions
for scan progress; and no information conveyed by colour alone — severity
always carries a text label and a glyph, and map nodes carry distinct ring
treatments.

---

## Repository layout

```
index.html            Document shell and module loader (lists all 26 modules)
styles.css            Design system
src/                  Application modules, loaded in dependency order

manifest.webmanifest  Home-screen install metadata
sw.js                 Offline application shell
pwa.js                Service worker registration and the iOS icon
icon.svg              App icon (full bleed, maskable safe zone)
favicon.svg           Browser tab icon

README.md             This file
SECURITY.md           Safety boundaries and scope model
docs/ARCHITECTURE.md  Module contracts and data model
```

The three PWA files are deployment plumbing, not part of `CT`. Delete them and
the application behaves identically — it simply stops installing to a home
screen and stops working offline.
