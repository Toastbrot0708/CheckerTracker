# Security boundaries and scope model

CheckerTracker is built for **authorized** security assessment only. This
document states what the tool does, what it structurally refuses to do, and how
the authorization model is enforced.

## Intended use

Assessing an environment you own, or one you have explicit written permission
to test. Typical users: security engineers, system and network administrators,
internal audit, and penetration testers working within an agreed engagement
scope.

Active security testing without the system owner's permission is a criminal
offence in most jurisdictions. Obtain written authorization first.

## Authorization model

Every active operation is bound to a declared scope.

1. **Scope is explicit.** The operator declares it as a CIDR block, a single
   host, an asset group, or a saved scope. It is parsed, validated and
   normalised before anything runs.
2. **Scopes are bounded.** Blocks broader than `/16` are rejected outright.
3. **Confirmation is mandatory.** An active scan cannot start until the
   operator confirms *"I confirm that I am authorized to test these systems."*
   The start control stays disabled until then, and the scan engine
   independently rejects any run whose `authorized` flag is false — the check
   is not only in the UI.
4. **Authorization expires.** Confirmation opens a 24-hour window tied to that
   specific scope. It lapses automatically.
5. **Everything is recorded.** Scope, profile, confirmation timestamp,
   execution mode and outcome go into a local audit log that the operator can
   review and export.
6. **Nothing outside the scope is contacted.** Targets are filtered by the
   parsed scope before any stage runs.

## Capabilities that are deliberately absent

These are architectural boundaries, not configuration options. No part of the
codebase implements them, and no setting enables them.

- Credential theft, harvesting or storage
- Password cracking, reversal or recovery
- Keylogging or input capture
- Malware or ransomware delivery of any kind
- Persistence or backdoor installation
- Privilege escalation
- Exploit development or deployment
- Account takeover
- Phishing or credential-collection pages
- Authentication bypass
- Evasion of security controls, logging or detection
- Covert surveillance
- Exfiltration of data to any remote endpoint

The application makes **no** outbound request except two, both user-initiated
and both clearly labelled: DNS-over-HTTPS lookups in the DNS Inspector, and the
optional URL fetch in the HTTP Header Analyzer.

## Observation, not exploitation

Every rule in the finding catalog describes a **configuration state** and how
to correct it. None instruct, automate or assist an attack.

Where a check could only be completed by exploiting something, CheckerTracker
reports the observation and hands it back to the operator:

> Potential issue detected — verify manually within the authorized environment.

Concretely:

- **Default configuration indicator** reports that a device *presents* factory
  identifiers. No credentials are ever submitted or tested.
- **Outdated software indicator** reports a self-reported version banner and
  explicitly notes that backported patches are invisible this way. It does not
  claim a vulnerability is present or exploitable.
- **Exposed administrative service** reports reachability and asks the operator
  to verify access restrictions. It does not attempt to authenticate.
- **IoT device exposing an unauthenticated service** notes that such services
  commonly ship without authentication, and states that no authentication was
  attempted.

Finding detail screens carry a standing reminder that CheckerTracker reports
observed configuration state, does not confirm exploitability, and that
findings should be validated manually before remediation.

## Data the application will not hold

- Passwords or passphrases for any third-party system
- Private keys or key material
- Session tokens, API tokens or bearer credentials
- Cookie *values* (the header analyzer evaluates cookie *attributes* only)

Evidence attached to findings is limited to non-secret technical facts: port
numbers, protocol versions, header names and values, certificate metadata,
MAC/OUI data and timestamps.

## Data at rest

- Storage is local to the device. There is no backend and no account.
- With an app passcode set, the entire store is sealed with AES-256-GCM under
  a key derived by PBKDF2-SHA256 at 210,000 iterations. The key lives only in
  memory while the app is unlocked and is discarded on auto-lock.
- There is no passcode recovery mechanism. This is intentional.
- If the store is locked and no key is held in memory, the app will not write
  at all rather than silently fall back to a plaintext write.
- Exports are generated on device and gated behind a confirmation prompt by
  default.

## Reporting a problem

If you find a way to make CheckerTracker exceed the boundaries described here
— in particular, anything that contacts a host outside the declared scope,
captures credential material, or performs an action rather than an observation
— treat it as a security defect and report it.
