# Running it entirely on a phone

No second computer, no server elsewhere. The scanner runs on the phone and
you open it in the phone's own browser.

## Why the hosted page alone cannot scan

This is a browser limit, not a limit of this project. A web page has no API
for raw sockets, ICMP or ARP, cannot read the interface configuration, and
cannot see a TLS peer certificate. The one remaining trick — inferring open
ports from `fetch` timing — is now blocked before the request leaves:

- **Chrome / Edge** enforce Private Network Access: a page served from a
  public origin may not contact `192.168.x.x`, `10.x.x.x` or `172.16-31.x.x`.
- **Safari** blocks the same thing under its mixed-content rule, since a
  page on HTTPS cannot reach a plain-HTTP address on your LAN.

So the hosted page gives you the analysis console and the offline tools —
real certificate parsing, DNS, header analysis, CIDR maths, hashing — and
says plainly that discovery is unavailable. It never fills the gap with
invented hosts.

## Android: the whole thing on the phone

[Termux](https://f-droid.org/packages/com.termux/) is a real Linux
environment on Android. Install it **from F-Droid** — the Play Store build
is abandoned and will fail.

```sh
pkg update
pkg install nodejs git openssl-tool
git clone https://github.com/Toastbrot0708/CheckerTracker.git
cd CheckerTracker
node server/checkertracker.js
```

Then open **http://localhost:8899/** in Chrome on the same phone.

`localhost` counts as a secure context, so this route also gives you
WebCrypto: the encrypted store and SHA hashing both work, with no
certificate warning to click through.

### What works, and what Android restricts

| | On Termux |
| --- | --- |
| Host discovery, port scan, banners | Works — Termux may open TCP sockets freely |
| TLS handshakes and certificates | Works |
| HTTP headers and cookie attributes | Works |
| Hostnames via mDNS and NetBIOS | Works |
| Reverse DNS | Works |
| ICMP TTL for OS hints | Usually works; Android's `ping` is unprivileged |
| **MAC addresses and vendors** | **Usually unavailable** — Android 10+ blocks `/proc/net/arp` for non-root apps |
| **Wi-Fi SSID** | **Unavailable** — no `nmcli` or `iwgetid` in Termux |

The two restricted items degrade the way everything else in this project
does: the field reports as not determined, and the capability screen states
the reason. Nothing is substituted.

Keep Termux in the foreground, or grant it the battery exemption Android
offers, or the sweep is suspended mid-run.

## iPhone and iPad

There is no equivalent. iOS has no general-purpose local shell, and an app
that scans a network needs entitlements only a signed native app can hold.
The realistic options are a native app built with Xcode and an Apple
developer account, or running the service on any other machine on the same
Wi-Fi and opening its URL from the phone.

## A native Android app

Android grants ordinary apps enough network access to do this properly —
TCP connect sweeps, `NetworkInterface` for the local address and netmask,
`WifiManager` for the SSID and DHCP lease, `InetAddress.isReachable()` for
liveness. A Kotlin port would remove Termux from the picture entirely.

The layering already anticipates this: `CT.engines.capabilities` is the
platform boundary, and `analyzer`, `tls`, `web`, `risk`, `assetdb` and
`report` are pure logic over the data model and port unchanged.
