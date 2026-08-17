"""One assessment run: stages, progress, pause and cancel.

Emits the events the browser progress screen already consumes. Progress
counts completed work, never elapsed time.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import httpprobe, names, probe, sysinfo, tlsprobe


class Cancelled(Exception):
    pass


class Assessment(object):
    def __init__(self, run_id, scope, depth="services", stages=None,
                 gateway=None, concurrency=64):
        self.id = run_id
        self.scope = scope
        self.depth = depth
        self.stage_ids = stages or []
        self.gateway = gateway
        self.concurrency = concurrency

        self.state = "running"
        self.started_at = int(time.time() * 1000)
        self.ended_at = None
        self.progress = 0
        self.assets = []
        self.log = []
        self.events = []
        self.counters = {"hosts": 0, "hostsTotal": scope.total, "services": 0}

        self._lock = threading.Lock()
        self._resume = threading.Event()
        self._resume.set()
        self._cancelled = False
        self._units = scope.total
        self._done = 0

    def emit(self, kind, payload):
        with self._lock:
            self.events.append({"type": kind, "data": payload})
            if len(self.events) > 4000:
                del self.events[:1000]

    def add_log(self, text, kind="info"):
        entry = {"ts": int(time.time() * 1000), "text": text, "kind": kind}
        self.log.append(entry)
        if len(self.log) > 800:
            self.log.pop(0)
        self.emit("log", entry)

    def tick(self):
        self._done += 1
        pct = min(99, int(self._done * 100 / max(1, self._units)))
        if pct != self.progress:
            self.progress = pct
            self.emit("progress", {"progress": pct, "counters": self.counters})

    def stage(self, stage_id, state, meta=None):
        self.emit("stage", {"id": stage_id, "state": state, "meta": meta})

    def checkpoint(self):
        self._resume.wait()
        if self._cancelled:
            raise Cancelled()

    def pause(self):
        self._resume.clear()
        self.state = "paused"
        self.emit("state", "paused")

    def resume(self):
        self._resume.set()
        self.state = "running"
        self.emit("state", "running")

    def cancel(self):
        self._cancelled = True
        self._resume.set()
        self.state = "cancelled"

    def wants(self, stage_id):
        return stage_id in self.stage_ids

    def _parallel(self, items, worker, workers):
        if not items:
            return []
        self.checkpoint()
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
            return list(pool.map(worker, items))

    # -- stages ------------------------------------------------------------

    def _discover(self):
        def check(ip):
            self.checkpoint()
            live = probe.probe_liveness(ip)
            self.tick()
            if live["alive"]:
                self.add_log("Host responding: %s (%s)" % (ip, live["evidence"]), "hit")
            return live

        results = self._parallel(self.scope.addresses, check, self.concurrency)
        return [r for r in results if r and r["alive"]]

    def _identify(self, live):
        if self.depth != "services":
            for _ in live:
                self.tick()
            return {}

        def sweep(host):
            self.checkpoint()
            scan = probe.scan_ports(host["ip"], probe.TOP_PORTS)
            self.tick()
            if scan["open"]:
                self.add_log("%s: %d open of %d tested (%s)" % (
                    host["ip"], len(scan["open"]), scan["tested"],
                    ", ".join(str(p) for p in scan["open"][:8])), "hit")
            return host["ip"], scan

        return dict(self._parallel(live, sweep, max(4, self.concurrency // 8)))

    def _metadata(self, live, port_map):
        def gather(host):
            self.checkpoint()
            ip = host["ip"]
            scan = port_map.get(ip)
            open_ports = (scan or {}).get("open") or host["openPorts"]

            name = names.resolve_hostname(ip)
            ttl = None if self.depth == "passive" else sysinfo.ping_ttl(ip)

            banners = {}
            if self.depth == "services":
                for port in [p for p in open_ports if p not in probe.TLS_PORTS][:10]:
                    text = probe.grab_banner(ip, port)
                    if text:
                        banners[port] = text

            info = sysinfo.classify(
                open_ports, name["name"] if name else None,
                list(banners.values()), ttl, self.gateway == ip)

            self.tick()
            if name:
                self.add_log("Resolved %s -> %s (%s)" % (ip, name["name"], name["source"]))
            return ip, {"name": name, "ttl": ttl, "banners": banners, "classification": info}

        return dict(self._parallel(live, gather, 12))

    def _endpoints(self, live, port_map, predicate):
        targets = []
        for host in live:
            scan = port_map.get(host["ip"])
            open_ports = (scan or {}).get("open") or host["openPorts"]
            matches = sorted(p for p in open_ports if predicate(p))
            if matches:
                targets.append((host["ip"], matches[0]))
        return targets

    # -- run ---------------------------------------------------------------

    def run(self):
        try:
            self.stage("authorize", "active")
            self.add_log("Scope authorized: %s (%d addresses)"
                         % (self.scope.label, self.scope.total))
            self.stage("authorize", "done", "%d addresses" % self.scope.total)

            self.stage("discover", "active")
            live = self._discover()
            self.counters["hosts"] = len(live)
            self.stage("discover", "done", "%d hosts" % len(live))
            if not live:
                self.finish([], {})
                return

            self._units += len(live) * 2

            port_map = {}
            if self.wants("identify"):
                self.stage("identify", "active")
                port_map = self._identify(live)
                self.counters["services"] = sum(len(s["open"]) for s in port_map.values())
                self.stage("identify", "done", "%d services" % self.counters["services"])

            self.stage("metadata", "active")
            meta = self._metadata(live, port_map)
            named = sum(1 for m in meta.values() if m["name"])
            self.stage("metadata", "done", "%d names resolved" % named)

            tls_map = {}
            if self.wants("tls"):
                targets = self._endpoints(live, port_map, lambda p: p in probe.TLS_PORTS)
                self._units += len(targets)
                self.stage("tls", "active")
                for ip, port in targets:
                    self.checkpoint()
                    host_name = (meta.get(ip, {}).get("name") or {}).get("name")
                    result = tlsprobe.inspect(ip, port, host_name)
                    self.tick()
                    if result["reachable"]:
                        tls_map[ip] = result
                        self.add_log("TLS %s:%d  %s  %s" % (
                            ip, port, result["negotiated"], result["cipher"] or "cipher unknown"))
                self.stage("tls", "done", "%d endpoints" % len(tls_map))

            http_map = {}
            if self.wants("headers"):
                targets = self._endpoints(
                    live, port_map,
                    lambda p: p in probe.HTTP_PORTS or p in probe.TLS_PORTS)
                self._units += len(targets)
                self.stage("headers", "active")
                for ip, port in targets:
                    self.checkpoint()
                    host_name = (meta.get(ip, {}).get("name") or {}).get("name")
                    result = httpprobe.probe_web(ip, port, port in probe.TLS_PORTS, host_name)
                    self.tick()
                    if result:
                        http_map[ip] = result
                        self.add_log("HTTP %s:%d  %s  %d headers" % (
                            ip, port, result["status"], len(result["headers"])))
                self.stage("headers", "done", "%d responses" % len(http_map))

            self.finish(build_assets(live, port_map, meta, tls_map, http_map), meta)

        except Cancelled:
            self.state = "cancelled"
            self.ended_at = int(time.time() * 1000)
            self.emit("failed", {"code": "cancelled",
                                 "message": "Assessment cancelled by the operator."})
        except Exception as err:      # noqa: BLE001 - report, never crash the service
            self.state = "error"
            self.ended_at = int(time.time() * 1000)
            self.add_log("Assessment failed: %s" % err, "fnd")
            self.emit("failed", {"code": "error", "message": str(err)})

    def finish(self, assets, meta):
        self.assets = assets
        self.progress = 100
        self.state = "done"
        self.ended_at = int(time.time() * 1000)
        self.counters["services"] = sum(len(a["services"]) for a in assets)
        self.add_log("Sweep complete: %d hosts, %d services observed"
                     % (len(assets), self.counters["services"]))
        self.emit("progress", {"progress": 100, "counters": self.counters})
        self.emit("done", {
            "id": self.id,
            "startedAt": self.started_at,
            "endedAt": self.ended_at,
            "durationMs": self.ended_at - self.started_at,
            "scopeLabel": self.scope.label,
            "assets": assets,
            "counters": self.counters,
            "log": list(self.log),
        })


def build_assets(live, port_map, meta, tls_map, http_map):
    """Shape observations into CT asset records.

    Fields with no source stay empty: owner because nobody assigned one,
    inInventory because the browser sets it against the baseline, and mac
    because iOS and Android both deny the ARP table to sandboxed apps.
    """
    observed_at = int(time.time() * 1000)
    assets = []

    for host in live:
        ip = host["ip"]
        info = meta.get(ip, {})
        scan = port_map.get(ip)
        open_ports = (scan or {}).get("open") or host["openPorts"]
        banners = info.get("banners") or {}
        classification = info.get("classification") or {
            "deviceType": "Unknown", "os": None, "osConfidence": None,
            "typeConfidence": None, "signals": []}
        name = info.get("name")

        services = []
        for port in sorted(open_ports):
            ident = probe.identify_banner(banners.get(port))
            services.append({
                "port": port,
                "proto": "udp" if port in probe.UDP_PORTS else "tcp",
                "name": None, "service": None,
                "product": ident["product"], "version": ident["version"],
                "versionConfidence": ident["confidence"],
                "banner": banners.get(port),
            })

        tls = tls_map.get(ip)
        assets.append({
            "id": "asset-" + ip.replace(".", "-"),
            "ip": ip,
            "hostname": name["name"] if name else None,
            "hostnameSource": name["source"] if name else None,
            "ipv6": None, "mac": None, "macRandomised": False, "vendor": None,
            "deviceType": classification["deviceType"],
            "deviceTypeConfidence": classification["typeConfidence"],
            "os": classification["os"],
            "osConfidence": classification["osConfidence"],
            "inferenceSignals": classification["signals"],
            "owner": None, "criticality": "standard", "inInventory": None, "tags": [],
            "status": "reachable",
            "reachedBy": host["evidence"],
            "rttMs": host["rttMs"],
            "ttl": info.get("ttl"),
            "firstSeen": observed_at, "lastSeen": observed_at,
            "services": services,
            "tls": tls, "http": http_map.get(ip),
            "coverage": {
                "portsTested": (scan or {}).get("tested", len(probe.LIVENESS_PORTS)),
                "portsOpen": len(open_ports),
                "portsClosed": (scan or {}).get("closed"),
                "portsFiltered": (scan or {}).get("filtered"),
                "method": "tcp-connect" if scan else "tcp-connect (liveness only)",
            },
        })

    return assets
