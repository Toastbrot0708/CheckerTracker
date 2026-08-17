#!/usr/bin/env python3
"""CheckerTracker scanner service.

    python3 server/checkertracker.py
    python3 server/checkertracker.py --port 8899 --allow-public

Python 3.8+. No dependencies. Serves the application and the probe API from
one port, so a phone needs one URL and nothing else.
"""

import argparse
import json
import mimetypes
import os
import posixpath
import secrets
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from py import httpprobe, probe, scan, scope as scope_mod, sysinfo, tlsprobe  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = {}
CONFIG = {"allow_public": False, "token": None}

mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("image/svg+xml", ".svg")


def audit(action, detail):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    sys.stdout.write("[%s] %s  %s\n" % (stamp, action, detail))
    sys.stdout.flush()


class Handler(BaseHTTPRequestHandler):
    server_version = "CheckerTracker"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass                      # the audit log is the record, not access noise

    # -- helpers -----------------------------------------------------------

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            return {}

    def authorised(self, query):
        """Loopback callers are already on the machine running the scanner."""
        if not CONFIG["token"]:
            return True
        if self.client_address[0] in ("127.0.0.1", "::1"):
            return True
        header = self.headers.get("Authorization") or ""
        supplied = header[7:].strip() if header.startswith("Bearer ") else \
            (query.get("t") or [None])[0]
        return bool(supplied) and secrets.compare_digest(CONFIG["token"], supplied)

    # -- routing -----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path.startswith("/api"):
            if not self.authorised(query):
                self.send_json(401, {"error": "unauthorized",
                                     "message": "Open the URL the service printed."})
                return
            self.api_get(parsed.path[4:] or "/")
            return
        self.serve_static(parsed.path)

    def do_POST(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api"):
            self.send_error(405)
            return
        if not self.authorised(parse_qs(parsed.query)):
            self.send_json(401, {"error": "unauthorized",
                                 "message": "Open the URL the service printed."})
            return
        self.api_post(parsed.path[4:] or "/")

    def api_get(self, path):
        if path == "/health":
            self.send_json(200, {
                "ok": True, "service": "checkertracker", "runtime": "python",
                "version": "1.0.0", "platform": sys.platform,
                "allowPublic": CONFIG["allow_public"],
                "capabilities": {
                    "hostDiscovery": "real", "portScan": "real",
                    "interfaceInfo": "real", "tlsHandshake": "real",
                    "httpFetch": "real", "macAddress": "unavailable",
                    "hostnameResolution": "real",
                },
            })
            return
        if path == "/interfaces":
            self.send_json(200, sysinfo.environment())
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "scan" and parts[2] == "events":
            self.stream_events(parts[1])
            return
        self.send_json(404, {"error": "Unknown endpoint."})

    def api_post(self, path):
        body = self.read_json()

        if path == "/scan":
            self.start_scan(body)
            return

        if path == "/tls":
            if not body.get("host"):
                self.send_json(400, {"error": "host is required"})
                return
            audit("tls.inspect", "%s:%s" % (body["host"], body.get("port", 443)))
            self.send_json(200, tlsprobe.inspect(
                str(body["host"]), int(body.get("port") or 443),
                body.get("servername") or body["host"]))
            return

        if path == "/http":
            if not body.get("url"):
                self.send_json(400, {"error": "url is required"})
                return
            audit("http.fetch", str(body["url"]))
            self.send_json(200, httpprobe.fetch_head(str(body["url"])))
            return

        if path == "/port":
            if not body.get("host") or not body.get("port"):
                self.send_json(400, {"error": "host and port are required"})
                return
            host, port = str(body["host"]), int(body["port"])
            result = probe.probe_port(host, port, 3.0)
            banner = probe.grab_banner(host, port) if result["state"] == "open" else None
            result["banner"] = banner
            result["identity"] = probe.identify_banner(banner)
            self.send_json(200, result)
            return

        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "scan" and parts[2] == "control":
            run = RUNS.get(parts[1])
            if not run:
                self.send_json(404, {"error": "No such run."})
                return
            action = body.get("action")
            if action == "pause":
                run.pause()
            elif action == "resume":
                run.resume()
            elif action == "cancel":
                run.cancel()
            else:
                self.send_json(400, {"error": "Unknown action."})
                return
            self.send_json(200, {"state": run.state})
            return

        self.send_json(404, {"error": "Unknown endpoint."})

    def start_scan(self, body):
        # The gate. Not advisory, and not delegated to the UI.
        if body.get("authorized") is not True:
            self.send_json(403, {
                "error": "unauthorized",
                "message": "An assessment cannot start until the operator "
                           "confirms authorization for the systems in scope."})
            return

        try:
            parsed_scope = scope_mod.parse_scope(
                str(body.get("scope") or ""), CONFIG["allow_public"])
        except scope_mod.ScopeError as err:
            self.send_json(400, {"error": "scope", "message": str(err)})
            return

        env = sysinfo.environment()
        depth = body.get("depth")
        run = scan.Assessment(
            run_id="run-" + secrets.token_hex(6),
            scope=parsed_scope,
            depth=depth if depth in ("passive", "hosts", "services") else "services",
            stages=body.get("stages") or
            ["discover", "identify", "metadata", "tls", "headers"],
            gateway=env.get("gateway"),
            concurrency=max(8, min(128, int(body.get("concurrency") or 48))))

        RUNS[run.id] = run
        audit("scan.start", "%s (%d addresses, depth %s)"
              % (parsed_scope.label, parsed_scope.total, run.depth))
        threading.Thread(target=run.run, daemon=True).start()

        self.send_json(202, {
            "runId": run.id,
            "scope": {"label": parsed_scope.label, "total": parsed_scope.total},
            "network": env,
            "events": "/api/scan/%s/events" % run.id,
        })

    def stream_events(self, run_id):
        """Server-Sent Events. No extra protocol, and it survives a phone sleeping."""
        run = RUNS.get(run_id)
        if not run:
            self.send_json(404, {"error": "No such run."})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "close")
        self.end_headers()

        def write(kind, payload):
            self.wfile.write(("event: %s\ndata: %s\n\n"
                              % (kind, json.dumps(payload))).encode("utf-8"))
            self.wfile.flush()

        try:
            write("hello", {"runId": run.id, "state": run.state, "progress": run.progress})
            cursor = 0
            idle = 0
            while True:
                events = run.events[cursor:]
                cursor += len(events)
                for event in events:
                    write(event["type"], event["data"])
                    if event["type"] in ("done", "failed"):
                        return
                if events:
                    idle = 0
                else:
                    idle += 1
                    if idle % 60 == 0:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def serve_static(self, url_path):
        rel = unquote(url_path).lstrip("/") or "index.html"
        target = os.path.normpath(os.path.join(ROOT, rel))
        if not target.startswith(ROOT):
            self.send_error(403)
            return
        if not os.path.isfile(target):
            # A path with no extension belongs to the hash router; hand back
            # the shell so a deep link survives a reload.
            if not os.path.splitext(target)[1]:
                target = os.path.join(ROOT, "index.html")
            else:
                self.send_error(404)
                return
        try:
            with open(target, "rb") as handle:
                data = handle.read()
        except OSError:
            self.send_error(404)
            return

        ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description="CheckerTracker scanner service")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--allow-public", action="store_true",
                        help="permit scanning outside private address space")
    parser.add_argument("--no-token", action="store_true",
                        help="disable API authentication (localhost testing only)")
    args = parser.parse_args()

    CONFIG["allow_public"] = args.allow_public
    CONFIG["token"] = None if args.no_token else secrets.token_hex(16)

    local = sysinfo.local_address()
    query = ("/?t=" + CONFIG["token"]) if CONFIG["token"] else "/"

    print("\nCheckerTracker scanner service (Python)")
    print("  scanning        " + ("private and public addresses" if args.allow_public
                                  else "private address space only"))
    print("  api auth        " + ("token required" if CONFIG["token"]
                                  else "DISABLED (--no-token)"))
    print("\n  On this device:\n    http://localhost:%d/\n" % args.port)
    if local:
        print("  From another device on the same network:")
        print("    http://%s:%d%s\n" % (local, args.port, query))
    print("  Assess only networks you own or are authorized to test.")
    print("  Ctrl+C to stop.\n")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
