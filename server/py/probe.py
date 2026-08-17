"""TCP probing: liveness, open ports, service banners.

Ordinary connect() scanning. The handshake completes and the socket closes
cleanly, which is visible in any target's logs, deliberately so.
"""

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

# Ports checked to decide whether an address is alive at all.
LIVENESS_PORTS = [80, 443, 22, 445, 139, 53, 8080, 3389, 631, 62078]

TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 80, 81, 88, 110, 111, 123, 135, 137, 138, 139, 143,
    161, 389, 443, 445, 465, 500, 515, 548, 554, 587, 631, 636, 873, 902, 993,
    995, 1080, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2082, 2083, 2086,
    2181, 2375, 2376, 3000, 3128, 3260, 3268, 3306, 3389, 4443, 4444, 5000,
    5001, 5060, 5061, 5222, 5353, 5432, 5555, 5601, 5672, 5900, 5901, 5985,
    5986, 6379, 6443, 7000, 7001, 8000, 8006, 8008, 8009, 8080, 8081, 8086,
    8088, 8123, 8443, 8500, 8888, 9000, 9090, 9092, 9100, 9200, 9300, 10000,
    11211, 27017, 32400, 49152, 51820, 62078,
]

SPEAKS_FIRST = {21, 22, 23, 25, 110, 143, 587, 3306, 5222, 6667}

HTTP_PORTS = {
    80, 81, 88, 591, 2082, 2086, 3000, 3128, 5000, 5001, 5601, 7000, 7001,
    8000, 8006, 8008, 8080, 8081, 8086, 8088, 8123, 8500, 8888, 9000, 9090,
    9200, 10000, 32400,
}

TLS_PORTS = {443, 465, 636, 989, 990, 993, 995, 2083, 2087, 4443, 5061, 5986,
             6443, 8443, 9443}

UDP_PORTS = {53, 67, 68, 123, 137, 138, 161, 500, 1900, 5353}


def probe_port(ip, port, timeout=0.9):
    """Probe one TCP port.

    A refusal is a reply: the host is up and this port is shut. Anything else
    is inconclusive and reported as filtered, never as closed.
    """
    started = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        state = "open"
    except ConnectionRefusedError:
        state = "closed"
    except (socket.timeout, OSError):
        state = "filtered"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return {"port": port, "state": state, "rttMs": int((time.time() - started) * 1000)}


def _map(items, worker, workers):
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        return list(pool.map(worker, items))


def probe_liveness(ip, timeout=0.7, ports=None):
    results = _map(ports or LIVENESS_PORTS, lambda p: probe_port(ip, p, timeout), 8)
    open_ports = [r["port"] for r in results if r["state"] == "open"]
    closed = [r for r in results if r["state"] == "closed"]
    rtts = [r["rttMs"] for r in results if r["state"] in ("open", "closed")]
    return {
        "ip": ip,
        "alive": bool(open_ports or closed),
        "evidence": "tcp-open" if open_ports else ("tcp-refused" if closed else None),
        "openPorts": open_ports,
        "rttMs": min(rtts) if rtts else None,
    }


def scan_ports(ip, ports, timeout=0.9, workers=24):
    results = _map(ports, lambda p: probe_port(ip, p, timeout), workers)
    return {
        "open": sorted(r["port"] for r in results if r["state"] == "open"),
        "closed": sum(1 for r in results if r["state"] == "closed"),
        "filtered": sum(1 for r in results if r["state"] == "filtered"),
        "tested": len(results),
    }


def grab_banner(ip, port, timeout=1.2):
    """Read whatever a service volunteers.

    Servers that greet first are simply listened to; HTTP ports get a HEAD
    request that identifies the scanner. Nothing resembling a credential is
    ever sent.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    chunks = b""
    try:
        sock.connect((ip, port))
        if port in SPEAKS_FIRST:
            try:
                chunks = sock.recv(2048)
            except (socket.timeout, OSError):
                chunks = b""
        if not chunks and port in HTTP_PORTS:
            sock.sendall(
                b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n"
                b"User-Agent: CheckerTracker/1.0 (authorized assessment)\r\n"
                b"Connection: close\r\n\r\n")
            deadline = time.time() + timeout
            while time.time() < deadline and len(chunks) < 4096:
                try:
                    part = sock.recv(2048)
                except (socket.timeout, OSError):
                    break
                if not part:
                    break
                chunks += part
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    text = chunks.decode("latin-1", "replace").strip()
    return text[:1024] or None


# Patterns matched against banners a service actually returned. No match
# means no claim: product and version stay None.
BANNER_PATTERNS = [
    (re.compile(r"^SSH-[\d.]+-OpenSSH[_-]([\w.]+)", re.I), "OpenSSH", 1),
    (re.compile(r"^SSH-[\d.]+-dropbear[_-]?([\w.]*)", re.I), "Dropbear", 1),
    (re.compile(r"^SSH-[\d.]+-(.+)$", re.I | re.M), 1, None),
    (re.compile(r"^220[- ].*?Postfix", re.I | re.M), "Postfix", None),
    (re.compile(r"^220[- ].*?Exim ([\w.]+)", re.I | re.M), "Exim", 1),
    (re.compile(r"^220[- ].*?vsFTPd ([\w.]+)", re.I | re.M), "vsftpd", 1),
    (re.compile(r"^Server:\s*nginx/([\w.]+)", re.I | re.M), "nginx", 1),
    (re.compile(r"^Server:\s*nginx", re.I | re.M), "nginx", None),
    (re.compile(r"^Server:\s*Apache/([\w.]+)", re.I | re.M), "Apache httpd", 1),
    (re.compile(r"^Server:\s*Apache", re.I | re.M), "Apache httpd", None),
    (re.compile(r"^Server:\s*Microsoft-IIS/([\w.]+)", re.I | re.M), "Microsoft IIS", 1),
    (re.compile(r"^Server:\s*lighttpd/([\w.]+)", re.I | re.M), "lighttpd", 1),
    (re.compile(r"^Server:\s*CUPS/([\w.]+)", re.I | re.M), "CUPS", 1),
    (re.compile(r"^Server:\s*(.+)$", re.I | re.M), 1, None),
    (re.compile(r"\+OK.*?Dovecot", re.I), "Dovecot", None),
    (re.compile(r"([\d.]+)-MariaDB", re.I), "MariaDB", 1),
]


def identify_banner(banner):
    if not banner:
        return {"product": None, "version": None, "confidence": None}
    for pattern, product, version_group in BANNER_PATTERNS:
        match = pattern.search(banner)
        if not match:
            continue
        name = match.group(product).strip() if isinstance(product, int) else product
        version = match.group(version_group) if version_group else None
        return {
            "product": name[:80] if name else None,
            "version": version[:40] if version else None,
            "confidence": "high" if version else "medium",
        }
    return {"product": None, "version": None, "confidence": None}
