"""Local environment, and inference about what was found.

Where a value cannot be read on this platform it is reported as None, and
the UI renders that as 'not determined'. On iOS especially, several of these
are simply unavailable to a sandboxed app; filling the gap with something
plausible is the behaviour this project exists to avoid.
"""

import re
import socket
import subprocess
import sys
import time

from . import scope as scope_mod


def _run(args, timeout=4):
    try:
        out = subprocess.run(args, capture_output=True, timeout=timeout, text=True)
        return out.stdout if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def local_address():
    """The address this machine would use to reach the network.

    Opening a UDP socket to a routable address sends nothing, but makes the
    kernel choose a source address and interface. It is the only portable way
    to learn this without platform APIs.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.0)
        sock.connect(("192.0.2.1", 9))     # TEST-NET-1, never routed
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def netmask_for(address):
    """Prefix length, if a system tool will tell us. Otherwise None.

    Guessing /24 would be wrong often enough to matter, so the UI asks for
    the CIDR instead when this comes back empty.
    """
    if not address:
        return None
    out = _run(["ip", "-4", "addr"]) or _run(["ifconfig"])
    if not out:
        return None
    match = re.search(re.escape(address) + r"/(\d{1,2})", out)
    if match:
        return int(match.group(1))
    match = re.search(re.escape(address) + r"\s+netmask\s+(?:0x([0-9a-f]{8})|([\d.]+))", out, re.I)
    if match:
        if match.group(1):
            return bin(int(match.group(1), 16)).count("1")
        try:
            return bin(scope_mod.ip_to_int(match.group(2))).count("1")
        except scope_mod.ScopeError:
            return None
    return None


def default_gateway():
    out = _run(["ip", "-4", "route", "show", "default"])
    if out:
        match = re.search(r"default\s+via\s+([\d.]+)", out)
        if match:
            return match.group(1)
    out = _run(["netstat", "-rn"])
    if out:
        match = re.search(r"(?:^|\n)(?:default|0\.0\.0\.0)\s+([\d.]+)", out)
        if match:
            return match.group(1)
    return None


def resolvers():
    """Configured DNS servers, where the platform exposes them."""
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
            return re.findall(r"^nameserver\s+([\d.]+)", handle.read(), re.M)
    except OSError:
        return []


def environment():
    address = local_address()
    prefix = netmask_for(address)
    subnet = None
    host_range = usable = None

    if address and prefix:
        info = scope_mod.cidr_info("%s/%d" % (address, prefix))
        subnet = "%s/%d" % (info["network"], prefix)
        host_range = "%s – %s" % (info["firstHost"], info["lastHost"])
        usable = info["usableHosts"]

    primary = {
        "name": None, "address": address, "netmask": None, "prefix": prefix,
        "mac": None, "subnet": subnet, "hostRange": host_range,
        "usableHosts": usable, "ipv6": None,
        "addressSpace": scope_mod.safe_range_of(address) if address else None,
    } if address else None

    return {
        "hostname": socket.gethostname(),
        "platform": sys.platform,
        "interfaces": [primary] if primary else [],
        "primary": primary,
        "gateway": default_gateway(),
        "dnsServers": resolvers(),
        "wifi": None,          # no portable source outside a native app
        "dhcpServer": None,
        "dhcpLease": None,
        "observedAt": int(time.time() * 1000),
    }


# ---------------------------------------------------------------------------
# Inference. Never an observation, so every result carries its signals.
# ---------------------------------------------------------------------------

FINGERPRINTS = [
    ("Printer", [9100], [515, 631], None, "raw print port 9100 with a spooler service"),
    ("Printer", [631], [515], None, "IPP and LPD print services"),
    ("Camera", [554], [80, 443, 8000], None, "RTSP stream endpoint"),
    ("NAS", [445], [5000, 5001, 548, 2049, 873], None,
     "SMB alongside NFS, AFP or a storage management interface"),
    ("Smartphone", [62078], [], "iOS", "iOS lockdown service on port 62078"),
    ("Smartphone", [5555], [], "Android", "Android debug bridge on port 5555"),
    ("Router", [53], [80, 443, 1900, 7547], None, "DNS forwarder with a management interface"),
    ("Switch", [161], [22, 23], None, "SNMP agent with a management shell"),
    ("Server", [3306], [], None, "MySQL/MariaDB listener"),
    ("Server", [5432], [], None, "PostgreSQL listener"),
    ("Server", [27017], [], None, "MongoDB listener"),
    ("Server", [6379], [], None, "Redis listener"),
    ("IoT", [1883], [], None, "MQTT broker"),
    ("IoT", [8123], [], None, "Home Assistant interface"),
    ("Desktop", [3389], [445, 139], "Windows", "RDP with SMB — a Windows machine"),
    ("Server", [22], [80, 443, 8080], None, "SSH alongside a web service"),
]

NAME_HINTS = [
    (r"(printer|drucker|mfp|officejet|laserjet|brother|epson|kyocera)", "Printer"),
    (r"(iphone|ipad|android|galaxy|pixel|oneplus)", "Smartphone"),
    (r"(macbook|thinkpad|laptop|notebook|xps)", "Laptop"),
    (r"(nas|synology|qnap|diskstation|truenas|unraid)", "NAS"),
    (r"(router|fritz|gateway|openwrt|unifi|speedport)", "Router"),
    (r"(cam|kamera|doorbell|ring|nest)", "Camera"),
    (r"(esp|shelly|tasmota|sonoff|tuya|hue|echo|alexa|chromecast|firetv)", "IoT"),
    (r"(srv|server|vm\d|docker|proxmox)", "Server"),
]

OS_BANNERS = [
    (r"ubuntu", "Linux (Ubuntu)"), (r"debian", "Linux (Debian)"),
    (r"raspbian", "Linux (Raspberry Pi OS)"), (r"centos|red hat|rhel", "Linux (RHEL family)"),
    (r"alpine", "Linux (Alpine)"), (r"freebsd", "FreeBSD"),
    (r"microsoft|win32|windows", "Windows"), (r"synology|dsm", "Synology DSM"),
    (r"openwrt", "OpenWrt"), (r"mikrotik|routeros", "MikroTik RouterOS"),
]


def ping_ttl(ip, timeout=1):
    """Reply TTL from a real ICMP echo, where ping exists and is permitted."""
    out = _run(["ping", "-c", "1", "-W", str(timeout), ip], timeout=timeout + 2)
    if out is None:
        out = _run(["ping", "-c", "1", "-t", str(timeout), ip], timeout=timeout + 2)
    if not out:
        return None
    match = re.search(r"ttl[=\s:]*(\d+)", out, re.I)
    return int(match.group(1)) if match else None


def os_from_ttl(ttl):
    """Hops only decrement TTL, so it rounds up to the nearest start value."""
    if not ttl:
        return None
    if ttl > 128:
        return ("Network device or BSD", "IP TTL near 255")
    if ttl > 64:
        return ("Windows", "IP TTL near 128")
    if ttl > 32:
        return ("Linux, macOS, Android or iOS", "IP TTL near 64")
    return None


def classify(ports, hostname=None, banners=None, ttl=None, is_gateway=False):
    signals = []
    device_type = None
    operating_system = None
    port_set = set(ports or [])

    if is_gateway:
        device_type = "Router"
        signals.append("carries the default route for this segment")

    if not device_type:
        for name, core, extra, os_hint, why in FINGERPRINTS:
            if all(p in port_set for p in core) and (not extra or any(p in port_set for p in extra)):
                device_type = name
                operating_system = os_hint
                signals.append(why)
                break

    if hostname:
        for pattern, name in NAME_HINTS:
            if re.search(pattern, hostname, re.I):
                signals.append('hostname "%s" matches a %s naming convention'
                               % (hostname, name.lower()))
                device_type = device_type or name
                break

    banner_text = "\n".join(banners or [])
    banner_os = False
    for pattern, name in OS_BANNERS:
        if re.search(pattern, banner_text, re.I):
            operating_system = name
            banner_os = True
            signals.append("service banner names " + name)
            break

    if not operating_system:
        guess = os_from_ttl(ttl)
        if guess:
            operating_system, why = guess
            signals.append(why)

    # Two independent signals is a classification. One is a lead.
    confidence = "high" if len(signals) >= 2 else ("medium" if signals else None)

    return {
        "deviceType": device_type or "Unknown",
        "os": operating_system,
        "osConfidence": ("high" if banner_os else "low") if operating_system else None,
        "typeConfidence": confidence if device_type else None,
        "signals": signals,
    }
