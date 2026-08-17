"""Scope parsing and enforcement.

Mirrors the JavaScript service. This copy is the one that matters: the UI
can be bypassed by anything that reaches the port, this cannot.
"""

MAX_PREFIX = 16
MAX_ADDRESSES = 65536

# Ranges an assessment may touch without an explicit override.
SAFE_RANGES = [
    ("10.0.0.0", 8, "RFC 1918 private"),
    ("172.16.0.0", 12, "RFC 1918 private"),
    ("192.168.0.0", 16, "RFC 1918 private"),
    ("100.64.0.0", 10, "RFC 6598 carrier-grade NAT"),
    ("169.254.0.0", 16, "RFC 3927 link-local"),
    ("127.0.0.0", 8, "loopback"),
]


class ScopeError(ValueError):
    pass


def ip_to_int(ip):
    parts = str(ip).strip().split(".")
    if len(parts) != 4:
        raise ScopeError("Not an IPv4 address: %s" % ip)
    value = 0
    for part in parts:
        if not part.isdigit() or len(part) > 3:
            raise ScopeError("Not an IPv4 address: %s" % ip)
        octet = int(part)
        if octet > 255:
            raise ScopeError("Octet out of range: %s" % ip)
        value = value * 256 + octet
    return value


def int_to_ip(value):
    value &= 0xFFFFFFFF
    return "%d.%d.%d.%d" % (
        (value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255)


def mask_for(prefix):
    return 0 if prefix == 0 else ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)


def safe_range_of(ip):
    """Which private range an address falls in, or None if it is routable."""
    value = ip_to_int(ip)
    for base, prefix, label in SAFE_RANGES:
        mask = mask_for(prefix)
        network = ip_to_int(base) & mask
        broadcast = network | (~mask & 0xFFFFFFFF)
        if network <= value <= broadcast:
            return label
    return None


def cidr_info(text):
    raw = str(text).strip()
    if "/" in raw:
        addr, _, prefix_text = raw.partition("/")
        if not prefix_text.isdigit():
            raise ScopeError("Prefix must be a number: %s" % raw)
        prefix = int(prefix_text)
    else:
        addr, prefix = raw, 32
    if not 0 <= prefix <= 32:
        raise ScopeError("Prefix must be between /0 and /32: %s" % raw)

    mask = mask_for(prefix)
    network = ip_to_int(addr) & mask
    broadcast = network | (~mask & 0xFFFFFFFF)
    total = broadcast - network + 1

    return {
        "input": raw,
        "prefix": prefix,
        "network": int_to_ip(network),
        "broadcast": int_to_ip(broadcast),
        "netmask": int_to_ip(mask),
        "firstHost": int_to_ip(network if prefix >= 31 else network + 1),
        "lastHost": int_to_ip(broadcast if prefix >= 31 else broadcast - 1),
        "totalAddresses": total,
        "usableHosts": total if prefix >= 31 else max(0, total - 2),
        "safeRange": safe_range_of(int_to_ip(network)),
    }


class Scope(object):
    def __init__(self, label, entries, addresses):
        self.label = label
        self.entries = entries
        self.addresses = addresses
        self.total = len(addresses)
        self._set = set(addresses)

    def contains(self, ip):
        return ip in self._set


def parse_scope(text, allow_public=False):
    """Parse an operator scope into the exact addresses that may be touched."""
    pieces = [p.strip() for p in str(text or "").split(",") if p.strip()]
    if not pieces:
        raise ScopeError("No scope was supplied.")

    entries, addresses, seen = [], [], set()

    for piece in pieces:
        info = None
        if "-" in piece and "/" not in piece:
            low, _, high = piece.partition("-")
            first, last = ip_to_int(low.strip()), ip_to_int(high.strip())
            if last < first:
                raise ScopeError("Range runs backwards: %s" % piece)
        else:
            info = cidr_info(piece)
            if info["prefix"] < MAX_PREFIX:
                raise ScopeError(
                    "Scope %s is broader than /%d. Narrow it to the segment you "
                    "are authorized to assess." % (piece, MAX_PREFIX))
            first = ip_to_int(info["network"])
            last = ip_to_int(info["broadcast"])
            if info["prefix"] < 31:
                first += 1
                last -= 1

        if last < first:
            raise ScopeError("Scope %s contains no usable address." % piece)

        for value in range(first, last + 1):
            ip = int_to_ip(value)
            if not allow_public and safe_range_of(ip) is None:
                raise ScopeError(
                    "Address %s is outside private address space. Start the "
                    "service with --allow-public to assess routable addresses, "
                    "and only with written authorization for those systems." % ip)
            if ip in seen:
                continue
            seen.add(ip)
            addresses.append(ip)
            if len(addresses) > MAX_ADDRESSES:
                raise ScopeError("Scope exceeds %d addresses." % MAX_ADDRESSES)

        entries.append({
            "input": piece, "info": info,
            "first": int_to_ip(first), "last": int_to_ip(last),
            "count": last - first + 1,
        })

    return Scope(", ".join(e["input"] for e in entries), entries, addresses)
