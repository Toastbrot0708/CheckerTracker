"""Hostname resolution from three real sources.

Home networks rarely have PTR records, so reverse DNS alone leaves an
inventory full of bare addresses. mDNS covers Apple, Android and most IoT;
NetBIOS covers Windows and NAS boxes. Each answer records where it came
from, so no name is unattributable.

All three are read-only lookups. No zone transfer, no name enumeration.
"""

import socket
import struct


def _encode_name(name):
    out = b""
    for label in str(name).split("."):
        if not label:
            continue
        raw = label.encode("ascii", "ignore")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(buf, offset):
    """Read a possibly compressed name. Returns (name, offset_after)."""
    labels = []
    pos = offset
    after = None
    hops = 0
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                break
            if after is None:
                after = pos + 2
            pos = ((length & 0x3F) << 8) | buf[pos + 1]
            hops += 1
            if hops > 16:          # malformed packet, refuse to loop
                break
            continue
        if pos + 1 + length > len(buf):
            break
        labels.append(buf[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return ".".join(labels), (pos if after is None else after)


def _query_packet(ident, name, qtype, qclass):
    header = struct.pack(">HHHHHH", ident, 0x0000, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack(">HH", qtype, qclass)


def _send_udp(packet, host, port, timeout, multicast=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        if multicast:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            except OSError:
                pass
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def reverse_dns(ip, timeout=2.0):
    original = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return {"name": name, "source": "reverse-dns"}
    except (socket.herror, socket.gaierror, OSError):
        return None          # NXDOMAIN is the normal case on a home LAN
    finally:
        socket.setdefaulttimeout(original)


def mdns_name(ip, timeout=1.2):
    """Reverse PTR over multicast DNS.

    Class 0x8001 sets the unicast-response bit, so the answer returns to this
    socket directly instead of requiring multicast group membership.
    """
    arpa = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    reply = _send_udp(_query_packet(0, arpa, 12, 0x8001), "224.0.0.251", 5353,
                      timeout, multicast=True)
    if not reply or len(reply) < 12:
        return None

    questions, answers = struct.unpack(">HH", reply[4:8])
    if not answers:
        return None

    pos = 12
    for _ in range(questions):
        pos = _read_name(reply, pos)[1] + 4

    for _ in range(answers):
        if pos + 10 > len(reply):
            break
        pos = _read_name(reply, pos)[1]
        if pos + 10 > len(reply):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", reply[pos:pos + 10])
        rdata = pos + 10
        if rtype == 12:
            name = _read_name(reply, rdata)[0]
            if name:
                return {"name": name.rstrip("."), "source": "mdns"}
        pos = rdata + rdlen
    return None


def _encode_netbios(name):
    """First-level encoding: each byte becomes two nibble characters from 'A'."""
    padded = bytearray(b" " * 16)
    raw = name.encode("ascii")[:15]
    padded[0:len(raw)] = raw
    padded[15] = 0x00
    out = bytearray([0x20])
    for byte in padded:
        out.append(0x41 + ((byte >> 4) & 0x0F))
        out.append(0x41 + (byte & 0x0F))
    out.append(0x00)
    return bytes(out)


def netbios_name(ip, timeout=1.2):
    """NBSTAT node status: asks a host to list its own NetBIOS names."""
    header = struct.pack(">HHHHHH", 0x4354, 0x0000, 1, 0, 0, 0)
    packet = header + _encode_netbios("*") + struct.pack(">HH", 0x0021, 0x0001)
    reply = _send_udp(packet, ip, 137, timeout)
    if not reply or len(reply) < 57:
        return None

    # header(12) + echoed question(34 + 4) + type/class/ttl/rdlength(10)
    pos = 12 + 34 + 4 + 10
    if pos >= len(reply):
        return None
    count = reply[pos]
    pos += 1

    workstation = group = None
    for _ in range(count):
        if pos + 18 > len(reply):
            break
        label = reply[pos:pos + 15].decode("ascii", "replace").strip()
        suffix = reply[pos + 15]
        flags = struct.unpack(">H", reply[pos + 16:pos + 18])[0]
        is_group = bool(flags & 0x8000)
        if suffix == 0x00:
            if is_group and group is None:
                group = label
            elif not is_group and workstation is None:
                workstation = label
        pos += 18

    if not workstation:
        return None
    return {"name": workstation, "workgroup": group, "source": "netbios"}


def resolve_hostname(ip, timeout=1.2):
    """Reverse DNS is most authoritative where it exists; the other two fill
    the gap it usually leaves on a private network."""
    return (reverse_dns(ip, timeout)
            or mdns_name(ip, timeout)
            or netbios_name(ip, timeout))
