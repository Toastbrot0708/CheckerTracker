"""Deeper checks: UDP services, SSH algorithms, exposed web paths.

Everything here is read-only. Two boundaries are deliberate and worth
stating, because both would be easy to cross by accident:

  * SNMP presence is recorded, but no community string is ever sent. Trying
    'public' would be testing a credential, which this tool does not do.
  * Exposure checks use HEAD and keep only the status code. That an .env or
    .git directory is reachable is the finding; downloading it would make
    this tool the leak it exists to warn about.
"""

import socket
import struct


def _udp_ask(ip, port, payload, timeout=1.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(4096)
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def ssdp_discover(ip, timeout=2.0):
    """UPnP M-SEARCH. Devices answer with a model and a description URL,
    which is often the clearest identification an IoT device will give."""
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: %s:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n" % ip
    ).encode("ascii")
    reply = _udp_ask(ip, 1900, request, timeout)
    if not reply:
        return None

    text = reply.decode("latin-1", "replace")
    fields = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip().lower()] = value.strip()
    return {
        "server": fields.get("server"),
        "location": fields.get("location"),
        "usn": fields.get("usn"),
        "st": fields.get("st"),
    }


def dns_version(ip, timeout=1.5):
    """version.bind CHAOS TXT. A resolver that answers is disclosing its
    software version to anyone who asks."""
    header = struct.pack(">HHHHHH", 0x4354, 0x0000, 1, 0, 0, 0)
    name = b"\x07version\x04bind\x00"
    question = struct.pack(">HH", 16, 3)          # TXT, CHAOS
    reply = _udp_ask(ip, 53, header + name + question, timeout)
    if not reply or len(reply) < 12:
        return None
    if struct.unpack(">H", reply[6:8])[0] == 0:   # no answers
        return {"responds": True, "version": None}

    # Walk to the answer's rdata and read the single TXT string.
    pos = 12 + len(name) + 4
    try:
        while pos < len(reply) and reply[pos] not in (0, 0xC0):
            pos += 1
        pos += 2 if reply[pos] == 0xC0 else 1
        rdlen = struct.unpack(">H", reply[pos + 8:pos + 10])[0]
        rdata = reply[pos + 10:pos + 10 + rdlen]
        if rdata:
            return {"responds": True,
                    "version": rdata[1:1 + rdata[0]].decode("latin-1", "replace")}
    except (IndexError, struct.error):
        pass
    return {"responds": True, "version": None}


def ntp_present(ip, timeout=1.5):
    """Plain client request. Presence only — no monlist, nothing amplifiable."""
    packet = b"\x1b" + b"\x00" * 47
    return _udp_ask(ip, 123, packet, timeout) is not None


SSH_LISTS = ["kex", "hostKeyAlgorithms", "ciphersClientToServer",
             "ciphersServerToClient", "macsClientToServer", "macsServerToClient",
             "compressionClientToServer", "compressionServerToClient"]


def ssh_algorithms(ip, port=22, timeout=4.0):
    """Read the server's KEXINIT and list what it will negotiate.

    Nothing is authenticated and no key is exchanged: the banner and the
    first packet are enough to see whether weak key exchange, ciphers or MACs
    are still offered.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        banner = b""
        while b"\n" not in banner and len(banner) < 512:
            chunk = sock.recv(256)
            if not chunk:
                return None
            banner += chunk
        sock.sendall(b"SSH-2.0-CheckerTracker_1.0\r\n")

        data = b""
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 8 and len(data) >= struct.unpack(">I", data[:4])[0] + 4:
                break
        if len(data) < 22 or data[5] != 20:      # 20 = SSH_MSG_KEXINIT
            return {"banner": banner.decode("latin-1", "replace").strip()}

        pos = 22                                  # header(5) + type(1) + cookie(16)
        result = {"banner": banner.decode("latin-1", "replace").strip()}
        for key in SSH_LISTS:
            if pos + 4 > len(data):
                break
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            pos += 4
            raw = data[pos:pos + length].decode("latin-1", "replace")
            pos += length
            result[key] = [item for item in raw.split(",") if item]
        return result
    except (socket.timeout, OSError, struct.error):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


# Paths worth knowing about if they answer. Requested with HEAD; only the
# status code is kept, never a body.
EXPOSED_PATHS = [
    ("/.git/HEAD", "Source repository metadata"),
    ("/.env", "Environment file"),
    ("/server-status", "Apache status page"),
    ("/actuator/health", "Spring Boot actuator"),
    ("/phpinfo.php", "PHP configuration dump"),
    ("/.well-known/security.txt", "Security contact (informational)"),
]


def exposed_paths(ip, port, use_tls=False, hostname=None, timeout=4.0):
    import http.client
    import ssl

    host = hostname or ip
    found = []
    for path, label in EXPOSED_PATHS:
        try:
            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request("HEAD", path, headers={
                "Host": host,
                "User-Agent": "CheckerTracker/1.0 (authorized assessment)"})
            res = conn.getresponse()
            status = res.status
            length = res.getheader("Content-Length")
            conn.close()
            if status < 300:
                found.append({"path": path, "label": label,
                              "status": status, "size": length})
        except Exception:  # noqa: BLE001 - an unreachable path is simply absent
            continue
    return found
