"""Real TLS handshakes.

Verification is off throughout, and that is the point: an expired or
self-signed certificate is exactly what an assessment needs to see. Nothing
is ever written to these sockets.

The certificate comes back as DER and is decoded by the ASN.1 parser the
browser already has, so there is one parser rather than two that can
disagree.
"""

import base64
import socket
import ssl

VERSIONS = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


def _context(version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            # OpenSSL 3 refuses legacy versions at the default security level.
            # Relaxed here solely so they can be tested *for*.
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=0")
            except ssl.SSLError:
                pass
    return ctx


def handshake(host, port, servername=None, timeout=6.0, version=None):
    ctx = _context(version)
    sni = servername if servername and not servername.replace(".", "").isdigit() else None
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((host, port))
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            cipher = tls.cipher() or (None, None, None)
            return {
                "ok": True,
                "protocol": tls.version(),
                "cipher": cipher[0],
                "cipherVersion": cipher[1],
                "alpn": tls.selected_alpn_protocol(),
                "certDer": base64.b64encode(der).decode("ascii") if der else None,
            }
    except ssl.SSLError as err:
        return {"ok": False, "reason": "ssl", "message": str(err)}
    except (socket.timeout, OSError) as err:
        return {"ok": False, "reason": "connect", "message": str(err)}
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _local_refusal(result):
    """Errors raised by our own OpenSSL before anything reached the network."""
    text = ((result.get("reason") or "") + " " + (result.get("message") or "")).lower()
    return any(needle in text for needle in (
        "no protocols available", "unsupported protocol", "version too low",
        "no ciphers available", "wrong_version"))


def enumerate_protocols(host, port, servername=None, timeout=4.0):
    """Three outcomes per version, kept distinct.

    'untestable' means this Python build would not offer the version, which
    is a fact about the scanner, not the target. Reporting it as unsupported
    would be a result we never observed.
    """
    accepted, refused, untestable = [], [], []
    for label, version in VERSIONS:
        result = handshake(host, port, servername, timeout, version)
        if result["ok"]:
            accepted.append(label)
        elif _local_refusal(result):
            untestable.append(label)
        else:
            refused.append(label)
    return accepted, refused, untestable


def inspect(host, port, servername=None, timeout=6.0, enumerate_versions=True):
    primary = handshake(host, port, servername, timeout)
    if not primary["ok"]:
        return {"port": port, "reachable": False,
                "reason": primary["reason"], "message": primary.get("message")}

    if enumerate_versions:
        accepted, refused, untestable = enumerate_protocols(host, port, servername)
    else:
        accepted = [primary["protocol"]] if primary["protocol"] else []
        refused, untestable = [], [v[0] for v in VERSIONS]

    return {
        "port": port,
        "reachable": True,
        "negotiated": primary["protocol"],
        "protocols": accepted,
        "protocolsRefused": refused,
        "protocolsUntestable": untestable,
        "minProtocol": accepted[0] if accepted else primary["protocol"],
        "cipher": primary["cipher"],
        "alpn": primary["alpn"],
        "trusted": False,
        "trustError": "chain not validated — inspection mode",
        "certDer": primary["certDer"],
        "chainDer": [],
    }
