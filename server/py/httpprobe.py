"""Real HTTP responses.

Outside the browser the full response head is visible, which is what makes
header analysis worth anything on a third-party host.

Cookie values are dropped at parse time. The analyzer judges attributes and
has no use for the value, so it never enters a record that could be exported
or persisted.
"""

import http.client
import re
import ssl
from urllib.parse import urlparse

MAX_BODY = 64 * 1024
UA = "CheckerTracker/1.0 (authorized assessment)"


def _insecure_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_head(url, timeout=8.0):
    """Fetch one URL. Redirects are reported, not followed."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"ok": False, "reason": "invalid-url"}

    secure = parsed.scheme == "https"
    port = parsed.port or (443 if secure else 80)
    path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")

    try:
        if secure:
            conn = http.client.HTTPSConnection(
                parsed.hostname, port, timeout=timeout, context=_insecure_context())
        else:
            conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        conn.request("GET", path, headers={
            "User-Agent": UA, "Accept": "*/*", "Connection": "close"})
        res = conn.getresponse()
        body = res.read(MAX_BODY).decode("utf-8", "replace")
        headers = {}
        cookies = []
        for name, value in res.getheaders():
            lower = name.lower()
            if lower == "set-cookie":
                cookies.append(parse_cookie(value))
            else:
                headers[lower] = value
        conn.close()

        return {
            "ok": True,
            "url": url,
            "scheme": parsed.scheme,
            "port": port,
            "status": res.status,
            "statusText": res.reason,
            "headers": headers,
            "cookies": cookies,
            "redirect": headers.get("location"),
            "server": headers.get("server"),
            "title": extract_title(body),
        }
    except Exception as err:  # noqa: BLE001 - any transport failure is a result
        return {"ok": False, "reason": "error", "message": str(err)}


def parse_cookie(line):
    """Reduce a Set-Cookie line to name plus protective attributes.

    The value is never copied out of this function.
    """
    parts = str(line).split(";")
    name = parts[0].split("=", 1)[0].strip()
    flags = [p.strip() for p in parts[1:]]
    lowered = [f.lower() for f in flags]

    def attr(prefix):
        for flag in flags:
            if flag.lower().startswith(prefix):
                return flag.split("=", 1)[1] if "=" in flag else None
        return None

    return {
        "name": name,
        "secure": "secure" in lowered,
        "httpOnly": "httponly" in lowered,
        "sameSite": attr("samesite="),
        "path": attr("path="),
        "hostOnly": attr("domain=") is None,
    }


def extract_title(body):
    match = re.search(r"<title[^>]*>([\s\S]{0,200}?)</title>", body or "", re.I)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120] or None


def probe_web(ip, port, use_tls=False, hostname=None, timeout=8.0):
    """Probe an open port as a web service, shaped for CT's asset.http field."""
    scheme = "https" if use_tls else "http"
    host = hostname or ip
    authority = host if port in (80, 443) else "%s:%d" % (host, port)
    res = fetch_head("%s://%s/" % (scheme, authority), timeout)
    if not res["ok"]:
        return None
    return {
        "port": port,
        "scheme": res["scheme"],
        "status": res["status"],
        "redirect": res["redirect"],
        "server": res["server"],
        "headers": res["headers"],
        "cookies": res["cookies"],
        "title": res["title"],
    }
