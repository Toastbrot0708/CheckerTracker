#!/usr/bin/env python3
"""Launcher for the scanner service.

    python3 server/start.py

Use this rather than calling checkertracker.py directly. It guards the two
failure modes seen on a-Shell for iOS, where Python runs inside the app
process rather than as a separate one:

  1. Output is block-buffered, so the startup banner never appears and the
     service looks like it exited. stdout is switched to line buffering here,
     which removes the need for -u.

  2. A previous serve_forever() keeps running after the prompt returns. A
     second start cannot bind the port, and a third crashes the interpreter
     with 'pyinit_core_reconfigure: failed to read thread state'. The port is
     therefore tested first, and a clear message replaces the segfault.
"""

import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def port_is_free(port, host="0.0.0.0"):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        try:
            probe.close()
        except OSError:
            pass


def requested_port(argv):
    if "--port" in argv:
        index = argv.index("--port")
        if index + 1 < len(argv) and argv[index + 1].isdigit():
            return int(argv[index + 1])
    return 8899


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass                      # older interpreters simply stay buffered

    argv = sys.argv[1:]
    port = requested_port(argv)

    if not port_is_free(port):
        sys.stdout.write(
            "\nPort %d is already in use.\n\n"
            "On a-Shell this almost always means an earlier run of the service\n"
            "is still alive even though the prompt came back. Starting another\n"
            "one can crash the interpreter, so this stops here instead.\n\n"
            "Fix it one of two ways:\n"
            "  * Force-quit a-Shell (swipe it away in the app switcher) and\n"
            "    reopen it. That clears the stuck thread.\n"
            "  * Or use a different port:  python3 server/start.py --port 8900\n\n"
            "If the earlier run is still serving, you do not need a new one —\n"
            "just open http://localhost:%d/ in Safari.\n\n" % (port, port))
        sys.stdout.flush()
        sys.exit(1)

    import checkertracker
    checkertracker.main()


if __name__ == "__main__":
    main()
