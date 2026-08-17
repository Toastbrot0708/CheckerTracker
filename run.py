#!/usr/bin/env python3
"""CheckerTracker — one command to run everything.

    python3 run.py              start the scanner service
    python3 run.py --update     fetch the latest build, then start
    python3 run.py --port 8900  use a different port

Written for a-Shell on iOS, where Python runs inside the host app. Three
things there need handling that a desktop does not:

  * Output is block-buffered and reconfigure(line_buffering=True) is not
    enough, so print is replaced with a flushing version. Without this the
    startup banner never appears and the service looks like it died.
  * A previous run keeps serving after the prompt returns, so a second start
    cannot bind the port and a third crashes the interpreter.
  * The shell's working directory is easy to lose, so every path here is
    absolute.
"""

import builtins
import os
import socket
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BRANCH = "claude/checkertracker-security-app-x37epz"
ZIP_URL = ("https://github.com/Toastbrot0708/CheckerTracker/archive/refs/heads/%s.zip"
           % BRANCH)


def force_flush():
    """Make every print reach the screen immediately.

    Applies to imported modules too, since they all call builtins.print.
    """
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    original = builtins.print

    def flushing(*args, **kwargs):
        kwargs["flush"] = True
        original(*args, **kwargs)

    builtins.print = flushing


def port_is_free(port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        try:
            probe.close()
        except OSError:
            pass


def update():
    """Replace the working copy with the latest build."""
    import io
    import shutil
    import urllib.request
    import zipfile

    print("Downloading the latest build ...")
    try:
        payload = urllib.request.urlopen(ZIP_URL, timeout=60).read()
    except Exception as err:                       # noqa: BLE001
        print("Download failed: %s" % err)
        print("If the repository is private, make it public first.")
        return False
    print("Received %d bytes." % len(payload))

    staging = os.path.join(os.path.dirname(ROOT), "_ct_staging")
    shutil.rmtree(staging, ignore_errors=True)
    try:
        zipfile.ZipFile(io.BytesIO(payload)).extractall(staging)
    except zipfile.BadZipFile:
        print("That was not a zip file — the repository is probably private.")
        return False

    folders = [n for n in os.listdir(staging)
               if os.path.isdir(os.path.join(staging, n))]
    if not folders:
        print("The archive contained nothing.")
        shutil.rmtree(staging, ignore_errors=True)
        return False

    source = os.path.join(staging, folders[0])
    for name in os.listdir(source):
        src = os.path.join(source, name)
        dst = os.path.join(ROOT, name)
        if os.path.isdir(src):
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    shutil.rmtree(staging, ignore_errors=True)

    print("Updated.")
    print("GitHub caches this archive briefly, so a build pushed in the last")
    print("minute or two may not be in it yet.\n")
    return True


def port_from(argv):
    if "--port" in argv:
        index = argv.index("--port")
        if index + 1 < len(argv) and argv[index + 1].isdigit():
            return int(argv[index + 1])
    return 8899


def main():
    force_flush()
    argv = [a for a in sys.argv[1:] if a != "--update"]

    if "--update" in sys.argv[1:] and not update():
        sys.exit(1)

    port = port_from(argv)
    if not port_is_free(port):
        print(
            "\nPort %d is already in use.\n\n"
            "An earlier run is almost certainly still serving — in a-Shell the\n"
            "prompt comes back but the service keeps going. You do not need a\n"
            "new one:\n\n"
            "    open http://localhost:%d/ in Safari\n\n"
            "To actually restart, force-quit a-Shell (swipe it away in the app\n"
            "switcher) and run this again. Or pick another port:\n\n"
            "    python3 run.py --port %d\n" % (port, port, port + 1))
        sys.exit(1)

    server_dir = os.path.join(ROOT, "server")
    if not os.path.isdir(server_dir):
        print("server/ is missing. Run:  python3 run.py --update")
        sys.exit(1)

    sys.path.insert(0, server_dir)
    sys.argv = [sys.argv[0]] + argv
    import checkertracker
    checkertracker.main()


if __name__ == "__main__":
    main()
