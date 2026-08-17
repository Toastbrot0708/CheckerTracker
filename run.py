#!/usr/bin/env python3
"""CheckerTracker — one command to run everything.

    python3 run.py              start the scanner service
    python3 run.py --update     fetch the latest build, then start
    python3 run.py --port 8900  use a different port

Written for a-Shell on iOS, where Python runs inside the host app. Two
things there need handling that a desktop does not: output is block-buffered
unless told otherwise, and a previous run keeps serving after the prompt
returns, so a second start cannot bind and a third crashes the interpreter.
Both are dealt with before anything else happens.
"""

import os
import socket
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BRANCH = "claude/checkertracker-security-app-x37epz"
ZIP_URL = ("https://github.com/Toastbrot0708/CheckerTracker/archive/refs/heads/%s.zip"
           % BRANCH)


def unbuffer():
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass


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
    import shutil
    import tempfile
    import urllib.request
    import zipfile

    workspace = tempfile.mkdtemp()
    archive_path = os.path.join(workspace, "ct.zip")
    print("Downloading the latest build ...")
    try:
        urllib.request.urlretrieve(ZIP_URL, archive_path)
    except Exception as err:                       # noqa: BLE001
        print("Download failed: %s" % err)
        print("If the repository is private, make it public first.")
        return False

    try:
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(workspace)
    except zipfile.BadZipFile:
        print("That was not a zip file. The repository is probably still private.")
        return False

    folders = [name for name in os.listdir(workspace)
               if os.path.isdir(os.path.join(workspace, name))]
    if not folders:
        print("The archive contained nothing.")
        return False

    source = os.path.join(workspace, folders[0])
    for name in os.listdir(source):
        src = os.path.join(source, name)
        dst = os.path.join(ROOT, name)
        if os.path.isdir(src):
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)

    shutil.rmtree(workspace, ignore_errors=True)
    print("Updated.\n")
    print("Note: GitHub caches this archive for a few minutes, so a build")
    print("pushed just now may take a moment to appear here.\n")
    return True


def port_from(argv):
    if "--port" in argv:
        index = argv.index("--port")
        if index + 1 < len(argv) and argv[index + 1].isdigit():
            return int(argv[index + 1])
    return 8899


def main():
    unbuffer()
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
