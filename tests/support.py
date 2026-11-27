"""Cross-platform helpers shared by the test-suite."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def finalize_fake_cli(script_path) -> str:
    """Make a Python-script fake of an external CLI executable on this platform.

    Test fakes of the ``claude`` CLI are written as ``#!<python>`` scripts. POSIX can execute
    those directly (after ``chmod``). Windows cannot: CreateProcess ignores shebangs, so the
    fake was reported as "CLI not found". On Windows the body is moved to ``<name>.py`` and a
    ``<name>.cmd`` launcher runs it with the current interpreter; the path to use as the
    command is returned in both cases.
    """
    path = Path(script_path)
    if os.name != "nt":
        path.chmod(0o755)
        return str(path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    body = path.with_name(path.name + ".py")
    body.write_text("".join(lines), encoding="utf-8")
    launcher = path.with_name(path.name + ".cmd")
    launcher.write_text('@"%s" "%s" %%*\r\n' % (sys.executable, body), encoding="utf-8")
    return str(launcher)


def make_dir_link(link, target) -> str:
    """Create a directory redirect at ``link`` pointing to ``target`` and return its kind.

    POSIX and privileged Windows use a real symlink. Unprivileged Windows cannot create
    symlinks (WinError 1314) but can create an NTFS junction, which redirects path
    resolution in exactly the same way and is what the confinement checks must also catch.
    """
    link, target = Path(link), Path(target)
    try:
        os.symlink(target, link, target_is_directory=True)
        return "symlink"
    except OSError:
        if os.name != "nt":
            raise
    import subprocess
    completed = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                               capture_output=True, text=True)
    if completed.returncode != 0:
        raise OSError("could not create a junction: " + completed.stderr.strip())
    return "junction"


def pid_alive(pid: int) -> bool:
    """True if a process with this id is currently running (zombies count as dead)."""
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259          # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    stat_path = f"/proc/{int(pid)}/stat"
    if os.path.exists(stat_path):
        with open(stat_path, "rb") as handle:
            if handle.read().rsplit(b")", 1)[-1].split()[:1] == [b"Z"]:
                return False
    return True


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.05) -> bool:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
