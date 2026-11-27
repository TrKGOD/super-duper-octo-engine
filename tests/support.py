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


# -- real-browser tests ----------------------------------------------------------------------
BROWSER_GATE = "WITHERHOARD_REQUIRE_BROWSER"
_BROWSER_PROBE: list = []          # [problem-or-None], filled once per process


def browser_problem() -> str | None:
    """Why a real headless Chromium cannot be launched here, or ``None`` when it can (probed once).

    The ``playwright`` pip package can be installed without a browser binary (``playwright install``
    is a separate step), so importing it proves nothing: the probe launches a browser.
    """
    if not _BROWSER_PROBE:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            _BROWSER_PROBE.append("Playwright optional dependency is not installed")
        else:
            try:
                with sync_playwright() as playwright:
                    playwright.chromium.launch(headless=True).close()
                _BROWSER_PROBE.append(None)
            except Exception as exc:  # noqa: BLE001 - any launch failure means no usable browser
                _BROWSER_PROBE.append("Playwright browser binary is unavailable: " + type(exc).__name__)
    return _BROWSER_PROBE[0]


_UNPROBED = object()


def require_browser_or_skip(problem=_UNPROBED, *, require: bool | None = None) -> None:
    """Gate for real-browser tests, called from ``setUpClass``.

    * a usable browser: returns;
    * none, gate off: ``unittest.SkipTest`` with the reason (a default run needs no browser);
    * none, ``WITHERHOARD_REQUIRE_BROWSER=1``: ``AssertionError`` — the CI job that installs Chromium
      sets the gate, so "the browser tests did not run" can never be reported as green there.
    """
    import unittest
    problem = browser_problem() if problem is _UNPROBED else problem       # None means "usable"
    require = os.environ.get(BROWSER_GATE) == "1" if require is None else require
    if not problem:
        return
    if require:
        raise AssertionError(f"{BROWSER_GATE}=1 but no usable browser: {problem}")
    raise unittest.SkipTest(problem)
