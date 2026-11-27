"""Isolated Playwright form-login runner.

The browser is constrained to one origin, headless by default, with downloads, popups and
service workers disabled. It never writes a browser profile or storage state, takes no
screenshots, and never lets the credentials it typed leave this function (errors are scrubbed;
Playwright call logs can echo the value passed to ``fill``).

Browser traffic is the one network path that does *not* go through the HTTP broker, so it
needs its own guards:

* ``scope_guard`` (supplied by the broker) re-uses the broker's engagement-scope and
  non-public-address policy for the login origin, and returns the validated IP.
* The validated IP is **pinned inside Chromium** with ``--host-resolver-rules`` (everything
  else resolves to NOTFOUND), so a hostile DNS answer cannot redirect the browser after the
  check. IP-literal origins need no mapping.
* Every request, and every WebSocket, outside the single login origin is aborted.
"""
import ipaddress
from urllib.parse import urlsplit

from core.redaction import redact

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _origin(parsed):
    scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme, parsed.scheme)
    return (scheme, parsed.hostname, parsed.port or _DEFAULT_PORTS.get(parsed.scheme))


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _scrub(message, *secrets):
    text = str(message)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return redact(text)[:300]


class PlaywrightAuthRunner:
    def __init__(self, playwright_factory=None, scope_guard=None):
        self.playwright_factory = playwright_factory
        # ``scope_guard(url)`` raises if the URL is out of scope and returns the validated IP.
        self.scope_guard = scope_guard

    def __call__(self, *, config, secret_resolver):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Install the optional Playwright dependency to use browser authentication") from exc

        target = config.get("base_url")
        login_url = config.get("login_url")
        username_env = config.get("username_env")
        password_env = config.get("password_env")
        username_selector = config.get("username_selector")
        password_selector = config.get("password_selector")
        submit_selector = config.get("submit_selector")
        if not all((target, login_url, username_env, password_env,
                    username_selector, password_selector, submit_selector)):
            raise RuntimeError("Browser auth configuration is incomplete")
        base = urlsplit(target)
        login = urlsplit(login_url)
        if (base.scheme not in {"https", "http"} or not base.hostname or
                (base.scheme, base.hostname, base.port) !=
                (login.scheme, login.hostname, login.port)):
            raise RuntimeError("Browser login URL must share the exact configured origin")
        if base.scheme != "https" and base.hostname not in {"localhost", "127.0.0.1"}:
            raise RuntimeError("Browser authentication requires HTTPS outside localhost labs")
        pinned_ip = self.scope_guard(login_url) if self.scope_guard is not None else None

        username = secret_resolver(username_env)
        password = secret_resolver(password_env)
        timeout = min(max(int(config.get("timeout_ms", 15000)), 1000), 30000)
        challenge_selectors = config.get("challenge_selectors", [
            'iframe[src*="captcha"]', '[data-sitekey]', 'input[autocomplete="one-time-code"]',
            'input[name*="otp" i]', 'input[name*="mfa" i]',
        ])
        launch_args = []
        if pinned_ip and not _is_ip_literal(base.hostname):
            launch_args += [f"--host-resolver-rules=MAP {base.hostname} {pinned_ip},MAP * ~NOTFOUND",
                            "--no-proxy-server"]
        try:
            return self._login(
                sync_playwright, base, login_url, target, username, password, timeout,
                (username_selector, password_selector, submit_selector), challenge_selectors, launch_args)
        except Exception as exc:  # noqa: BLE001 - re-raised scrubbed; the cause chain is dropped on purpose
            raise RuntimeError("Browser authentication failed: " + _scrub(exc, username, password)) from None

    def _login(self, sync_playwright, base, login_url, target, username, password, timeout,
               selectors, challenge_selectors, launch_args):
        username_selector, password_selector, submit_selector = selectors
        factory = self.playwright_factory or sync_playwright
        origin = (base.scheme, base.hostname, base.port or _DEFAULT_PORTS[base.scheme])
        with factory() as playwright:
            browser = playwright.chromium.launch(headless=True, args=launch_args) \
                if launch_args else playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    accept_downloads=False, service_workers="block",
                    ignore_https_errors=False,
                )

                def guard(route):
                    if _origin(urlsplit(route.request.url)) != origin:
                        route.abort()
                    else:
                        route.continue_()
                context.route("**/*", guard)
                if hasattr(context, "route_web_socket"):
                    def websocket_guard(socket):
                        if _origin(urlsplit(socket.url)) != origin:
                            socket.close(code=1008, reason="blocked by scope guard")
                        else:
                            socket.connect_to_server()
                    context.route_web_socket("**/*", websocket_guard)
                page = context.new_page()
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout)
                page.locator(username_selector).fill(username, timeout=timeout)
                page.locator(password_selector).fill(password, timeout=timeout)
                page.locator(submit_selector).click(timeout=timeout)
                page.wait_for_load_state("domcontentloaded", timeout=timeout)
                for selector in challenge_selectors:
                    if page.locator(selector).count():
                        return {"challenge_required": True}
                cookies = context.cookies([target])
                if not cookies:
                    raise RuntimeError("Browser login completed without an origin-scoped session cookie")
                cookie_header = "; ".join(
                    item["name"] + "=" + item["value"] for item in cookies
                    if item.get("name") and item.get("value")
                )
                if not cookie_header:
                    raise RuntimeError("Browser session cookies were empty")
                return {"session_headers": {"Cookie": cookie_header}}
            finally:
                browser.close()
