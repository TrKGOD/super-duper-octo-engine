"""Isolated Playwright form-login runner.

The browser is constrained to one HTTPS origin, headless by default, with downloads,
popups and service workers disabled. It never writes a browser profile or storage state.
"""
from urllib.parse import urlsplit


class PlaywrightAuthRunner:
    def __init__(self, playwright_factory=None):
        self.playwright_factory = playwright_factory

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
        username = secret_resolver(username_env)
        password = secret_resolver(password_env)
        timeout = min(max(int(config.get("timeout_ms", 15000)), 1000), 30000)
        challenge_selectors = config.get("challenge_selectors", [
            'iframe[src*="captcha"]', '[data-sitekey]', 'input[autocomplete="one-time-code"]',
            'input[name*="otp" i]', 'input[name*="mfa" i]',
        ])

        factory = self.playwright_factory or sync_playwright
        with factory() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    accept_downloads=False, service_workers="block",
                    ignore_https_errors=False,
                )
                origin = (base.scheme, base.hostname, base.port or (443 if base.scheme == "https" else 80))
                def guard(route):
                    parsed = urlsplit(route.request.url)
                    candidate = (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
                    if candidate != origin:
                        route.abort()
                    else:
                        route.continue_()
                context.route("**/*", guard)
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
