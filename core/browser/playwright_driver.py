"""Optional Playwright-backed browser driver.

This is the real-browser implementation of the :class:`~core.browser.runner.BrowserDriver`
interface. It is deliberately constrained to the engagement scope: every request is
routed through an origin guard that aborts out-of-scope traffic, downloads and service
workers are disabled, navigation is headless, and resource/time limits are bounded.

Playwright is an optional dependency; the import is lazy so the rest of the engine (and
CI) never requires it. The real-browser path is exercised only by an optional E2E test.
"""
from __future__ import annotations

from core.browser.runner import PageObservation
from core.browser.scope import OriginScope

_DEFAULT_CHALLENGE_SELECTORS = (
    'iframe[src*="captcha"]', '[data-sitekey]', 'input[autocomplete="one-time-code"]',
    'input[name*="otp" i]', 'input[name*="mfa" i]', 'input[name*="2fa" i]',
)


class PlaywrightBrowserDriver:
    def __init__(self, origin_scope: OriginScope, *, headless: bool = True,
                 timeout_ms: int = 15000, session_headers: dict | None = None,
                 challenge_selectors=_DEFAULT_CHALLENGE_SELECTORS, playwright_factory=None) -> None:
        self.scope = origin_scope
        self.headless = bool(headless)
        self.timeout_ms = min(max(int(timeout_ms), 1000), 60000)
        self.session_headers = dict(session_headers or {})
        self.challenge_selectors = tuple(challenge_selectors)
        self._playwright_factory = playwright_factory
        self._pw = None
        self._browser = None

    def _ensure_browser(self):
        if self._browser is not None:
            return
        if self._playwright_factory is not None:
            factory = self._playwright_factory
        else:
            try:
                from playwright.sync_api import sync_playwright
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "Install the optional Playwright dependency to use the browser driver"
                ) from exc
            factory = sync_playwright
        self._pw = factory().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)

    def navigate(self, url: str) -> PageObservation:
        allowed, reason = self.scope.check(url)
        if not allowed:
            return PageObservation(url=url, error="refused_out_of_scope: " + str(reason))
        self._ensure_browser()
        context = self._browser.new_context(accept_downloads=False, service_workers="block",
                                             ignore_https_errors=False)
        if self.session_headers:
            context.set_extra_http_headers(self.session_headers)
        captured: list[dict] = []

        def guard(route):
            target = route.request.url
            if self.scope.allows(target):
                route.continue_()
            else:
                captured.append({"url": target, "method": route.request.method,
                                 "resource_type": route.request.resource_type,
                                 "blocked": True})
                route.abort()

        def on_response(response):
            request = response.request
            if not self.scope.allows(request.url):
                return
            captured.append({
                "url": request.url, "method": request.method,
                "status": response.status, "resource_type": request.resource_type,
                "headers": {name: "" for name in request.headers.keys()},
                "content_type": response.headers.get("content-type"),
                "initiator": None,
            })

        context.route("**/*", guard)
        context.on("response", on_response)
        page = context.new_page()
        try:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            except Exception as exc:
                return PageObservation(url=url, error="navigation_error: " + type(exc).__name__)
            final_url = page.url
            for selector in self.challenge_selectors:
                try:
                    if page.locator(selector).count():
                        return PageObservation(url=final_url, challenge=True)
                except Exception:
                    continue
            html = page.content()
            hrefs = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.getAttribute('href'))") or []
            links = tuple(href for href in hrefs if href)
            return PageObservation(url=final_url, status=200, html=html,
                                   links=links, network=tuple(captured))
        finally:
            context.close()

    def close(self) -> None:
        if self._browser is not None:
            try:
                self._browser.close()
            finally:
                self._browser = None
        if self._pw is not None:
            try:
                self._pw.stop()
            finally:
                self._pw = None
