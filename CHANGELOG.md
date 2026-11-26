# Changelog

## Unreleased
- Added the Browser Intelligence Engine (`core/browser/`): scope-bounded SPA route,
  network and form discovery with normalization/deduplication, coverage accounting,
  secret-safe capture, human-challenge pause, and an injectable driver with an optional
  Playwright backend. Lab-verified by `tests/test_browser_intelligence.py`.
- Added `docs/BROWSER_INTELLIGENCE.md`, `docs/IMPLEMENTATION_STATUS.md` and
  `docs/ROADMAP_IMPLEMENTATION_AUDIT.md` (roadmap audit and phase/capability status).

## 0.1.0 — Bootstrap
- Added hybrid architecture specification.
- Preserved Model 1 baseline.
- Added Claude Code agent, skill, and command scaffolds.
- Added default-deny engagement configuration and Bash tripwire.
- Added SQLite schema, finding/handoff schemas, and bootstrap tests.
