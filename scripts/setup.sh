#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python scripts/validate_config.py
python -m unittest discover -s tests -v
echo "Bootstrap checks passed. Start Claude Code with: claude"
