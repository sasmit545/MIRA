#!/usr/bin/env bash
# Initializes the rules/ submodules (capa-rules, signature-base) so
# run_capa / scan_yara have real content to load.
#
# rules/capa and rules/signature-base are git submodules (see .gitmodules),
# not plain files - a normal `git clone` leaves them as empty directories
# until this runs. wiring.py falls back to rules/capa and
# rules/signature-base/yara automatically once they're populated; override
# per-deployment with MIRA_CAPA_RULES_DIR / MIRA_YARA_RULES_DIR.
#
# To update to a newer upstream version:
#   git -C rules/capa fetch --tags && git -C rules/capa checkout <new-tag>
#   git -C rules/signature-base pull origin master
#   git add rules/capa rules/signature-base && git commit
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

git submodule update --init --recursive

echo
echo "Done. rules/capa and rules/signature-base are populated at their pinned commits."
git -C rules/capa describe --tags 2>/dev/null | sed 's/^/  capa-rules:      /'
git -C rules/signature-base log -1 --format='  signature-base:  %h (%cs)'
