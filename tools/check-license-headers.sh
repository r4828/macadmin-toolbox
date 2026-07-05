#!/bin/bash
# SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors
# SPDX-License-Identifier: MIT
#
# Name:      check-license-headers.sh
# Purpose:   Fail if any script or document is missing its MIT attribution
#            header: an SPDX license identifier and a copyright line.
# Context:   Runs in CI and locally. From the repo root: tools/check-license-headers.sh
# Tested on: bash 3.2 (macOS), bash 5 (Ubuntu CI runners)

set -uo pipefail

# The top of a file counts as "the header" for this many lines.
HEADER_LINES=20

# License every in-scope file must declare, in SPDX form.
REQUIRED_SPDX="SPDX-License-Identifier: MIT"

# Files exempt from the check, with the reason each is exempt:
#   LICENSE             - it is the license text itself.
#   CODE_OF_CONDUCT.md  - the Contributor Covenant, licensed CC BY 4.0, not MIT;
#                         it attributes itself in its own text.
#   .github templates   - GitHub issue/PR meta files, not distributed content.
is_exempt() {
  case "$1" in
    LICENSE) return 0 ;;
    CODE_OF_CONDUCT.md) return 0 ;;
    .github/PULL_REQUEST_TEMPLATE.md) return 0 ;;
    .github/ISSUE_TEMPLATE/*) return 0 ;;
    *) return 1 ;;
  esac
}

# A file is in scope if it is a script or a document.
in_scope() {
  local f="$1"
  case "$f" in
    *.sh|*.bash|*.zsh|*.py|*.rb|*.pl|*.md) return 0 ;;
  esac
  # An extensionless file that opens with a shebang is a script.
  if [[ "$f" != *.* ]] && [ -f "$f" ]; then
    IFS= read -r first < "$f" || first=""
    case "$first" in
      '#!'*) return 0 ;;
    esac
  fi
  return 1
}

has_license() {
  head -n "$HEADER_LINES" "$1" | grep -Fq "$REQUIRED_SPDX"
}

has_copyright() {
  head -n "$HEADER_LINES" "$1" | grep -Eiq 'SPDX-FileCopyrightText:|Copyright'
}

fail=0
missing=()

# git ls-files keeps the check to tracked files and matches what ships.
while IFS= read -r f; do
  in_scope "$f" || continue
  is_exempt "$f" && continue
  problems=""
  has_license "$f"   || problems="${problems} [missing ${REQUIRED_SPDX}]"
  has_copyright "$f" || problems="${problems} [missing copyright line]"
  if [ -n "$problems" ]; then
    fail=1
    missing+=("${f}:${problems}")
  fi
done < <(git ls-files)

if [ "$fail" -ne 0 ]; then
  echo "License header check FAILED. These files need an MIT attribution header:"
  printf '  %s\n' "${missing[@]}"
  echo ""
  echo "Add these two lines to the file header, commented for the file type:"
  echo "  SPDX-FileCopyrightText: <year> <your name> and macadmin-toolbox contributors"
  echo "  ${REQUIRED_SPDX}"
  echo ""
  echo "See CONTRIBUTING.md for examples. Third-party files are exempt in tools/check-license-headers.sh."
  exit 1
fi

echo "License header check passed. Every script and document carries an MIT attribution header."
