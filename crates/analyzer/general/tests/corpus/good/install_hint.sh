#!/usr/bin/env bash
# Checks for a tool and prints how to install it; it never runs the installer itself.
set -euo pipefail
if ! command -v forge >/dev/null 2>&1; then
  echo "forge not found. Install Foundry with:"
  echo "  curl -L https://foundry.paradigm.xyz | bash"
  exit 1
fi
forge --version
