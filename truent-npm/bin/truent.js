#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const { getBinaryPath, isBinaryInstalled } = require("../lib/binary-path");

if (!isBinaryInstalled()) {
  console.error([
    "",
    "  error: Truent binary is not installed.",
    "",
    "  This can happen if the postinstall script was skipped.",
    "  Run one of the following to fix it:",
    "",
    "    npm install @truent/cli              (reinstall the npm package)",
    "    cargo install truent-cli             (install via Rust)",
    "",
    "  Or download manually from:",
    "  https://github.com/Emmyhack/Truent/releases",
    "",
  ].join("\n"));
  process.exit(2);
}

const binaryPath = getBinaryPath();
const args = process.argv.slice(2);

const result = spawnSync(binaryPath, args, {
  stdio: "inherit",
  env: process.env,
  windowsHide: false,
});

if (result.error) {
  console.error(`error: Failed to execute Truent binary: ${result.error.message}`);
  process.exit(2);
}

process.exit(result.status ?? 0);
