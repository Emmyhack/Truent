#!/usr/bin/env node
"use strict";

/**
 * Postinstall script — downloads the Truent binary for the current platform.
 * 
 * Failures are non-fatal. We never want to break someone's npm install
 * because of a binary download issue.
 */

const { detectPlatform } = require("../lib/detect-platform");
const { downloadBinary } = require("../lib/download");
const { verifyChecksum, verifyBinaryExecutable } = require("../lib/verify");
const { isBinaryInstalled } = require("../lib/binary-path");

async function main() {
  // Check if installation is being skipped
  if (process.env.TRUENT_SKIP_DOWNLOAD === "1") {
    return;
  }

  // Check if running in CI environment
  const isCI = !!(
    process.env.CI ||
    process.env.CONTINUOUS_INTEGRATION ||
    process.env.GITHUB_ACTIONS ||
    process.env.TRAVIS ||
    process.env.CIRCLECI
  );

  try {
    // Check if already installed
    if (isBinaryInstalled()) {
      console.log("✓ Truent binary is already installed");
      return;
    }

    // Detect platform
    const platformInfo = detectPlatform();
    console.log(`Downloading Truent v${platformInfo.version} for ${platformInfo.platform}-${platformInfo.arch}...`);

    // Download binary
    const binaryPath = await downloadBinary(platformInfo, { verbose: false });

    // Verify executable works
    await verifyBinaryExecutable(binaryPath);

    console.log(`✓ Truent v${platformInfo.version} installed successfully (${platformInfo.platform}-${platformInfo.arch})`);
    console.log(`Run: truent --version`);
  } catch (error) {
    // Non-fatal error — warn but don't break npm install
    console.warn([
      "",
      "⚠ Truent binary download failed:",
      `  ${error.message}`,
      "",
      "You can manually install via one of:",
      "  - cargo install truent-cli",
      "  - Download from: https://github.com/Emmyhack/Truent/releases",
      "  - Re-run: npm install @truent/cli",
      "",
    ].join("\n"));
  }
}

main().catch((error) => {
  // Should not happen, but catch any uncaught errors
  console.error("Unexpected error in postinstall:", error);
  // Still exit 0 — never fail npm install
});
