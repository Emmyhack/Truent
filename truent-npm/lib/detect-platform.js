"use strict";

const os = require("os");
const path = require("path");
const { familySync, GLIBC, MUSL } = require("detect-libc");

const { version: TRUENT_VERSION } = require("../package.json");
const GITHUB_REPO = "Emmyhack/Truent";
const BINARY_DIR = path.join(__dirname, "..", ".truent-bin");

/**
 * Detect the current platform and return information needed for binary download.
 * 
 * @returns {object} Platform information including platform, arch, binaryName, etc.
 * @throws {Error} If platform is not supported
 */
function detectPlatform() {
  const platform = os.platform();
  const arch = os.arch();
  
  const mapping = {
    "linux-x64-glibc": {
      platform: "linux",
      arch: "x86_64",
      binaryName: "truent",
      target: "x86_64-unknown-linux-gnu",
      archiveFormat: "tar.gz",
    },
    "linux-x64-musl": {
      platform: "linux",
      arch: "x86_64",
      binaryName: "truent",
      target: "x86_64-unknown-linux-musl",
      archiveFormat: "tar.gz",
    },
    "linux-arm64": {
      platform: "linux",
      arch: "aarch64",
      binaryName: "truent",
      target: "aarch64-unknown-linux-gnu",
      archiveFormat: "tar.gz",
    },
    "darwin-x64": {
      platform: "macos",
      arch: "x86_64",
      binaryName: "truent",
      target: "x86_64-apple-darwin",
      archiveFormat: "tar.gz",
    },
    "darwin-arm64": {
      platform: "macos",
      arch: "aarch64",
      binaryName: "truent",
      target: "aarch64-apple-darwin",
      archiveFormat: "tar.gz",
    },
    "win32-x64": {
      platform: "windows",
      arch: "x86_64",
      binaryName: "truent.exe",
      target: "x86_64-pc-windows-msvc",
      archiveFormat: "zip",
    },
  };

  // Map os.arch() to our format
  let mappingKey;
  if (platform === "linux") {
    if (arch === "x64") {
      // Alpine and other musl-based distros need the musl-linked binary -
      // the glibc build fails to even start (missing dynamic linker) there.
      const libcFamily = familySync();
      mappingKey = libcFamily === MUSL ? "linux-x64-musl" : "linux-x64-glibc";
    } else if (arch === "arm64") {
      const libcFamily = familySync();
      if (libcFamily === MUSL) {
        throw new Error(
          "Error: Truent does not publish a musl build for linux-aarch64 yet.\n" +
          "Supported platforms: linux-x86_64 (glibc or musl), linux-aarch64 (glibc), macos-x86_64, macos-aarch64, windows-x86_64\n" +
          "Please open an issue at https://github.com/Emmyhack/Truent/issues"
        );
      }
      mappingKey = "linux-arm64";
    } else {
      mappingKey = null;
    }
  } else if (platform === "darwin") {
    mappingKey = arch === "x64" ? "darwin-x64" : arch === "arm64" ? "darwin-arm64" : null;
  } else if (platform === "win32") {
    mappingKey = arch === "x64" ? "win32-x64" : null;
  }

  if (!mappingKey || !mapping[mappingKey]) {
    throw new Error(
      `Error: Truent does not support your platform: ${platform}-${arch}\n` +
      `Supported platforms: linux-x86_64 (glibc or musl), linux-aarch64 (glibc), macos-x86_64, macos-aarch64, windows-x86_64\n` +
      `Please open an issue at https://github.com/Emmyhack/Truent/issues`
    );
  }

  const info = mapping[mappingKey];
  // Download the binary release matching this npm package's own version -
  // publish-npm.yml sets package.json's version to the release tag being
  // published, so these always stay in lockstep.
  const binaryVersion = TRUENT_VERSION;
  // release.yml names assets "truent-v<version>-<target>.<ext>" (note the "v"
  // immediately after "truent-") - this must match exactly or the download
  // (and the SHA256SUMS lookup, which matches on this same archiveName) 404s.
  const archiveName = `truent-v${binaryVersion}-${info.target}.${info.archiveFormat}`;
  const downloadUrl = `https://github.com/${GITHUB_REPO}/releases/download/v${binaryVersion}/${archiveName}`;

  return {
    platform: info.platform,
    arch: info.arch,
    binaryName: info.binaryName,
    target: info.target,
    archiveName,
    archiveFormat: info.archiveFormat,
    downloadUrl,
    // `version` is read by postinstall.js's log messages and by verify.js's
    // SHA256SUMS URL construction - omitting it silently produced
    // ".../download/vundefined/SHA256SUMS", 404ing the checksum fetch.
    version: binaryVersion,
  };
}

module.exports = {
  detectPlatform,
  TRUENT_VERSION,
  GITHUB_REPO,
  BINARY_DIR,
};
