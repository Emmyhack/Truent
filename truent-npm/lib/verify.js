"use strict";

const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const { spawnSync } = require("child_process");
const HttpsProxyAgent = require("https-proxy-agent");

/**
 * Verify SHA256 checksum of downloaded binary archive.
 * 
 * @param {string} archivePath - Path to downloaded archive
 * @param {object} platformInfo - Platform info from detectPlatform()
 * @returns {Promise<void>}
 * @throws {Error} If checksum doesn't match
 */
async function verifyChecksum(archivePath, platformInfo) {
  // Download SHA256SUMS file
  const sha256sumsUrl = `https://github.com/Emmyhack/Truent/releases/download/v${platformInfo.version}/SHA256SUMS`;
  
  const checksumContent = await downloadSha256Sums(sha256sumsUrl);
  
  // Parse SHA256SUMS file to find entry for this platform
  const lines = checksumContent.split("\n");
  let expectedChecksum = null;

  for (const line of lines) {
    if (line.includes(platformInfo.archiveName)) {
      const parts = line.split(/\s+/);
      expectedChecksum = parts[0];
      break;
    }
  }

  if (!expectedChecksum) {
    throw new Error(
      `Checksum for ${platformInfo.archiveName} not found in SHA256SUMS.\n` +
      `Available in GitHub release: https://github.com/Emmyhack/Truent/releases`
    );
  }

  // Compute SHA256 of downloaded file
  const fileContent = await fs.promises.readFile(archivePath);
  const actualChecksum = crypto.createHash("sha256").update(fileContent).digest("hex");

  if (actualChecksum !== expectedChecksum) {
    throw new Error(
      `Checksum verification failed!\n` +
      `Expected: ${expectedChecksum}\n` +
      `Actual:   ${actualChecksum}\n` +
      `The downloaded archive may be corrupted. Try re-installing: npm install @truent/cli`
    );
  }
}

/**
 * Download the SHA256SUMS file from GitHub releases.
 * 
 * @private
 * @param {string} url - URL to SHA256SUMS file
 * @returns {Promise<string>} File content
 */
async function downloadSha256Sums(url) {
  return new Promise((resolve, reject) => {
    const agent = process.env.HTTPS_PROXY || process.env.HTTP_PROXY
      ? new HttpsProxyAgent(process.env.HTTPS_PROXY || process.env.HTTP_PROXY)
      : undefined;

    https.get(url, { agent }, (response) => {
      // Handle redirects
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        downloadSha256Sums(response.headers.location).then(resolve).catch(reject);
        return;
      }

      if (response.statusCode !== 200) {
        reject(new Error(
          `Failed to download SHA256SUMS: HTTP ${response.statusCode}\n` +
          `URL: ${url}`
        ));
        return;
      }

      let data = "";
      response.on("data", (chunk) => {
        data += chunk;
      });
      response.on("end", () => {
        resolve(data);
      });
    }).on("error", reject);
  });
}

/**
 * Verify that the downloaded binary is executable and works.
 * 
 * @param {string} binaryPath - Path to binary executable
 * @returns {Promise<void>}
 * @throws {Error} If binary is not working
 */
async function verifyBinaryExecutable(binaryPath) {
  return new Promise((resolve, reject) => {
    const result = spawnSync(binaryPath, ["--version"], {
      encoding: "utf8",
      timeout: 5000,
    });

    if (result.error) {
      reject(new Error(
        `Cannot execute Truent binary: ${result.error.message}\n` +
        `Binary path: ${binaryPath}\n` +
        `The binary may be corrupted or built for the wrong architecture.\n` +
        `Try reinstalling: npm install @truent/cli`
      ));
      return;
    }

    if (result.status !== 0) {
      reject(new Error(
        `Truent binary returned error code ${result.status}\n` +
        `stderr: ${result.stderr}`
      ));
      return;
    }

    const versionOutput = result.stdout.trim();
    const semverMatch = versionOutput.match(/\d+\.\d+\.\d+/);

    if (!semverMatch) {
      reject(new Error(
        `Invalid version output from Truent: ${versionOutput}\n` +
        `Expected format: truent X.Y.Z`
      ));
      return;
    }

    resolve();
  });
}

module.exports = { verifyChecksum, verifyBinaryExecutable };
