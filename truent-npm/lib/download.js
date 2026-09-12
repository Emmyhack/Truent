"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execFile } = require("child_process");
const { detectPlatform, BINARY_DIR } = require("./detect-platform");
const { verifyChecksum } = require("./verify");
const HttpsProxyAgent = require("https-proxy-agent");

/**
 * Search for `binaryName` directly inside `dir` or one level down (to cover
 * archives that extract into a wrapping staging directory, e.g. the .tar.gz
 * layout release.yml produces).
 *
 * @private
 * @param {string} dir - Directory to search
 * @param {string} binaryName - File name to find (e.g. "truent" or "truent.exe")
 * @returns {Promise<string|null>} Full path if found, else null
 */
async function findExtractedBinary(dir, binaryName) {
  const direct = path.join(dir, binaryName);
  if (fs.existsSync(direct)) {
    return direct;
  }

  const entries = await fs.promises.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && entry.name !== ".tmp") {
      const candidate = path.join(dir, entry.name, binaryName);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }

  return null;
}

/**
 * Download the Truent binary for the current platform.
 * 
 * @param {object} platformInfo - Platform info from detectPlatform()
 * @param {object} [options] - Download options
 * @param {boolean} [options.verbose] - Log progress
 * @param {boolean} [options.force] - Force re-download even if exists
 * @returns {Promise<string>} Path to downloaded binary
 */
async function downloadBinary(platformInfo, options = {}) {
  const { verbose = false, force = false } = options;

  const binaryDir = BINARY_DIR;
  const binaryPath = path.join(binaryDir, platformInfo.binaryName);

  // Check if already installed
  if (!force && fs.existsSync(binaryPath)) {
    if (verbose) {
      console.log(`✓ Truent binary already installed at ${binaryPath}`);
    }
    return binaryPath;
  }

  // Ensure directory exists
  await fs.promises.mkdir(binaryDir, { recursive: true });

  const downloadUrl = platformInfo.downloadUrl;
  const tempDir = path.join(binaryDir, ".tmp");
  await fs.promises.mkdir(tempDir, { recursive: true });

  const archivePath = path.join(tempDir, platformInfo.archiveName);

  try {
    // Download binary
    if (verbose) {
      console.log(`Downloading Truent v${platformInfo.version} for ${process.platform}-${process.arch}...`);
    }

    await downloadFile(downloadUrl, archivePath, verbose);

    // Verify the downloaded archive against the published SHA256SUMS before
    // extracting or executing anything from it - never trust a download by
    // TLS alone (redirects, a compromised release asset, or a CDN issue can
    // all substitute the wrong bytes).
    if (verbose) {
      console.log(`Verifying checksum for ${platformInfo.archiveName}...`);
    }
    await verifyChecksum(archivePath, platformInfo);

    // Extract binary
    if (verbose) {
      console.log(`Extracting ${platformInfo.archiveName}...`);
    }

    await extractArchive(archivePath, binaryDir, platformInfo);

    // release.yml's .zip archives (Windows) are flat - built by `cd`-ing into
    // the staging directory before zipping - but its .tar.gz archives
    // (Linux/macOS) tar the staging directory itself from outside it, so the
    // binary actually lands one level down, e.g.
    // `.truent-bin/truent-v1.2.3-x86_64-unknown-linux-gnu/truent`, not
    // `.truent-bin/truent` as this code otherwise assumes. Locate it wherever
    // it actually ended up and move it to the flat path the rest of this
    // package expects, rather than hardcoding one archive layout.
    if (!fs.existsSync(binaryPath)) {
      const nestedPath = await findExtractedBinary(binaryDir, platformInfo.binaryName);
      if (!nestedPath) {
        throw new Error(
          `Extracted archive did not contain expected binary '${platformInfo.binaryName}' ` +
          `anywhere under ${binaryDir}`
        );
      }
      await fs.promises.rename(nestedPath, binaryPath);
      // Clean up the now-empty (aside from LICENSE/README/VERSION) staging
      // directory the archive extracted into.
      const stagingDir = path.dirname(nestedPath);
      if (stagingDir !== binaryDir) {
        await fs.promises.rm(stagingDir, { recursive: true, force: true });
      }
    }

    // Make executable on Unix
    if (process.platform !== "win32") {
      await fs.promises.chmod(binaryPath, 0o755);
    }

    // Cleanup temp directory
    await fs.promises.rm(tempDir, { recursive: true, force: true });

    if (verbose) {
      console.log(`✓ Truent binary extracted to ${binaryPath}`);
    }

    return binaryPath;
  } catch (error) {
    // Cleanup on failure
    await fs.promises.rm(tempDir, { recursive: true, force: true });
    throw error;
  }
}

/**
 * Download a file from URL to local path with progress.
 * 
 * @private
 * @param {string} url - File URL
 * @param {string} destinationPath - Where to save
 * @param {boolean} verbose - Show progress
 * @returns {Promise<void>}
 */
async function downloadFile(url, destinationPath, verbose) {
  return new Promise((resolve, reject) => {
    const request = (url) => {
      const client = url.startsWith("https") ? https : require("http");
      const agent = process.env.HTTPS_PROXY || process.env.HTTP_PROXY
        ? new HttpsProxyAgent(process.env.HTTPS_PROXY || process.env.HTTP_PROXY)
        : undefined;

      const options = {
        agent,
        timeout: 30_000, // 30 second socket timeout
      };

      // Hard timeout for entire download (60 seconds)
      let timedOut = false;
      const downloadTimeout = setTimeout(() => {
        timedOut = true;
        req.destroy();
        reject(new Error(`Download timeout: no progress for 60 seconds (${url})`));
      }, 60_000);

      const req = client.get(url, options, (response) => {
        // Reset timeout on successful response
        clearTimeout(downloadTimeout);

        // Handle redirects
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          response.resume(); // Consume response data to free up memory
          request(response.headers.location);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(
            `Failed to download from ${url}\n` +
            `HTTP ${response.statusCode}: ${response.statusMessage}\n` +
            `Check the GitHub releases page: https://github.com/Emmyhack/Truent/releases`
          ));
          response.resume(); // drain the response
          return;
        }

        const contentLength = parseInt(response.headers["content-length"], 10);
        let downloadedBytes = 0;
        const startTime = Date.now();

        const file = fs.createWriteStream(destinationPath);

        response.on("data", (chunk) => {
          downloadedBytes += chunk.length;
          if (verbose && process.stdout.isTTY && contentLength) {
            const percent = Math.round((downloadedBytes / contentLength) * 100);
            process.stdout.write(`\rDownloading... ${percent}% (${formatBytes(downloadedBytes)}/${formatBytes(contentLength)})`);
          }
        });

        response.pipe(file);

        file.on("finish", () => {
          clearTimeout(downloadTimeout);
          file.close(() => {
            if (verbose) {
              const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
              console.log(`\nDownload complete (${elapsed}s)`);
            }
            resolve();
          });
        });

        file.on("error", (error) => {
          clearTimeout(downloadTimeout);
          fs.unlink(destinationPath, () => {
            reject(error);
          });
        });
      });

      req.on("error", (error) => {
        clearTimeout(downloadTimeout);
        if (!timedOut) {
          reject(error);
        }
      });

      req.on("timeout", () => {
        clearTimeout(downloadTimeout);
        req.destroy();
        reject(new Error(`Connection timeout: ${url}`));
      });
    };

    request(url);
  });
}

/**
 * Extract archive to binary directory.
 * 
 * @private
 * @param {string} archivePath - Path to archive file
 * @param {string} destDir - Destination directory
 * @param {object} platformInfo - Platform info
 * @returns {Promise<void>}
 */
async function extractArchive(archivePath, destDir, platformInfo) {
  return new Promise((resolve, reject) => {
    let bin;
    let args;

    if (platformInfo.archiveFormat === "tar.gz") {
      bin = "tar";
      args = ["xzf", archivePath, "-C", destDir];
    } else if (platformInfo.archiveFormat === "zip") {
      bin = "powershell";
      args = [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Expand-Archive",
        "-Path",
        archivePath,
        "-DestinationPath",
        destDir,
        "-Force",
      ];
    } else {
      reject(new Error(`Unknown archive format: ${platformInfo.archiveFormat}`));
      return;
    }

    // Use execFile (argument array, no shell) rather than exec (shell string)
    // so archive/destination paths can never be interpreted as shell syntax.
    execFile(bin, args, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(
          `Failed to extract archive: ${error.message}\n` +
          `Command: ${bin} ${args.join(" ")}\n` +
          `stderr: ${stderr}`
        ));
        return;
      }
      resolve();
    });
  });
}

/**
 * Format bytes as human-readable string.
 * 
 * @private
 */
function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(1) + " " + sizes[i];
}

module.exports = { downloadBinary };
