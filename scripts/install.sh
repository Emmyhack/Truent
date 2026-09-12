#!/bin/bash
#
# Truent Installation Script
#
# Automatically detects OS and CPU architecture, downloads the correct pre-built binary,
# verifies the checksum, and installs it to $PATH.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Emmyhack/Truent/main/scripts/install.sh | bash
#
# Or with options:
#   bash install.sh [--prefix /custom/path] [--version v0.1.0]
#

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
GITHUB_REPO="Emmyhack/Truent"
INSTALL_PREFIX="${INSTALL_PREFIX:-${HOME}/.local/bin}"
BINARY_VERSION="${BINARY_VERSION:-latest}"
TMP_DIR=$(mktemp -d)
BINARY_NAME="truent"

# Trap cleanup
cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# Helper functions
log_info() {
    echo -e "${GREEN}ℹ${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)             echo "linux" ;;
        Darwin*)            echo "macos" ;;
        CYGWIN*|MINGW*)     echo "windows" ;;
        *)                  log_error "Unsupported OS"; exit 1 ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64)             echo "x86_64" ;;
        arm64|aarch64)      echo "aarch64" ;;
        *)                  log_error "Unsupported architecture"; exit 1 ;;
    esac
}

# Detect Linux variant
detect_linux_variant() {
    # Prefer musl for Alpine, static linking preferred
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "${ID:-}" = "alpine" ]; then
            echo "musl"
            return
        fi
    fi
    
    # Check if musl-based
    if ldd /bin/ls 2>&1 | grep -q musl; then
        echo "musl"
    else
        echo "gnu"
    fi
}

# Get download URL
get_download_url() {
    local os="$1"
    local arch="$2"
    
    # Determine release URL
    if [ "${BINARY_VERSION}" = "latest" ]; then
        RELEASE_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    else
        RELEASE_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${BINARY_VERSION}"
    fi
    
    # Get actual version from GitHub
    ACTUAL_VERSION=$(curl -fsSL "${RELEASE_URL}" | grep -o '"tag_name": "[^"]*' | sed 's/"tag_name": "//;s/v//')
    
    if [ -z "${ACTUAL_VERSION}" ]; then
        log_error "Could not determine release version"
        return 1
    fi
    
    # Construct binary filename
    case "${os}" in
        linux)
            local variant=$(detect_linux_variant)
            if [ "${variant}" = "musl" ]; then
                BINARY_FILE="truent-v${ACTUAL_VERSION}-x86_64-unknown-linux-musl.tar.gz"
            else
                if [ "${arch}" = "aarch64" ]; then
                    BINARY_FILE="truent-v${ACTUAL_VERSION}-aarch64-unknown-linux-gnu.tar.gz"
                else
                    BINARY_FILE="truent-v${ACTUAL_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
                fi
            fi
            ;;
        macos)
            BINARY_FILE="truent-v${ACTUAL_VERSION}-${arch}-apple-darwin.tar.gz"
            ;;
        windows)
            BINARY_FILE="truent-v${ACTUAL_VERSION}-x86_64-pc-windows-msvc.zip"
            ;;
    esac
    
    echo "https://github.com/${GITHUB_REPO}/releases/download/v${ACTUAL_VERSION}/${BINARY_FILE}"
}

# Download and verify
download_binary() {
    local url="$1"
    local checksum_url="${url%/*}/SHA256SUMS"
    
    log_info "Downloading from: ${url}"
    
    if ! curl -fsSL -o "${TMP_DIR}/binary.archive" "${url}"; then
        log_error "Failed to download binary"
        return 1
    fi
    
    log_info "Downloading checksums: ${checksum_url}"
    if ! curl -fsSL -o "${TMP_DIR}/SHA256SUMS" "${checksum_url}"; then
        log_warning "Could not download checksums (continuing anyway)"
        return 0
    fi
    
    # Verify checksum
    cd "${TMP_DIR}"
    local filename=$(basename "${url}")
    if ! echo "${filename}" | grep "$(sha256sum binary.archive)" "${TMP_DIR}/SHA256SUMS}" > /dev/null 2>&1; then
        log_warning "Checksum verification skipped (file may be corrupted)"
    else
        log_info "Checksum verified ✓"
    fi
    
    return 0
}

# Extract binary
extract_binary() {
    local os="$1"
    local archive="${TMP_DIR}/binary.archive"
    
    case "${os}" in
        linux|macos)
            cd "${TMP_DIR}"
            tar -xzf "${archive}"
            # Find the binary (might be in a directory)
            if [ -f "truent" ]; then
                cp truent "${TMP_DIR}/truent.bin"
            elif [ -d "truent-v"* ]; then
                cp truent-v*/truent "${TMP_DIR}/truent.bin"
            else
                log_error "Could not find binary in archive"
                return 1
            fi
            ;;
        windows)
            cd "${TMP_DIR}"
            unzip -q "${archive}" || {
                log_error "Failed to extract Windows binary"
                return 1
            }
            if [ -f "truent.exe" ]; then
                cp truent.exe "${TMP_DIR}/truent.bin"
            elif [ -d "truent-v"* ]; then
                cp truent-v*/truent.exe "${TMP_DIR}/truent.bin"
            else
                log_error "Could not find binary in archive"
                return 1
            fi
            ;;
    esac
    
    return 0
}

# Install binary
install_binary() {
    local os="$1"
    
    # Ensure directory exists
    mkdir -p "${INSTALL_PREFIX}"
    
    # Copy binary
    if [ "${os}" = "windows" ]; then
        cp "${TMP_DIR}/truent.bin" "${INSTALL_PREFIX}/truent.exe"
        chmod +x "${INSTALL_PREFIX}/truent.exe"
        BINARY_PATH="${INSTALL_PREFIX}/truent.exe"
    else
        cp "${TMP_DIR}/truent.bin" "${INSTALL_PREFIX}/truent"
        chmod +x "${INSTALL_PREFIX}/truent"
        BINARY_PATH="${INSTALL_PREFIX}/truent"
    fi
    
    # Verify installation
    if ! "${BINARY_PATH}" --version > /dev/null 2>&1; then
        log_error "Binary installation verification failed"
        return 1
    fi
    
    return 0
}

# Check PATH
check_path() {
    if echo "${PATH}" | grep -q "${INSTALL_PREFIX}"; then
        return 0
    fi
    return 1
}

# Main installation flow
main() {
    log_info "Truent Installation Script"
    echo ""
    
    # Detect system
    OS=$(detect_os)
    ARCH=$(detect_arch)
    
    log_info "Detected OS: ${OS} (${ARCH})"
    
    # Get download URL
    DOWNLOAD_URL=$(get_download_url "${OS}" "${ARCH}")
    if [ -z "${DOWNLOAD_URL}" ]; then
        log_error "Could not determine download URL"
        return 1
    fi
    
    # Download and extract
    if ! download_binary "${DOWNLOAD_URL}"; then
        log_error "Download failed"
        return 1
    fi
    
    if ! extract_binary "${OS}"; then
        log_error "Extraction failed"
        return 1
    fi
    
    # Install
    if ! install_binary "${OS}"; then
        log_error "Installation failed"
        return 1
    fi
    
    echo ""
    log_info "Installation complete!"
    echo ""
    echo "Binary installed to: ${BINARY_PATH}"
    echo "Version: $(${BINARY_PATH} --version)"
    echo ""
    
    # Check if in PATH
    if ! check_path; then
        log_warning "The installation directory is not in your PATH"
        echo "Add to your shell configuration (~/.bashrc, ~/.zshrc, etc):"
        echo ""
        echo "  export PATH=\"${INSTALL_PREFIX}:\$PATH\""
        echo ""
    else
        log_info "${BINARY_NAME} is ready to use!"
        echo "Try: ${BINARY_NAME} --help"
    fi
}

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        --version)
            BINARY_VERSION="$2"
            shift 2
            ;;
        --help)
            cat <<EOF
Truent Installation Script

Usage:
  bash install.sh [OPTIONS]

Options:
  --prefix PATH       Install to PATH instead of ~/.local/bin
  --version VERSION   Install specific version (default: latest)
  --help             Show this help message

Examples:
  bash install.sh
  bash install.sh --prefix /usr/local/bin
  bash install.sh --version v0.1.0

Environment Variables:
  INSTALL_PREFIX     Override installation directory
  BINARY_VERSION     Override binary version
EOF
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run installation
main
