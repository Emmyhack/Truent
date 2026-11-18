#!/usr/bin/env bash
# Update the workspace version, internal dependency pins, and npm package.
# Usage: ./scripts/update_version.sh 0.6.1

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <new_version>"
  echo "Example: $0 0.6.1"
  exit 1
fi

NEW_VERSION="$1"

# Validate semver format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-.*)? ]]; then
  echo "ERROR: Invalid semver format: $NEW_VERSION"
  echo "Expected format: X.Y.Z or X.Y.Z-prerelease"
  exit 1
fi

echo "Updating version to $NEW_VERSION..."
echo ""

# Function to update version in Cargo.toml
update_cargo_toml() {
  local file="$1"
  if [ ! -f "$file" ]; then
    echo "⚠ Skipping $file (not found)"
    return
  fi
  
  # [workspace.package] / [package] version — anchored, so it only matches the
  # crate's own version line.
  if grep -q '^version = "' "$file"; then
    sed -i.bak 's/^version = "[^"]*"/version = "'$NEW_VERSION'"/' "$file"
    rm -f "$file.bak"
    echo "✓ Updated $file"
  fi

  # Internal [workspace.dependencies] pins, e.g.
  #   truent-core = { path = "crates/core", version = "0.4.1" }
  # These are not anchored to the start of the line, so the check above misses
  # them. Leaving them stale makes every internal dep require the *previous*
  # version and the workspace stops resolving.
  if grep -q 'path = "crates/.*version = "' "$file"; then
    sed -i.bak 's/\(path = "crates\/[^"]*", version = \)"[^"]*"/\1"'$NEW_VERSION'"/g' "$file"
    rm -f "$file.bak"
    echo "✓ Updated internal dependency pins in $file"
  fi
}

# Function to update version in package.json
update_package_json() {
  local file="$1"
  if [ ! -f "$file" ]; then
    echo "⚠ Skipping $file (not found)"
    return
  fi
  
  # Use sed to replace "version": "X.Y.Z" with new version
  if grep -q '"version": "*' "$file"; then
    sed -i.bak 's/"version": "[^"]*"/"version": "'$NEW_VERSION'"/' "$file"
    rm -f "$file.bak"
    echo "✓ Updated $file"
  fi
}

# Update workspace Cargo.toml
update_cargo_toml "Cargo.toml"

# Member crates use `version.workspace = true`; updating them individually is
# both unnecessary and error-prone when a new crate is added.

# Update npm package
echo ""
echo "Updating npm package..."
update_package_json "truent-npm/package.json"

# Update CHANGELOG with new entry (optional)
echo ""
echo "Next steps:"
echo "1. Update CHANGELOG.md with release notes"
echo "2. Commit: git add -A && git commit -m 'chore: bump version to $NEW_VERSION'"
echo "3. Tag: git tag -a v$NEW_VERSION -m 'Release v$NEW_VERSION'"
echo "4. Push: git push origin main && git push origin v$NEW_VERSION"
echo ""
echo "✓ Version updated to $NEW_VERSION"
