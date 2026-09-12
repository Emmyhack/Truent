#!/bin/bash
# Publication script for Truent crates v0.1.7
# Publishes all crates to crates.io in dependency order

set -e

echo "================================"
echo "Truent Crate Publishing Script"
echo "Version: 0.1.7"
echo "================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d "crates" ]; then
    echo -e "${RED}Error: Must be run from Truent workspace root${NC}"
    exit 1
fi

# List of crates in dependency order
CRATES=(
    "truent-utils"
    "truent-core"
    "truent-ir"
    "truent-dsl-parser"
    "truent-solana-macro"
    "truent-analyzer-evm"
    "truent-analyzer-solana"
    "truent-analyzer-move"
    "truent-analyzer-soroban"
    "truent-analyzer-general"
    "truent-sca"
    "truent-pathways"
    "truent-runtime"
    "truent-symbolic"
    "truent-generator-evm"
    "truent-generator-solana"
    "truent-generator-move"
    "truent-library"
    "truent-report"
    "truent-skills"
    "truent-dynamic-core"
    "truent-dynamic-evm"
    "truent-dynamic-solana"
    "truent-cli"
)

# Check cargo auth
echo "Verifying cargo credentials..."
if ! cargo login --check 2>/dev/null; then
    echo -e "${YELLOW}Please login to crates.io first:${NC}"
    echo "  cargo login"
    exit 1
fi

echo -e "${GREEN}✓ Credentials verified${NC}"
echo ""

# Ask for confirmation
echo "About to publish ${#CRATES[@]} crates:"
for i in "${!CRATES[@]}"; do
    echo "  $((i+1)). ${CRATES[$i]}"
done
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Starting publication..."
echo ""

# Publish each crate
PUBLISHED=0
FAILED=0

for crate in "${CRATES[@]}"; do
    echo -e "${YELLOW}Publishing $crate...${NC}"
    
    if cargo publish -p "$crate" --allow-dirty; then
        echo -e "${GREEN}✓ $crate published successfully${NC}"
        ((PUBLISHED++))
        # Wait between publishes to ensure dependency resolution
        sleep 2
    else
        echo -e "${RED}✗ Failed to publish $crate${NC}"
        ((FAILED++))
    fi
    echo ""
done

# Summary
echo "================================"
echo "Publication Summary"
echo "================================"
echo -e "Published: ${GREEN}${PUBLISHED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All crates published successfully!${NC}"
    echo ""
    echo "Verify at: https://crates.io/crates/truent-cli/0.1.7"
else
    echo -e "${RED}✗ Some crates failed to publish${NC}"
    exit 1
fi
