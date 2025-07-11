#!/bin/bash
set -e

echo "🚀 NIP-44 Integration Testing Suite"
echo "=================================="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "build.zig" ]; then
    echo -e "${RED}Error: Must be run from integration_testing directory${NC}"
    exit 1
fi

# Step 1: Build all implementations
echo -e "${YELLOW}Step 1: Building all implementations...${NC}"
echo

echo "Building Zig wrapper..."
zig build

echo
echo "Building C reference implementation..."
if [ ! -f "c/build.sh" ]; then
    echo -e "${RED}Error: C build script not found${NC}"
    exit 1
fi
cd c && sh build.sh && cd ..

echo
echo "Building Rust reference implementation..."
if [ ! -f "rust/build.sh" ]; then
    echo -e "${RED}Error: Rust build script not found${NC}"
    exit 1
fi
cd rust && sh build.sh && cd ..

echo
echo -e "${GREEN}✅ All implementations built successfully${NC}"
echo

# Step 2: Run integration tests
echo -e "${YELLOW}Step 2: Running cross-implementation tests...${NC}"
echo

zig build test-integration

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Integration tests passed${NC}"
else
    echo -e "${RED}❌ Integration tests failed${NC}"
    exit 1
fi

echo
# Step 3: Run fuzz tests
echo -e "${YELLOW}Step 3: Running fuzz tests...${NC}"
echo

zig build fuzz

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Fuzz tests passed${NC}"
else
    echo -e "${RED}❌ Fuzz tests failed${NC}"
    exit 1
fi

echo
echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
echo
echo "Summary:"
echo "  - ✅ Zig implementation tested"
echo "  - ✅ C reference implementation tested"
echo "  - ✅ Rust reference implementation tested"
echo "  - ✅ Cross-implementation compatibility verified"
echo "  - ✅ Fuzz testing completed"