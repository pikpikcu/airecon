#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Checking environment...${NC}"

# Define system python
PYTHON_CMD="python3"
if [ -f "/usr/bin/python3" ]; then
    PYTHON_CMD="/usr/bin/python3"
fi

echo -e "${GREEN}[+] Using Python: $PYTHON_CMD${NC}"

# Function to uninstall airecon completely
uninstall_airecon() {
    echo -e "${YELLOW}[!] Cleaning previous installations...${NC}"
    
    # 1. Uninstall from current environment (venv or otherwise)
    if pip show airecon &> /dev/null; then
        echo -e "${YELLOW}[!] Found existing AIRecon in current environment. Removing...${NC}"
        pip uninstall -y airecon --break-system-packages 2>/dev/null || pip uninstall -y airecon 2>/dev/null
    fi

    # 2. Uninstall from system python user site (force clean slate)
    if $PYTHON_CMD -m pip show airecon &> /dev/null; then
         echo -e "${YELLOW}[!] Found existing AIRecon in user site ($PYTHON_CMD). Removing...${NC}"
         $PYTHON_CMD -m pip uninstall -y airecon --break-system-packages 2>/dev/null || true
    fi

    # Try to clear pip cache for airecon
    echo -e "${YELLOW}[!] Clearing pip cache definition...${NC}"
    pip cache remove airecon &> /dev/null || true
    $PYTHON_CMD -m pip cache remove airecon &> /dev/null || true
    
    # Also remove build artifacts
    echo -e "${YELLOW}[!] Cleaning build artifacts...${NC}"
    rm -rf dist/ build/ *.egg-info
}

# Check Poetry
if ! command -v poetry &> /dev/null; then
    echo -e "${YELLOW}[!] Poetry not found. Installing via pip...${NC}"
    if command -v pip3 &> /dev/null; then
        pip3 install poetry --break-system-packages
    elif command -v pip &> /dev/null; then
        pip install poetry --break-system-packages
    else
        echo -e "${RED}[!] pip not found. Cannot install poetry.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] Poetry is already installed.${NC}"
fi

# Clean previous installs
uninstall_airecon

echo -e "${GREEN}[+] Updating dependencies...${NC}"
poetry install

echo -e "${GREEN}[+] Installing Playwright browsers...${NC}"
poetry run playwright install chromium

echo -e "${GREEN}[+] Building package...${NC}"
poetry build

echo -e "${GREEN}[+] Installing to ~/.local/bin...${NC}"
# Create local bin if it doesn't exist
mkdir -p "$HOME/.local/bin"

# Find the built wheel
WHEEL_FILE=$(find dist -name "airecon-*.whl" | head -n 1)
if [ -z "$WHEEL_FILE" ]; then
    echo -e "${RED}[!] Build failed. No wheel file found.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Installing wheel globally to user site...${NC}"
# FORCE install to system user site, ignoring active venv
# using /usr/bin/python3 explicitly ensures we bypass the venv python
if $PYTHON_CMD -m pip install "$WHEEL_FILE" --user --no-cache-dir --force-reinstall --break-system-packages; then
    echo -e "${GREEN}[+] Package installed successfully to user site.${NC}"
else
    echo -e "${RED}[!] Installation failed.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Done!${NC}"

# Check location - verify using the INSTALLER path
INSTALLED_BIN="$HOME/.local/bin/airecon"
if [ ! -f "$INSTALLED_BIN" ]; then
    echo -e "${YELLOW}[!] 'airecon' binary not found at $INSTALLED_BIN.${NC}"
    echo -e "${YELLOW}[!] Checking where it might be...${NC}"
    $PYTHON_CMD -m pip show -f airecon | grep "bin/airecon" || true
else
    echo -e "${GREEN}[+] Verified: $INSTALLED_BIN exists.${NC}"
    # Verify exact version
    $INSTALLED_BIN --version
    
    # Check if it's in PATH
    if command -v airecon &> /dev/null; then
        echo -e "${GREEN}[+] 'airecon' is in your PATH.${NC}"
    else
        echo -e "${YELLOW}[!] 'airecon' is installed but NOT in your PATH.${NC}"
        echo -e "You need to add ~/.local/bin to your PATH."
        echo -e "Add this to your .bashrc or .zshrc:"
        echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi
