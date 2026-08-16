#!/usr/bin/env bash
set -eo pipefail

INSTALL_DIR="${1:-$HOME/.local/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$INSTALL_DIR"
ln -sfn "$SCRIPT_DIR/arch_map.py" "$INSTALL_DIR/arch-map"
chmod +x "$SCRIPT_DIR/arch_map.py"
chmod +x "$INSTALL_DIR/arch-map"

echo "✅ arch-map installed to $INSTALL_DIR/arch-map"
echo "Run 'arch-map --help' to get started."
