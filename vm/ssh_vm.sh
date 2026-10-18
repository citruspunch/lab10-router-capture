#!/usr/bin/env bash
# ssh_vm.sh - Connect to the Debian ARM64 micro-VM via SSH

set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_KEY="$VM_DIR/id_ed25519"
PORT="2222"
USER="debian"
HOST="127.0.0.1"

if [[ ! -f "$SSH_KEY" ]]; then
    echo "[-] ERROR: Llave SSH no encontrada en $SSH_KEY. Ejecute provision_vm.sh primero."
    exit 1
fi

# Ensure correct permissions
chmod 600 "$SSH_KEY" 2>/dev/null || true

ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=10 \
    -p "$PORT" \
    "$USER@$HOST" \
    "$@"
