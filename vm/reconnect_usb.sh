#!/usr/bin/env bash
# reconnect_usb.sh - Hotplug/Re-attach USB Wi-Fi Adapter via QEMU Monitor Socket
# Refinement 1: Instant USB Hotplug Recovery without rebooting the VM

set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR_SOCK="$VM_DIR/qemu-monitor.sock"

if [[ ! -S "$MONITOR_SOCK" ]]; then
    echo "[-] ERROR: Socket de monitor QEMU no encontrado en $MONITOR_SOCK. ¿Está la VM corriendo?"
    exit 1
fi

echo "[*] Enviando comandos de re-adhesión USB a QEMU Monitor..."

# Try to remove any stale device instance, then add
{
    echo "device_del wifi0"
    sleep 0.5
    echo "device_add usb-host,bus=xhci.0,vendorid=0x0bda,productid=0x8179,id=wifi0"
    sleep 0.5
    echo "info usb"
} | nc -U "$MONITOR_SOCK"

echo "[✔] Comando de conexión USB enviado a QEMU."
