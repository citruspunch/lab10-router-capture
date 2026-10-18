#!/usr/bin/env bash
# stop_vm.sh - Graceful shutdown and storage trim for Debian ARM64 micro-VM

set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$VM_DIR/qemu.pid"
SSH_SCRIPT="$VM_DIR/ssh_vm.sh"

if [[ ! -f "$PID_FILE" ]]; then
    echo "[*] La micro-VM no se encuentra en ejecución."
    exit 0
fi

PID=$(cat "$PID_FILE")
if ! kill -0 "$PID" 2>/dev/null; then
    echo "[*] Proceso QEMU no encontrado. Limpiando PID stale."
    rm -f "$PID_FILE"
    exit 0
fi

echo "[*] Ejecutando 'fstrim' y apagando sistema de forma segura..."
if [[ -x "$SSH_SCRIPT" ]] && nc -z 127.0.0.1 2222 2>/dev/null; then
    "$SSH_SCRIPT" "sudo fstrim -av && sudo poweroff" 2>/dev/null || true
fi

echo "[*] Esperando a que el proceso QEMU termine (PID: $PID)..."
for i in {1..20}; do
    if ! kill -0 "$PID" 2>/dev/null; then
        break
    fi
    sleep 1
done

if kill -0 "$PID" 2>/dev/null; then
    echo "[!] La VM no se apagó en el tiempo esperado. Enviando SIGTERM..."
    kill "$PID" 2>/dev/null || true
    sleep 2
    if kill -0 "$PID" 2>/dev/null; then
        echo "[!] Forzando apagado con SIGKILL..."
        kill -9 "$PID" 2>/dev/null || true
    fi
fi

rm -f "$PID_FILE" "$VM_DIR/qemu-monitor.sock"
echo "[✔] Micro-VM detenida con éxito."
