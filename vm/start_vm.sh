#!/usr/bin/env bash
# start_vm.sh - Launch the Debian 12 ARM64 micro-VM with USB passthrough & VirtIO
# For Laboratorio #10: Captura el Router (CC8)

set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$VM_DIR/.." && pwd)"
PID_FILE="$VM_DIR/qemu.pid"
MONITOR_SOCK="$VM_DIR/qemu-monitor.sock"
CONSOLE_LOG="$VM_DIR/console.log"
EDK2_CODE="/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
EFI_VARS="$VM_DIR/efi-vars.fd"
OVERLAY_QCOW2="$VM_DIR/overlay.qcow2"
SEED_ISO="$VM_DIR/seed.iso"

# 1. Check if VM is already running
if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[!] La micro-VM ya se encuentra en ejecución (PID: $PID)."
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# Clean up stale monitor socket
rm -f "$MONITOR_SOCK"

# 2. Check prerequisites
if [[ ! -f "$OVERLAY_QCOW2" ]] || [[ ! -f "$EFI_VARS" ]] || [[ ! -f "$SEED_ISO" ]]; then
    echo "[-] ERROR: Archivos de la VM no encontrados. Ejecute './vm/provision_vm.sh' primero."
    exit 1
fi

# 3. Check Host Storage Headroom
HOST_AVAIL_KB=$(df -k "$VM_DIR" | awk 'NR==2 {print $4}')
if [[ "$HOST_AVAIL_KB" -lt 5242880 ]]; then
    echo "[-] ERROR: Menos de 5 GB de espacio libre en el host ($((HOST_AVAIL_KB / 1024)) MB libres)."
    exit 1
fi

echo "================================================================="
echo "[*] INICIANDO MICRO-VM DEBIAN 12 ARM64 (QEMU + HVF)"
echo "================================================================="
echo "[+] CPU: 2 vCPUs (Apple Silicon host) | RAM: 1536 MB"
echo "[+] Disco: virtio-scsi con discard=unmap (fstrim activo)"
echo "[+] VirtFS 9p: $PROJECT_ROOT -> /mnt/host"
echo "[+] QEMU Monitor Socket: $MONITOR_SOCK"

# 4. Check USB Wi-Fi Adapter Presence
USB_ARGS=()
if ioreg -r -c IOUSBHostDevice -w0 -l | grep -E -q '33145|0x8179'; then
    echo "[+] Adaptador USB Wi-Fi detectado en el host (0x0bda:0x8179 Realtek RTL8188EUS)."
    USB_ARGS=(
        -device qemu-xhci,id=xhci
        -device usb-host,bus=xhci.0,vendorid=0x0bda,productid=0x8179,id=wifi0
    )
else
    echo "[!] ADVERTENCIA: Adaptador USB 0x0bda:0x8179 no detectado en el host en este momento."
    echo "    Iniciando controlador XHCI sin dispositivo adherido. Podrá conectarlo en caliente."
    USB_ARGS=(-device qemu-xhci,id=xhci)
fi

# 5. Launch QEMU with new session (setsid) to prevent macOS SIGHUP termination
python3 -c '
import sys, subprocess
cmd = sys.argv[1:]
with open(sys.argv[1], "a"): pass
with open("vm/qemu.log", "a") as logfile:
    p = subprocess.Popen(cmd, stdout=logfile, stderr=subprocess.STDOUT, start_new_session=True)
    with open("vm/qemu.pid", "w") as pidfile:
        pidfile.write(str(p.pid))
' qemu-system-aarch64 \
    -machine virt,accel=hvf \
    -cpu host -smp 2 -m 1536 \
    -drive if=pflash,format=raw,readonly=on,file="$EDK2_CODE" \
    -drive if=pflash,format=raw,file="$EFI_VARS" \
    -device virtio-scsi-pci,id=scsi0 \
    -drive if=none,id=hd0,format=qcow2,discard=unmap,detect-zeroes=unmap,file="$OVERLAY_QCOW2" \
    -device scsi-hd,drive=hd0,bus=scsi0.0 \
    -drive if=virtio,format=raw,readonly=on,file="$SEED_ISO" \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -virtfs local,path="$PROJECT_ROOT",mount_tag=hostshare,security_model=mapped-xattr,id=hostshare \
    "${USB_ARGS[@]}" \
    -monitor unix:"$MONITOR_SOCK",server,nowait \
    -display none \
    -serial file:"$CONSOLE_LOG"

sleep 1
if [[ -f "$PID_FILE" ]]; then
    NEW_PID=$(cat "$PID_FILE")
    echo "[✔] Micro-VM lanzada con éxito (PID: $NEW_PID)."
    echo "[*] Esperando inicialización del servicio SSH en puerto 2222..."
    
    # Wait up to 45 seconds for SSH
    READY=0
    for i in {1..30}; do
        if nc -z 127.0.0.1 2222 2>/dev/null; then
            READY=1
            break
        fi
        sleep 1
    done

    if [[ "$READY" -eq 1 ]]; then
        echo "[✔] Puerto SSH (2222) abierto y listo."
        echo "    Para acceder: ./vm/ssh_vm.sh"
    else
        echo "[!] SSH aún inicializándose. Revise logs con: tail -f vm/console.log"
    fi
else
    echo "[-] ERROR: QEMU falló al iniciar. Revise $CONSOLE_LOG"
    exit 1
fi
