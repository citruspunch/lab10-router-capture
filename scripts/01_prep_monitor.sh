#!/usr/bin/env bash
# 01_prep_monitor.sh - Wireless Monitor Mode & Channel Preparation
# For Laboratorio #10: Captura el Router (CC8)
# Designed for Realtek RTL8188EUS (0bda:8179) inside headless Linux ARM64 VM

set -euo pipefail

CHANNEL="6"
IFACE=""
BSSID=""

show_usage() {
    cat <<EOF
Uso: $0 [opciones]
Opciones:
  -i, --iface <iface>    Nombre de la interfaz (por defecto: auto-detectada)
  -c, --channel <1-14>   Canal 802.11b/g a fijar (por defecto: 6)
  -b, --bssid <MAC>      BSSID opcional a fijar/filtrar
  -h, --help             Muestra esta ayuda
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--iface)
            IFACE="$2"
            shift 2
            ;;
        -c|--channel)
            CHANNEL="$2"
            shift 2
            ;;
        -b|--bssid)
            BSSID="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "[-] Opción desconocida: $1"
            show_usage
            ;;
    esac
done

echo "================================================================="
echo "[*] INICIANDO PREPARACIÓN MODO MONITOR - LAB 10 (CC8)"
echo "================================================================="

# 1. Headroom & RAM Disk preparation
mkdir -p /dev/shm/captures
chmod 777 /dev/shm/captures
echo "[+] Buffer RAM-Disk verificado en /dev/shm/captures/"

# 2. Selective process termination (safe for VirtIO SSH session)
echo "[*] Limpiando procesos inalámbricos que puedan causar interferencia..."
# Only kill wireless specific managers, NEVER touch systemd-networkd / dhclient on enp0s1
pkill -9 wpa_supplicant 2>/dev/null || true
pkill -9 iwd 2>/dev/null || true
pkill -9 avahi-daemon 2>/dev/null || true

# 3. Interface auto-detection if not specified
if [[ -z "$IFACE" ]]; then
    # Look for wireless interfaces in /sys/class/net
    for dev in /sys/class/net/*; do
        dev_name=$(basename "$dev")
        if [[ -d "$dev/wireless" ]] || [[ "$dev_name" =~ ^wlan ]] || [[ "$dev_name" =~ ^wlx ]]; then
            IFACE="$dev_name"
            break
        fi
    done
fi

if [[ -z "$IFACE" ]]; then
    echo "[-] ERROR: No se detectó ninguna interfaz inalámbrica."
    echo "    Verifique 'lsusb' y 'dmesg | grep -iE \"usb|rtl|wlan\"'."
    exit 1
fi

echo "[+] Interfaz inalámbrica objetivo: $IFACE"

# 4. Bring interface down before mode change
echo "[*] Desactivando interfaz $IFACE..."
ip link set "$IFACE" down || true
sleep 1

# 5. Switch to monitor mode (Supports both 'iw' and 'iwconfig' for maximum driver compatibility)
echo "[*] Cambiando modo a 'monitor'..."
MONITOR_SUCCESS=0

# Method A: modern nl80211 via iw
if iw dev "$IFACE" set type monitor 2>/dev/null; then
    echo "[+] Modo monitor activado mediante 'iw dev $IFACE set type monitor'"
    MONITOR_SUCCESS=1
else
    echo "[!] 'iw dev set type monitor' no soportado por el driver. Probando 'iwconfig'..."
fi

# Method B: wext/cfg80211 fallback via iwconfig
if [[ "$MONITOR_SUCCESS" -eq 0 ]]; then
    if iwconfig "$IFACE" mode monitor 2>/dev/null; then
        echo "[+] Modo monitor activado mediante 'iwconfig $IFACE mode monitor'"
        MONITOR_SUCCESS=1
    else
        echo "[-] ERROR: No fue posible poner $IFACE en modo monitor."
        exit 1
    fi
fi

# 6. Bring interface up
echo "[*] Levantando interfaz $IFACE..."
ip link set "$IFACE" up
sleep 1

# 7. Lock channel
echo "[*] Fijando canal $CHANNEL en $IFACE..."
if iw dev "$IFACE" set channel "$CHANNEL" 2>/dev/null; then
    echo "[+] Canal $CHANNEL fijado mediante 'iw'"
elif iwconfig "$IFACE" channel "$CHANNEL" 2>/dev/null; then
    echo "[+] Canal $CHANNEL fijado mediante 'iwconfig'"
else
    echo "[!] Advertencia: No se pudo fijar el canal inmediatamente; airodump-ng lo fijará al iniciar."
fi

# 8. Verification & Driver Health Checks
echo "-----------------------------------------------------------------"
echo "[+] ESTADO ACTUAL DE LA INTERFAZ:"
if command -v iw >/dev/null 2>&1; then
    iw dev "$IFACE" info 2>/dev/null || true
fi
if command -v iwconfig >/dev/null 2>&1; then
    iwconfig "$IFACE" 2>/dev/null || true
fi

# Check for USB/Driver errors in dmesg
echo "-----------------------------------------------------------------"
echo "[*] Verificando logs del kernel (dmesg)..."
if dmesg | tail -n 15 | grep -iE 'error|-110|reset|stall|failed'; then
    echo "[!] ADVERTENCIA: Se detectaron posibles anomalías en dmesg."
else
    echo "[+] Driver y bus USB estables: sin errores de firmware ni reinicios."
fi

echo "================================================================="
echo "[✔] MODO MONITOR PREPARADO CORRECTAMENTE EN $IFACE (Canal $CHANNEL)"
echo "================================================================="
