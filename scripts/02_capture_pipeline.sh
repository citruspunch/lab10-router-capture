#!/usr/bin/env bash
# 02_capture_pipeline.sh - Orchestrated High-Throughput Capture Workspace
# For Laboratorio #10: Captura el Router (CC8)
# Runs inside Linux ARM64 micro-VM. Writes to /dev/shm/captures/ and syncs to /mnt/host/captures/

set -euo pipefail

CHANNEL="6"
IFACE=""
BSSID=""
PREFIX="lab10_wep"
SESSION_NAME="lab10_capture"

show_usage() {
    cat <<EOF
Uso: $0 [opciones]
Opciones:
  -i, --iface <iface>    Interfaz en modo monitor (ej. wlan0)
  -c, --channel <1-14>   Canal a capturar (por defecto: 6)
  -b, --bssid <MAC>      BSSID objetivo (opcional, recomendado para filtrar WEP)
  -p, --prefix <name>    Prefijo de captura (por defecto: lab10_wep)
  -s, --standalone       Ejecuta solo el capturador + sincronizador en primer plano sin tmux
  -h, --help             Muestra esta ayuda
EOF
    exit 1
}

STANDALONE=0
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
        -p|--prefix)
            PREFIX="$2"
            shift 2
            ;;
        -s|--standalone)
            STANDALONE=1
            shift
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

# Auto-detect interface if not provided
if [[ -z "$IFACE" ]]; then
    for dev in /sys/class/net/*; do
        dev_name=$(basename "$dev")
        if [[ -d "$dev/wireless" ]] || [[ "$dev_name" =~ ^wlan ]] || [[ "$dev_name" =~ ^wlx ]]; then
            IFACE="$dev_name"
            break
        fi
    done
fi

if [[ -z "$IFACE" ]]; then
    echo "[-] ERROR: Interfaz inalámbrica no detectada."
    exit 1
fi

# Ensure storage directories exist
mkdir -p /dev/shm/captures
chmod 777 /dev/shm/captures
mkdir -p /mnt/host/captures
mkdir -p /mnt/host/captures/.staging

# Build airodump-ng command
AIRODUMP_CMD="airodump-ng -c $CHANNEL --write /dev/shm/captures/$PREFIX --output-format pcap,csv $IFACE"
if [[ -n "$BSSID" ]]; then
    AIRODUMP_CMD="airodump-ng --bssid $BSSID -c $CHANNEL --write /dev/shm/captures/$PREFIX --output-format pcap,csv $IFACE"
fi

# Script for the smart sync worker
SYNC_SCRIPT="/dev/shm/sync_worker.sh"
cat <<'EOF' > "$SYNC_SCRIPT"
#!/usr/bin/env bash
PREFIX="$1"
SRC_DIR="/dev/shm/captures"
DST_DIR="/mnt/host/captures"
STAGING_DIR="/mnt/host/captures/.staging"

declare -A LAST_MOD_TIME

echo "[*] Smart Snapshot Sync Worker iniciado."
echo "[*] Monitorizando $SRC_DIR y sincronizando hacia $DST_DIR de forma atómica..."

while true; do
    # Check RAM disk headroom
    SHM_AVAIL=$(df -m /dev/shm | awk 'NR==2 {print $4}')
    if [[ "$SHM_AVAIL" -lt 100 ]]; then
        echo "[!] ALERTA: Espacio bajo en /dev/shm: ${SHM_AVAIL}MB libres!"
    fi

    # Check each file matching prefix
    for src_file in "$SRC_DIR"/"$PREFIX"*; do
        if [[ -f "$src_file" ]]; then
            fname=$(basename "$src_file")
            # Get current modification time (epoch seconds)
            cur_mod=$(stat -c %Y "$src_file" 2>/dev/null || stat -f %m "$src_file" 2>/dev/null || echo 0)
            cur_size=$(stat -c %s "$src_file" 2>/dev/null || stat -f %z "$src_file" 2>/dev/null || echo 0)

            last_mod="${LAST_MOD_TIME[$fname]:-0}"

            # Only sync if modified
            if [[ "$cur_mod" -gt "$last_mod" ]] && [[ "$cur_size" -gt 0 ]]; then
                cp -f "$src_file" "$STAGING_DIR/$fname.tmp" 2>/dev/null || true
                mv -f "$STAGING_DIR/$fname.tmp" "$DST_DIR/$fname" 2>/dev/null || true
                LAST_MOD_TIME["$fname"]="$cur_mod"
            fi
        fi
    done
    sleep 2
done
EOF
chmod +x "$SYNC_SCRIPT"

if [[ "$STANDALONE" -eq 1 ]] || ! command -v tmux >/dev/null 2>&1; then
    echo "[*] Ejecutando pipeline en modo standalone..."
    "$SYNC_SCRIPT" "$PREFIX" &
    SYNC_PID=$!
    trap 'kill $SYNC_PID 2>/dev/null || true' EXIT
    echo "[*] Lanzando airodump-ng..."
    exec $AIRODUMP_CMD
fi

# Launch 3-pane tmux session
echo "[*] Creando sesión de tmux: $SESSION_NAME..."
tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true

# Pane 0: airodump-ng
tmux new-session -d -s "$SESSION_NAME" -n "capture" "$AIRODUMP_CMD"

# Pane 1: Smart Sync Worker & Storage Monitor
tmux split-window -h -t "$SESSION_NAME:0" "$SYNC_SCRIPT $PREFIX"

# Pane 2: RF Telemetry Watchdog
WATCHDOG_PATH="/mnt/host/scripts/03_rf_telemetry_watchdog.py"
if [[ ! -f "$WATCHDOG_PATH" ]] && [[ -f "./scripts/03_rf_telemetry_watchdog.py" ]]; then
    WATCHDOG_PATH="./scripts/03_rf_telemetry_watchdog.py"
fi
tmux split-window -v -t "$SESSION_NAME:0.1" "python3 $WATCHDOG_PATH --iface $IFACE --csv-dir /dev/shm/captures --window 5"

# Arrange panes
tmux select-layout -t "$SESSION_NAME" tiled

echo "[✔] Pipeline iniciado en sesión de tmux '$SESSION_NAME'."
echo "    Para conectarse a la interfaz interactiva: tmux attach -t $SESSION_NAME"
echo "    Para salir de tmux sin detener la captura: presione Ctrl+B y luego D"
