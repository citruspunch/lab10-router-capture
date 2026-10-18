#!/usr/bin/env python3
"""
03_rf_telemetry_watchdog.py - Defensive RF Telemetry & Anomaly Watchdog
Laboratorio #10: Captura el Router (Ciencias de la Computación VIII)

Analyzes 802.11 management/control traffic using kernel BPF filters (type mgt or type ctl)
alongside lightweight CSV polling to detect adversarial anomalies in real time:
  - Deauthentication & Disassociation flooding
  - Beacon flooding & Fake AP generation (mdk3/mdk4)
  - Virtual Carrier-Sense (NAV) jamming & timer manipulation
  - Frame retry spikes indicating channel congestion/packet loss
  - IV/Data capture velocity drops
"""

import sys
import os
import time
import re
import glob
import subprocess
import argparse
from collections import defaultdict, deque

# ANSI color escape codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

class TelemetryWatchdog:
    def __init__(self, iface=None, pcap_file=None, csv_dir="/dev/shm/captures", window=5):
        self.iface = iface
        self.pcap_file = pcap_file
        self.csv_dir = csv_dir
        self.window = window
        self.history = deque()
        self.last_csv_ivs = 0
        self.last_csv_time = time.time()
        self.csv_velocity = 0.0
        
        # Regex matchers for tcpdump -e -n -tt output
        self.re_dbm = re.compile(r'(-\d{1,3})dBm')
        self.re_duration = re.compile(r'duration (\d+)(?:us)?')
        self.re_retry = re.compile(r'\b(retry|Retry)\b')

    def parse_frame_line(self, line):
        """Parses a single line of tcpdump -e -n output."""
        line = line.strip()
        if not line:
            return None

        # Extract timestamp
        ts = time.time()
        parts = line.split(maxsplit=2)
        if len(parts) >= 2:
            try:
                ts = float(parts[0])
            except ValueError:
                ts = time.time()

        frame_type = "other"
        lower_line = line.lower()

        # Classification of management subtypes
        if "beacon" in lower_line:
            frame_type = "beacon"
        elif "deauthentication" in lower_line or "deauth" in lower_line:
            frame_type = "deauth"
        elif "disassociation" in lower_line or "disassoc" in lower_line:
            frame_type = "disassoc"
        elif "authentication" in lower_line or "auth" in lower_line:
            frame_type = "auth"
        elif "probe req" in lower_line:
            frame_type = "probe_req"
        elif "probe resp" in lower_line:
            frame_type = "probe_resp"
        elif "rts" in lower_line:
            frame_type = "rts"
        elif "cts" in lower_line:
            frame_type = "cts"
        elif "ack" in lower_line:
            frame_type = "ack"

        # Signal (dBm)
        dbm = None
        dbm_match = self.re_dbm.search(line)
        if dbm_match:
            try:
                dbm = int(dbm_match.group(1))
            except ValueError:
                pass

        # Duration/NAV timer
        duration = 0
        dur_match = self.re_duration.search(line)
        if dur_match:
            try:
                duration = int(dur_match.group(1))
            except ValueError:
                pass

        # Retry flag
        is_retry = bool(self.re_retry.search(line))

        # Extract BSSID/MAC if available
        macs = re.findall(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
        bssid = macs[0].lower() if macs else None

        return {
            "ts": ts,
            "type": frame_type,
            "dbm": dbm,
            "duration": duration,
            "retry": is_retry,
            "bssid": bssid,
            "raw": line
        }

    def poll_csv_metrics(self):
        """Safely inspects airodump-ng CSV files to extract total #Data (IVs)."""
        if not os.path.isdir(self.csv_dir):
            return 0, 0.0

        csv_files = glob.glob(os.path.join(self.csv_dir, "*.csv"))
        if not csv_files:
            return 0, 0.0

        # Sort by mtime to get the latest
        latest_csv = max(csv_files, key=os.path.getmtime)
        try:
            with open(latest_csv, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return self.last_csv_ivs, self.csv_velocity

        total_ivs = 0
        in_client_section = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if "Station MAC" in line:
                in_client_section = True
                continue
            if not in_client_section and "," in line:
                cols = [c.strip() for c in line.split(",")]
                # WEP/AP table format: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
                if len(cols) >= 11:
                    try:
                        iv_val = int(cols[10])
                        total_ivs += iv_val
                    except (ValueError, IndexError):
                        pass

        now = time.time()
        elapsed = now - self.last_csv_time
        if elapsed >= 1.0:
            delta_ivs = max(0, total_ivs - self.last_csv_ivs)
            self.csv_velocity = delta_ivs / elapsed
            self.last_csv_ivs = total_ivs
            self.last_csv_time = now

        return self.last_csv_ivs, self.csv_velocity

    def evaluate_window(self):
        """Analyzes frames accumulated in the rolling time window."""
        if not self.history:
            ivs, vel = self.poll_csv_metrics()
            return {
                "total_frames": 0,
                "fps": 0.0,
                "deauth_fps": 0.0,
                "beacon_fps": 0.0,
                "unique_bssids": 0,
                "retry_pct": 0.0,
                "avg_dbm": None,
                "max_nav": 0,
                "anomalies": [],
                "ivs": ivs,
                "iv_velocity": vel
            }

        # If analyzing an offline PCAP, window spans from the last timestamp in history
        if self.pcap_file:
            latest_ts = self.history[-1]["ts"]
            cutoff = latest_ts - self.window
        else:
            now = time.time()
            cutoff = now - self.window
            # Purge old events in live mode
            while self.history and self.history[0]["ts"] < cutoff:
                self.history.popleft()

        total_frames = len(self.history)
        if total_frames == 0:
            ivs, vel = self.poll_csv_metrics()
            return {
                "total_frames": 0,
                "fps": 0.0,
                "deauth_fps": 0.0,
                "beacon_fps": 0.0,
                "unique_bssids": 0,
                "retry_pct": 0.0,
                "avg_dbm": None,
                "max_nav": 0,
                "anomalies": [],
                "ivs": ivs,
                "iv_velocity": vel
            }

        counts = defaultdict(int)
        retries = 0
        durations = []
        dbms = []
        bssids = set()

        for item in self.history:
            counts[item["type"]] += 1
            if item["retry"]:
                retries += 1
            if item["duration"] > 0:
                durations.append(item["duration"])
            if item["dbm"] is not None:
                dbms.append(item["dbm"])
            if item["bssid"]:
                bssids.add(item["bssid"])

        time_span = max(1.0, self.window)
        fps = total_frames / time_span
        deauth_fps = (counts["deauth"] + counts["disassoc"]) / time_span
        beacon_fps = counts["beacon"] / time_span
        retry_pct = (retries / total_frames) * 100.0 if total_frames > 0 else 0.0
        avg_dbm = int(sum(dbms) / len(dbms)) if dbms else None
        max_nav = max(durations) if durations else 0

        anomalies = []
        if deauth_fps >= 5.0:
            anomalies.append(f"DEAUTH/DISASSOC FLOOD DETECTED ({deauth_fps:.1f} frames/s)")
        if beacon_fps >= 50.0 and len(bssids) > 10:
            anomalies.append(f"BEACON FLOOD / FAKE AP ATTACK ({beacon_fps:.1f} b/s, {len(bssids)} BSSIDs)")
        if retry_pct >= 35.0:
            anomalies.append(f"HIGH PACKET RETRY RATE ({retry_pct:.1f}% retries)")
        if max_nav >= 5000:
            anomalies.append(f"VIRTUAL CARRIER-SENSE (NAV) JAMMING (NAV duration: {max_nav}us)")

        ivs, vel = self.poll_csv_metrics()
        if vel < 1.0 and ivs > 500 and deauth_fps > 3.0:
            anomalies.append("IV CAPTURE VELOCITY STALL UNDER ADVERSARIAL FLOODING")

        return {
            "total_frames": total_frames,
            "fps": fps,
            "deauth_fps": deauth_fps,
            "beacon_fps": beacon_fps,
            "unique_bssids": len(bssids),
            "retry_pct": retry_pct,
            "avg_dbm": avg_dbm,
            "max_nav": max_nav,
            "anomalies": anomalies,
            "ivs": ivs,
            "iv_velocity": vel
        }

    def render_dashboard(self, metrics):
        """Displays formatted telemetry stats in the terminal."""
        os.system("clear" if os.name != "nt" else "cls")
        print(f"{BOLD}{CYAN}=== 03_RF_TELEMETRY_WATCHDOG - LAB #10 TELEMETRÍA INALÁMBRICA ==={RESET}")
        print(f"Modo: {'En Vivo (BPF: type mgt or type ctl)' if self.iface else 'Análisis PCAP'}")
        print(f"Ventana Deslizante: {self.window}s | Interfaz: {self.iface or 'N/A'}")
        print("-----------------------------------------------------------------")
        
        # Capture metrics
        print(f"Tasa de Tramas de Control/Gestión: {BOLD}{metrics['fps']:.1f} fps{RESET} (Total ventana: {metrics['total_frames']})")
        print(f"Tramas Deauth/Disassoc:            {BOLD}{metrics['deauth_fps']:.1f} fps{RESET}")
        print(f"Tramas Beacon / BSSIDs Únicos:     {BOLD}{metrics['beacon_fps']:.1f} fps{RESET} ({metrics['unique_bssids']} BSSIDs)")
        
        # Signal & Quality
        retry_color = GREEN if metrics['retry_pct'] < 20 else (YELLOW if metrics['retry_pct'] < 35 else RED)
        dbm_str = f"{metrics['avg_dbm']} dBm" if metrics['avg_dbm'] else "N/A"
        print(f"Nivel de Señal Promedio:           {BOLD}{dbm_str}{RESET}")
        print(f"Tasa de Retransmisión (Retry %):   {retry_color}{BOLD}{metrics['retry_pct']:.1f}%{RESET}")
        print(f"Temporizador NAV Máximo:           {metrics['max_nav']} µs")
        
        # IV Velocity from CSV
        print("-----------------------------------------------------------------")
        print(f"Total IVs Capturados (#Data):      {BOLD}{GREEN}{metrics['ivs']}{RESET}")
        print(f"Velocidad de Captura de IVs:       {BOLD}{metrics['iv_velocity']:.1f} IVs/s{RESET}")
        
        # Alerts section
        print("-----------------------------------------------------------------")
        if metrics["anomalies"]:
            print(f"{BOLD}{RED}[!] CONDICIONES ADVERSARIAS DETECTADAS:{RESET}")
            for a in metrics["anomalies"]:
                print(f"  {RED}▶ {a}{RESET}")
        else:
            print(f"{BOLD}{GREEN}[✔] CANAL ESTABLE: Sin anomalías activas ni saturación adversarial.{RESET}")
        print("=================================================================")

    def run_live(self):
        """Executes live tcpdump process with strict BPF filter."""
        cmd = [
            "tcpdump", "-l", "-e", "-n", "-tt", "-i", self.iface,
            "type mgt or type ctl"
        ]
        print(f"[*] Iniciando tcpdump con filtro BPF: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                bufsize=1
            )
        except Exception as e:
            print(f"[-] ERROR al ejecutar tcpdump: {e}")
            sys.exit(1)

        last_render = time.time()
        try:
            for line in proc.stdout:
                parsed = self.parse_frame_line(line)
                if parsed:
                    self.history.append(parsed)
                
                now = time.time()
                if now - last_render >= 1.0:
                    metrics = self.evaluate_window()
                    self.render_dashboard(metrics)
                    last_render = now
        except KeyboardInterrupt:
            print("\n[*] Telemetría detenida por el usuario.")
        finally:
            proc.terminate()

    def analyze_pcap(self):
        """Analyzes an offline PCAP file using tcpdump reading from file."""
        cmd = ["tcpdump", "-e", "-n", "-tt", "-r", self.pcap_file]
        print(f"[*] Analizando archivo PCAP: {self.pcap_file}")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = proc.communicate()
        except Exception as e:
            print(f"[-] Error al leer PCAP: {e}")
            sys.exit(1)

        for line in stdout.splitlines():
            parsed = self.parse_frame_line(line)
            if parsed:
                self.history.append(parsed)

        metrics = self.evaluate_window()
        self.render_dashboard(metrics)
        return metrics

def run_self_test():
    """Validates parser logic with synthetic radiotap & 802.11 frames."""
    print("[*] Ejecutando auto-test interno de 03_rf_telemetry_watchdog.py...")
    watchdog = TelemetryWatchdog(window=5)
    now = time.time()
    
    # Synthetic samples
    samples = [
        f"{now - 2.0:.6f} -45dBm signal 2437MHz BSSID:00:11:22:33:44:55 Beacon (TestSSID) duration 0us",
        f"{now - 1.8:.6f} -48dBm signal 2437MHz BSSID:00:11:22:33:44:55 DeAuthentication: Reason 7 duration 0us",
        f"{now - 1.5:.6f} -50dBm signal 2437MHz BSSID:00:11:22:33:44:55 Disassociation duration 0us",
        f"{now - 1.0:.6f} -42dBm signal 2437MHz RTS duration 6500us [Retry]",
        f"{now - 0.5:.6f} -44dBm signal 2437MHz CTS duration 6000us"
    ]
    
    for s in samples:
        parsed = watchdog.parse_frame_line(s)
        assert parsed is not None, f"Falló parseo de: {s}"
        watchdog.history.append(parsed)
        
    metrics = watchdog.evaluate_window()
    assert metrics["total_frames"] == 5, f"Expected 5 frames, got {metrics['total_frames']}"
    assert metrics["max_nav"] == 6500, f"Expected max_nav 6500, got {metrics['max_nav']}"
    assert metrics["retry_pct"] == 20.0, f"Expected 20.0 retry pct, got {metrics['retry_pct']}"
    print("[✔] Auto-test exitoso: todas las aserciones de parseo y telemetría pasaron.")
    return 0

def main():
    parser = argparse.ArgumentParser(description="Watchdog de Telemetría Inalámbrica y Detección de Anomalías")
    parser.add_argument("-i", "--iface", help="Interfaz de red en modo monitor")
    parser.add_argument("-w", "--window", type=int, default=5, help="Ventana deslizante de análisis en segundos")
    parser.add_argument("--csv-dir", default="/dev/shm/captures", help="Directorio de archivos CSV de airodump-ng")
    parser.add_argument("--pcap", help="Ruta a archivo .pcap para análisis estático")
    parser.add_argument("--self-test", action="store_true", help="Ejecuta auto-test del analizador y sale")

    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    if args.pcap:
        watchdog = TelemetryWatchdog(pcap_file=args.pcap, csv_dir=args.csv_dir, window=args.window)
        watchdog.analyze_pcap()
        sys.exit(0)

    if not args.iface:
        # Try finding a wireless interface
        for dev in glob.glob("/sys/class/net/*"):
            dev_name = os.path.basename(dev)
            if "wlan" in dev_name or "wlx" in dev_name:
                args.iface = dev_name
                break

    if not args.iface:
        print("[-] ERROR: Debe especificar una interfaz con -i/--iface o un archivo con --pcap.")
        parser.print_help()
        sys.exit(1)

    watchdog = TelemetryWatchdog(iface=args.iface, csv_dir=args.csv_dir, window=args.window)
    watchdog.run_live()

if __name__ == "__main__":
    main()
