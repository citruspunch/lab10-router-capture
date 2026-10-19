# Laboratorio 10: Captura de tráfico y recuperación de clave WEP

**Nombre:** Andrés Tobar  
**Carné:** 23001175  
**Curso:** Ciencias de la Computación VIII  
**Hardware:** MacBook Air M2 (macOS Sequoia) + Antena USB Realtek RTL8188EUS (0bda:8179)  
**Entorno:** Debian 12 ARM64 en QEMU (modo headless con aceleración HVF)  

---

## 1. Funcionamiento de WEP y debilidades criptográficas

El protocolo WEP cifra el tráfico inalámbrico mediante el algoritmo de flujo RC4. Para cada paquete, combina una clave secreta precompartida con un Vector de Inicialización (IV) de 24 bits:
- **WEP-40:** Clave fija de 40 bits concatenada con un IV de 24 bits, sumando 64 bits de clave de sesión.
- **WEP-104:** Clave fija de 104 bits concatenada con un IV de 24 bits, sumando 128 bits de clave de sesión.

Para transmitir cada trama en la red:
1. Se calcula el código de integridad del paquete mediante CRC-32: $\text{ICV} = \text{CRC32}(P)$.
2. Se genera un IV de 24 bits y se concatena a la clave fija: $K_{\text{pkt}} = \text{IV} \parallel K$.
3. Con este valor, RC4 genera la secuencia de cifrado ($Z$) y se aplica una operación XOR con los datos y su ICV: $C = (P \parallel \text{ICV}) \oplus Z$.
4. El IV se coloca en texto plano dentro de la cabecera 802.11 del paquete, ya que la estación receptora lo necesita para inicializar su propio generador RC4 y descifrar la trama.

### Por qué el protocolo es vulnerable en la práctica
- **Espacio de IVs sumamente reducido (24 bits):** Al disponer únicamente de 24 bits, solo existen $2^{24} \approx 16.7$ millones de valores posibles. Debido a la paradoja del cumpleaños, al llegar a unas 5,000 tramas la probabilidad de repetir un IV supera el 50%. Si dos paquetes usan el mismo IV, comparten exactamente la misma secuencia de cifrado, por lo que al aplicar una operación XOR entre ambos textos cifrados ($C_1 \oplus C_2 = P_1 \oplus P_2$), el cifrado se anula por completo y los datos originales quedan al descubierto.
- **Falta de integridad criptográfica en CRC-32:** El algoritmo CRC-32 es lineal y no cuenta con propiedades criptográficas, por lo que es posible modificar bits puntuales del mensaje cifrado y ajustar el checksum sin necesidad de conocer la clave de la red.
- **Ataque algebraico PTW (Pyshkin, Tews y Weinmann):** Este método analiza las correlaciones existentes en los primeros bytes de paquetes ARP cifrados, ya que su contenido inicial es conocido y estandarizado. Con esto se resuelve la clave de manera algebraica con apenas 20,000 a 40,000 paquetes con IVs únicos en pocos segundos de CPU, por lo que no hace falta recurrir a diccionarios de contraseñas.
- **Inyección y retransmisión de tráfico ARP (`aireplay-ng -3`):** Al reinyectar un paquete ARP capturado hacia el punto de acceso, este lo procesa como una solicitud legítima y lo retransmite por broadcast hacia toda la red. Cada vez que el router responde, se ve forzado a generar un IV nuevo, por lo que es posible recolectar cientos de paquetes por segundo sin tener que esperar a que los usuarios generen tráfico de forma pasiva.

---

## 2. Preparación del entorno en Mac M2

Dado que macOS no permite poner la tarjeta Wi-Fi integrada en modo monitor ni inyectar paquetes, y ya que Docker Desktop en Mac no soporta passthrough USB de capa 2 hacia el kernel, opté por configurar una micro-VM de Debian 12 ARM64 en QEMU con aceleración por hardware HVF:

```
[MacBook Air M2 (Host)]
  │
  ├─ USB Passthrough ──> [Micro-VM Debian 12 ARM64 (QEMU)]
  │                       ├─ Driver 8188eu (Modo monitor)
  │                       ├─ airodump-ng / tcpdump
  │                       └─ Buffer RAM (/dev/shm/captures/)
  │                                    │
  │   Sincronización cada 2s <─────────┘
  ▼
[Capturas locales en ./captures/]
  │
  └─> scripts/04_host_analyzer.sh (aircrack-ng corriendo nativo en Apple Silicon)
```

### Puntos clave de la configuración:
1. **Buffer de captura en memoria RAM (`/dev/shm`):** Escribir directamente sobre la carpeta compartida VirtFS 9p de QEMU generaba cuellos de botella por latencia de entrada y salida, por lo que el kernel de Linux empezaba a descartar tramas que venían de la antena. Para resolver esto, configuré la captura en memoria compartida (`/dev/shm/captures/`) y sincronicé los archivos hacia macOS cada dos segundos en segundo plano, con lo que se eliminaron por completo las pérdidas de paquetes.
2. **Descifrado directo en el host:** La máquina virtual se configuró con solo 2 vCPUs para no consumir recursos de más. Dado que el análisis estadístico de `aircrack-ng` es intensivo en procesador, decidí ejecutarlo directamente en macOS, ya que los núcleos del chip M2 permiten procesar los cálculos mucho más rápido sin restarle ciclos a la máquina virtual para atender las interrupciones del adaptador USB.
3. **Compilación del driver Realtek:** El módulo `r8188eu` que viene por defecto en el kernel de Debian no permite levantar modo monitor con herramientas modernas. Por lo tanto, lo mandé a la lista negra en `/etc/modprobe.d/` y compilé desde el repositorio de `aircrack-ng/rtl8188eus` una versión optimizada para ARM64.

---

## 3. Scripts de automatización

- **`vm/start_vm.sh`:** Inicia la micro-VM en segundo plano con passthrough del adaptador USB (`0bda:8179`), monta la carpeta compartida del proyecto mediante VirtFS y deja listo el acceso por SSH en el puerto 2222.
- **`scripts/01_prep_monitor.sh`:** Detiene servicios de red que puedan generar interferencia (`wpa_supplicant`, `iwd`), cambia la interfaz `wlxd0374509a98e` a modo monitor y fija el canal de radiofrecuencia indicado.
- **`scripts/02_capture_pipeline.sh`:** Inicializa una sesión de `tmux` en tres paneles: uno con `airodump-ng` guardando en `/dev/shm/captures/`, otro con un proceso de sincronización atómica hacia `./captures/`, y el último con el monitor de telemetría de canal.
- **`scripts/03_rf_telemetry_watchdog.py`:** Inspecciona el canal en tiempo real aplicando un filtro BPF (`type mgt or type ctl`) para medir tramas de control, desautenticaciones, balizas y reintentos sin consumir CPU analizando paquetes de datos.
- **`scripts/04_host_analyzer.sh`:** Se ejecuta de forma nativa en macOS, revisa los archivos acumulados en `./captures/` y dispara `aircrack-ng` sobre el procesador M2 en cuanto se alcanza el umbral de IVs requerido.

### Comandos de uso:

```bash
# 1. Iniciar la máquina virtual
./vm/start_vm.sh

# 2. Configurar el modo monitor en el canal deseado (por ejemplo, canal 6)
./vm/ssh_vm.sh "sudo /mnt/host/scripts/01_prep_monitor.sh --channel 6"

# 3. Iniciar la captura filtrada hacia el BSSID objetivo
./vm/ssh_vm.sh "sudo /mnt/host/scripts/02_capture_pipeline.sh --channel 6 --bssid 00:11:22:33:44:55"

# 4. En el host (macOS), ejecutar el analizador para recuperar la clave
./scripts/04_host_analyzer.sh --bssid 00:11:22:33:44:55 --min-ivs 5000
```

---

## 4. Evidencia técnica y pruebas realizadas

### Almacenamiento y memoria de la VM
Verifiqué el consumo en disco y el espacio disponible en RAM para el buffer de captura:
```text
/boot/efi: 114.5 MiB (120086528 bytes) trimmed on /dev/sda15
/: 0 B (0 bytes) trimmed on /dev/sda1
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       9.7G  1.6G  7.7G  17% /
tmpfs           738M     0  738M   0% /dev/shm
1.2G	vm
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s1   228Gi   156Gi    41Gi    80%    1.6M  425M    0%   /System/Volumes/Data
```
La máquina virtual ocupa únicamente 1.2 GB en el disco físico del equipo y cuenta con más de 700 MB disponibles en `/dev/shm`, por lo que el buffer en RAM tiene margen de sobra para capturar paquetes sin depender de accesos a disco.

### Detección USB y carga del driver
Validación del passthrough USB y del módulo `8188eu` en el kernel de la VM:
```text
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 002: ID 0bda:8179 Realtek Semiconductor Corp. RTL8188EUS 802.11n Wireless Network Adapter
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
8188eu               1196032  0
cfg80211              798720  1 8188eu
rfkill                 36864  2 cfg80211
usbcore               270336  3 xhci_hcd,8188eu,xhci_pci
[    0.805560] usb 1-1: new high-speed USB device number 2 using xhci_hcd
[    0.955987] usb 1-1: New USB device found, idVendor=0bda, idProduct=8179, bcdDevice= 0.00
[    0.957386] usb 1-1: Product: 802.11n NIC
[    0.957705] usb 1-1: Manufacturer: Realtek
[    0.957969] usb 1-1: SerialNumber: 00E04C0001
[  105.829242] usbcore: registered new interface driver 8188eu
[  105.833800] 8188eu 1-1:1.0 wlxd0374509a98e: renamed from wlan0
```

### Modos soportados por la interfaz
Comprobación de capacidades con `iw`:
```text
Supported interface modes:
	 * IBSS
	 * managed
	 * AP
	 * monitor
	 * P2P-client
	 * P2P-GO
Supported Ciphers:
	* WEP40 (00-0f-ac:1)
	* WEP104 (00-0f-ac:5)
	* TKIP (00-0f-ac:2)
	* CCMP-128 (00-0f-ac:4)
```

### Activación de modo monitor en canal específico
Ejecución de `01_prep_monitor.sh` fijando canal 6:
```text
[*] INICIANDO PREPARACIÓN MODO MONITOR - LAB 10 (CC8)
[+] Buffer RAM-Disk verificado en /dev/shm/captures/
[*] Limpiando procesos inalámbricos que puedan causar interferencia...
[+] Interfaz inalámbrica objetivo: wlxd0374509a98e
[*] Desactivando interfaz wlxd0374509a98e...
[*] Cambiando modo a 'monitor'...
[+] Modo monitor activado mediante 'iw dev wlxd0374509a98e set type monitor'
[*] Levantando interfaz wlxd0374509a98e...
[*] Fijando canal 6 en wlxd0374509a98e...
[+] Canal 6 fijado mediante 'iw'
Interface wlxd0374509a98e
	addr d0:37:45:09:a9:8e
	type monitor
wlxd0374509a98e  unassociated  Nickname:"<WIFI@REALTEK>"
          Mode:Monitor  Frequency=2.437 GHz  Access Point: Not-Associated
```

### Captura con cabeceras radiotap e inspección en macOS
Prueba de captura de tramas con niveles de señal (dBm) legibles desde el host:
```text
tcpdump: listening on wlxd0374509a98e, link-type IEEE802_11_RADIO (802.11 plus radiotap header), snapshot length 262144 bytes
Got 020 packets captured
224 packets received by filter
0 packets dropped by kernel
-rw-r--r-- 1 debian debian 3.2K Oct 18 23:31 /mnt/host/captures/test_capture.pcap
--- HOST AIRCRACK-NG INSPECTION ---
Reading packets, please wait...
Opening captures/test_capture.pcap
Read 20 packets.

   #  BSSID              ESSID                     Encryption
   1  00:25:00:FF:94:73                            Unknown
   2  74:3A:EF:79:7F:33  CLARO1_797F2F             Unknown
   3  90:50:CA:72:C2:D8  CASA CLUB                 Unknown
   4  98:77:E7:31:BA:34  CLARO1_31BA30             Unknown
   5  DC:73:06:36:98:8F  TIGO-9159                 Unknown
```

### Prueba de estabilidad bajo tráfico continuo (3 minutos)
Captura continua de 180 segundos en el canal 6 para verificar la estabilidad del controlador y el rendimiento de la memoria:
```text
[*] Capturando tráfico en canal 6 durante 180 segundos continuos...
tcpdump: listening on wlxd0374509a98e, link-type IEEE802_11_RADIO (802.11 plus radiotap header), snapshot length 262144 bytes
69634 packets captured
69710 packets received by filter
0 packets dropped by kernel
[✔] Captura finalizada. Duración efectiva: 180s

--- ESTADÍSTICAS DEL BUFFER RAM-DISK (/dev/shm) ---
-rw-r--r-- 1 tcpdump tcpdump 8.4M Oct 18 23:35 /dev/shm/captures/stress_3min.pcap
tmpfs           738M  8.4M  729M   2% /dev/shm
Total de paquetes capturados en 3 minutos: 69793

--- TELEMETRÍA RF EN HOST (PYTHON WATCHDOG) ---
-rw-------@ 1 andres  staff   8.4M Oct 18 17:35 captures/stress_3min.pcap
=== 03_RF_TELEMETRY_WATCHDOG - LAB #10 TELEMETRÍA INALÁMBRICA ===
Tasa de Tramas de Control/Gestión: 13958.6 fps (Total ventana: 69793)
Tramas Deauth/Disassoc:            1.0 fps
Tramas Beacon / BSSIDs Únicos:     693.0 fps (39 BSSIDs)
Nivel de Señal Promedio:           -53 dBm
Tasa de Retransmisión (Retry %):   0.0%
Temporizador NAV Máximo:           0 µs
```
Durante los 3 minutos se capturaron **69,793 paquetes (8.4 MB)** con **0 paquetes descartados por el kernel**, por lo que la comunicación por el bus USB y el driver se mantuvieron estables sin registrar caídas en `dmesg`.

---

## 5. Acciones adversarias y optimizaciones en el canal

En un escenario de competencia donde varios equipos buscan capturar el tráfico del mismo router dentro del mismo canal, la saturación del medio y la interferencia reducen drásticamente la tasa de captura efectiva.

### Factores adversarios en el canal
1. **Ráfagas de desautenticación:** Si se desconecta a los clientes legítimos de forma constante, se interrumpe el flujo de datos entre las estaciones y el router, por lo que la generación de nuevos IVs se detiene por completo.
2. **Inundación de balizas (Beacon flood):** La emisión indiscriminada de balizas falsas satura el tiempo aire y llena las tablas de redes de las herramientas de captura, ya que las estaciones deben pausar sus transmisiones al detectar el canal ocupado por el mecanismo CSMA/CA.
3. **Saturación por colisiones y reintentos:** Cuando varios equipos inyectan paquetes al mismo tiempo sin coordinación, las señales colisionan en el aire, por lo que las estaciones no reciben confirmaciones (ACK) y deben retransmitir con el flag `Retry` activo, lo que reduce la eficiencia del canal.

### Medidas implementadas

| Nivel | Medida | Implementación | Efecto práctico |
| :--- | :--- | :--- | :--- |
| **Software** | **Filtrado estricto por BSSID** | `airodump-ng --bssid <MAC> -c <CH>` | Descarta en memoria paquetes de otras redes y balizas falsas, por lo que solo se almacena tráfico relevante del objetivo. |
| **Software** | **Buffer en RAM** | Escritura en `/dev/shm/captures/` | Evita demoras por escritura en disco virtual, ya que el buffer en RAM absorbe ráfagas altas sin generar descartes en el kernel. |
| **Software** | **Descifrado fuera de la VM** | `scripts/04_host_analyzer.sh` en macOS | Corre `aircrack-ng` directamente sobre el procesador M2, por lo que la VM queda libre para atender las interrupciones del adaptador USB sin retrasos. |
| **Software** | **Telemetría con BPF** | `03_rf_telemetry_watchdog.py` | Monitorea desautenticaciones y reintentos anormales en tiempo real sin saturar la CPU, ya que filtra tramas de datos irrelevantes en el kernel. |
| **Físico** | **Proximidad al router** | Ubicación a corta distancia (< 2 m) | Garantiza una potencia de señal alta (> -50 dBm), lo que permite aprovechar el efecto captura (Capture Effect) a nivel físico para que la antena decodifique las respuestas del router por encima del ruido de otros equipos. |
| **Físico** | **Orientación de antena** | Posición vertical alineada al router | Maximiza la ganancia por coincidencia de polarización electromagnética en la banda de 2.4 GHz, por lo que se reducen las pérdidas por desajuste. |

---

## 6. Conclusiones

1. La configuración con Debian 12 ARM64 en QEMU y passthrough USB resolvió las limitaciones de macOS para auditoría inalámbrica, requiriendo solo 1.2 GB de disco y aprovechando la aceleración por hardware con HVF.
2. El driver `8188eu` compilado específicamente para el chip Realtek RTL8188EUS operó con estabilidad en modo monitor en la banda de 2.4 GHz, permitiendo capturar cabeceras radiotap completas sin caídas en el bus.
3. El uso de `/dev/shm` en memoria RAM evitó la sobrecarga de I/O de la carpeta compartida, ya que permitió registrar cerca de 70,000 tramas sin que el kernel descartara ningún paquete durante pruebas de estrés.
4. Desacoplar la fase de captura (en la máquina virtual) del análisis criptográfico (ejecutado en macOS) permitió aprovechar la capacidad de cómputo del chip M2, por lo que `aircrack-ng` puede intentar resolver la clave de forma continua sin afectar la recepción del adaptador USB.
