#!/usr/bin/env bash
# provision_vm.sh - Fully automated provisioning of Debian 12 ARM64 micro-VM
# Laboratorio #10: Captura el Router (Ciencias de la Computación VIII)
# Builds QEMU micro-VM with direct USB passthrough for Realtek RTL8188EUS (0bda:8179)

set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$VM_DIR/.." && pwd)"
BASE_IMAGE="$VM_DIR/base.qcow2"
OVERLAY_IMAGE="$VM_DIR/overlay.qcow2"
EFI_VARS="$VM_DIR/efi-vars.fd"
SEED_DIR="$VM_DIR/seed"
SEED_ISO="$VM_DIR/seed.iso"
SSH_KEY="$VM_DIR/id_ed25519"
DEBIAN_IMAGE_URL="https://gemmei.ftp.acc.umu.se/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2"

echo "================================================================="
echo "[*] INICIANDO PROVISIONAMIENTO DE MICRO-VM ARM64 (DEBIAN 12)"
echo "================================================================="

# 1. Pre-flight host disk space check
AVAIL_GB=$(df -g "$PROJECT_ROOT" | awk 'NR==2 {print $4}')
echo "[+] Espacio libre verificado en host: ${AVAIL_GB} GB"
if [[ "$AVAIL_GB" -lt 10 ]]; then
    echo "[-] ERROR: Se requieren al menos 10 GB libres para provisionamiento."
    exit 1
fi

# 2. Setup SSH Keypair
if [[ ! -f "$SSH_KEY" ]]; then
    echo "[*] Generando llave SSH Ed25519 para la micro-VM..."
    ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "lab10-debian-vm"
fi
SSH_PUB_KEY=$(cat "$SSH_KEY.pub")

# 3. UEFI Variables Template
if [[ ! -f "$EFI_VARS" ]]; then
    echo "[*] Inicializando variables UEFI para ARM64..."
    cp "/opt/homebrew/share/qemu/edk2-arm-vars.fd" "$EFI_VARS"
fi

# 4. Download Official Debian 12 Generic ARM64 Cloud Image
if [[ ! -f "$BASE_IMAGE" ]]; then
    echo "[*] Descargando imagen oficial Debian 12 Generic ARM64 (~416 MB)..."
    curl -L --progress-bar -o "$BASE_IMAGE" "$DEBIAN_IMAGE_URL"
    echo "[✔] Imagen base descargada."
fi

# 5. Create Copy-on-Write Sparse Overlay (10 GB logical, < 1.5 GB physical post-trim)
if [[ ! -f "$OVERLAY_IMAGE" ]]; then
    echo "[*] Creando imagen copy-on-write sparse (overlay.qcow2)..."
    qemu-img create -f qcow2 -b "base.qcow2" -F qcow2 "$OVERLAY_IMAGE" 10G
fi

# 6. Generate Cloud-Init NoCloud Seed ISO
echo "[*] Generando configuración cloud-init (NoCloud)..."
mkdir -p "$SEED_DIR"

cat <<EOF > "$SEED_DIR/meta-data"
instance-id: lab10-debian-arm64
local-hostname: lab10-router-capture
EOF

cat <<EOF > "$SEED_DIR/user-data"
#cloud-config
users:
  - name: debian
    gecos: Debian User
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
      - $SSH_PUB_KEY
chpasswd:
  list: |
    debian:debian
  expire: false
ssh_pwauth: true
package_update: false
bootcmd:
  - mkdir -p /mnt/host
runcmd:
  - modprobe 9pnet_virtio 2>/dev/null || true
  - mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host 2>/dev/null || true
  - echo "hostshare /mnt/host 9p trans=virtio,version=9p2000.L,_netdev 0 0" >> /etc/fstab
EOF

rm -f "$SEED_ISO"
hdiutil makehybrid -iso -joliet -default-volume-name cidata "$SEED_DIR" -o "$SEED_ISO" >/dev/null
echo "[✔] Seed ISO creado en $SEED_ISO"

# 7. Start Micro-VM
echo "[*] Iniciando micro-VM para configuración de paquetes y drivers..."
"$VM_DIR/start_vm.sh"

echo "[*] Esperando a que el sistema operativo y SSH estén listos..."
for i in {1..40}; do
    if "$VM_DIR/ssh_vm.sh" "echo ready" >/dev/null 2>&1; then
        echo "[✔] Conexión SSH establecida con éxito."
        break
    fi
    sleep 2
done

# 8. Setup Repositories & Install Toolchain Inside Guest
echo "================================================================="
echo "[*] INSTALANDO COMPONENTES DENTRO DE LA MICRO-VM"
echo "================================================================="

"$VM_DIR/ssh_vm.sh" bash -s <<'GUEST_SETUP'
set -euo pipefail

echo "[*] Habilitando repositorios non-free y non-free-firmware..."
if [ -f /etc/apt/sources.list.d/debian.sources ]; then
    sudo sed -i 's/Components: main/Components: main contrib non-free non-free-firmware/g' /etc/apt/sources.list.d/debian.sources
fi
if [ -f /etc/apt/sources.list ]; then
    sudo sed -i 's/main$/main contrib non-free non-free-firmware/g' /etc/apt/sources.list
fi

sudo apt-get update

echo "[*] Instalando dependencias de compilación y utilidades inalámbricas..."
sudo apt-get install -y --no-install-recommends \
    linux-headers-arm64 \
    build-essential \
    dkms \
    git \
    bc \
    firmware-realtek \
    aircrack-ng \
    iw \
    wireless-tools \
    tcpdump \
    tmux \
    usbutils \
    pciutils \
    python3 \
    rsync \
    iproute2 \
    rfkill

# 9. Clone and Build aircrack-ng/rtl8188eus (Latest Active HEAD)
echo "[*] Descargando y compilando driver especializado aircrack-ng/rtl8188eus..."
cd /usr/src
if [ ! -d "rtl8188eus" ]; then
    sudo git clone --depth 1 https://github.com/aircrack-ng/rtl8188eus.git
fi
cd rtl8188eus
sudo sed -i 's/\.usbdrv\.drvwrap\.driver\.shutdown/\.usbdrv\.driver\.shutdown/g' os_dep/linux/usb_intf.c
sudo make -j2
sudo make install

# 10. Blacklist conflicting in-tree drivers
echo "[*] Configurando blacklist para r8188eu y rtl8xxxu..."
sudo tee /etc/modprobe.d/realtek.conf <<'EOF'
blacklist r8188eu
blacklist rtl8xxxu
EOF

sudo depmod -a

# Ensure 8188eu loads
sudo modprobe 8188eu || true

# 11. Storage Hygiene inside Guest
echo "[*] Limpiando cachés de paquetes y ejecutando fstrim..."
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
sudo fstrim -av

echo "[✔] Configuración interna completada con éxito."
GUEST_SETUP

echo "================================================================="
echo "[✔] PROVISIONAMIENTO DE MICRO-VM FINALIZADO CON ÉXITO"
echo "================================================================="
