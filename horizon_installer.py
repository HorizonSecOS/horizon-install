#!/usr/bin/env python3
"""
HorizonSec OS - Professional Penetration Testing Distribution
Complete Arch Linux installer with 100+ security tools
"""

import os
import sys
import subprocess
import time
import json
import getpass
import argparse
import hashlib

VERBOSE = False
INSTALL_TYPE = 'full'

class Color:
    """ANSI color codes for terminal output"""
    ORANGE = '\033[38;5;208m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

def cmd(command, capture=False, check=True, silent=False):
    """Execute shell command"""
    try:
        if VERBOSE:
            print(f"{Color.PURPLE}[DEBUG] $ {command}{Color.END}")
        if capture:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=check)
            return result.stdout.strip()
        
        if silent:
            subprocess.run(command, shell=True, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True, check=check)
        return True
    except subprocess.CalledProcessError as e:
        if not check:
            return False
        print(f"{Color.RED}[!] Command failed: {command}{Color.END}")
        if capture and e.stderr:
            print(f"{Color.RED}{e.stderr}{Color.END}")
        return False

def header(text):
    """Print formatted header"""
    width = 70
    print(f"\n{Color.ORANGE}{Color.BOLD}╔{'═' * (width - 2)}╗{Color.END}")
    print(f"{Color.ORANGE}{Color.BOLD}║ {text:<{width-4}} ║{Color.END}")
    print(f"{Color.ORANGE}{Color.BOLD}╚{'═' * (width - 2)}╝{Color.END}\n")

def info(text):
    print(f"{Color.CYAN}[→]{Color.END} {text}")

def success(text):
    print(f"{Color.GREEN}[✓]{Color.END} {text}")

def warning(text):
    print(f"{Color.YELLOW}[!]{Color.END} {text}")

def error(text):
    print(f"{Color.RED}[✗]{Color.END} {text}")

def logo():
    print(f"""{Color.ORANGE}
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   HORIZON▓ SEC                                            ║
  ║   Professional Penetration Testing Distribution           ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
            v1.0 - Advanced Security Testing Platform
{Color.END}""")

def check_root():
    if os.geteuid() != 0:
        error("This installer must be run as root!")
        sys.exit(1)

def check_uefi():
    """Check if system is UEFI or BIOS"""
    is_uefi = os.path.exists('/sys/firmware/efi')
    header("Firmware Detection")
    if is_uefi:
        success("UEFI firmware detected")
    else:
        success("BIOS firmware detected")
    return is_uefi

def setup_network():
    """Configure network connectivity"""
    header("Network Configuration")
    cmd("systemctl start NetworkManager", check=False)
    time.sleep(2)
    
    info("Network configuration manager (nmtui) will open in 4 seconds...")
    time.sleep(4)
    subprocess.run("nmtui", check=False)
    
    if cmd("ping -c 2 archlinux.org", check=False):
        success("Network is active")
    else:
        warning("Network may not be connected.")
    
    info("Initializing package keys...")
    cmd("pacman-key --init", check=False)
    cmd("pacman-key --populate archlinux", check=False)
    cmd("pacman -Sy --noconfirm", check=False)

def detect_gpu():
    """Auto-detect GPU and return appropriate drivers"""
    header("GPU Detection")
    gpu_output = cmd("lspci 2>/dev/null | grep -iE 'vga|3d|display'", capture=True, check=False) or ""
    gpu_lower = gpu_output.lower()
    
    if 'nvidia' in gpu_lower:
        success("NVIDIA GPU detected")
        return "NVIDIA", ["nvidia", "nvidia-utils", "nvidia-settings"]
    elif 'amd' in gpu_lower or 'ati' in gpu_lower:
        success("AMD GPU detected")
        return "AMD", ["mesa", "xf86-video-amdgpu", "vulkan-radeon"]
    elif 'intel' in gpu_lower:
        success("Intel GPU detected")
        return "Intel", ["mesa", "intel-media-driver", "vulkan-intel"]
    else:
        warning("Generic GPU detected")
        return "Generic", ["mesa", "xf86-video-vesa"]

def list_disks():
    try:
        output = cmd('lsblk -J -d -o NAME,SIZE,MODEL,TYPE', capture=True, check=False)
        data = json.loads(output)
        return [d for d in data.get('blockdevices', []) if d['type'] == 'disk' and not d['name'].startswith('loop')]
    except:
        error("Failed to enumerate disks")
        sys.exit(1)

def select_disk():
    header("Disk Selection")
    disks = list_disks()
    if not disks:
        error("No suitable disks found!")
        sys.exit(1)
    
    print(f"{Color.BOLD}Available Disks:{Color.END}")
    for i, disk in enumerate(disks, 1):
        print(f"  {Color.ORANGE}{i}){Color.END} /dev/{disk['name']} - {disk['size']} - {disk.get('model', 'Unknown')}")
    
    while True:
        try:
            choice = int(input(f"\n{Color.CYAN}Select disk [1-{len(disks)}]: {Color.END}")) - 1
            if 0 <= choice < len(disks):
                disk = disks[choice]
                path = f"/dev/{disk['name']}"
                print(f"\n{Color.RED}{Color.BOLD}WARNING: ALL DATA ON {path} WILL BE ERASED!{Color.END}")
                if input(f"{Color.RED}Type 'yes' to continue: {Color.END}").strip().lower() == 'yes':
                    return disk['name'], path
        except ValueError:
            pass

def partition_disk(disk_name, disk_path, is_uefi):
    """Partition and format disk"""
    header("Disk Partitioning")
    
    info("Unmounting and wiping...")
    cmd("umount -R /mnt 2>/dev/null", check=False)
    cmd("swapoff -a", check=False)
    cmd(f"wipefs -af {disk_path}", check=False)
    cmd(f"sgdisk --zap-all {disk_path}", check=False)
    
    # Partition Naming Scheme
    sep = 'p' if 'nvme' in disk_name or 'mmcblk' in disk_name else ''
    
    if is_uefi:
        info("Creating GPT partition table (UEFI)...")
        # 1: EFI (512M), 2: Swap (8G), 3: Root (Rest)
        cmd(f"sgdisk -n 1:0:+512M -t 1:ef00 -c 1:EFI {disk_path}")
        cmd(f"sgdisk -n 2:0:+8G -t 2:8200 -c 2:SWAP {disk_path}")
        cmd(f"sgdisk -n 3:0:0 -t 3:8300 -c 3:ROOT {disk_path}")
        
        efi = f"{disk_path}{sep}1"
        swap = f"{disk_path}{sep}2"
        root = f"{disk_path}{sep}3"
        
        cmd(f"partprobe {disk_path}")
        time.sleep(2)
        
        info("Formatting...")
        cmd(f"mkfs.fat -F32 {efi}")
        cmd(f"mkswap {swap}")
        cmd(f"mkfs.ext4 -F {root}")
        
        info("Mounting...")
        cmd(f"mount {root} /mnt")
        # CRITICAL FIX: Mount EFI to /mnt/boot/efi for standard GRUB path
        cmd("mkdir -p /mnt/boot/efi")
        cmd(f"mount {efi} /mnt/boot/efi")
        cmd(f"swapon {swap}")
        
    else:
        info("Creating MBR partition table (BIOS)...")
        # Switch to sfdisk for reliable MBR creation
        layout = f"""
label: dos
device: {disk_path}
unit: sectors

{disk_path}{sep}1 : size=512M, type=83, bootable
{disk_path}{sep}2 : size=8G, type=82
{disk_path}{sep}3 : type=83
"""
        subprocess.run(f"echo '{layout}' | sfdisk {disk_path}", shell=True, check=True)
        
        boot = f"{disk_path}{sep}1"
        swap = f"{disk_path}{sep}2"
        root = f"{disk_path}{sep}3"
        
        cmd(f"partprobe {disk_path}")
        time.sleep(2)
        
        info("Formatting...")
        cmd(f"mkfs.ext4 -F {boot}")
        cmd(f"mkswap {swap}")
        cmd(f"mkfs.ext4 -F {root}")
        
        info("Mounting...")
        cmd(f"mount {root} /mnt")
        cmd("mkdir -p /mnt/boot")
        cmd(f"mount {boot} /mnt/boot")
        cmd(f"swapon {swap}")

    success("Disk prepared successfully")

def install_base():
    """Install minimal base system"""
    header("Phase 1: Base System Installation")
    
    info("Ranking mirrors...")
    cmd("reflector --latest 20 --protocol https --sort rate --save /etc/pacman.d/mirrorlist", check=False)
    
    info("Installing base packages...")
    pkgs = "base linux linux-firmware base-devel git grub efibootmgr networkmanager sudo vim nano"
    cmd(f"pacstrap -K /mnt {pkgs}")
    
    info("Generating fstab...")
    cmd("genfstab -U /mnt >> /mnt/etc/fstab")
    success("Base system installed")

def create_install_script(username, password, root_password, desktop, gpu_drivers, is_uefi, disk_path, hostname, timezone, install_type='full'):
    """Generate the chroot installation script"""
    
    # 1. Define Packages
    system_pkgs = [
        "alacritty", "fastfetch", "htop", "ranger", "thunar", "gvfs", "zsh", 
        "zsh-completions", "zsh-syntax-highlighting", "fzf", "ripgrep", "bat", 
        "tmux", "ttf-jetbrains-mono-nerd", "noto-fonts-emoji", "p7zip", "unzip", 
        "ntfs-3g", "dosfstools", "wget", "curl", "openssh", "ufw", "fail2ban", 
        "python", "python-pip", "docker", "docker-compose"
    ]

    pentest_pkgs = [
        "nmap", "masscan", "netdiscover", "wireshark-qt", "tcpdump", "bettercap", 
        "ettercap", "nikto", "sqlmap", "gobuster", "ffuf", "burpsuite", "metasploit", 
        "hydra", "john", "hashcat", "aircrack-ng", "wifite", "kismet", "ghidra", 
        "radare2", "binwalk", "strace", "gdb", "volatility3", "autopsy", "veracrypt", 
        "tor", "torsocks", "proxychains-ng"
    ]
    
    if install_type == 'full':
        # Add extra tools for full install
        pentest_pkgs.extend([
            "responder", "mitmproxy", "empire", "bloodhound", "neo4j", "evil-winrm",
            "crackmapexec", "impacket", "apktool", "frida", "yara", "clamav"
        ])

    # 2. Construct Script
    # NOTE: We must use {{ }} for Bash curly braces and { } for Python f-string variables
    script = f"""#!/bin/bash
set -e

echo "Configuring Timezone..."
ln -sf /usr/share/zoneinfo/{timezone} /etc/localtime
hwclock --systohc
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen
echo "LANG=en_US.UTF-8" > /etc/locale.conf

echo "Configuring Hostname..."
echo "{hostname}" > /etc/hostname
echo "127.0.0.1 localhost" >> /etc/hosts
echo "127.0.1.1 {hostname}.localdomain {hostname}" >> /etc/hosts

echo "Setting Passwords..."
echo "root:{root_password}" | chpasswd
useradd -m -G wheel,docker -s /bin/zsh {username}
echo "{username}:{password}" | chpasswd
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

echo "Installing Packages..."
pacman -S --noconfirm --needed {' '.join(system_pkgs)}
pacman -S --noconfirm --needed {' '.join(gpu_drivers)}
pacman -S --noconfirm --needed {' '.join(desktop['packages'])} {desktop['portal']}
pacman -S --noconfirm --needed {' '.join(pentest_pkgs)}

echo "Configuring Bootloader..."
IS_UEFI="{is_uefi}"

if [ "$IS_UEFI" = "True" ]; then
    # UEFI: Mount point is /boot/efi
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=HorizonSec --recheck
else
    # BIOS: Install to MBR of the disk
    grub-install --target=i386-pc --recheck {disk_path}
fi

grub-mkconfig -o /boot/grub/grub.cfg

echo "Enabling Services..."
systemctl enable NetworkManager
systemctl enable ufw
systemctl enable docker
systemctl enable {desktop['dm']}

echo "Finalizing..."
# Set Alacritty as default terminal based on DE
if [ "{desktop['name']}" = "XFCE" ]; then
    mkdir -p /home/{username}/.config/xfce4
    echo "TerminalEmulator=alacritty" > /home/{username}/.config/xfce4/helpers.rc
fi

chown -R {username}:{username} /home/{username}
mkinitcpio -P
"""
    return script

def select_install_type():
    print(f"\n{Color.BOLD}1) Full Installation (All tools){Color.END}")
    print(f"{Color.BOLD}2) Lite Installation (Essentials){Color.END}")
    return 'lite' if input("Select [1/2]: ").strip() == '2' else 'full'

def select_desktop():
    desktops = {
        '1': {'name': 'KDE Plasma', 'packages': ['plasma-meta', 'sddm'], 'dm': 'sddm', 'portal': 'xdg-desktop-portal-kde'},
        '2': {'name': 'GNOME', 'packages': ['gnome', 'gdm'], 'dm': 'gdm', 'portal': 'xdg-desktop-portal-gnome'},
        '3': {'name': 'XFCE', 'packages': ['xfce4', 'lightdm', 'lightdm-gtk-greeter'], 'dm': 'lightdm', 'portal': 'xdg-desktop-portal-gtk'},
    }
    print(f"\n{Color.BOLD}Desktop Environments:{Color.END}")
    for k, v in desktops.items():
        print(f"  {k}) {v['name']}")
    
    choice = input("Select Desktop [1-3] (default 1): ").strip() or '1'
    return desktops.get(choice, desktops['1'])

def main():
    global VERBOSE
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    VERBOSE = args.verbose

    logo()
    check_root()
    setup_network()
    
    install_type = select_install_type()
    is_uefi = check_uefi()
    gpu_name, gpu_drivers = detect_gpu()
    disk_name, disk_path = select_disk()
    desktop = select_desktop()
    
    username = input(f"{Color.CYAN}Username: {Color.END}").strip() or "pentester"
    password = getpass.getpass(f"{Color.CYAN}User Password: {Color.END}")
    root_password = getpass.getpass(f"{Color.CYAN}Root Password: {Color.END}")
    
    print(f"\n{Color.GREEN}Ready to install to {disk_path}{Color.END}")
    if input("Type 'yes' to start: ").lower() != 'yes':
        sys.exit()

    # --- EXECUTION START ---
    
    # 1. Partition & Format
    partition_disk(disk_name, disk_path, is_uefi)
    
    # 2. Install Base System
    install_base()
    
    # 3. Generate & Write Chroot Script
    header("Phase 2: Configuration")
    script_content = create_install_script(
        username, password, root_password, desktop, gpu_drivers, 
        is_uefi, disk_path, "horizonsec", "UTC", install_type
    )
    
    with open("/mnt/install_script.sh", "w") as f:
        f.write(script_content)
    
    cmd("chmod +x /mnt/install_script.sh")
    
    # 4. Enter Chroot and Execute
    info("Entering chroot environment...")
    cmd("arch-chroot /mnt /install_script.sh")
    
    # 5. Cleanup
    cmd("rm /mnt/install_script.sh")
    cmd("umount -R /mnt")
    
    print(f"""
{Color.GREEN}
╔═══════════════════════════════════════════╗
║       INSTALLATION COMPLETE!              ║
║                                           ║
║  You can now reboot into HorizonSec OS    ║
╚═══════════════════════════════════════════╝
{Color.END}""")

if __name__ == "__main__":
    main()
