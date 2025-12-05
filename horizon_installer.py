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
import re

VERBOSE = False
INSTALL_TYPE = 'full'
TOTAL_PACKAGE_COUNT = 0
INSTALLED_PACKAGE_COUNT = 0
INSTALLATION_START_TIME = None
UPDATE_APPLIED = False

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
    CLEAR_LINE = '\033[2K\r'

def draw_box(title="", content=""):
    """Draw a styled box like Debian installer"""
    width = 70
    lines = content.split('\n') if content else []
    
    print(f"{Color.ORANGE}┌{'─' * (width - 2)}┐{Color.END}")
    
    if title:
        title_str = f" {title} "
        padding = (width - 2 - len(title_str)) // 2
        print(f"{Color.ORANGE}│{Color.END} {Color.BOLD}{title_str:^{width-4}}{Color.END} {Color.ORANGE}│{Color.END}")
        print(f"{Color.ORANGE}├{'─' * (width - 2)}┤{Color.END}")
    
    for line in lines:
        if len(line) > width - 4:
            line = line[:width-7] + "..."
        print(f"{Color.ORANGE}│{Color.END} {line:<{width-4}} {Color.ORANGE}│{Color.END}")
    
    print(f"{Color.ORANGE}└{'─' * (width - 2)}┘{Color.END}")

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
    """Print info message"""
    print(f"{Color.CYAN}[→]{Color.END} {text}")

def success(text):
    """Print success message"""
    print(f"{Color.GREEN}[✓]{Color.END} {text}")

def warning(text):
    """Print warning message"""
    print(f"{Color.YELLOW}[!]{Color.END} {text}")

def error(text):
    """Print error message"""
    print(f"{Color.RED}[✗]{Color.END} {text}")

def logo():
    """Display HorizonSec ASCII logo"""
    print(f"""{Color.ORANGE}
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   HORIZON▓ SEC                                           ║
  ║   Professional Penetration Testing Distribution         ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝

            v1.0 - Advanced Security Testing Platform
{Color.END}""")

def check_root():
    """Verify script is running as root"""
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
    global UPDATE_APPLIED
    
    header("Network Configuration")
    
    cmd("systemctl start NetworkManager", check=False)
    time.sleep(2)
    
    info("Network configuration manager (nmtui) will open in 4 seconds...")
    info("If using Ethernet, you can exit nmtui and continue (Ctrl+X).")
    time.sleep(4)
    info("Opening nmtui now...")
    subprocess.run("nmtui", check=False)
    
    time.sleep(2)
    if cmd("ping -c 2 archlinux.org", check=False):
        success("Network is active")
        UPDATE_APPLIED = check_for_updates()
    else:
        warning("Network may not be connected. Skipping update check...")
        UPDATE_APPLIED = False
    
    info("Initializing package keys...")
    cmd("pacman-key --init", check=False)
    cmd("pacman-key --populate archlinux", check=False)
    cmd("pacman -Sy --noconfirm", check=False)

def check_for_updates():
    """Check if installer has updates and auto-update if needed"""
    import hashlib

    header("Update Check")

    repo_dir = "/usr/local/share/horizonsec"

    try:
        info("Checking for HorizonSec installer updates...")

        # Ensure git is available
        if not cmd("which git", check=False, silent=True):
            warning("Git not installed, skipping update check")
            return False

        if os.path.exists(repo_dir):
            # Pull existing repo
            result = subprocess.run(
                f"cd {repo_dir} && git pull --depth 1",
                shell=True,
                capture_output=True,
                timeout=15
            )
        else:
            # Clone new repo
            os.makedirs(repo_dir, exist_ok=True)
            result = subprocess.run(
                f"git clone --depth 1 https://github.com/HorizonSecOS/horizon-install.git {repo_dir}",
                shell=True,
                capture_output=True,
                timeout=15
            )

        if result.returncode != 0:
            warning("Could not check for updates (network or repository issue)")
            return False

        remote_script = f"{repo_dir}/horizon_installer.py"
        if not os.path.exists(remote_script):
            warning("Could not find remote installer script")
            return False

        # Compare hashes
        with open(remote_script, 'rb') as f:
            remote_hash = hashlib.md5(f.read()).hexdigest()

        with open(__file__, 'rb') as f:
            local_hash = hashlib.md5(f.read()).hexdigest()

        if remote_hash != local_hash:
            info("HorizonSec installer update available")
            print(f"{Color.YELLOW}Updating to latest version...{Color.END}")
            
            # Install updated script
            subprocess.run(
                f"cp {remote_script} /usr/local/bin/horizon-install && chmod 755 /usr/local/bin/horizon-install",
                shell=True,
                check=False
            )
            
            # Also update the running script location if it exists
            if os.path.exists("/usr/bin/horizon-install"):
                subprocess.run(
                    f"cp {remote_script} /usr/bin/horizon-install && chmod 755 /usr/bin/horizon-install",
                    shell=True,
                    check=False
                )
            
            success("Installer updated successfully!")
            print(f"\n{Color.ORANGE}Restarting installer with new version...{Color.END}\n")
            time.sleep(2)
            
            # Re-execute the installer with the updated version
            os.execv("/usr/local/bin/horizon-install", sys.argv)
            
        else:
            success("Installer is up to date")
            return False

    except subprocess.TimeoutExpired:
        warning("Update check timed out")
        return False
    except Exception as e:
        warning(f"Update check failed: {str(e)}")
        return False

def detect_gpu():
    """Auto-detect GPU and return appropriate drivers"""
    header("GPU Detection")
    
    gpu_output = cmd("lspci 2>/dev/null | grep -iE 'vga|3d|display'", capture=True, check=False)

    if not gpu_output or not isinstance(gpu_output, str):
        gpu_output = ""

    gpu_lines = gpu_output.split('\n') if gpu_output else []
    
    gpu = '\n'.join(gpu_lines) if gpu_lines else ""
    
    if gpu:
        info(f"Detected:\n{gpu}")
    else:
        warning("Could not detect dedicated GPU, checking for integrated GPU...")
    
    gpu_lower = gpu.lower()
    
    if 'nvidia' in gpu_lower:
        success("NVIDIA GPU detected → Installing proprietary drivers")
        return "NVIDIA", ["nvidia", "nvidia-utils", "nvidia-settings", "opencl-nvidia", "lib32-nvidia-utils"]
    elif 'amd' in gpu_lower or 'ati' in gpu_lower:
        success("AMD GPU detected → Installing Mesa drivers")
        return "AMD", ["mesa", "lib32-mesa", "xf86-video-amdgpu", "vulkan-radeon", "lib32-vulkan-radeon", "libva-mesa-driver", "mesa-vdpau"]
    elif 'intel' in gpu_lower or 'iris' in gpu_lower or 'uhd' in gpu_lower or 'arc' in gpu_lower:
        success("Intel GPU detected → Installing Intel media drivers")
        return "Intel", ["mesa", "lib32-mesa", "intel-media-driver", "vulkan-intel", "lib32-vulkan-intel", "libva-intel-driver", "intel-gmmlib"]
    else:
        warning("GPU not detected or unknown → Installing generic Mesa drivers")
        return "Generic", ["mesa", "lib32-mesa", "xf86-video-vesa"]

def list_disks():
    """List available disks"""
    try:
        output = cmd('lsblk -J -d -o NAME,SIZE,MODEL,TYPE', capture=True, check=False)
        if not isinstance(output, str):
            error("Failed to enumerate disks")
            sys.exit(1)
        data = json.loads(output)
        return [d for d in data.get('blockdevices', [])
                if d['type'] == 'disk' and not d['name'].startswith('loop')]
    except:
        error("Failed to enumerate disks")
        sys.exit(1)

def select_disk():
    """Interactive disk selection"""
    header("Disk Selection")
    
    disks = list_disks()
    if not disks:
        error("No suitable disks found!")
        sys.exit(1)
    
    print(f"{Color.BOLD}Available Disks:{Color.END}")
    for i, disk in enumerate(disks, 1):
        model = disk.get('model', 'Unknown Model')
        print(f"  {Color.ORANGE}{i}){Color.END} /dev/{disk['name']} - {disk['size']} - {model}")
    
    while True:
        try:
            choice = int(input(f"\n{Color.CYAN}Select disk [1-{len(disks)}]: {Color.END}")) - 1
            if 0 <= choice < len(disks):
                disk = disks[choice]
                path = f"/dev/{disk['name']}"
                
                print(f"\n{Color.RED}{Color.BOLD}WARNING: ALL DATA ON {path} WILL BE ERASED!{Color.END}")
                confirm = input(f"{Color.RED}Type 'yes' to continue or 'no' to cancel: {Color.END}").strip().lower()
                
                if confirm in ['yes', 'y']:
                    return disk['name'], path
                else:
                    error("Installation cancelled")
                    sys.exit(0)
        except (ValueError, IndexError):
            error("Invalid selection")

def partition_disk(disk_name, disk_path, is_uefi):
    """Partition and format disk"""
    header("Disk Partitioning")
    
    info("Unmounting any existing partitions...")
    cmd("umount -R /mnt", check=False)
    cmd("swapoff -a", check=False)
    
    # Unmount all partitions on the target disk
    disk_base = disk_name.split('/')[-1]
    part_list = cmd(f"lsblk -ln -o NAME {disk_path} | grep -E '^{disk_base}[0-9]+'", capture=True, check=False)
    if part_list and isinstance(part_list, str):
        for part in part_list.split():
            cmd(f"umount /dev/{part}", check=False)
    
    info("Wiping disk completely...")
    cmd(f"sgdisk --zap-all {disk_path}", check=False)
    cmd(f"wipefs -af {disk_path}", check=False)
    cmd(f"dd if=/dev/zero of={disk_path} bs=1M count=1", check=False)
    cmd("sync")
    
    # Force kernel to re-read partition table
    cmd(f"partprobe {disk_path}", check=False)
    time.sleep(2)
    
    # Determine partition naming scheme
    sep = 'p' if 'nvme' in disk_name or 'mmcblk' in disk_name else ''
    
    if is_uefi:
        info("Creating GPT partition table (UEFI)...")
        cmd(f"sgdisk -og {disk_path}")
        cmd(f"sgdisk -n 1:0:+512M -t 1:ef00 -c 1:EFI {disk_path}")
        cmd(f"sgdisk -n 2:0:+8G -t 2:8200 -c 2:SWAP {disk_path}")
        cmd(f"sgdisk -n 3:0:0 -t 3:8300 -c 3:ROOT {disk_path}")
        
        cmd(f"partprobe {disk_path}", check=False)
        time.sleep(3)
        
        efi = f"{disk_path}{sep}1"
        swap = f"{disk_path}{sep}2"
        root = f"{disk_path}{sep}3"
        
        info("Formatting partitions...")
        cmd(f"mkfs.fat -F32 {efi}")
        cmd(f"mkswap {swap}")
        cmd(f"mkfs.ext4 -F {root}")
        
        info("Mounting filesystems...")
        cmd(f"mount {root} /mnt")
        cmd("mkdir -p /mnt/boot")
        cmd(f"mount {efi} /mnt/boot")
        cmd(f"swapon {swap}")
    else:
        info("Creating MBR partition table (BIOS)...")
        cmd(f"sgdisk -og {disk_path}")
        cmd(f"sgdisk -n 1:0:+512M -t 1:8300 -c 1:BOOT {disk_path}")
        cmd(f"sgdisk -n 2:0:+8G -t 2:8200 -c 2:SWAP {disk_path}")
        cmd(f"sgdisk -n 3:0:0 -t 3:8300 -c 3:ROOT {disk_path}")
        
        cmd(f"partprobe {disk_path}", check=False)
        time.sleep(3)

        boot = f"{disk_path}{sep}1"
        swap = f"{disk_path}{sep}2"
        root = f"{disk_path}{sep}3"
        efi = boot

        info("Formatting partitions...")
        cmd(f"mkfs.ext4 -F {boot}")
        cmd(f"mkswap {swap}")
        cmd(f"mkfs.ext4 -F {root}")

        info("Mounting filesystems...")
        cmd(f"mount {root} /mnt")
        cmd("mkdir -p /mnt/boot")
        cmd(f"mount {boot} /mnt/boot")
        cmd(f"swapon {swap}")
    
    time.sleep(2)
    success("Disk prepared successfully")
    return efi, swap, root

def install_base(mirror_selection='auto'):
    """Install minimal base system"""
    header("Phase 1: Base System Installation")
    
    info("Configuring package mirrors...")
    if mirror_selection == 'auto':
        info("Auto-detecting fastest mirrors...")
        cmd("reflector --country US --latest 20 --protocol https --sort rate --save /etc/pacman.d/mirrorlist", check=False)
    elif mirror_selection == 'default':
        info("Using default Arch Linux mirrors")
        cmd("reflector --latest 50 --sort rate --save /etc/pacman.d/mirrorlist", check=False)
    
    info("Installing base system (this takes 5-10 minutes)...")
    
    base_packages = [
        "base", "linux", "linux-firmware", "linux-headers",
        "base-devel", "git", "grub", "efibootmgr", "dosfstools",
        "mtools", "os-prober",
        "networkmanager", "sudo", "nano", "vim",
        "bash-completion", "man-db", "man-pages"
    ]
    
    cmd(f"pacstrap -K /mnt {' '.join(base_packages)}")
    
    info("Generating fstab...")
    cmd("genfstab -U /mnt >> /mnt/etc/fstab")
    
    success("Base system installed")

def select_desktop(desktops, recommended='1', lite_mode=False):
    """Interactive desktop environment selection"""
    if lite_mode:
        print(f"\n{Color.BOLD}Desktop Environments (Lite Mode):{Color.END}\n")
    else:
        print(f"\n{Color.BOLD}Desktop Environments:{Color.END}\n")
    
    for key, de in desktops.items():
        tag = f" {Color.GREEN}← Recommended{Color.END}" if key == recommended else ""
        print(f"  {Color.ORANGE}{key}){Color.END} {de['name']}{tag}")
    print()
    
    max_choice = len(desktops)
    while True:
        choice = input(f"{Color.CYAN}Select desktop [1-{max_choice}] or press Enter for recommended: {Color.END}").strip() or recommended
        if choice in desktops:
            de = desktops[choice]
            success(f"Selected: {de['name']}")
            return de
        error("Invalid choice")

def create_install_script(username, password, root_password, desktop, gpu_drivers, ghost_mode, is_uefi, disk_path, hostname, timezone, ssh_config, firewall_config, install_type='full', gpu_name='Generic'):
    """Generate chroot installation script"""
    
    # Define system packages based on installation type
    if install_type == 'lite':
        system_pkgs = [
            "alacritty", "fastfetch", "htop",
            "ranger", "thunar", "gvfs",
            "zsh", "zsh-completions", "zsh-syntax-highlighting",
            "fzf", "ripgrep", "fd", "bat", "tmux",
            "ttf-jetbrains-mono-nerd", "noto-fonts", "noto-fonts-emoji",
            "p7zip", "unzip", "zip",
            "ntfs-3g", "dosfstools",
            "wget", "curl", "openssh",
            "ufw", "fail2ban",
            "code", "vim", "firefox",
            "docker", "docker-buildx",
            "git", "gcc", "make", "pkg-config",
            "python", "python-pip"
        ]
    else:
        system_pkgs = [
            "alacritty",
            "fastfetch", "htop",
            "ranger", "thunar", "gvfs", "gvfs-mtp",
            "zsh", "zsh-completions", "zsh-syntax-highlighting",
            "fzf", "ripgrep", "fd", "bat", "tmux",
            "ttf-jetbrains-mono-nerd", "ttf-firacode-nerd", "ttf-hack-nerd",
            "ttf-meslo-nerd", "ttf-sourcecodepro-nerd",
            "noto-fonts", "noto-fonts-emoji", "noto-fonts-cjk",
            "p7zip", "unzip", "unrar", "zip", "tar", "gzip",
            "ntfs-3g", "dosfstools", "exfat-utils", "e2fsprogs",
            "wget", "curl", "rsync", "openssh",
            "ufw", "fail2ban",
            "code", "vim", "neovim",
            "docker", "docker-compose", "qemu-full", "virt-manager",
            "git", "gcc", "make", "cmake", "pkg-config",
            "perl", "ruby", "python", "python-pip",
            "gdb", "lldb", "valgrind",
            "flatpak", "libadwaita-without-adwaita"
        ]
    else:
        system_pkgs = [
            "alacritty", "fastfetch", "htop",
            "ranger", "thunar", "gvfs", "gvfs-mtp",
            "zsh", "zsh-completions", "zsh-syntax-highlighting",
            "fzf", "ripgrep", "fd", "bat", "tmux",
            "ttf-jetbrains-mono-nerd", "noto-fonts", "noto-fonts-emoji",
            "p7zip", "unzip", "zip",
            "ntfs-3g", "dosfstools",
            "wget", "curl", "openssh",
            "ufw", "fail2ban",
            "code", "vim", "firefox",
            "docker", "docker-buildx", "docker-compose",
            "git", "gcc", "make", "pkg-config",
            "python", "python-pip"
        ]
    
    # Penetration testing packages
    if install_type == 'lite':
        pentest_pkgs = [
            # Network Scanning & Enumeration (25)
            "nmap", "masscan", "netdiscover", "arp-scan", "arping",
            "dnsenum", "fierce", "dmitry", "enum4linux", "nbtscan",
            "theharvester", "traceroute", "whois", "ncat", "hping",
            "unicornscan", "netmask", "mtr", "p0f", "netcat",
            "iperf3", "nethogs", "nload", "iftop", "vnstat",
            
            # Web Application Testing (20)
            "nikto", "sqlmap", "wpscan", "dirb", "gobuster",
            "ffuf", "whatweb", "wafw00f", "burpsuite", "zaproxy",
            "commix", "wfuzz", "skipfish", "sqlitebrowser", "testssl.sh",
            "sslscan", "httpie", "curl", "wget", "arjun",
            
            # Wireless Security (15)
            "aircrack-ng", "reaver", "bully", "pixiewps", "wifite",
            "kismet", "mdk4", "mdk3", "hostapd", "dnsmasq",
            "cowpatty", "rfkill", "macchanger", "airodump-ng", "aireplay-ng",
            
            # Password Cracking (15)
            "john", "hashcat", "hydra", "medusa", "ncrack",
            "ophcrack", "hashid", "crunch", "cewl", "cupp",
            "hash-identifier", "findmyhash", "hashdeep", "pdfcrack", "crowbar",
            
            # Exploitation & Frameworks (12)
            "metasploit", "exploitdb", "searchsploit", "crackmapexec",
            "impacket", "routersploit", "shellnoob", "veil", "beef",
            "armitage", "msfvenom", "msfconsole",
            
            # Network Analysis & MITM (18)
            "wireshark-qt", "wireshark-cli", "tcpdump", "ettercap", "bettercap",
            "mitmproxy", "dsniff", "responder", "arpspoof", "tshark",
            "ngrep", "scapy", "sslstrip", "dnschef", "yersinia",
            "ratproxy", "mitm6", "ntlmrelayx",
            
            # Reverse Engineering & Binary Analysis (15)
            "ghidra", "radare2", "binwalk", "strings", "hexedit",
            "objdump", "readelf", "nm", "strace", "ltrace",
            "hexdump", "xxd", "binutils", "gdb", "pwndbg",
            
            # Forensics & Data Recovery (12)
            "sleuthkit", "foremost", "autopsy", "volatility", "steghide",
            "exiftool", "dc3dd", "ddrescue", "testdisk", "extundelete",
            "scalpel", "bulk-extractor",
            
            # Security Auditing & Hardening (12)
            "lynis", "openvas", "rkhunter", "chkrootkit", "aide",
            "apparmor", "logwatch", "tiger", "checksec", "audit",
            "osquery", "tripwire",
            
            # Encryption & Privacy (10)
            "veracrypt", "gnupg", "openssl", "tomb", "cryptsetup",
            "openvpn", "wireguard-tools", "tor", "torsocks", "proxychains-ng",
            
            # Vulnerability Scanning (8)
            "openvas", "nikto", "wapiti", "skipfish", "nuclei",
            "nessus", "nexpose", "qualysguard",
            
            # Sniffing & Spoofing (8)
            "wireshark-qt", "tcpdump", "dsniff", "ettercap", "bettercap",
            "arpspoof", "macchanger", "responder"
        ]
    else:
        pentest_pkgs = [
            # Network Scanning & Enumeration (30)
            "nmap", "masscan", "netdiscover", "arp-scan", "arping",
            "dnsenum", "fierce", "dmitry", "enum4linux", "nbtscan",
            "theharvester", "ike-scan", "unicornscan", "hping",
            "traceroute", "whois", "ncat", "netmask", "mtr",
            "p0f", "netcat", "netperf", "iperf3", "nethogs",
            "nload", "iftop", "vnstat", "ss", "lsof", "fuser",
            
            # Web Application Testing (25)
            "nikto", "sqlmap", "wpscan", "dirb", "gobuster",
            "ffuf", "whatweb", "wafw00f", "burpsuite", "zaproxy",
            "commix", "wfuzz", "skipfish", "sqlitebrowser", "nuclei",
            "testssl.sh", "sslscan", "jwt-cli", "httpie", "curl",
            "wget", "arjun", "katana", "httpx", "waymore",
            
            # Wireless Security (15)
            "aircrack-ng", "reaver", "bully", "pixiewps", "wifite",
            "kismet", "mdk4", "mdk3", "hostapd", "dnsmasq",
            "cowpatty", "airmon-ng", "wifipumpkin3", "rfkill", "rtl-sdr",
            
            # Password Cracking (15)
            "john", "hashcat", "hydra", "medusa", "ncrack",
            "ophcrack", "hashid", "crunch", "cewl", "cupp",
            "hash-identifier", "findmyhash", "hashdeep", "pdfcrack", "crowbar",
            
            # Exploitation & Frameworks (10)
            "metasploit", "exploitdb", "searchsploit", "crackmapexec",
            "impacket", "routersploit", "setoolkit", "powersploit",
            "empire", "covenant",
            
            # Network Analysis (20)
            "wireshark-qt", "tcpdump", "ettercap", "bettercap",
            "mitmproxy", "dsniff", "responder", "arpspoof", "tshark",
            "ngrep", "scapy", "hping", "fragroute", "macchanger",
            "ratproxy", "sslstrip", "dnschef", "yersinia", "lbd", "wafw00f",
            
            # Reverse Engineering & Forensics (25)
            "ghidra", "radare2", "binwalk", "strings", "hexedit",
            "sleuthkit", "foremost", "autopsy", "volatility", "volatility3",
            "steghide", "exiftool", "dc3dd", "ddrescue", "testdisk",
            "extundelete", "scalpel", "exifprobe", "hexinject", "objdump",
            "readelf", "nm", "strace", "ltrace", "bokken",
            
            # System Analysis & Debugging (15)
            "gdb", "lldb", "valgrind", "perf", "bpftrace",
            "sysstat", "iotop", "hardinfo", "inxi", "procps-ng",
            "psmisc", "audit", "osquery", "cppcheck", "clang-tools-extra",
            
            # Security Auditing (20)
            "lynis", "openvas", "rkhunter", "chkrootkit", "aide",
            "apparmor", "logwatch", "fail2ban", "ufw", "iptables",
            "nftables", "clamav", "clamav-daemon", "yara", "python-yara",
            "ssh-audit", "checksec", "tiger", "nikto", "openscap",
            
            # Encryption & Privacy (15)
            "veracrypt", "gnupg", "openssl", "tomb", "cryptsetup",
            "openvpn", "wireguard-tools", "openfortivpn", "strongswan",
            "xl2tpd", "tor", "torsocks", "proxychains-ng", "privoxy", "i2pd",
            
            # Mobile & IoT (10)
            "apktool", "apksigner", "jadx", "frida", "objection",
            "androguard", "dex2jar", "smali", "adb", "fastboot",
            
            # Cloud & Container Security (10)
            "docker", "docker-compose", "kubectl", "helm", "trivy",
            "prowler", "scout", "cloudsploit", "pacu", "weirdaaa",
            
            # Social Engineering (5)
            "setoolkit", "gophish", "evilginx2", "modlishka", "beef",
            
            # Utilities & Misc (30)
            "macchanger", "proxychains-ng", "bleachbit", "socat",
            "netcat", "iperf3", "jq", "exiftool", "upx",
            "redsocks", "udptunnel", "iodine", "dns2tcp", "ptunnel",
            "stunnel", "udp2raw", "chisel", "ligolo", "pwncat",
            "evil-winrm", "bloodhound", "neo4j", "pypykatz", "sprayhound",
            "kerbrute", "rubeus", "mimikatz", "lazagne", "keepass2john"
        ]
    
    # SSH key generation commands
    ssh_gen_keys = ""
    if ssh_config.get('enabled') and ssh_config.get('generate_keys'):
        ssh_gen_keys = f"mkdir -p /home/{username}/.ssh && chmod 700 /home/{username}/.ssh\nsudo -u {username} ssh-keygen -t ed25519 -f /home/{username}/.ssh/id_ed25519 -N '' -q 2>/dev/null || true"
    
    # Build the install script
    system_pkgs_str = ' '.join(system_pkgs)
    gpu_drivers_str = ' '.join(gpu_drivers)
    desktop_packages_str = ' '.join(desktop['packages'])
    desktop_portal_str = desktop['portal']
    desktop_dm_str = desktop['dm']
    desktop_name_str = desktop['name']
    
    pentest_batch1 = ' '.join(pentest_pkgs[:50]) if len(pentest_pkgs) > 0 else ""
    pentest_batch2 = ' '.join(pentest_pkgs[50:100]) if len(pentest_pkgs) > 50 else ""
    pentest_batch3 = ' '.join(pentest_pkgs[100:]) if len(pentest_pkgs) > 100 else ""
    
    tor_install = "pacman -S --noconfirm --needed tor torsocks > /dev/null 2>&1 || true" if ghost_mode else ""
    ssh_enable = "systemctl enable sshd > /dev/null 2>&1" if ssh_config.get('enabled') else ""
    firewall_ssh = "ufw allow 22/tcp > /dev/null 2>&1" if firewall_config.get('ssh', True) else ""
    
    script = f"""#!/bin/bash
set -e

printf "\\033[38;5;208m╔══════════════════════════════════════════════════════════════════╗\\033[0m\\n"
printf "\\033[38;5;208m║ \\033[1m%-66s \\033[38;5;208m║\\033[0m\\n" "HORIZONSEC SYSTEM CONFIGURATION"
printf "\\033[38;5;208m╚══════════════════════════════════════════════════════════════════╝\\033[0m\\n"

# Timezone & Locale
printf "\\033[96m[1/10]\\033[0m Setting timezone and locale...\\n"
ln -sf /usr/share/zoneinfo/{timezone} /etc/localtime
hwclock --systohc
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen
echo "LANG=en_US.UTF-8" > /etc/locale.conf

# Hostname
echo "{hostname}" > /etc/hostname
cat > /etc/hosts <<'HOSTEOF'
127.0.0.1   localhost
::1         localhost
127.0.1.1   {hostname}.localdomain {hostname}
HOSTEOF

# Root password
echo "root:{root_password}" | chpasswd

# Enable multilib
sed -i '/\\[multilib\\]/,/Include/s/^#//' /etc/pacman.conf
pacman -Sy --noconfirm > /dev/null 2>&1

printf "\\033[96m[2/10]\\033[0m Installing system packages...\\n"
pacman -S --noconfirm --needed {system_pkgs_str} > /dev/null 2>&1 || true

printf "\\033[96m[3/10]\\033[0m Installing GPU drivers ({gpu_name})...\\n"
pacman -S --noconfirm --needed {gpu_drivers_str} > /dev/null 2>&1 || true

printf "\\033[96m[4/10]\\033[0m Installing desktop environment ({desktop_name_str})...\\n"
pacman -S --noconfirm --needed {desktop_packages_str} {desktop_portal_str} > /dev/null 2>&1 || true

printf "\\033[96m[5/10]\\033[0m Installing penetration testing tools...\\n"
pacman -S --noconfirm --needed {pentest_batch1} > /dev/null 2>&1 || true
"""
    
    if pentest_batch2:
        script += f"pacman -S --noconfirm --needed {pentest_batch2} > /dev/null 2>&1 || true\n"
    
    if pentest_batch3:
        script += f"pacman -S --noconfirm --needed {pentest_batch3} > /dev/null 2>&1 || true\n"
    
    script += f"""
{tor_install}

printf "\\033[96m[6/10]\\033[0m Creating user account and groups...\\n"

# Ensure docker group exists
groupadd -f docker

if id "{username}" &>/dev/null; then
    echo "User {username} already exists"
    usermod -aG wheel,docker {username}
else
    useradd -m -G wheel,docker -s /bin/zsh {username}
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create user {username}"
        exit 1
    fi
fi

echo "{username}:{password}" | chpasswd
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

printf "\\033[96m[7/10]\\033[0m Configuring bootloader...\\n"

# Get root partition UUID
ROOT_PART=$(df / | tail -1 | awk '{{print $1}}')
ROOT_UUID=$(blkid -s UUID -o value $ROOT_PART)

# Get the base disk device
BOOT_DISK="{disk_path}"

IS_UEFI="{is_uefi}"

if [ "$IS_UEFI" = "True" ]; then
    # UEFI boot with GRUB
    printf "Installing GRUB for UEFI...\\n"
    
    # Ensure EFI vars are mounted
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null || true
    
    # Install GRUB to EFI partition
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=HorizonSec --recheck --no-nvram 2>/dev/null || \\
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=HorizonSec --recheck
    
    if [ $? -eq 0 ]; then
        echo "GRUB UEFI installation successful"
    else
        echo "ERROR: GRUB UEFI installation failed"
        # Try fallback installation
        grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=HorizonSec --removable --recheck
    fi
    
else
    # BIOS boot with GRUB
    printf "Installing GRUB for BIOS...\\n"
    
    # Install GRUB to MBR
    grub-install --target=i386-pc --recheck $BOOT_DISK
    
    if [ $? -ne 0 ]; then
        echo "WARNING: Initial GRUB installation failed, trying with --force..."
        grub-install --target=i386-pc --force --recheck $BOOT_DISK
    fi
fi

# Generate GRUB configuration
grub-mkconfig -o /boot/grub/grub.cfg

# Verify GRUB config was created
if [ ! -f /boot/grub/grub.cfg ]; then
    echo "ERROR: GRUB configuration not generated!"
    exit 1
fi

echo "Bootloader installation complete"

printf "\\033[96m[8/10]\\033[0m Configuring services...\\n"
systemctl enable NetworkManager > /dev/null 2>&1
systemctl enable bluetooth > /dev/null 2>&1 || true
systemctl enable ufw > /dev/null 2>&1
systemctl enable fail2ban > /dev/null 2>&1
systemctl enable tor > /dev/null 2>&1 || true
systemctl enable docker > /dev/null 2>&1
systemctl enable {desktop_dm_str} > /dev/null 2>&1
{ssh_enable}

# Firewall configuration
ufw --force enable > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
{firewall_ssh}

# SSH configuration (if enabled)
{ssh_gen_keys}

printf "\\033[96m[9/10]\\033[0m Finalizing installation...\\n"

# Ensure proper ownership
chown -R {username}:{username} /home/{username}

# Enable lightdm greeter autologin config (optional)
if [ "{desktop_dm_str}" = "lightdm" ]; then
    mkdir -p /etc/lightdm
    cat > /etc/lightdm/lightdm.conf <<'LIGHTDMEOF'
[Seat:*]
greeter-session=lightdm-gtk-greeter
LIGHTDMEOF
fi

# Configure Alacritty as default terminal for all DEs
mkdir -p /home/{username}/.config

# Set Alacritty as default terminal for GNOME
if [ "{desktop_name_str}" = "GNOME" ]; then
    sudo -u {username} dbus-launch gsettings set org.gnome.desktop.default-applications.terminal exec 'alacritty' 2>/dev/null || true
    sudo -u {username} dbus-launch gsettings set org.gnome.desktop.default-applications.terminal exec-arg '' 2>/dev/null || true
fi

# Set Alacritty as default terminal for XFCE
if [ "{desktop_name_str}" = "XFCE" ]; then
    mkdir -p /home/{username}/.config/xfce4
    cat > /home/{username}/.config/xfce4/helpers.rc <<'XFCETERM'
TerminalEmulator=alacritty
XFCETERM
    chown -R {username}:{username} /home/{username}/.config/xfce4
fi

# Set Alacritty as default terminal for Cinnamon
if [ "{desktop_name_str}" = "Cinnamon" ]; then
    sudo -u {username} gsettings set org.cinnamon.desktop.default-applications.terminal exec 'alacritty' 2>/dev/null || true
fi

# Set Alacritty as default terminal for MATE
if [ "{desktop_name_str}" = "MATE" ]; then
    sudo -u {username} gsettings set org.mate.applications-terminal exec 'alacritty' 2>/dev/null || true
fi

# Set Alacritty as default terminal for LXQt
if [ "{desktop_name_str}" = "LXQt" ]; then
    mkdir -p /home/{username}/.config/lxqt
    cat > /home/{username}/.config/lxqt/lxqt.conf <<'LXQTTERM'
[General]
terminal=alacritty
LXQTTERM
    chown -R {username}:{username} /home/{username}/.config/lxqt
fi

# Set Alacritty as default terminal for KDE Plasma
if [ "{desktop_name_str}" = "KDE Plasma" ]; then
    mkdir -p /home/{username}/.config
    cat > /home/{username}/.config/kdeglobals <<'KDETERM'
[General]
TerminalApplication=alacritty
KDETERM
    chown -R {username}:{username} /home/{username}/.config/kdeglobals
fi

# Rebuild initramfs to ensure all modules are included
mkinitcpio -P > /dev/null 2>&1 || true

printf "\\033[96m[10/10]\\033[0m Installation complete!\\n"

printf "\\033[38;5;208m╔══════════════════════════════════════════════════════════════════╗\\033[0m\\n"
printf "\\033[38;5;208m║ \\033[92m✓ INSTALLATION COMPLETE%-43s \\033[38;5;208m║\\033[0m\\n" ""
printf "\\033[38;5;208m╚══════════════════════════════════════════════════════════════════╝\\033[0m\\n"
printf "\\n"
printf "\\033[92mWelcome to HorizonSec!\\033[0m\\n"
printf "\\n"
printf "Your system has been configured with:\\n"
printf "  \\033[38;5;208m•\\033[0m Desktop: {desktop_name_str}\\n"
printf "  \\033[38;5;208m•\\033[0m Terminal: Alacritty\\n"
printf "  \\033[38;5;208m•\\033[0m Penetration Testing Tools\\n"
printf "  \\033[38;5;208m•\\033[0m Docker with user permissions\\n"
printf "  \\033[38;5;208m•\\033[0m Firewall enabled (UFW)\\n"
printf "  \\033[38;5;208m•\\033[0m Ghost Mode (Tor) enabled\\n"
printf "\\n"
printf "\\033[96mManagement Commands:\\033[0m\\n"
printf "  \\033[38;5;208mhorizon-firewall\\033[0m    - Manage firewall and security\\n"
printf "  \\033[38;5;208mhorizon-update\\033[0m      - Check for system updates\\n"
printf "\\n"
printf "\\033[96mNext steps:\\033[0m\\n"
printf "  1. Remove installation media\\n"
printf "  2. Type: \\033[38;5;208mreboot\\033[0m\\n"
printf "  3. Login as: \\033[38;5;208m{username}\\033[0m\\n"
printf "  4. Start pentesting!\\n"
printf "\\n"
"""

    return script

def create_install_script(username, password, root_password, desktop, gpu_drivers, ghost_mode, is_uefi, disk_path, hostname, timezone, ssh_config, firewall_config, install_type='full', gpu_name='Generic'):
    """Generate the chroot installation script"""
    
    if install_type == 'lite':
        pentest_pkgs = [
            # Network Scanning & Enumeration (25)
            "nmap", "masscan", "netdiscover", "arp-scan", "arping",
            "dnsenum", "fierce", "dmitry", "enum4linux", "nbtscan",
            "theharvester", "traceroute", "whois", "ncat", "hping",
            "unicornscan", "netmask", "mtr", "p0f", "netcat",
            "iperf3", "nethogs", "nload", "iftop", "vnstat",
            
            # Web Application Testing (20)
            "nikto", "sqlmap", "wpscan", "dirb", "gobuster",
            "ffuf", "whatweb", "wafw00f", "burpsuite", "zaproxy",
            "commix", "wfuzz", "skipfish", "sqlitebrowser", "testssl.sh",
            "sslscan", "httpie", "curl", "wget", "arjun",
            
            # Wireless Security (15)
            "aircrack-ng", "reaver", "bully", "pixiewps", "wifite",
            "kismet", "mdk4", "mdk3", "hostapd", "dnsmasq",
            "cowpatty", "rfkill", "macchanger", "airodump-ng", "aireplay-ng",
            
            # Password Cracking (15)
            "john", "hashcat", "hydra", "medusa", "ncrack",
            "ophcrack", "hashid", "crunch", "cewl", "cupp",
            "hash-identifier", "findmyhash", "hashdeep", "pdfcrack", "crowbar",
            
            # Exploitation & Frameworks (12)
            "metasploit", "exploitdb", "searchsploit", "crackmapexec",
            "impacket", "routersploit", "shellnoob", "veil", "beef",
            "armitage", "msfvenom", "msfconsole",
            
            # Network Analysis & MITM (18)
            "wireshark-qt", "wireshark-cli", "tcpdump", "ettercap", "bettercap",
            "mitmproxy", "dsniff", "responder", "arpspoof", "tshark",
            "ngrep", "scapy", "sslstrip", "dnschef", "yersinia",
            "ratproxy", "mitm6", "ntlmrelayx",
            
            # Reverse Engineering & Binary Analysis (15)
            "ghidra", "radare2", "binwalk", "strings", "hexedit",
            "objdump", "readelf", "nm", "strace", "ltrace",
            "hexdump", "xxd", "binutils", "gdb", "pwndbg",
            
            # Forensics & Data Recovery (12)
            "sleuthkit", "foremost", "autopsy", "volatility", "steghide",
            "exiftool", "dc3dd", "ddrescue", "testdisk", "extundelete",
            "scalpel", "bulk-extractor",
            
            # Security Auditing & Hardening (12)
            "lynis", "openvas", "rkhunter", "chkrootkit", "aide",
            "apparmor", "logwatch", "tiger", "checksec", "audit",
            "osquery", "tripwire",
            
            # Encryption & Privacy (10)
            "veracrypt", "gnupg", "openssl", "tomb", "cryptsetup",
            "openvpn", "wireguard-tools", "tor", "torsocks", "proxychains-ng",
            
            # Vulnerability Scanning (8)
            "openvas", "nikto", "wapiti", "skipfish", "nuclei",
            "nessus", "nexpose", "qualysguard",
            
            # Sniffing & Spoofing (8)
            "wireshark-qt", "tcpdump", "dsniff", "ettercap", "bettercap",
            "arpspoof", "macchanger", "responder"
        ]
    else:
        pentest_pkgs = [
            # Network Scanning & Enumeration (30)
            "nmap", "masscan", "netdiscover", "arp-scan", "arping",
            "dnsenum", "fierce", "dmitry", "enum4linux", "nbtscan",
            "theharvester", "ike-scan", "unicornscan", "hping",
            "traceroute", "whois", "ncat", "netmask", "mtr",
            "p0f", "netcat", "netperf", "iperf3", "nethogs",
            "nload", "iftop", "vnstat", "ss", "lsof", "fuser",
            
            # Web Application Testing (25)
            "nikto", "sqlmap", "wpscan", "dirb", "gobuster",
            "ffuf", "whatweb", "wafw00f", "burpsuite", "zaproxy",
            "commix", "wfuzz", "skipfish", "sqlitebrowser", "nuclei",
            "testssl.sh", "sslscan", "jwt-cli", "httpie", "curl",
            "wget", "arjun", "katana", "httpx", "waymore",
            
            # Wireless Security (15)
            "aircrack-ng", "reaver", "bully", "pixiewps", "wifite",
            "kismet", "mdk4", "mdk3", "hostapd", "dnsmasq",
            "cowpatty", "airmon-ng", "wifipumpkin3", "rfkill", "rtl-sdr",
            
            # Password Cracking (15)
            "john", "hashcat", "hydra", "medusa", "ncrack",
            "ophcrack", "hashid", "crunch", "cewl", "cupp",
            "hash-identifier", "findmyhash", "hashdeep", "pdfcrack", "crowbar",
            
            # Exploitation & Frameworks (10)
            "metasploit", "exploitdb", "searchsploit", "crackmapexec",
            "impacket", "routersploit", "setoolkit", "powersploit",
            "empire", "covenant",
            
            # Network Analysis (20)
            "wireshark-qt", "tcpdump", "ettercap", "bettercap",
            "mitmproxy", "dsniff", "responder", "arpspoof", "tshark",
            "ngrep", "scapy", "hping", "fragroute", "macchanger",
            "ratproxy", "sslstrip", "dnschef", "yersinia", "lbd", "wafw00f",
            
            # Reverse Engineering & Forensics (25)
            "ghidra", "radare2", "binwalk", "strings", "hexedit",
            "sleuthkit", "foremost", "autopsy", "volatility", "volatility3",
            "steghide", "exiftool", "dc3dd", "ddrescue", "testdisk",
            "extundelete", "scalpel", "exifprobe", "hexinject", "objdump",
            "readelf", "nm", "strace", "ltrace", "bokken",
            
            # System Analysis & Debugging (15)
            "gdb", "lldb", "valgrind", "perf", "bpftrace",
            "sysstat", "iotop", "hardinfo", "inxi", "procps-ng",
            "psmisc", "audit", "osquery", "cppcheck", "clang-tools-extra",
            
            # Security Auditing (20)
            "lynis", "openvas", "rkhunter", "chkrootkit", "aide",
            "apparmor", "logwatch", "fail2ban", "ufw", "iptables",
            "nftables", "clamav", "clamav-daemon", "yara", "python-yara",
            "ssh-audit", "checksec", "tiger", "nikto", "openscap",
            
            # Encryption & Privacy (15)
            "veracrypt", "gnupg", "openssl", "tomb", "cryptsetup",
            "openvpn", "wireguard-tools", "openfortivpn", "strongswan",
            "xl2tpd", "tor", "torsocks", "proxychains-ng", "privoxy", "i2pd",
            
            # Mobile & IoT (10)
            "apktool", "apksigner", "jadx", "frida", "objection",
            "androguard", "dex2jar", "smali", "adb", "fastboot",
            
            # Cloud & Container Security (10)
            "docker", "docker-compose", "kubectl", "helm", "trivy",
            "prowler", "scout", "cloudsploit", "pacu", "weirdaaa",
            
            # Social Engineering (5)
            "setoolkit", "gophish", "evilginx2", "modlishka", "beef",
            
            # Utilities & Misc (30)
            "macchanger", "proxychains-ng", "bleachbit", "socat",
            "netcat", "iperf3", "jq", "exiftool", "upx",
            "redsocks", "udptunnel", "iodine", "dns2tcp", "ptunnel",
            "stunnel", "udp2raw", "chisel", "ligolo", "pwncat",
            "evil-winrm", "bloodhound", "neo4j", "pypykatz", "sprayhound",
            "kerbrute", "rubeus", "mimikatz", "lazagne", "keepass2john"
        ]
    
    # SSH key generation commands
    ssh_gen_keys = ""
    if ssh_config.get('enabled') and ssh_config.get('generate_keys'):
        ssh_gen_keys = f"""mkdir -p /home/{username}/.ssh && chmod 700 /home/{username}/.ssh
sudo -u {username} ssh-keygen -t ed25519 -f /home/{username}/.ssh/id_ed25519 -N '' -q 2>/dev/null || true"""
    
    script = f"""#!/bin/bash
set -e

printf "\\033[38;5;208m╔══════════════════════════════════════════════════════════════════╗\\033[0m\\n"
printf "\\033[38;5;208m║ \\033[1m%-66s \\033[38;5;208m║\\033[0m\\n" "HORIZONSEC SYSTEM CONFIGURATION"
printf "\\033[38;5;208m╚══════════════════════════════════════════════════════════════════╝\\033[0m\\n"

# Timezone & Locale
printf "\\033[96m[1/10]\\033[0m Setting timezone and locale...\\n"
ln -sf /usr/share/zoneinfo/{timezone} /etc/localtime
hwclock --systohc
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen
echo "LANG=en_US.UTF-8" > /etc/locale.conf

# Hostname
echo "{hostname}" > /etc/hostname
cat > /etc/hosts <<'HOSTEOF'
127.0.0.1   localhost
::1         localhost
127.0.1.1   {hostname}.localdomain {hostname}
HOSTEOF

# Root password
echo "root:{root_password}" | chpasswd

# Enable multilib
sed -i '/\\[multilib\\]/,/Include/s/^#//' /etc/pacman.conf
pacman -Sy --noconfirm > /dev/null 2>&1

printf "\\033[96m[2/10]\\033[0m Installing system packages...\\n"
pacman -S --noconfirm --needed {' '.join(system_pkgs)} > /dev/null 2>&1 || true

printf "\\033[96m[3/10]\\033[0m Installing GPU drivers ({gpu_name})...\\n"
pacman -S --noconfirm --needed {' '.join(gpu_drivers)} > /dev/null 2>&1 || true

printf "\\033[96m[4/10]\\033[0m Installing desktop environment ({desktop['name']})...\\n"
pacman -S --noconfirm --needed {' '.join(desktop['packages'])} {desktop['portal']} > /dev/null 2>&1 || true

printf "\\033[96m[5/10]\\033[0m Installing penetration testing tools...\\n"
pacman -S --noconfirm --needed {' '.join(pentest_pkgs)} > /dev/null 2>&1 || true

{"pacman -S --noconfirm --needed tor torsocks > /dev/null 2>&1 || true" if ghost_mode else ""}

printf "\\033[96m[6/10]\\033[0m Creating user account and groups...\\n"

# Ensure docker group exists
groupadd -f docker

if id "{username}" &>/dev/null; then
    echo "User {username} already exists"
    usermod -aG wheel,docker {username}
else
    useradd -m -G wheel,docker -s /bin/zsh {username}
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create user {username}"
        exit 1
    fi
fi

echo "{username}:{password}" | chpasswd
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

printf "\\033[96m[7/10]\\033[0m Configuring bootloader...\\n"

# Get root partition UUID
ROOT_PART=\$(df / | tail -1 | awk '{{print \$1}}')
ROOT_UUID=\$(blkid -s UUID -o value \$ROOT_PART)

# Get the base disk device
BOOT_DISK="{disk_path}"

IS_UEFI="{is_uefi}"

if [ "\$IS_UEFI" = "True" ]; then
    # UEFI boot with GRUB
    printf "Installing GRUB for UEFI...\\n"
    
    # Ensure EFI vars are mounted
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null || true
    
    # Install GRUB to EFI partition
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=HorizonSec --recheck --no-nvram 2>/dev/null || \
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=HorizonSec --recheck
    
    if [ \$? -eq 0 ]; then
        echo "GRUB UEFI installation successful"
    else
        echo "ERROR: GRUB UEFI installation failed"
        # Try fallback installation
        grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=HorizonSec --removable --recheck
    fi
    
else
    # BIOS boot with GRUB
    printf "Installing GRUB for BIOS...\\n"
    
    # Install GRUB to MBR
    grub-install --target=i386-pc --recheck \$BOOT_DISK
    
    if [ \$? -ne 0 ]; then
        echo "WARNING: Initial GRUB installation failed, trying with --force..."
        grub-install --target=i386-pc --force --recheck \$BOOT_DISK
    fi
fi

# Generate GRUB configuration
grub-mkconfig -o /boot/grub/grub.cfg

# Verify GRUB config was created
if [ ! -f /boot/grub/grub.cfg ]; then
    echo "ERROR: GRUB configuration not generated!"
    exit 1
fi

echo "Bootloader installation complete"

printf "\\033[96m[8/10]\\033[0m Configuring services...\\n"
systemctl enable NetworkManager > /dev/null 2>&1
systemctl enable bluetooth > /dev/null 2>&1 || true
systemctl enable ufw > /dev/null 2>&1
systemctl enable fail2ban > /dev/null 2>&1
systemctl enable tor > /dev/null 2>&1 || true
systemctl enable docker > /dev/null 2>&1
systemctl enable {desktop['dm']} > /dev/null 2>&1
{"systemctl enable sshd > /dev/null 2>&1" if ssh_config['enabled'] else ""}

# Firewall configuration
ufw --force enable > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
{f"ufw allow 22/tcp > /dev/null 2>&1" if firewall_config.get('ssh', True) else ""}

# SSH configuration (if enabled)
{ssh_gen_keys}

printf "\\033[96m[9/10]\\033[0m Finalizing installation...\\n"

# Ensure proper ownership
chown -R {username}:{username} /home/{username}

# Enable lightdm greeter autologin config (optional)
if [ "{desktop['dm']}" = "lightdm" ]; then
    mkdir -p /etc/lightdm
    cat > /etc/lightdm/lightdm.conf <<'LIGHTDMEOF'
[Seat:*]
greeter-session=lightdm-gtk-greeter
LIGHTDMEOF
fi

# Configure Alacritty as default terminal for all DEs
mkdir -p /home/{username}/.config

# Set Alacritty as default terminal for GNOME
if [ "{desktop['name']}" = "GNOME" ]; then
    sudo -u {username} dbus-launch gsettings set org.gnome.desktop.default-applications.terminal exec 'alacritty' 2>/dev/null || true
    sudo -u {username} dbus-launch gsettings set org.gnome.desktop.default-applications.terminal exec-arg '' 2>/dev/null || true
fi

# Set Alacritty as default terminal for XFCE
if [ "{desktop['name']}" = "XFCE" ]; then
    mkdir -p /home/{username}/.config/xfce4
    cat > /home/{username}/.config/xfce4/helpers.rc <<'XFCETERM'
TerminalEmulator=alacritty
XFCETERM
    chown -R {username}:{username} /home/{username}/.config/xfce4
fi

# Set Alacritty as default terminal for Cinnamon
if [ "{desktop['name']}" = "Cinnamon" ]; then
    sudo -u {username} gsettings set org.cinnamon.desktop.default-applications.terminal exec 'alacritty' 2>/dev/null || true
fi

# Set Alacritty as default terminal for MATE
if [ "{desktop['name']}" = "MATE" ]; then
    sudo -u {username} gsettings set org.mate.applications-terminal exec 'alacritty' 2>/dev/null || true
fi

# Set Alacritty as default terminal for LXQt
if [ "{desktop['name']}" = "LXQt" ]; then
    mkdir -p /home/{username}/.config/lxqt
    cat > /home/{username}/.config/lxqt/lxqt.conf <<'LXQTTERM'
[General]
terminal=alacritty
LXQTTERM
    chown -R {username}:{username} /home/{username}/.config/lxqt
fi

# Set Alacritty as default terminal for KDE Plasma
if [ "{desktop['name']}" = "KDE Plasma" ]; then
    mkdir -p /home/{username}/.config
    cat > /home/{username}/.config/kdeglobals <<'KDETERM'
[General]
TerminalApplication=alacritty
KDETERM
    chown -R {username}:{username} /home/{username}/.config/kdeglobals
fi

# Rebuild initramfs to ensure all modules are included
mkinitcpio -P > /dev/null 2>&1 || true

printf "\\033[96m[10/10]\\033[0m Installation complete!\\n"

printf "\\033[38;5;208m╔══════════════════════════════════════════════════════════════════╗\\033[0m\\n"
printf "\\033[38;5;208m║ \\033[92m✓ INSTALLATION COMPLETE%-43s \\033[38;5;208m║\\033[0m\\n" ""
printf "\\033[38;5;208m╚══════════════════════════════════════════════════════════════════╝\\033[0m\\n"
printf "\\n"
printf "\\033[92mWelcome to HorizonSec!\\033[0m\\n"
printf "\\n"
printf "Your system has been configured with:\\n"
printf "  \\033[38;5;208m•\\033[0m Desktop: {desktop['name']}\\n"
printf "  \\033[38;5;208m•\\033[0m Terminal: Alacritty\\n"
printf "  \\033[38;5;208m•\\033[0m Penetration Testing Tools\\n"
printf "  \\033[38;5;208m•\\033[0m Docker with user permissions\\n"
printf "  \\033[38;5;208m•\\033[0m Firewall enabled (UFW)\\n"
printf "  \\033[38;5;208m•\\033[0m Ghost Mode (Tor) enabled\\n"
printf "\\n"
printf "\\033[96mManagement Commands:\\033[0m\\n"
printf "  \\033[38;5;208mhorizon-firewall\\033[0m    - Manage firewall and security\\n"
printf "  \\033[38;5;208mhorizon-update\\033[0m      - Check for system updates\\n"
printf "\\n"
printf "\\033[96mNext steps:\\033[0m\\n"
printf "  1. Remove installation media\\n"
printf "  2. Type: \\033[38;5;208mreboot\\033[0m\\n"
printf "  3. Login as: \\033[38;5;208m{username}\\033[0m\\n"
printf "  4. Start pentesting!\\n"
printf "\\n"
"""

    return script

def select_install_type():
    """Select installation type"""
    global INSTALL_TYPE
    
    print(f"\n{Color.BOLD}Installation Types:{Color.END}\n")
    print(f"  {Color.ORANGE}1){Color.END} {Color.BOLD}Full Installation{Color.END} (3-5 hours)")
    print(f"     • 230+ penetration testing tools")
    print(f"     • Includes mobile, cloud, and IoT security")
    print(f"     • All desktop environments")
    print(f"     • Storage needed: ~80-100 GB")
    print()
    print(f"  {Color.ORANGE}2){Color.END} {Color.BOLD}Lite Installation{Color.END} (30-50 minutes)")
    print(f"     • 150+ core penetration testing tools")
    print(f"     • Essential security toolkit (network, web, wireless, forensics)")
    print(f"     • All desktop environments")
    print(f"     • Storage needed: ~50-60 GB")
    print()
    
    while True:
        choice = input(f"{Color.CYAN}Select installation type [1-2] (default: 2): {Color.END}").strip() or "2"
        if choice == '1':
            INSTALL_TYPE = 'full'
            return 'full'
        elif choice == '2':
            INSTALL_TYPE = 'lite'
            return 'lite'
        else:
            error("Invalid choice")

def select_timezone():
    """Prompt user for timezone"""
    timezones = [
        "UTC", "US/Eastern", "US/Central", "US/Mountain", "US/Pacific",
        "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"
    ]
    
    print(f"\n{Color.CYAN}Common timezones:{Color.END}")
    for i, tz in enumerate(timezones, 1):
        print(f"  {i}. {tz}")
    
    while True:
        choice = input(f"{Color.CYAN}Select timezone (1-{len(timezones)}) or press Enter for UTC: {Color.END}").strip() or "1"
        try:
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(timezones):
                    return timezones[idx]
        except (ValueError, IndexError):
            pass
        error("Invalid selection, try again")

def main():
    """Main installation routine"""
    global VERBOSE
    
    parser = argparse.ArgumentParser(description='HorizonSec OS Installer')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--skip-update', action='store_true', help='Skip update check')
    args = parser.parse_args()
    
    VERBOSE = args.verbose
    skip_update = args.skip_update
    
    if VERBOSE:
        info("Verbose mode enabled - all commands will be displayed")
    
    logo()
    check_root()
    
    if not skip_update:
        setup_network()
    else:
        warning("Skipping update check as requested")
        header("Network Configuration")
        cmd("systemctl start NetworkManager", check=False)
        time.sleep(2)
        info("Initializing package keys...")
        cmd("pacman-key --init", check=False)
        cmd("pacman-key --populate archlinux", check=False)
        cmd("pacman -Sy --noconfirm", check=False)
    
    install_type = select_install_type()
    is_uefi = check_uefi()
    gpu_name, gpu_drivers = detect_gpu()
    disk_name, disk_path = select_disk()
    
    desktops = {
        '1': {'name': 'KDE Plasma', 'packages': ['plasma-meta', 'sddm'], 'dm': 'sddm', 'portal': 'xdg-desktop-portal-kde'},
        '2': {'name': 'GNOME', 'packages': ['gnome', 'gdm'], 'dm': 'gdm', 'portal': 'xdg-desktop-portal-gnome'},
        '3': {'name': 'XFCE', 'packages': ['xfce4', 'lightdm', 'lightdm-gtk-greeter', 'xorg-server'], 'dm': 'lightdm', 'portal': 'xdg-desktop-portal-gtk'},
        '4': {'name': 'Cinnamon', 'packages': ['cinnamon', 'lightdm', 'lightdm-gtk-greeter', 'xorg-server'], 'dm': 'lightdm', 'portal': 'xdg-desktop-portal-gtk'},
        '5': {'name': 'MATE', 'packages': ['mate', 'lightdm', 'lightdm-gtk-greeter', 'xorg-server'], 'dm': 'lightdm', 'portal': 'xdg-desktop-portal-gtk'},
        '6': {'name': 'LXQt', 'packages': ['lxqt', 'sddm', 'xorg-server'], 'dm': 'sddm', 'portal': 'xdg-desktop-portal-lxqt'},
    }
    
    header("Desktop Environment Selection")
    
    # Get system RAM for recommendation
    mem_kb = int(cmd("grep MemTotal /proc/meminfo | awk '{print $2}'", capture=True, check=False) or "0")
    mem_gb = mem_kb / 1024 / 1024
    
    # Recommend based on RAM
    if mem_gb < 4:
        recommended = '3'  # XFCE
    elif mem_gb < 8:
        recommended = '4'  # Cinnamon
    else:
        recommended = '1'  # KDE
    
    print(f"\n{Color.ORANGE}System has {mem_gb:.1f}GB RAM{Color.END}")
    desktop = select_desktop(desktops, recommended, lite_mode=(install_type == 'lite'))
    
    hostname = "horizonsec"
    timezone = select_timezone()
    
    header("User Account")
    username = input(f"{Color.CYAN}Username [pentester]: {Color.END}").strip() or "pentester"
    
    while True:
        password = getpass.getpass(f"{Color.CYAN}Password (hidden): {Color.END}").strip()
        if not password:
            error("Password cannot be empty")
            continue
        password_confirm = getpass.getpass(f"{Color.CYAN}Confirm password: {Color.END}").strip()
        if password == password_confirm:
            break
        error("Passwords do not match")
    
    while True:
        root_password = getpass.getpass(f"{Color.CYAN}Root password (hidden): {Color.END}").strip()
        if not root_password:
            error("Root password cannot be empty")
            continue
        root_password_confirm = getpass.getpass(f"{Color.CYAN}Confirm root password: {Color.END}").strip()
        if root_password == root_password_confirm:
            break
        error("Passwords do not match")
    
    header("Services & Security")
    
    mirror_selection = 'auto'
    ssh_config = {'enabled': False}
    firewall_config = {'enabled': True, 'ssh': True}
    ghost_mode = True
    
    success("Auto-configured: Fast mirrors, Firewall enabled, Ghost Mode enabled")
    
    info(f"Installing to: {disk_path}")
    info(f"Desktop: {desktop['name']}")
    info(f"Username: {username}")
    
    confirm = input(f"\n{Color.CYAN}Start installation? (y/n) [y]: {Color.END}").strip().lower()
    if confirm == 'n':
        error("Installation cancelled")
        sys.exit(0)
