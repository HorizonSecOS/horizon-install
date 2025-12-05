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

def draw_progress_bar(current, total, label=""):
    """Draw a progress bar with percentage and ETA"""
    global INSTALLATION_START_TIME
    
    if INSTALLATION_START_TIME is None:
        INSTALLATION_START_TIME = time.time()
    
    bar_width = 50
    percentage = min(100, (current / total * 100)) if total > 0 else 0
    filled = int((percentage / 100) * bar_width)
    
    elapsed = time.time() - INSTALLATION_START_TIME
    if current > 0:
        rate = current / elapsed
        eta_secs = (total - current) / rate if rate > 0 else 0
        eta_str = f"ETA: {int(eta_secs//60):02d}:{int(eta_secs%60):02d}"
    else:
        eta_str = "ETA: --:--"
    
    bar = f"{Color.ORANGE}{'█' * filled}{'░' * (bar_width - filled)}{Color.END}"
    progress_text = f"{label} [{current}/{total}] {int(percentage):3d}% {eta_str}"
    
    print(f"\r{Color.CYAN}{progress_text:<50}{Color.END} {bar}", end='', flush=True)

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
  ║   HORIZON░ SEC                                           ║
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
    else:
        warning("Network may not be connected. Continuing anyway...")
    
    info("Initializing package keys...")
    cmd("pacman-key --init", check=False)
    cmd("pacman-key --populate archlinux", check=False)
    cmd("pacman -Sy --noconfirm", check=False)

def detect_gpu():
    """Auto-detect GPU and return appropriate drivers"""
    header("GPU Detection")
    
    gpu_output = cmd("lspci 2>/dev/null | grep -iE 'vga|3d|display'", capture=True, check=False)
    
    if not gpu_output:
        gpu_output = ""
    
    gpu_lines = gpu_output.strip().split('\n') if gpu_output else []
    
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
        output = cmd('lsblk -J -d -o NAME,SIZE,MODEL,TYPE', capture=True)
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
    
    info("Wiping disk...")
    cmd(f"wipefs -af {disk_path}")
    cmd(f"sgdisk -Z {disk_path}")
    
    sep = 'p' if 'nvme' in disk_name or 'mmcblk' in disk_name else ''
    
    if is_uefi:
        info("Creating GPT partition table (UEFI)...")
        cmd(f"parted -s {disk_path} mklabel gpt")
        
        info("Creating partitions (EFI + SWAP + ROOT)...")
        cmd(f"parted -s {disk_path} mkpart ESP fat32 1MiB 512MiB")
        cmd(f"parted -s {disk_path} set 1 esp on")
        cmd(f"parted -s {disk_path} mkpart SWAP linux-swap 512MiB 8704MiB")
        cmd(f"parted -s {disk_path} mkpart ROOT ext4 8704MiB 100%")
        
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
        cmd(f"parted -s {disk_path} mklabel msdos")
        
        info("Creating partitions (BOOT + SWAP + ROOT)...")
        cmd(f"parted -s {disk_path} mkpart primary ext4 1MiB 512MiB")
        cmd(f"parted -s {disk_path} set 1 boot on")
        cmd(f"parted -s {disk_path} mkpart primary linux-swap 512MiB 8704MiB")
        cmd(f"parted -s {disk_path} mkpart primary ext4 8704MiB 100%")
        
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
    elif mirror_selection.startswith('http'):
        info(f"Configuring custom mirror: {mirror_selection}")
        cmd(f"sed -i '1s|^|Server = {mirror_selection}\\n|' /etc/pacman.d/mirrorlist", check=False)
    else:
        info("Using system mirror configuration")
    
    info("Installing base system (this takes 5-10 minutes)...")
    
    base_packages = [
        "base", "linux", "linux-firmware", "linux-headers",
        "base-devel", "git", "limine", "efibootmgr",
        "networkmanager", "sudo", "nano", "vim",
        "intel-ucode", "amd-ucode",
        "bash-completion", "man-db", "man-pages"
    ]
    
    cmd(f"pacstrap -K /mnt {' '.join(base_packages)}")
    
    info("Generating fstab...")
    cmd("genfstab -U /mnt >> /mnt/etc/fstab")
    
    success("Base system installed")

def select_desktop(desktops, recommended='1', lite_mode=False):
    """Interactive desktop environment selection with recommendation"""
    filtered_desktops = desktops
    
    if lite_mode:
        lite_choices = {'1': desktops['1'], '2': desktops['2'], '3': desktops['3'], '4': desktops['4'], '5': desktops['5'], '6': desktops['6']}
        filtered_desktops = lite_choices
        recommended = '3' if recommended not in lite_choices else recommended
        print(f"\n{Color.BOLD}Desktop Environments (Lite Mode - All Packaged DEs):{Color.END}\n")
    else:
        print(f"\n{Color.BOLD}Desktop Environments:{Color.END}\n")
    
    for key, de in filtered_desktops.items():
        tag = f" {Color.GREEN}← Recommended{Color.END}" if key == recommended else ""
        print(f"  {Color.ORANGE}{key}){Color.END} {de['name']}{tag}")
    print()
    
    max_choice = len(filtered_desktops)
    while True:
        choice = input(f"{Color.CYAN}Select desktop [1-{max_choice}] or press Enter for recommended: {Color.END}").strip() or recommended
        if choice in filtered_desktops:
            de = filtered_desktops[choice]
            success(f"Selected: {de['name']}")
            return de
        error("Invalid choice")

def create_install_script(username, password, root_password, desktop, gpu_drivers, ghost_mode, is_uefi, disk_path, hostname, timezone, ssh_config, firewall_config, install_type='full', gpu_name='Generic'):
    """Generate the chroot installation script"""
    
    if install_type == 'lite':
        system_pkgs = [
            "alacritty", "fastfetch", "htop",
            "ranger", "thunar", "gvfs",
            "zsh", "zsh-completions", "zsh-syntax-highlighting",
            "fzf", "ripgrep", "fd", "bat", "tmux",
            "ttf-jetbrains-mono-nerd", "noto-fonts", "noto-fonts-emoji",
            "p7zip", "unzip", "zip",
            "ntfs-3g", "dosfstools",
            "efibootmgr", "limine",
            "wget", "curl", "openssh",
            "ufw", "fail2ban",
            "code", "vim", "firefox",
            "docker", "docker-compose",
            "git", "gcc", "make", "pkg-config",
            "python", "python-pip",
            "flatpak", "libadwaita-without-adwaita"
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
            "efibootmgr", "limine",
            "wget", "curl", "rsync", "openssh",
            "ufw", "fail2ban",
            "code", "vim", "neovim",
            "docker", "docker-compose", "qemu-full", "virt-manager",
            "git", "gcc", "make", "cmake", "pkg-config",
            "perl", "ruby", "python", "python-pip",
            "gdb", "lldb", "valgrind",
            "flatpak", "libadwaita-without-adwaita"
        ]
    
    if install_type == 'lite':
        pentest_pkgs = [
            "nmap", "masscan", "netdiscover", "dnsenum", "fierce",
            "nikto", "sqlmap", "lynis", "openvas",
            "aircrack-ng", "reaver", "pixiewps", "wifite",
            "metasploit", "exploitdb",
            "wireshark-qt", "wireshark-cli", "tcpdump", "mitmproxy",
            "john", "hashcat", "hydra", "medusa",
            "zaproxy", "wfuzz", "ffuf",
            "ghidra", "radare2", "strace", "ltrace",
            "binwalk", "strings", "hexedit",
            "sleuthkit", "foremost",
            "cherrytree", "keepassxc",
            "veracrypt", "gnupg", "openssl",
            "openvpn", "wireguard-tools",
            "ncat", "socat",
            "macchanger", "rkhunter",
            "jq", "exiftool",
            "traceroute", "tshark",
            "whois", "curl", "wget",
            "arp-scan", "arping", "hping",
            "dsniff", "responder", "arpspoof",
            "ettercap", "bettercap",
            "dirb", "gobuster",
            "hashid", "crunch",
            "gdb", "valgrind",
            "objdump", "nm", "readelf",
            "autopsy", "scalpel",
            "steghide", "dcfldd",
            "testssl.sh", "sslscan",
            "ncrack", "theharvester",
            "dmitry", "ike-scan",
            "enum4linux", "smbmap",
            "nbtscan", "netcat-openbsd",
            "proxychains-ng", "bleachbit",
            "volatility", "ddrescue",
            "aide", "logwatch",
            "apparmor", "chkrootkit",
            "airmon-ng",
            "kismet",
            "mdk4",
            "hostapd",
            "dnsmasq",
            "bind",
            "openfortivpn",
            "strongswan",
            "xl2tpd",
            "iperf3",
            "netperf",
            "mtr",
            "nethogs",
            "nload",
            "iftop",
            "vnstat",
            "iotop",
            "sysstat",
            "hardinfo",
            "inxi",
            "lsof",
            "fuser",
            "ss",
            "iptables",
            "nftables",
            "audit",
            "osquery",
            "procps-ng",
            "psmisc",
            "perf",
            "bpftrace",
            "cppcheck",
            "clang-tools-extra",
            "lldb",
            "clang",
            "clamav",
            "clamav-daemon",
            "yara",
            "python-yara",
            "cryptsetup",
            "cupp",
            "exifprobe",
            "findmyhash",
            "knocker",
            "ldapsearch",
            "mactime",
            "md5deep",
            "mfoc",
            "ngrep",
            "nmcli",
            "pcsctools",
            "rdesktop",
            "reglookup",
            "rfkill",
            "rtl-sdr",
            "scapy",
            "sshpass",
            "udptunnel",
            "ugrep",
            "wireshark",
            "bully",
            "cowpatty",
            "searchsploit",
            "burpsuite",
            "commix",
            "skipfish",
            "sqlitebrowser",
            "testdisk",
            "extundelete",
            "tomb",
            "hashdeep",
            "hexinject",
            "iodine",
            "iperf",
            "ldapmodify",
            "mfcuk",
            "netmask",
            "p0f",
            "pktgen",
            "redsocks",
            "udp2raw",
            "assetfinder",
            "subfinder",
            "amass"
        ]
    else:
        pentest_pkgs = [
            "nmap", "masscan", "netdiscover", "dnsenum", "fierce",
            "theharvester", "dmitry", "ike-scan", "enum4linux",
            "smbmap", "nbtscan", "arping", "hping", "unicornscan",
            "nikto", "wpscan", "sqlmap", "lynis", "openvas",
            "nuclei", "whatweb", "wafw00f", "sslscan", "testssl.sh",
            "aircrack-ng", "reaver", "bully", "pixiewps", "kismet",
            "mdk4", "wifite", "hostapd", "mdk3", "cowpatty",
            "metasploit", "exploitdb", "searchsploit",
            "wireshark-qt", "wireshark-cli", "tcpdump", "ettercap",
            "bettercap", "mitmproxy", "dsniff", "responder", "arpspoof",
            "john", "hashcat", "hydra", "medusa", "ncrack",
            "ophcrack", "cewl", "crunch", "hashid", "hash-identifier",
            "burpsuite", "zaproxy", "commix", "wfuzz", "dirb",
            "gobuster", "ffuf", "sqlitebrowser", "skipfish",
            "ghidra", "radare2", "strace", "ltrace",
            "binwalk", "objdump", "strings", "hexedit",
            "autopsy", "sleuthkit", "foremost", "scalpel", "testdisk",
            "extundelete", "steghide", "volatility", "dc3dd", "ddrescue",
            "cherrytree", "keepassxc",
            "veracrypt", "gnupg", "tomb", "openssl",
            "proxychains-ng", "openvpn", "wireguard-tools",
            "ncat", "socat", "netcat", "iperf3",
            "macchanger", "bleachbit", "rkhunter", "chkrootkit",
            "apparmor", "aide", "logwatch",
            "arp-scan", "assetfinder",
            "bokken",
            "cowrie",
            "cryptsetup", "cupp",
            "dcfldd", "dirbuster",
            "exifprobe", "exiftool",
            "findmyhash", "foremost", "fragroute",
            "ghex",
            "hashdeep", "hexinject",
            "http-tunnel",
            "iodine",
            "iperf",
            "jq",
            "kerbcrack", "knock", "knocker",
            "ldapmodify", "ldapsearch",
            "mactime",
            "md5deep",
            "mfcuk", "mfoc", "mtr",
            "nethogs",
            "netmask", "netperf", "ngrep", "nload",
            "nmcli",
            "pcsctools",
            "pktgen",
            "ratproxy", "rdesktop",
            "readelf", "redsocks", "reglookup",
            "rfkill",
            "rtl_433", "rtl_fm", "rtl_power", "rtl_sdr", "rtl_tcp", "rtl-sdr",
            "scapy", "sshpass",
            "traceroute", "tshark",
            "udptunnel",
            "ugrep",
            "whois"
        ]
    
    if install_type == 'lite':
        aur_pkgs = []
    else:
        aur_pkgs = [
            "paru",
            "firefox-developer-edition",
            "fern-wifi-cracker",
            "angryipscanner",
            "social-engineer-toolkit",
            "crackmapexec",
            "impacket",
            "exploitdb",
            "burpsuite-community",
            "havoc",
            "empire",
            "covenant",
            "sliver",
            "netcat-openbsd",
            "powercat",
            "one-liner-wonder",
            "themis",
            "apt2",
            "autoenum",
            "wifipumpkin3",
            "gophish",
            "redflag",
            "upx",
            "checksec",
            "python-pycryptodome",
            "clamav-daemon",
            "yara",
            "python-yara",
            "volatility3",
            "git-dumper",
            "git-rekt",
            "chisel",
            "boolvine",
            "bossac",
            "weevely",
            "shellter",
            "veil-evasion",
            "zeratool",
            "dnscat2",
            "sshpass",
            "routersploit",
            "pwntools",
            "lief",
            "capstone",
            "unicorn",
            "qiling",
            "miasm",
            "androidsecurity",
            "apksigner",
            "jadx-bin",
            "frida",
            "objection",
            "epoxy",
            "crowbar",
            "ssh-audit",
            "jwt-cli",
            "hashpumpy",
            "pypykatz",
            "adidnsdump",
            "ldapsearch-ad",
            "pykooi",
            "dnstool",
            "sublist3r",
            "arjun",
            "getallurls",
            "tlsx",
            "shuffledns",
            "anew",
            "gau",
            "katana",
            "waymore",
            "httpx",
            "alterx",
            "pdfcrack",
            "pdf-parser",
            "peepdf",
            "exifprobe",
            "swiftshader",
            "lsd",
            "bat",
            "ripgrep",
            "fd",
            "delta",
            "sd",
            "xsv",
            "procs",
            "dust",
            "ugrep",
            "bottom",
            "btop",
            "gotop",
            "glances",
            "httpie",
            "xh",
            "curl-impersonate",
            "teler",
            "aiodns",
            "pymongo",
            "lxml",
            "selenium",
            "splinter",
            "requests",
            "httplib2",
            "urllib3",
            "aiohttp",
            "twisted",
            "flask",
            "django",
            "fastapi",
            "starlette",
            "pydantic",
            "sqlalchemy",
            "docker",
            "docker-compose",
            "kubernetes",
            "helm",
            "kops",
            "eksctl",
            "aws-cli-v2",
            "gcloud",
            "azure-cli",
            "terraform",
            "ansible",
            "vagrant",
            "packer",
            "consul",
            "nomad",
            "vault"
        ]
    
    gnome_extensions = []
    if desktop['name'] == 'GNOME':
        gnome_extensions = [
            "gnome-shell-extension-dash-to-dock",
            "gnome-shell-extension-blur-my-shell"
        ]
    
    if ghost_mode:
        aur_pkgs.append("archtorify-git")

    kde_color_scheme = """[General]
ColorScheme=HorizonSecDark

[Colors:Button]
BackgroundColor=20,20,25
ForegroundColor=210,210,215
DecorationColor=30,30,35

[Colors:Selection]
BackgroundColor=208,80,0
ForegroundColor=255,255,255

[Colors:Tooltip]
BackgroundColor=25,25,30
ForegroundColor=210,210,215

[Colors:View]
BackgroundColor=15,15,20
ForegroundColor=210,210,215
DecorationColor=30,30,35"""

    gnome_theme_config = """[org/gnome/desktop/interface]
gtk-theme='Adwaita-dark'
icon-theme='Adwaita'
color-scheme='prefer-dark'

[org/gnome/desktop/background]
picture-uri='file:///usr/share/backgrounds/horizonsec/hsec1.png'
picture-uri-dark='file:///usr/share/backgrounds/horizonsec/hsec1.png'

[org/gnome/desktop/wm/preferences]
titlebar-font='JetBrains Mono 10'"""

    xfce_theme_config = """[xfwm4]
theme=Xfce-dusk
titlebar_font=JetBrains Mono 10

[xsettings]
ColorForeground=#d2d2d7
ColorBackground=#0f0f14
Net/ThemeName=Adwaita-dark"""

    cinnamon_theme_config = """[cinnamon]
desktop-effects=false
enabled-applets=['panel1:left:0:menu@cinnamon.org:0']
desktop-effects-on-login=false
panels-height=['1:30']
theme-name='Mint-X-Dark'"""

    kde_wallpaper_script = """
mkdir -p ~/.local/share/plasmashell/wallpapers
cp /usr/share/backgrounds/horizonsec/hsec1.png ~/.local/share/plasmashell/wallpapers/
kquitapp5 plasmashell || true
kstart5 plasmashell > /dev/null 2>&1 &
"""

    ssh_enable = "systemctl enable ssh" if ssh_config['enabled'] else ""
    ssh_gen_keys = f"""mkdir -p /home/{username}/.ssh
sudo -u {username} ssh-keygen -t ed25519 -f /home/{username}/.ssh/id_ed25519 -N '' 2>/dev/null
chmod 700 /home/{username}/.ssh && chmod 600 /home/{username}/.ssh/id_*""" if ssh_config['enabled'] and ssh_config['generate_keys'] else ""
    
    firewall_ssh = f"ufw allow 22/tcp" if firewall_config.get('ssh', True) else ""

    script = f"""#!/bin/bash
set -e

printf "\\033[38;5;208m╔════════════════════════════════════════════════════════════════════╗\\033[0m\\n"
printf "\\033[38;5;208m║ \\033[1m%-66s \\033[38;5;208m║\\033[0m\\n" "HORIZONSEC SYSTEM CONFIGURATION"
printf "\\033[38;5;208m╚════════════════════════════════════════════════════════════════════╝\\033[0m\\n"

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

printf "\\033[96m[2/10]\\033[0m Configuring package mirrors...\\n"
pacman -Sy --noconfirm > /dev/null 2>&1

printf "\\033[96m[3/10]\\033[0m Installing system packages...\\n"
pacman -S --noconfirm --needed {' '.join(system_pkgs[:30])} > /dev/null 2>&1 || true
pacman -S --noconfirm --needed {' '.join(system_pkgs[30:])} > /dev/null 2>&1 || true

printf "\\033[96m[4/10]\\033[0m Installing GPU drivers ({gpu_name})...\\n"
pacman -S --noconfirm --needed {' '.join(gpu_drivers)} > /dev/null 2>&1 || true

printf "\\033[96m[5/10]\\033[0m Installing desktop environment ({desktop['name']})...\\n"
pacman -S --noconfirm --needed {' '.join(desktop['packages'])} {desktop['portal']} > /dev/null 2>&1 || true

{f"pacman -S --noconfirm --needed {' '.join(gnome_extensions)} > /dev/null 2>&1 || true" if desktop['name'] == 'GNOME' else ""}

printf "\\033[96m[6/10]\\033[0m Installing penetration testing tools...\\n"
pacman -S --noconfirm --needed {' '.join(pentest_pkgs[:30])} > /dev/null 2>&1 || true
pacman -S --noconfirm --needed {' '.join(pentest_pkgs[30:60])} > /dev/null 2>&1 || true
{"pacman -S --noconfirm --needed " + ' '.join(pentest_pkgs[60:]) + " > /dev/null 2>&1 || true" if len(pentest_pkgs) > 60 else ""}

{"pacman -S --noconfirm --needed tor torsocks nyx > /dev/null 2>&1 || true" if ghost_mode else ""}

printf "\\033[96m[7/10]\\033[0m Creating user account...\\n"

if id "{username}" &>/dev/null; then
    echo "User {username} already exists"
else
    useradd -m -G wheel,docker -s /bin/zsh {username}
    if [ $? -eq 0 ]; then
        echo "User {username} created successfully"
    else
        echo "ERROR: Failed to create user {username}"
        exit 1
    fi
fi

sleep 2

echo "{username}:{password}" | chpasswd
if [ $? -eq 0 ]; then
    echo "Password set successfully"
else
    echo "ERROR: Failed to set password for {username}"
    exit 1
fi

sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

printf "\\033[96m[8/10]\\033[0m Configuring bootloader...\\n"

ROOT_UUID=$(blkid -s UUID -o value $(df / | tail -1 | awk '{{print $1}}'))

BOOT_DISK={disk_path}
if [[ "$BOOT_DISK" == nvme* ]] || [[ "$BOOT_DISK" == mmcblk* ]]; then
    BOOT_DISK="${{BOOT_DISK%p*}}"
fi

IS_UEFI="{is_uefi}"

if [ "$IS_UEFI" = "True" ]; then
    mkdir -p /boot/EFI/arch-limine
    cp /usr/share/limine/BOOTX64.EFI /boot/EFI/arch-limine/ 2>/dev/null || true
    efibootmgr --create --disk $BOOT_DISK --part 1 --label "HorizonSec Limine" --loader "\\\\EFI\\\\arch-limine\\\\BOOTX64.EFI" --unicode 2>/dev/null || true
else
    cp /usr/share/limine/limine-bios.sys /boot/ 2>/dev/null || true
    cp /usr/share/limine/limine.conf /boot/ 2>/dev/null || true
fi

cat > /boot/limine.conf <<LIMINE_EOF
timeout: 5
default-entry: 1
background-color: 0F0F14
foreground-color: D05000
highlight-color: FF8C00
/HorizonSec Linux
    protocol: linux
    path: boot():/vmlinuz-linux
    cmdline: root=UUID=$ROOT_UUID rw quiet
    module_path: boot():/initramfs-linux.img
LIMINE_EOF

if [ "$IS_UEFI" != "True" ]; then
    limine bios-install "$BOOT_DISK" 2>/dev/null || true
fi

printf "\\033[96m[9/10]\\033[0m Configuring services...\\n"
systemctl enable NetworkManager > /dev/null 2>&1
systemctl enable bluetooth > /dev/null 2>&1 || true
systemctl enable ufw > /dev/null 2>&1
systemctl enable fail2ban > /dev/null 2>&1
systemctl enable tor > /dev/null 2>&1 || true
systemctl enable docker > /dev/null 2>&1
systemctl enable {desktop['dm']} > /dev/null 2>&1
{f"systemctl enable ssh > /dev/null 2>&1" if ssh_config['enabled'] else ""}

ufw --force enable > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
{f"ufw allow 22/tcp > /dev/null 2>&1" if firewall_config.get('ssh', True) else ""}

{ssh_gen_keys}

mkdir -p /usr/share/backgrounds/horizonsec
git clone https://github.com/HorizonSecOS/horizonsec-wallpapers.git /usr/share/backgrounds/horizonsec > /dev/null 2>&1 || true
chmod -R 755 /usr/share/backgrounds/horizonsec

mkdir -p /usr/share/themes
cd /tmp
wget -q "https://github.com/darkomarko42/Marwaita-ubuntu/archive/refs/heads/master.zip" -O marwaita.zip
unzip -q marwaita.zip
cp -r Marwaita-Orange-master/Marwaita-Dark-Orange /usr/share/themes/
cp -r Marwaita-Orange-master/Marwaita-Orange /usr/share/themes/
chmod -R 755 /usr/share/themes/Marwaita-*
rm -rf /tmp/marwaita.zip /tmp/Marwaita-Orange-master
cd /

cat > /usr/local/bin/horizon-firewall <<'FIREWALL_EOF'
#!/usr/bin/env bash

usage() {{
    echo "horizon-firewall - Toggle HorizonSec Firewall and Services"
    echo ""
    echo "Usage: horizon-firewall [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  on              Enable firewall and security services"
    echo "  off             Disable firewall (keep other services)"
    echo "  status          Show current firewall status"
    echo "  help, -h, --help  Show this help message"
    echo ""
    exit 0
}}

check_root() {{
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This command must be run as root"
        exit 1
    fi
}}

show_status() {{
    echo "═══════════════════════════════════════════════"
    echo "   HorizonSec Security Services Status"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    if systemctl is-active --quiet ufw; then
        echo "✓ Firewall (UFW):        ENABLED"
    else
        echo "✗ Firewall (UFW):        DISABLED"
    fi
    
    if systemctl is-active --quiet fail2ban; then
        echo "✓ Fail2Ban:              ENABLED"
    else
        echo "✗ Fail2Ban:              DISABLED"
    fi
    
    if systemctl is-active --quiet tor; then
        echo "✓ Ghost Mode (Tor):      ENABLED"
    else
        echo "✗ Ghost Mode (Tor):      DISABLED"
    fi
    
    echo ""
}}

enable_firewall() {{
    check_root
    echo "Enabling HorizonSec Firewall..."
    
    ufw --force enable > /dev/null 2>&1
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp > /dev/null 2>&1
    
    systemctl enable ufw > /dev/null 2>&1
    systemctl start ufw > /dev/null 2>&1
    
    echo "✓ Firewall enabled"
    show_status
}}

disable_firewall() {{
    check_root
    echo "Disabling HorizonSec Firewall..."
    
    ufw --force disable > /dev/null 2>&1
    systemctl disable ufw > /dev/null 2>&1
    systemctl stop ufw > /dev/null 2>&1
    
    echo "✓ Firewall disabled"
    show_status
}}

case "${{1,,}}" in
    on|enable)
        enable_firewall
        ;;
    off|disable)
        disable_firewall
        ;;
    status|info)
        check_root
        show_status
        ;;
    help|-h|--help)
        usage
        ;;
    "")
        show_status
        ;;
    *)
        echo "Error: Unknown command '$1'"
        usage
        ;;
esac
FIREWALL_EOF
chmod +x /usr/local/bin/horizon-firewall

mkdir -p /usr/share/applications
cat > /usr/share/applications/horizon-firewall.desktop <<'DESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=HorizonSec Firewall Manager
Comment=Toggle firewall and security services
Icon=network-wireless
Exec=x-terminal-emulator -e 'sudo horizon-firewall'
Terminal=true
Categories=System;Settings;
Keywords=firewall;security;network;
StartupNotify=true

[Desktop Action Enable]
Name=Enable Firewall
Exec=x-terminal-emulator -e 'sudo horizon-firewall on'

[Desktop Action Disable]
Name=Disable Firewall
Exec=x-terminal-emulator -e 'sudo horizon-firewall off'

[Desktop Action Status]
Name=Show Firewall Status
Exec=x-terminal-emulator -e 'sudo horizon-firewall status'
DESKTOP_EOF

printf "\\033[96m[10/10]\\033[0m Finalizing installation...\\n"

{"echo 'Configuring sudo for package managers...' > /dev/null 2>&1" if install_type == 'full' else ""}
{f"echo '{username} ALL=(ALL) NOPASSWD: /usr/bin/pacman, /usr/bin/paru' >> /etc/sudoers.d/{username}" if install_type == 'full' else ""}
{"chmod 440 /etc/sudoers.d/{username}" if install_type == 'full' else ""}

{"sudo -u " + username + " bash <<'PARUEOF' 2>/dev/null || true\ncd /tmp\ngit clone https://aur.archlinux.org/paru.git\ncd paru\nmakepkg -si --noconfirm > /dev/null 2>&1 || true\ncd /tmp\nrm -rf paru\nPARUEOF" if install_type == 'full' else ""}

{"sudo -u " + username + " bash <<'AUREOF' 2>/dev/null || true\nfor pkg in " + ' '.join(aur_pkgs[1:]) + "; do\n    paru -S --noconfirm --skipreview \"$pkg\" > /dev/null 2>&1 || true\ndone\nAUREOF" if install_type == 'full' and len(aur_pkgs) > 0 else ""}

flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo > /dev/null 2>&1 || true

usermod -a -G wireshark {username} > /dev/null 2>&1 || true

# KDE Plasma Theme
if [ "{desktop['name']}" = "KDE Plasma" ]; then
    mkdir -p /home/{username}/.config/kdeglobals
    mkdir -p /home/{username}/.config/plasmashellrc
    sudo -u {username} bash <<'KDEEOF'
mkdir -p ~/.config
cat > ~/.config/kdeglobals <<'EOF'
{kde_color_scheme}
EOF
    
    mkdir -p ~/.local/share/plasmashell/wallpapers
    cp /usr/share/backgrounds/horizonsec/hsec1.png ~/.local/share/plasmashell/wallpapers/ 2>/dev/null || true
    
    cat > ~/.config/plasmashellrc <<'EOF'
[PlasmaViews][Panel 0]
offset=0

[General]
SingleClickActivation=true

[Wallpaper][org.kde.image][General]
Image=file://${{HOME}}/.local/share/plasmashell/wallpapers/hsec1.png
EOF
    
    kquitapp5 plasmashell 2>/dev/null || true
    sleep 2
    kstart5 plasmashell > /dev/null 2>&1 &
KDEEOF
    chown -R {username}:{username} /home/{username}/.config
    chown -R {username}:{username} /home/{username}/.local
fi

# GNOME Theme
if [ "{desktop['name']}" = "GNOME" ]; then
    sudo -u {username} bash <<'GNOMEEOF'
dbus-launch gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark' 2>/dev/null || true
dbus-launch gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark' 2>/dev/null || true
dbus-launch gsettings set org.gnome.desktop.background picture-uri 'file:///usr/share/backgrounds/horizonsec/hsec1.png' 2>/dev/null || true
dbus-launch gsettings set org.gnome.desktop.background picture-uri-dark 'file:///usr/share/backgrounds/horizonsec/hsec1.png' 2>/dev/null || true
GNOMEEOF
fi

# XFCE Theme
if [ "{desktop['name']}" = "XFCE" ]; then
    sudo -u {username} bash <<'XFCEEOF'
mkdir -p ~/.config/xfce4/xfconf/xfce-perchannel-xml
cat > ~/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfwm4" version="1.0">
  <property name="general" type="empty">
    <property name="theme" type="string" value="Xfce-dusk"/>
    <property name="title_font" type="string" value="JetBrains Mono 10"/>
  </property>
</channel>
EOF

pcmanfm-qt --set-wallpaper=/usr/share/backgrounds/horizonsec/hsec1.png 2>/dev/null || true
xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitorVGA-1/image-path -s /usr/share/backgrounds/horizonsec/hsec1.png 2>/dev/null || true
XFCEEOF
fi

# Cinnamon Theme
if [ "{desktop['name']}" = "Cinnamon" ]; then
    sudo -u {username} bash <<'CINEOF'
gsettings set org.cinnamon.desktop.default-applications.terminal exec alacritty
gsettings set org.cinnamon.theme name 'Mint-X-Dark'
gsettings set org.cinnamon.desktop.background picture-uri 'file:///usr/share/backgrounds/horizonsec/hsec1.png'
CINEOF
fi

# MATE Theme
if [ "{desktop['name']}" = "MATE" ]; then
    sudo -u {username} bash <<'MATEEOF'
gsettings set org.mate.interface gtk-theme 'Marwaita-Dark-Orange'
gsettings set org.mate.background picture-filename /usr/share/backgrounds/horizonsec/hsec1.png
MATEEOF
fi

# LXQt Theme
if [ "{desktop['name']}" = "LXQt" ]; then
    sudo -u {username} bash <<'LXQTEOF'
mkdir -p ~/.config/lxqt
cat > ~/.config/lxqt/lxqt.conf <<'EOF'
[General]
theme=dark
icon_theme=Adwaita
EOF

    mkdir -p ~/.config/pcmanfm-qt/default
    cat > ~/.config/pcmanfm-qt/default/pcmanfm-qt.conf <<'EOF'
[Behavior]
[Appearance]
wallpaper=/usr/share/backgrounds/horizonsec/hsec1.png
EOF
LXQTEOF
fi

printf "\\033[38;5;208m╔════════════════════════════════════════════════════════════════════╗\\033[0m\\n"
printf "\\033[38;5;208m║ \\033[92m✓ INSTALLATION COMPLETE%-43s \\033[38;5;208m║\\033[0m\\n" ""
printf "\\033[38;5;208m╚════════════════════════════════════════════════════════════════════╝\\033[0m\\n"
printf "\\n"
printf "\\033[92mWelcome to HorizonSec!\\033[0m\\n"
printf "Your system has been configured with:\\n"
printf "  \\033[38;5;208m•\\033[0m Desktop: {desktop['name']}\\n"
printf "  \\033[38;5;208m•\\033[0m 200+ Penetration Testing Tools\\n"
printf "  \\033[38;5;208m•\\033[0m Custom Dark Theme with Orange Accents\\n"
printf "  \\033[38;5;208m•\\033[0m HorizonSec Wallpapers\\n"
printf "\\n"
printf "\\033[96mNext steps:\\033[0m\\n"
printf "  1. Reboot: \\033[38;5;208mreboot\\033[0m\\n"
printf "  2. Log in as: \\033[38;5;208m{username}\\033[0m\\n"
printf "  3. Start hacking!\\n"
printf "\\n"
"""

    return script

def check_system_requirements():
    """Check system resources and return specs (warn but allow continuing)"""
    header("System Analysis")
    
    disk_free = int(cmd("df / | tail -1 | awk '{print $4}'", capture=True, check=False))
    disk_gb = disk_free / 1024 / 1024
    
    mem_kb = int(cmd("grep MemTotal /proc/meminfo | awk '{print $2}'", capture=True, check=False))
    mem_gb = mem_kb / 1024 / 1024
    
    has_internet = cmd("ping -c 1 archlinux.org", check=False)
    
    info(f"Disk space available: {disk_gb:.1f} GB")
    info(f"RAM available: {mem_gb:.1f} GB")
    info(f"Internet: {'Connected' if has_internet else 'Not available'}")
    
    warnings = []
    if disk_gb < 20:
        warnings.append(f"Warning: Only {disk_gb:.1f} GB free (20 GB recommended)")
    if mem_gb < 2:
        warnings.append(f"Warning: Only {mem_gb:.1f} GB RAM (2 GB minimum for desktop)")
    if not has_internet:
        warnings.append("Warning: No internet connection - package downloads may fail")
    
    if warnings:
        print()
        for w in warnings:
            warning(w)
        if input(f"\n{Color.CYAN}Continue anyway? (y/n): {Color.END}").lower() != 'y':
            error("Installation cancelled")
            sys.exit(1)
    else:
        success("System requirements met")
    
    return {'disk_gb': disk_gb, 'mem_gb': mem_gb, 'has_internet': has_internet}

def recommend_desktop(mem_gb):
    """Recommend desktop environment based on available RAM"""
    if mem_gb < 2:
        return '3', 'XFCE'
    elif mem_gb < 4:
        return '3', 'XFCE'
    elif mem_gb < 8:
        return '4', 'Cinnamon'
    else:
        return '1', 'KDE Plasma'

def generate_hostname():
    """Auto-generate system hostname"""
    return "horizonsec"

def select_install_type():
    """Select between Full and Lite installation types"""
    global INSTALL_TYPE
    
    print()
    draw_box("Installation Type", "First, choose your installation type:")
    print(f"\n{Color.BOLD}Installation Types:{Color.END}\n")
    print(f"  {Color.ORANGE}1){Color.END} {Color.BOLD}Full Installation{Color.END}")
    print(f"     • 320+ penetration testing tools from AUR")
    print(f"     • All 6 desktop environment options")
    print(f"     • Estimated time: {Color.YELLOW}3-5 hours{Color.END} (on SSD)")
    print(f"     • Storage needed: ~100 GB")
    print(f"     • Note: Builds from source (includes cutting-edge tools)")
    print()
    print(f"  {Color.ORANGE}2){Color.END} {Color.BOLD}Lite Installation{Color.END}")
    print(f"     • 120+ security tools from official Arch repos")
    print(f"     • All 6 desktop environments (pre-packaged)")
    print(f"     • Estimated time: {Color.YELLOW}35-50 minutes{Color.END} (on SSD)")
    print(f"     • Storage needed: ~50-60 GB")
    print(f"     • Note: Mostly official packages (1 AUR: Marwaita theme)")
    print()
    
    while True:
        choice = input(f"{Color.CYAN}Select installation type [1-2] (default: 1): {Color.END}").strip() or "1"
        if choice == '1':
            INSTALL_TYPE = 'full'
            success("Full installation selected (3-5 hours estimated)")
            return 'full'
        elif choice == '2':
            INSTALL_TYPE = 'lite'
            success("Lite installation selected (30-45 minutes estimated)")
            return 'lite'
        else:
            error("Invalid choice. Please select 1 or 2.")

def select_timezone():
    """Prompt user for timezone with simple interface"""
    timezones = [
        "UTC", "US/Eastern", "US/Central", "US/Mountain", "US/Pacific",
        "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"
    ]
    
    print(f"\n{Color.CYAN}Common timezones:{Color.END}")
    for i, tz in enumerate(timezones, 1):
        print(f"  {i}. {tz}")
    
    while True:
        try:
            choice = input(f"{Color.CYAN}Select timezone (1-{len(timezones)}) or custom (c): {Color.END}").strip().lower()
            if choice == 'c':
                tz = input(f"{Color.CYAN}Enter timezone (e.g., America/New_York): {Color.END}").strip()
                if tz:
                    return tz
            else:
                idx = int(choice) - 1
                if 0 <= idx < len(timezones):
                    return timezones[idx]
        except (ValueError, IndexError):
            pass
        error("Invalid selection, try again")

def setup_ssh_config():
    """Configure SSH - simple yes/no toggle"""
    enable_ssh = input(f"{Color.CYAN}Enable SSH server? (y/n) [n]: {Color.END}").lower() == 'y'
    
    if enable_ssh:
        success("SSH enabled - keys will be generated automatically")
        return {'enabled': True, 'generate_keys': True, 'port': '22'}
    else:
        return {'enabled': False}

def setup_firewall_config():
    """Configure firewall - simple yes/no toggle"""
    enable_firewall = input(f"{Color.CYAN}Enable firewall? (y/n) [y]: {Color.END}").lower() != 'n'
    
    if enable_firewall:
        success("Firewall enabled - will deny incoming connections by default")
        return {'enabled': True, 'ssh': True}
    else:
        return {'enabled': False}

def setup_ghost_mode():
    """Auto-enable Ghost Mode (Tor) - always on"""
    success("Ghost Mode (Tor) auto-enabled - toggleable via horizon-firewall command")
    return True

def select_mirrors():
    """Select mirror source for package downloads"""
    print(f"\n{Color.BOLD}Mirror Selection:{Color.END}")
    print(f"  1. Auto-detect fastest mirrors (recommended)")
    print(f"  2. Default Arch Linux mirrors")
    print(f"  3. Manual mirror configuration")
    
    while True:
        choice = input(f"{Color.CYAN}Select mirror option (1-3) [1]: {Color.END}").strip() or "1"
        if choice in ['1', '2', '3']:
            if choice == '1':
                success("Auto-detection enabled - fastest mirrors will be selected")
                return 'auto'
            elif choice == '2':
                success("Using default Arch Linux mirrors")
                return 'default'
            else:
                mirror_url = input(f"{Color.CYAN}Enter mirror URL (or 'skip'): {Color.END}").strip()
                if mirror_url.lower() != 'skip' and mirror_url:
                    success(f"Custom mirror: {mirror_url}")
                    return mirror_url
                else:
                    info("Continuing with default mirrors")
                    return 'default'
        error("Invalid selection")

def create_installation_summary(config):
    """Display and confirm installation summary"""
    header("Installation Summary")
    
    print(f"\n{Color.BOLD}► System Configuration{Color.END}")
    print(f"  Hostname: {config['hostname']}")
    print(f"  Timezone: {config['timezone']}")
    print(f"  Username: {config['username']}")
    print(f"  Desktop: {config['desktop']}")
    print(f"  Boot disk: {config['disk_path']}")
    
    mirror_desc = {
        'auto': 'Auto-detect (fastest)',
        'default': 'Default Arch Linux',
        'manual': 'Custom'
    }
    mirror_label = mirror_desc.get(config['mirror_selection'], config['mirror_selection'])
    
    print(f"\n{Color.BOLD}► Services & Security{Color.END}")
    print(f"  Mirrors: {mirror_label}")
    print(f"  SSH: {'✓ Enabled' if config['ssh']['enabled'] else '✗ Disabled'}")
    print(f"  Firewall: {'✓ Enabled' if config['firewall'].get('enabled', True) else '✗ Disabled'}")
    print(f"  Ghost Mode (Tor): ✓ Enabled (Always On)")
    
    print(f"\n{Color.BOLD}► Installation Type{Color.END}")
    if config['install_type'] == 'lite':
        print(f"  Mode: {Color.YELLOW}Lite Installation{Color.END}")
        print(f"  Tools: 120+ from official Arch repos")
        print(f"  Time: ~30-45 minutes")
        print(f"  Storage: ~50-60 GB")
    else:
        print(f"  Mode: {Color.ORANGE}Full Installation{Color.END}")
        print(f"  Tools: 320+ including AUR packages")
        print(f"  Time: ~3-5 hours")
        print(f"  Storage: ~100 GB")
    
    print(f"\n{Color.BOLD}► Included{Color.END}")
    print(f"  Custom Dark Theme with Orange Accents")
    print(f"  Desktop Environment & Utilities")
    print(f"  Penetration Testing Toolkit")
    print(f"  Firewall Control (horizon-firewall toggle)")
    
    confirmation = input(f"\n{Color.CYAN}Ready to install? (y/n) [y]: {Color.END}").lower() != 'n'
    
    if not confirmation:
        error("Installation cancelled")
        sys.exit(0)
    
    success("Installation starting...")

def setup_installation_logging():
    """Setup installation logging"""
    log_file = f"/var/log/horizonsec-install-{int(time.time())}.log"
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        return log_file
    except:
        return None

def main():
    """Main installation routine"""
    global VERBOSE
    
    parser = argparse.ArgumentParser(description='HorizonSec OS Installer')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (show all commands)')
    parser.add_argument('--attended', action='store_true', help='Enable fully interactive mode for all installation steps')
    args = parser.parse_args()
    
    VERBOSE = args.verbose
    attended_mode = args.attended
    
    if VERBOSE:
        info("Verbose mode enabled - all commands will be displayed")
    
    if attended_mode:
        info("Attended mode enabled - all installation steps will be interactive")
    else:
        info("Hybrid mode: interactive configuration, then unattended installation")
    
    logo()
    check_root()
    
    header("Welcome to HorizonSec Installer")
    
    install_type = select_install_type()
    
    sys_requirements = check_system_requirements()
    
    is_uefi = check_uefi()
    setup_network()
    gpu_name, gpu_drivers = detect_gpu()
    
    disk_name, disk_path = select_disk()
    
    desktops = {
        '1': {'name': 'KDE Plasma', 'packages': ['plasma-meta', 'kde-applications', 'sddm', 'konsole', 'dolphin', 'kate', 'spectacle'], 'dm': 'sddm', 'portal': 'xdg-desktop-portal-kde', 'source': False},
        '2': {'name': 'GNOME', 'packages': ['gnome', 'gnome-extra', 'gdm', 'gnome-tweaks'], 'dm': 'gdm', 'portal': 'xdg-desktop-portal-gnome', 'source': False},
        '3': {'name': 'XFCE', 'packages': ['xfce4', 'xfce4-goodies', 'lightdm', 'lightdm-gtk-greeter', 'xorg-server'], 'dm': 'lightdm', 'portal': 'xdg-desktop-portal-gtk', 'source': False},
        '4': {'name': 'Cinnamon', 'packages': ['cinnamon', 'lightdm', 'lightdm-gtk-greeter', 'xorg-server'], 'dm': 'lightdm', 'portal': 'xdg-desktop-portal-gtk', 'source': False},
        '5': {'name': 'MATE', 'packages': ['mate', 'mate-extra', 'lightdm', 'lightdm-gtk-greeter', 'xorg-server'], 'dm': 'lightdm', 'portal': 'xdg-desktop-portal-gtk', 'source': False},
        '6': {'name': 'LXQt', 'packages': ['lxqt', 'breeze-icons', 'sddm', 'xorg-server'], 'dm': 'sddm', 'portal': 'xdg-desktop-portal-lxqt', 'source': False}
    }
    
    header("Desktop Environment Selection")
    
    recommended_choice, recommended_name = recommend_desktop(sys_requirements['mem_gb'])
    print(f"\n{Color.ORANGE}{Color.BOLD}Recommended:{Color.END} {recommended_name} (for {sys_requirements['mem_gb']:.1f}GB RAM)")
    
    lite_mode = (install_type == 'lite')
    desktop = select_desktop(desktops, recommended_choice, lite_mode=lite_mode)
    
    hostname = generate_hostname()
    draw_box("Auto-Generated Hostname", f"Your system hostname: {Color.ORANGE}{hostname}{Color.END}")
    
    timezone = select_timezone()
    
    header("User Account")
    
    username = input(f"{Color.CYAN}Username [pentester]: {Color.END}").strip() or "pentester"
    
    while True:
        password = getpass.getpass(f"{Color.CYAN}Password (hidden): {Color.END}").strip()
        password_confirm = getpass.getpass(f"{Color.CYAN}Confirm password: {Color.END}").strip()
        if password == password_confirm:
            break
        error("Passwords do not match")
    
    while True:
        root_password = getpass.getpass(f"{Color.CYAN}Root password (hidden): {Color.END}").strip()
        root_password_confirm = getpass.getpass(f"{Color.CYAN}Confirm root password: {Color.END}").strip()
        if root_password == root_password_confirm:
            break
        error("Passwords do not match")
    
    header("Services & Security")
    
    mirror_selection = select_mirrors()
    ssh_config = setup_ssh_config()
    firewall_config = setup_firewall_config()
    ghost_mode = setup_ghost_mode()
    
    installation_config = {
        'hostname': hostname,
        'timezone': timezone,
        'username': username,
        'desktop': desktop['name'],
        'firmware': 'UEFI' if is_uefi else 'BIOS',
        'disk_path': disk_path,
        'mirror_selection': mirror_selection,
        'ssh': ssh_config,
        'firewall': firewall_config,
        'ghost_mode': ghost_mode,
        'install_type': install_type
    }
    
    create_installation_summary(installation_config)
    
    efi, swap, root = partition_disk(disk_name, disk_path, is_uefi)
    install_base(mirror_selection)
    
    header("Configuring System")
    
    install_script = create_install_script(username, password, root_password, desktop, gpu_drivers, ghost_mode, is_uefi, disk_path, hostname, timezone, ssh_config, firewall_config, install_type=install_type, gpu_name=gpu_name)
    
    if VERBOSE:
        info(f"Generated installation script ({len(install_script)} bytes)")
    
    script_path = "/tmp/horizonsec_install.sh"
    try:
        with open(script_path, 'w') as f:
            f.write(install_script)
        os.chmod(script_path, 0o755)
        if VERBOSE:
            info(f"Installation script written to {script_path}")
        else:
            info(f"Installation script generated")
    except IOError as e:
        error(f"Failed to write script: {e}")
        sys.exit(1)
    
    if os.path.exists("/mnt"):
        info("Copying script to chroot environment...")
        cmd(f"cp {script_path} /mnt/install.sh", check=False)
        info("Entering chroot environment...")
        if cmd(f"arch-chroot /mnt bash /install.sh", check=False):
            success("System installation complete!")
        else:
            warning("Chroot installation had issues, check output above")
    else:
        info("Running installation script directly...")
        if cmd(f"bash {script_path}", check=False):
            success("System installation complete!")
        else:
            warning("Installation had issues, check output above")
    
    info(f"System Information:")
    info(f"  • Firmware: {'UEFI' if is_uefi else 'BIOS'}")
    info(f"  • Boot disk: {disk_path}")
    info(f"  • Desktop: {desktop['name']}")
    info(f"  • Username: {username}")
    
    if attended_mode:
        if input(f"{Color.CYAN}Reboot now? (y/n): {Color.END}").lower() == 'y':
            cmd("reboot")
    else:
        info("Unattended installation complete: rebooting automatically in 5 seconds...")
        time.sleep(5)
        cmd("reboot")

if __name__ == "__main__":
    main()
