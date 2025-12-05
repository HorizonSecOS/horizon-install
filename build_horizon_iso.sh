#!/bin/bash

# HorizonSec ISO Builder - Beta 2
set -e 

# Color codes
ORANGE='\033[38;5;208m'
CYAN='\033[96m'
GREEN='\033[92m'
RED='\033[91m'
BOLD='\033[1m'
END='\033[0m'

# Error handling with color
error_exit() {
    echo -e "${RED}${BOLD}✗ ERROR on line $1. Build failed.${END}"
    exit 1
}
trap 'error_exit $LINENO' ERR

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}${BOLD}✗ This script must be run as root${END}"
    exit 1
fi

if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi

ISO_CONFIG_DIR="/tmp/horizonsec_profile"
ISO_WORK_DIR="/tmp/archiso-tmp" 
ISO_OUT_DIR="$(pwd)" 
INSTALLER_SCRIPT="horizon_installer.py"
BUILD_START=$(date +%s)

if [ ! -f "$INSTALLER_SCRIPT" ]; then 
    echo -e "${RED}${BOLD}✗ Installer script missing!${END}"
    exit 1
fi

echo -e "${ORANGE}${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║       HorizonSec ISO Builder - Beta 2            ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${END}"

if ! command -v convert &> /dev/null; then
    echo -e "${CYAN}→${END} Installing ImageMagick..."
    pacman -S --needed --noconfirm imagemagick > /dev/null 2>&1
fi

echo -e "${CYAN}→${END} Checking Archiso..."
pacman -S --needed --noconfirm archiso > /dev/null 2>&1

echo -e "${CYAN}→${END} Preparing build directory..."
rm -rf "$ISO_WORK_DIR"
[ ! -d "$ISO_CONFIG_DIR" ] && mkdir -p "$ISO_CONFIG_DIR" 

if [ ! -f "$ISO_CONFIG_DIR/profiledef.sh" ]; then
    echo -e "${CYAN}→${END} Copying Archiso base..."
    cp -r /usr/share/archiso/configs/releng/* "$ISO_CONFIG_DIR/" 2>/dev/null || true
fi

echo -e "${CYAN}→${END} Configuring ISO metadata..."
sed -i 's/iso_name="archlinux"/iso_name="horizonsec"/g' "$ISO_CONFIG_DIR/profiledef.sh"
sed -i 's/iso_label="ARCH_/iso_label="HORIZON_/g' "$ISO_CONFIG_DIR/profiledef.sh"

echo -e "${CYAN}→${END} Injecting tools..."
mkdir -p "$ISO_CONFIG_DIR/airootfs/usr/local/bin"
cp "$INSTALLER_SCRIPT" "$ISO_CONFIG_DIR/airootfs/usr/local/bin/horizon-install"
chmod 755 "$ISO_CONFIG_DIR/airootfs/usr/local/bin/horizon-install"
sed -i "/file_permissions=(/a \ \ [\"/usr/local/bin/horizon-install\"]=\"0:0:755\"" "$ISO_CONFIG_DIR/profiledef.sh"

if [ -f "horizon-firewall" ]; then
    cp "horizon-firewall" "$ISO_CONFIG_DIR/airootfs/usr/local/bin/horizon-firewall"
    chmod 755 "$ISO_CONFIG_DIR/airootfs/usr/local/bin/horizon-firewall"
    sed -i "/file_permissions=(/a \ \ [\"/usr/local/bin/horizon-firewall\"]=\"0:0:755\"" "$ISO_CONFIG_DIR/profiledef.sh"
fi

if [ -f "horizon-firewall.desktop" ]; then
    mkdir -p "$ISO_CONFIG_DIR/airootfs/usr/share/applications"
    cp "horizon-firewall.desktop" "$ISO_CONFIG_DIR/airootfs/usr/share/applications/horizon-firewall.desktop"
    chmod 644 "$ISO_CONFIG_DIR/airootfs/usr/share/applications/horizon-firewall.desktop"
fi

echo -e "${CYAN}→${END} Optimizing Pacman..."
sed -i 's/#Color/Color\nILoveCandy/g' "$ISO_CONFIG_DIR/pacman.conf"
sed -i 's/#ParallelDownloads = 5/ParallelDownloads = 10/g' "$ISO_CONFIG_DIR/pacman.conf"
sed -i "/\[multilib\]/,/Include/"'s/^#//' "$ISO_CONFIG_DIR/pacman.conf"

echo -e "${CYAN}→${END} Adding packages..."
if ! grep -q "arch-install-scripts" "$ISO_CONFIG_DIR/packages.x86_64"; then
    cat >> "$ISO_CONFIG_DIR/packages.x86_64" <<EOF

# Core Install Tools
arch-install-scripts
reflector
parted
python
# Networking
networkmanager
# Polish
fastfetch
gparted
firefox
git
wget
nano
vim
zsh
grml-zsh-config
tmux
EOF
fi

echo -e "${CYAN}→${END} Applying branding..."
find "$ISO_CONFIG_DIR/syslinux" -name "*.cfg" -exec sed -i 's/Arch Linux/HorizonSec/g' {} + 2>/dev/null || true
find "$ISO_CONFIG_DIR/efiboot" -name "*.conf" -exec sed -i 's/Arch Linux/HorizonSec/g' {} + 2>/dev/null || true
find "$ISO_CONFIG_DIR" -type f -name "*.cfg" -o -name "*.conf" -exec sed -i 's/Arch Linux install medium/HorizonSec Install Medium/g' {} + 2>/dev/null || true

cat > "$ISO_CONFIG_DIR/airootfs/etc/os-release" <<EOF
NAME="HorizonSec"
PRETTY_NAME="HorizonSec OS"
ID=horizonsec
ID_LIKE=arch
BUILD_ID=rolling
ANSI_COLOR="0;33"
HOME_URL="https://horizonsec.org/"
LOGO=horizonsec
EOF

# FASTFETCH
mkdir -p "$ISO_CONFIG_DIR/airootfs/etc/fastfetch"
mkdir -p "$ISO_CONFIG_DIR/airootfs/usr/share/fastfetch"

cat > "$ISO_CONFIG_DIR/airootfs/usr/share/fastfetch/horizon_logo.txt" <<'EOF'
*%                                     
                                                             @@++-                                   
                                                             %+@@                                    
                                                            ==@                                      
                                                      #*@% @@@                                       
                                                  @   =  @@%@                                        
                                            @%   *=@    @+@#@*@                                      
                                             +@  @@# @%@:@=- %@%                                     
                                       @-=@  +=@ +#@#=@:#=  @                                        
                                         *-:%%+%=#@-=@:+==%#                                         
                                     @+   *+@@::-%==@-*=:%* @                                    
                                      @*:--@-=::-*:@-*=:=%@+%=*@                                     
                                        @@+-=:-:::@-#=:+@%==:                                        
                                   %::*-=-%:==:===#@@@+=+=@+++%+@                                    
                                     %%++*%==-=========++=#==@                                       
                                        @=@%+======+=+=++%++#@                                       
                                     @+%+*@-@=++===++++=@@@@@=+#                                     
                                    @    @=@+*@==+++==@+:%+@                                         
                                        %-*@ @=+@=@+%=+@+@=+                                         
                                       @%%  @*=+ #:+* =+-  #+%                                       
                                       * @:+@  @-#  @+                                             
                                          @:+@   @+     @                                            
                                         +-+@     @+                                                 
                                         @@
EOF

cat > "$ISO_CONFIG_DIR/airootfs/etc/fastfetch/config.jsonc" <<EOF
{
    "\$schema": "https://github.com/fastfetch-cli/fastfetch/raw/dev/doc/json_schema.json",
    "logo": {
        "source": "/usr/share/fastfetch/horizon_logo.txt",
        "padding": { "top": 1, "right": 2 }
    },
    "display": { "color": "yellow" },
    "modules": [ "title", "separator", "os", "host", "kernel", "uptime", "packages", "shell", "cpu", "gpu", "memory", "disk", "break", "colors" ]
}
EOF

echo -e "${CYAN}→${END} Configuring live environment..."
cat >> "$ISO_CONFIG_DIR/airootfs/root/.zshrc" <<EOF
alias neofetch='fastfetch --config /etc/fastfetch/config.jsonc'
alias install='horizon-install'

clear
echo -e "\033[1;38;5;208mWelcome to HorizonSec Live Environment\033[0m"
echo "Type 'horizon-install' to begin installation"
EOF

echo -e "${CYAN}→${END} Processing wallpapers..."
DEST_BG_DIR="$ISO_CONFIG_DIR/airootfs/usr/share/backgrounds/horizon"
mkdir -p "$DEST_BG_DIR"
cp *.jpg "$DEST_BG_DIR/" 2>/dev/null || true
cp *.png "$DEST_BG_DIR/" 2>/dev/null || true
cp *.jpeg "$DEST_BG_DIR/" 2>/dev/null || true

shopt -s nullglob
WALLPAPERS=("$DEST_BG_DIR/"*.{jpg,png,jpeg})
shopt -u nullglob

if [ ${#WALLPAPERS[@]} -gt 0 ]; then
    if [ -f "$DEST_BG_DIR/hsec1.png" ]; then
        SELECTED_WP="$DEST_BG_DIR/hsec1.png"
    else
        SELECTED_WP="${WALLPAPERS[0]}"
        cp "$SELECTED_WP" "$DEST_BG_DIR/hsec1.png"
    fi
    ln -sf "/usr/share/backgrounds/horizon/hsec1.png" "$DEST_BG_DIR/default.jpg"

    SPLASH_TARGET="$ISO_CONFIG_DIR/syslinux/splash.png"
    if command -v convert &> /dev/null; then
        convert "$DEST_BG_DIR/hsec1.png" -resize 800x600! -colors 14 "$SPLASH_TARGET" 2>/dev/null
    else
        cp "$DEST_BG_DIR/hsec1.png" "$SPLASH_TARGET"
    fi
fi

echo -e "${ORANGE}${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║           Building HorizonSec ISO...             ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${END}"

mkarchiso -v -w "$ISO_WORK_DIR" -o "$ISO_OUT_DIR" "$ISO_CONFIG_DIR"

BUILD_END=$(date +%s)
BUILD_TIME=$((BUILD_END - BUILD_START))
BUILD_MINS=$((BUILD_TIME / 60))
BUILD_SECS=$((BUILD_TIME % 60))

echo ""
if ls "$ISO_OUT_DIR"/horizonsec-*.iso 1> /dev/null 2>&1; then
    ISO_FILE=$(ls -1t "$ISO_OUT_DIR"/horizonsec-*.iso | head -1)
    ISO_SIZE=$(du -h "$ISO_FILE" | cut -f1)
    echo -e "${GREEN}${BOLD}✓ SUCCESS!${END} ISO built in ${BUILD_MINS}m ${BUILD_SECS}s"
    echo -e "  File: ${ORANGE}$(basename $ISO_FILE)${END}"
    echo -e "  Size: ${ORANGE}${ISO_SIZE}${END}"
    echo -e "  Path: ${ORANGE}${ISO_OUT_DIR}${END}"
else
    echo -e "${RED}${BOLD}✗ Build failed${END}"
    exit 1
fi

echo ""