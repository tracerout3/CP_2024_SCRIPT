#!/bin/bash
# System Hardening Script (Safe + Hardened Config Pull + User Management)
# Target: Debian/Ubuntu-based systems (systemd)
# Requires: bash 4+, curl

set -euo pipefail

# --- Configurable inputs (edit these as needed) ---
# Format: "username:group1,group2"
ADD_USERS=(
    # "alice:sudo,docker"
    # "charlie:www-data"
)

# Users to delete (will remove home directories)
DELETE_USERS=(
    # "bob"
)

# Change groups for existing users (replace memberships)
# Format: "username:group1,group2"
CHANGE_GROUPS=(
    # "dave:sudo,www-data"
)

# --- Constants ---
LOGFILE="/var/log/hardening.log"
RAW_BASE="https://raw.githubusercontent.com/tracerout3/CP_2024_SCRIPT/main/HardFiles"

# ANSI colors
RED="\033[0;31m"
NC="\033[0m" # No Color

# --- Utility functions ---
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOGFILE"
}

backup_file() {
    local path="$1"
    if [[ -f "$path" ]]; then
        local ts
        ts="$(date '+%Y%m%d_%H%M%S')"
        cp -a "$path" "${path}.bak_${ts}"
        log "Backed up $path -> ${path}.bak_${ts}"
    fi
}

fetch_hardened() {
    local file="$1" dest="$2"
    curl -fsSL "${RAW_BASE}/${file}" -o "${dest}"
    log "Fetched hardened file ${file} -> ${dest}"
}

is_service_active() {
    local svc="$1"
    systemctl is-active --quiet "$svc"
}

restart_service() {
    local svc="$1"
    if systemctl restart "$svc"; then
        log "Restarted service: $svc"
    else
        log "WARNING: Failed to restart $svc; please check journalctl -u $svc"
    fi
}

# --- User management functions ---
add_user() {
    local user="$1" groups="$2"
    if id "$user" &>/dev/null; then
        log "User $user already exists; skipping add."
    else
        useradd -m -s /bin/bash -G "$groups" "$user"
        log "Added user $user with groups: $groups"
        passwd -l "$user" || true
        log "Locked $user until password is set securely."
    fi
}

delete_user() {
    local user="$1"
    if id "$user" &>/dev/null; then
        userdel -r "$user"
        log "Deleted user $user and removed home directory."
    else
        log "User $user not found; skipping delete."
    fi
}

change_groups() {
    local user="$1" groups="$2"
    if id "$user" &>/dev/null; then
        usermod -G "$groups" "$user"
        log "Changed groups for $user -> $groups"
    else
        log "User $user not found; cannot change groups."
    fi
}

report_users() {
    log "Generating user report (sudo highlighted in red)..."
    echo -e "\n=== User Report ==="
    while IFS=: read -r username _ uid gid _ home shell; do
        # Consider regular interactive users (UID >= 1000) and valid shells
        if [[ "$uid" -ge 1000 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
            if groups "$username" | grep -qw "sudo"; then
                echo -e "${RED}${username}${NC} (UID:$uid, Home:$home, Shell:$shell, Groups: $(groups "$username"))"
            else
                echo "$username (UID:$uid, Home:$home, Shell:$shell, Groups: $(groups "$username"))"
            fi
        fi
    done < /etc/passwd
    echo "====================="
}

# --- 0. Preconditions ---
log "Ensuring required tools are present..."
apt-get update -y
apt-get install -y curl ufw auditd

# --- 1. Update system packages ---
log "Updating system packages..."
apt-get upgrade -y

# --- 2. User management (add/delete/change groups + auditing) ---
log "Applying user management actions..."

# Add users
for entry in "${ADD_USERS[@]}"; do
    IFS=":" read -r u g <<< "$entry"
    add_user "$u" "$g"
done

# Delete users
for u in "${DELETE_USERS[@]}"; do
    delete_user "$u"
done

# Change groups
for entry in "${CHANGE_GROUPS[@]}"; do
    IFS=":" read -r u g <<< "$entry"
    change_groups "$u" "$g"
done

# Password aging defaults for new accounts
log "Configuring default password aging for new accounts..."
backup_file /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
log "Updated /etc/login.defs (max 90, min 7, warn 14)."

# Apply password aging to existing interactive users
log "Enforcing password aging for interactive users..."
for user in $(awk -F: '$7 ~ /(\/bin\/bash|\/bin\/zsh)$/ {print $1}' /etc/passwd); do
    if [[ "$user" != "root" ]]; then
        chage --maxdays 90 --mindays 7 --warn 14 "$user" || true
        log "Set aging for $user."
    fi
done

# Lock non-essential system accounts (UID < 1000), keep core ones
log "Locking non-essential system accounts (UID < 1000)..."
for user in $(awk -F: '$3 < 1000 {print $1}' /etc/passwd); do
    case "$user" in
        root|sync|shutdown|halt) ;; # keep essential
        *)
            passwd -l "$user" 2>/dev/null || true
            ;;
    esac
done
log "System accounts locked where appropriate."

# Fix home directory permissions
log "Securing home directory permissions..."
for dir in /home/*; do
    [[ -d "$dir" ]] && chmod 700 "$dir" && log "Set 700 on $dir"
done

# Show report
report_users

# --- 3. PAM password quality (non-destructive append) ---
log "Configuring PAM password quality..."
if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3" >> /etc/pam.d/common-password
    log "Enforced pam_pwquality in common-password."
else
    log "pam_pwquality already present; skipping."
fi

# --- 4. UFW firewall baseline ---
log "Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
yes | ufw enable
log "UFW enabled: deny inbound by default, allow SSH."

# --- 5. Disable insecure legacy services if present ---
log "Disabling insecure legacy services (if present)..."
for svc in telnet ftp rlogin rexec; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
        systemctl disable "$svc" || true
        systemctl stop "$svc" || true
        log "Disabled/stopped $svc."
    fi
done

# --- 6. Baseline SSH hardening (before hardened replacement) ---
log "Applying baseline SSH hardening..."
SSHD_CONFIG="/etc/ssh/sshd_config"
backup_file "$SSHD_CONFIG"
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
sed -i 's/^#\?UsePAM.*/UsePAM yes/' "$SSHD_CONFIG"
restart_service "ssh" || restart_service "sshd"

# --- 7. Remove world-writable permissions ---
log "Removing world-writable permissions on files and directories..."
find / -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null || true
find / -xdev -type d -perm -0002 -exec chmod o-w {} \; 2>/dev/null || true

# --- 8. Enable auditing ---
log "Ensuring auditd is enabled..."
systemctl enable auditd
systemctl start auditd

# --- 9. Pull and apply hardened configs for active services ---
log "Pulling hardened configs for active services..."

declare -a MAP=(
    "apache2|/etc/apache2/apache2.conf|apache2.conf"
    "nginx|/etc/nginx/nginx.conf|nginx.conf"
    "ssh|/etc/ssh/sshd_config|sshd_config"
    "sshd|/etc/ssh/sshd_config|sshd_config"
    "squid|/etc/squid/squid.conf|squid.conf"
    "vsftpd|/etc/vsftpd.conf|vsftpd.conf"
    "smbd|/etc/samba/smb.conf|smb.conf"
    "cups|/etc/cups/cupsd.conf|cupsd.conf"
    "clamav-daemon|/etc/clamav/clamd.conf|clamd.conf"
    "bind9|/etc/bind/named.conf.options|named.conf.options"
    "tomcat9|/etc/tomcat9/server.xml|server.xml"
)

for entry in "${MAP[@]}"; do
    IFS="|" read -r svc path repo <<< "$entry"
    if is_service_active "$svc"; then
        log "Active service: $svc — applying hardened $repo to $path"
        backup_file "$path"
        tmp="$(mktemp)"
        fetch_hardened "$repo" "$tmp"
        case "$svc" in
            nginx)
                if nginx -t -c "$tmp"; then
                    cp "$tmp" "$path"
                    restart_service "$svc"
                else
                    log "ERROR: nginx config test failed; not applying."
                fi
                ;;
            apache2)
                if apache2ctl -t -f "$tmp"; then
                    cp "$tmp" "$path"
                    restart_service "$svc"
                else
                    log "ERROR: apache2 config test failed; not applying."
                fi
                ;;
            ssh|sshd)
                cp "$tmp" "$path"
                if command -v sshd >/dev/null 2>&1 && sshd -t 2>/dev/null; then
                    restart_service "$svc"
                else
                    log "WARNING: sshd config test reported issues or sshd missing; review before restart."
                fi
                ;;
            *)
                cp "$tmp" "$path"
                restart_service "$svc"
                ;;
        esac
        rm -f "$tmp"
    else
        log "Service not active: $svc — skipping $repo"
    fi
done

# --- User Management Function ---

manage_users() {
    # ANSI colors
    RED="\033[0;31m"
    NC="\033[0m" # No Color

    log() {
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "/var/log/hardening.log"
    }

    add_user() {
        local user="$1" groups="$2"
        if id "$user" &>/dev/null; then
            log "User $user already exists."
        else
            useradd -m -s /bin/bash -G "$groups" "$user"
            log "Added user $user with groups: $groups"
            passwd -l "$user" || true
            log "Locked $user until a secure password is set."
        fi
    }

    delete_user() {
        local user="$1"
        if id "$user" &>/dev/null; then
            userdel -r "$user"
            log "Deleted user $user"
        else
            log "User $user not found."
        fi
    }

    change_groups() {
        local user="$1" groups="$2"
        if id "$user" &>/dev/null; then
            usermod -G "$groups" "$user"
            log "Changed groups for $user -> $groups"
        else
            log "User $user not found."
        fi
    }

    report_users() {
        log "Generating user report..."
        echo -e "\n=== User Report ==="
        while IFS=: read -r username _ uid gid _ home shell; do
            if [[ "$uid" -ge 1000 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
                if groups "$username" | grep -qw "sudo"; then
                    echo -e "${RED}${username}${NC} (UID:$uid, Groups: $(groups "$username"))"
                else
                    echo "$username (UID:$uid, Groups: $(groups "$username"))"
                fi
            fi
        done < /etc/passwd
        echo "====================="
    }

    while true; do
        echo "Choose an action:"
        echo "1) Add user"
        echo "2) Delete user"
        echo "3) Change groups"
        echo "4) Report users"
        read -rp "Enter choice [1-4]: " choice

        case "$choice" in
            1)
                read -rp "Enter username to add: " u
                read -rp "Enter groups (comma-separated): " g
                add_user "$u" "$g"
                ;;
            2)
                read -rp "Enter username to delete: " u
                delete_user "$u"
                ;;
            3)
                read -rp "Enter username to modify: " u
                read -rp "Enter new groups (comma-separated): " g
                change_groups "$u" "$g"
                ;;
            4)
                report_users
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac

        read -rp "Do you want to manage another user? (y/n): " again
        [[ "$again" =~ ^[Yy]$ ]] || break
    done
}

manage_users


# --- Safer Package Removal Function ---
remove_unwanted_packages() {
    log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "/var/log/hardening.log"; }

    # List excludes critical system packages and core services
    PACKAGES=(
        beef bettercap burpsuite canvas caine core-impact cryptcat cain cowpatty dsniff ettercap
        fping foremost freeciv grendel-scan hashcat hping3 inssider john kismet l0phtcrack medusa
        mimikatz minetest minetest-server ngrep nikto nmap netscan openvas ophcrack powersploit
        pcredz reaver reelphish sqlmap superscan tftpd tightvncserver truecrack vega wifiphisher
        wifite x11vnc zap zenmap
        steam lutris playonlinux wine dosbox scummvm mame zsnes snes9x ppsspp cemu yuzu citra
        retroarch rpcs3 pcsx2 dolphin-emu fceux mednafen kega-fusion openra wine-staging vulkan-utils
        steamcmd bottles heroic-games-launcher gamehub feral-games lincity-ng trello tigervnc-viewer
        qbittorrent transmission deluge frostwire ktorrent aria2 fusee freedownloadmanager rtorrent
        monsoon popcorn-time jdownloader
        unrar p7zip rar libtorrent webtorrent-cli torrentfile nload iftop speedometer utorrent
        bittorrent filezilla syncthing torrentflux plex emby
        supertuxkart 0ad wesnoth tome bastion warsow xonotic red-eclipse hexen2 pioneer openxcom
        naev flames-of-revenge crea frozen-bubble darkplaces unvanquished freedoom glest megaglest
        battle-for-wesnoth liberated-pixel-cup super-tux the-curse teeworlds gargoyle zaz spring
    )

    log "Starting removal of non-essential packages..."
    for pkg in "${PACKAGES[@]}"; do
        if dpkg -l | grep -qw "$pkg"; then
            log "Removing $pkg..."
            apt-get purge -y "$pkg"
        else
            log "Package $pkg not installed; skipping."
        fi
    done
    apt-get autoremove -y
    apt-get clean
    log "Package removal complete."


# --- 10. Apply hardened sysctl.conf and reload ---
SYSCTL_LOCAL="/etc/sysctl.conf"
log "Applying hardened sysctl.conf..."
backup_file "$SYSCTL_LOCAL"
tmp_sysctl="$(mktemp)"
fetch_hardened "sysctl.conf" "$tmp_sysctl"
cp "$tmp_sysctl" "$SYSCTL_LOCAL"
rm -f "$tmp_sysctl"
if sysctl -p; then
    log "Kernel parameters reloaded via sysctl -p."
else
    log "WARNING: sysctl -p reported errors; review /etc/sysctl.conf."
fi

log "Hardened configuration deployment complete."

# Disable guest, auto-login, and root login for display managers
secure_login_managers() {
    log "Securing LightDM, GDM, and SDDM login managers..."
    for manager in lightdm gdm sddm; do
        if systemctl is-active --quiet "$manager"; then
            log "Hardening $manager..."
            case "$manager" in
                lightdm)
                    sed -i '/^allow-guest=/c\allow-guest=false' /etc/lightdm/lightdm.conf 2>/dev/null || echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
                    sed -i '/^autologin-user=/c\#autologin-user=' /etc/lightdm/lightdm.conf
                    sed -i '/^greeter-show-manual-login=/c\greeter-show-manual-login=false' /etc/lightdm/lightdm.conf
                    ;;
                gdm)
                    sed -i '/^AllowGuest=/c\AllowGuest=false' /etc/gdm/custom.conf 2>/dev/null || echo "AllowGuest=false" >> /etc/gdm/custom.conf
                    sed -i '/^AutomaticLoginEnable=/c\AutomaticLoginEnable=false' /etc/gdm/custom.conf
                    sed -i '/^EnableRoot=/c\EnableRoot=false' /etc/gdm/custom.conf
                    ;;
                sddm)
                    sed -i '/^AllowGuest=/c\AllowGuest=false' /etc/sddm.conf 2>/dev/null || echo "AllowGuest=false" >> /etc/sddm.conf
                    sed -i '/^AutomaticLoginEnable=/c\AutomaticLoginEnable=false' /etc/sddm.conf
                    sed -i '/^EnableRootLogin=/c\EnableRootLogin=false' /etc/sddm.conf
                    ;;
            esac
        else
            log "$manager not running, skipping..."
        fi
    done
}

# Disable TCP connections to X server
disable_x_tcp() {
    log "Disabling TCP connections to the X server..."
    if [ -f /etc/X11/xorg.conf ]; then
        grep -q "DisableTCP" /etc/X11/xorg.conf || sed -i '/^Section "ServerFlags"/a \ \ Option "DisableTCP" "true"' /etc/X11/xorg.conf
    fi
    if [ -f /etc/X11/xinit/xserverrc ]; then
        sed -i 's/^.*X .*$/exec /usr/bin/X -nolisten tcp $DISPLAY/' /etc/X11/xinit/xserverrc
    fi
}

# Disable ICMP echo requests (ping)
disable_icmp_echo() {
    log "Blocking ICMP echo requests..."
    iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
}

# Prevent null passwords
disable_null_passwords() {
    log "Ensuring null passwords cannot authenticate..."
    if grep -q "nullok" /etc/pam.d/common-auth; then
        sed -i 's/nullok//g' /etc/pam.d/common-auth
        log "Removed nullok from common-auth."
    fi
    null_accounts=$(awk -F: '($2==""){print $1}' /etc/shadow)
    if [ -n "$null_accounts" ]; then
        for acc in $null_accounts; do
            usermod -L "$acc"
            log "Locked account $acc due to null password."
        done
    else
        log "No accounts with null passwords found."
    fi
}

# --- Run all hardening steps ---
secure_login_managers
disable_x_tcp
disable_icmp_echo
disable_null_passwords

log "Login managers, X server, ICMP, and PAM hardened."
