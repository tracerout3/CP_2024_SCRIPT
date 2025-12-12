#!/bin/bash
# System Hardening Script (Safe + Hardened Config Pull)
# Target: Debian/Ubuntu-based systems
# Requires: curl, systemd-based system

set -euo pipefail

LOGFILE="/var/log/hardening.log"
RAW_BASE="https://raw.githubusercontent.com/tracerout3/CP_2024_SCRIPT/main/HardFiles"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOGFILE"
}

backup_file() {
    local path="$1"
    if [[ -f "$path" ]]; then
        local ts
        ts="$(date '+%Y%m%d_%H%M%S')"
        cp -a "$path" "${path}.bak_${ts}"
        log "Backed up $path to ${path}.bak_${ts}"
    fi
}

fetch_hardened() {
    local file="$1" dest="$2"
    curl -fsSL "${RAW_BASE}/${file}" -o "${dest}"
    log "Fetched hardened file ${file} to ${dest}"
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
        log "WARNING: Failed to restart $svc; please check logs."
    fi
}

# --- 0. Preconditions ---
log "Ensuring required tools are present..."
apt-get update -y
apt-get install -y curl ufw auditd

# --- 1. Update system ---
log "Updating system packages..."
apt-get upgrade -y

# --- 2. Secure user accounts (conservative) ---
log "Reviewing local interactive accounts..."
for user in $(awk -F: '$7 ~ /(\/bin\/bash|\/bin\/zsh)$/ {print $1}' /etc/passwd); do
    if [[ "$user" != "root" ]]; then
        log "Found interactive account: $user (no action taken automatically)"
    fi
done

# --- 3. Enforce password policy ---
log "Configuring password policy..."
if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3" >> /etc/pam.d/common-password
    log "Password quality enforced via pam_pwquality."
else
    log "pam_pwquality already present; skipping."
fi

# --- 4. Configure firewall ---
log "Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
yes | ufw enable
log "UFW enabled with default-deny inbound and SSH allowed."

# --- 5. Disable insecure legacy services if present ---
log "Disabling insecure legacy services..."
for svc in telnet ftp rlogin rexec; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
        systemctl disable "$svc" || true
        systemctl stop "$svc" || true
        log "Disabled and stopped $svc (if present)."
    fi
done

# --- 6. Secure SSH baseline (before hardened config pull) ---
log "Baseline SSH hardening..."
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

# Map of services to target config paths and repo filenames
# Format: service|local_path|repo_file
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
        log "Service active: $svc — applying hardened config for $path from $repo"
        backup_file "$path"
        tmp="$(mktemp)"
        fetch_hardened "$repo" "$tmp"
        # Validate basic syntax before replacing, where possible
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
                # Test sshd config if available
                if command -v sshd >/dev/null 2>&1; then
                    if sshd -t 2>/dev/null; then
                        restart_service "$svc"
                    else
                        log "ERROR: sshd config test failed; not restarting."
                    fi
                else
                    restart_service "$svc"
                fi
                ;;
            squid|vsftpd|smbd|cups|clamav-daemon|bind9|tomcat9)
                cp "$tmp" "$path"
                restart_service "$svc"
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

# --- 10. Apply hardened sysctl.conf and reload kernel params ---
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
    log "WARNING: sysctl -p reported errors; please review /etc/sysctl.conf."
fi

log "Hardened configuration deployment complete."
