#!/bin/bash
# System Hardening Script (Safe Version)
# Tested on Debian/Ubuntu-based systems

set -euo pipefail

LOGFILE="/var/log/hardening.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOGFILE"
}

# --- 1. Update system ---
log "Updating system packages..."
apt-get update -y && apt-get upgrade -y

# --- 2. Secure user accounts ---
log "Checking for accounts with /bin/bash shell..."
for user in $(awk -F: '$7 == "/bin/bash" {print $1}' /etc/passwd); do
    if [[ "$user" != "root" ]]; then
        log "Locking account: $user"
        passwd -l "$user"
    fi
done

# --- 3. Enforce password policy ---
log "Configuring password policy..."
if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    log "Password quality module already configured."
else
    echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3" >> /etc/pam.d/common-password
    log "Password policy enforced."
fi

# --- 4. Configure firewall ---
log "Configuring UFW firewall..."
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# --- 5. Disable unnecessary services ---
log "Disabling unnecessary services..."
for svc in telnet ftp rlogin rexec; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        systemctl disable "$svc"
        log "Disabled $svc"
    fi
done

# --- 6. Secure SSH ---
log "Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
systemctl restart sshd
log "SSH hardened."

# --- 7. Remove world-writable files ---
log "Removing world-writable permissions..."
find / -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null
find / -xdev -type d -perm -0002 -exec chmod o-w {} \; 2>/dev/null

# --- 8. Audit system ---
log "Installing auditd..."
apt-get install -y auditd
systemctl enable auditd
systemctl start auditd

log "System hardening complete."
