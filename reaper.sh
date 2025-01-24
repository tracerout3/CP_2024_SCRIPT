#!/bin/bash

# Create a directory for logs and backups
LOGS_DIR="$HOME/SecurityLogs"
mkdir -p "$LOGS_DIR"
LOG_FILE="$LOGS_DIR/notes.txt"

# Display ASCII Art at the beginning
cat << "EOF"
              ...                            
             ;::::;                          
           ;::::; :;                         
         ;:::::'   ;                         
        ;:::::;     ;.                       
       ,:::::'       ;           OOO\        
       ::::::;       ;          OOOOO\       
       ;:::::;       ;         OOOOOOOO      
      ,;::::::;     ;'         / OOOOOOO     
    ;:::::::::`. ,,,;.        /  / DOOOOOO   
  .';:::::::::::::::::;,     /  /     DOOOO  
 ,::::::;::::::;;;;::::;,   /  /        DOOO 
;`::::::`'::::::;;;::::: ,#/  /          DOOO 
:`:::::::`;::::::;;::: ;::#  /            DOOO
::`:::::::`;:::::::: ;::::# /              DOO
`:`:::::::`;:::::: ;::::::#/               DOO
 :::`:::::::`;; ;:::::::::##                OO
 ::::`:::::::`;::::::::;:::#                OO
 `:::::`::::::::::::;'`:;::#                O 
  `:::::`::::::::;' /  / `:#                  
   ::::::`:::::;'  /  /   `#   
EOF

# Display Credits
echo -e "\033[1;33mCredits:\033[0m"
echo "Reap And Sow...."
echo "Script created by Traceroute"

# Initialize log file
echo "Log of changes made by the script" > "$LOG_FILE"
echo "=================================" >> "$LOG_FILE"
echo "Execution started at $(date)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Function to log changes to the file
log_change() {
    echo "$(date): $1" >> "$LOG_FILE"
}

# Function to print progress bar
progress_bar() {
    local duration=$1
    local task=$2
    local bar_length=50
    echo -n "$task "
    for i in $(seq 1 $bar_length); do
        echo -n "█"
        sleep $(($duration / $bar_length))
    done
    echo -e "\nDone!"
}

# Function to print task title and icon
task_title() {
    local title=$1
    local icon=$2
    echo -e "\n\033[1;32m$icon $title\033[0m"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[1;31m❌ Error: Please run as root! Use 'sudo'.\033[0m"
    exit 1
fi

# Lock root and secure /etc/shadow
chmod 640 /etc/shadow
log_change "Secured /etc/shadow by setting permissions to 640."

# Update and install necessary tools
task_title "Updating and Installing Tools" "🔧"
apt-get update && apt-get upgrade -y
apt-get install -y ufw chkrootkit fail2ban iptables libpam-pwquality lynis vim net-tools
progress_bar 5 "Installing Packages"
log_change "Updated system and installed necessary tools."

# Disable guest login for LightDM, GDM, and SDDM
task_title "Securing Login Manager" "🔐"
for manager in lightdm gdm sddm; do
    if systemctl is-active --quiet "$manager"; then
        case "$manager" in
            lightdm)
                echo "allow-guest=false" | sudo tee -a /etc/lightdm/lightdm.conf > /dev/null
                ;;
            gdm)
                echo "AllowGuest=false" | sudo tee -a /etc/gdm/custom.conf > /dev/null
                ;;
            sddm)
                echo "AllowGuest=false" | sudo tee -a /etc/sddm.conf > /dev/null
                ;;
        esac
        log_change "Disabled guest login for $manager."
    else
        echo "$manager is not running, skipping..."
    fi
done
progress_bar 5 "Securing Login Managers"

# Disable TCP connections to the X server
task_title "Disabling X Server TCP Connections" "🚫"
if [ -f /etc/X11/xorg.conf ]; then
    sudo sed -i '/^Section "ServerFlags"/a \ \ Option "DisableTCP" "true"' /etc/X11/xorg.conf
else
    echo 'No /etc/X11/xorg.conf found. Proceeding with xinit configuration.'
fi

if [ -f /etc/X11/xinit/xserverrc ]; then
    sudo sed -i 's/^.*X .*$/exec /usr/bin/X -nolisten tcp $DISPLAY/' /etc/X11/xinit/xserverrc
else
    echo "No xinit configuration found. Skipping this step."
fi
log_change "Disabled TCP connections to the X server."

# Disable ICMP Echo Requests (Ping)
task_title "Disabling ICMP Echo Requests" "🚫"
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT
sudo iptables-save > /etc/iptables/rules.v4
log_change "Disabled ICMP Echo Requests (Ping)."

# Prevent Null Passwords from Authenticating
task_title "Preventing Null Passwords" "🔑"
if grep -q "nullok" /etc/pam.d/common-auth; then
    sudo sed -i 's/nullok//g' /etc/pam.d/common-auth
    log_change "Disabled null password authentication in common-auth."
else
    echo "Null passwords are already disabled in common-auth."
fi

null_password_accounts=$(sudo awk -F: '($2==""){print $1}' /etc/shadow)
if [ -n "$null_password_accounts" ]; then
    for account in $null_password_accounts; do
        sudo usermod -L "$account"
        log_change "Locked account $account due to null password."
    done
else
    echo "No accounts with null passwords found."
fi

# Automatically detect and manage services
task_title "Managing Services" "⚙️"
services=("ssh" "nginx" "ftp" "vsftpd" "apache2" "proftpd" "samba" "squid")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        read -p "Service '$service' is running. Do you want to keep or delete it? (keep/delete): " action
        case "$action" in
            keep)
                echo "Keeping $service running."
                log_change "Kept service: $service."

                # Replace configuration files with hardened versions
                case "$service" in
                    ssh)
                        source_file="$HOME/HardFiles/sshd_config"
                        target_file="/etc/ssh/sshd_config"
                        if [ -f "$source_file" ]; then
                            sudo cp "$source_file" "$target_file"
                            sudo systemctl restart ssh
                            log_change "Replaced SSH configuration with hardened version."
                        else
                            echo "Hardened SSH config file not found at $source_file."
                        fi
                        ;;
                    apache2)
                        source_file="$HOME/HardFiles/apache2.conf"
                        target_file="/etc/apache2/apache2.conf"
                        if [ -f "$source_file" ]; then
                            sudo cp "$source_file" "$target_file"
                            sudo systemctl restart apache2
                            log_change "Replaced Apache configuration with hardened version."
                        else
                            echo "Hardened Apache config file not found at $source_file."
                        fi
                        ;;
                    nginx)
                        source_file="$HOME/HardFiles/nginx.conf"
                        target_file="/etc/nginx/nginx.conf"
                        if [ -f "$source_file" ]; then
                            sudo cp "$source_file" "$target_file"
                            sudo systemctl restart nginx
                            log_change "Replaced Nginx configuration with hardened version."
                        else
                            echo "Hardened Nginx config file not found at $source_file."
                        fi
                        ;;
                    vsftpd)
                        source_file="$HOME/HardFiles/vsftpd.conf"
                        target_file="/etc/vsftpd.conf"
                        if [ -f "$source_file" ]; then
                            sudo cp "$source_file" "$target_file"
                            sudo systemctl restart vsftpd
                            log_change "Replaced vsftpd configuration with hardened version."
                        else
                            echo "Hardened vsftpd config file not found at $source_file."
                        fi
                        ;;
                    proftpd)
                        source_file="$HOME/HardFiles/proftpd.conf"
                        target_file="/etc/proftpd/proftpd.conf"
                        if [ -f "$source_file" ]; then
                            sudo cp "$source_file" "$target_file"
                            sudo systemctl restart proftpd
                            log_change "Replaced proftpd configuration with hardened version."
                        else
                            echo "Hardened proftpd config file not found at $source_file."
                        fi
                        ;;
                    samba)
                        source_file="$HOME/HardFiles/smb.conf"
                        target_file="/etc/samba/smb.conf"
                        if [ -f "$source_file" ]; then
                            sudo cp "$source_file" "$target_file"
                            sudo systemctl restart smbd
                            log_change "Replaced Samba configuration with hardened version."
                        else
                            echo "Hardened Samba config file not found at $source_file."
                        fi
                        ;;
                    squid)
                        source_file="$HOME/HardFiles/squid.conf"
                        target_file="/etc/squid/squid.conf"
                        if [ -f "$source_file" ]; then
                            sudo cp "$source_file" "$target_file"
                            sudo systemctl restart squid
                            log_change "Replaced Squid configuration with hardened version."
                        else
                            echo "Hardened Squid config file not found at $source_file."
                        fi
                        ;;
                    *)
                        echo "No hardening available for this service."
                        ;;
                esac
                ;;
            delete)
                echo "Deleting $service."
                sudo systemctl stop "$service"
                sudo systemctl disable "$service"
                log_change "Deleted service: $service."
                ;;
            *)
                echo "Invalid action for $service."
                ;;
        esac
    else
        echo "Service '$service' is not running."
    fi
done
progress_bar 5 "Managing Services"

# Replace sysctl.conf with hardened version
task_title "Replacing sysctl.conf" "🔧"
SYSCTL_SOURCE="$HOME/HardFiles/sysctl.conf"
SYSCTL_TARGET="/etc/sysctl.conf"

if [ -f "$SYSCTL_SOURCE" ]; then
    sudo cp "$SYSCTL_SOURCE" "$SYSCTL_TARGET"
    sudo sysctl --system
    log_change "Replaced sysctl.conf with hardened version from $SYSCTL_SOURCE."
else
    echo "Hardened sysctl.conf file not found at $SYSCTL_SOURCE."
fi
progress_bar 3 "Replacing sysctl.conf"

# Configure secure password and lockout policies
task_title "Configuring Password Policy" "🔑"
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   2/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
log_change "Configured password policy: min days=2, max days=90, warn age=7."

# Secure UFW and Fail2Ban configurations
task_title "Configuring UFW and Fail2Ban" "🔥"
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable
systemctl enable fail2ban
systemctl start fail2ban
log_change "Configured UFW and Fail2Ban."

# Remove common hacking tools
task_title "Removing Hacking Tools" "🛑"
tools=(
    "beef" "bettercap" "burpsuite" "canvas" "caine" "core-impact" "cryptcat" "cain" "cowpatty" "dsniff" "dovecot" "ettercap" "fping" "foremost" "freeciv" "ftp" "grendel-scan" "hashcat" "hping3" "inssider" "john" "kismet" "lighttpd" "l0phtcrack" "medusa" "mimikatz" "minetest" "minetest-server" "mysql" "nc" "netcat" "netcat-traditional" "ngrep" "nikto" "nmap" "netscan" "openvas" "openssl" "ophcrack" "postgresql" "powersploit" "pcredz" "reaver" "reelphish" "rexd" "rlogind" "rshd" "rcmd" "rbootd" "rquotad" "rstatd" "samba" "sendmail" "snmp" "sqlmap" "superscan" "systemd" "tftpd" "tightvncserver" "truecrack" "vega" "vsftpd" "wifiphisher" "wifite" "x11vnc" "zap" "zenmap" "zlib"
    "supertuxkart" "0ad" "wesnoth" "openra" "tome" "freeciv" "bastion" "minetest" "warsow" "xonotic" "red eclipse" "hexen2" "pioneer" "openxcom" "naev" "flames of revenge" "crea" "frozen-bubble" "darkplaces" "unvanquished" "freedoom" "glest" "megaglest" "battle for wesnoth" "liberated pixel cup" "super tux" "the-curse" "teeworlds" "gargoyle" "zaz" "spring"
    "unrar" "p7zip" "rar" "libtorrent" "webtorrent-cli" "torrentfile" "aria2" "nload" "iftop" "speedometer" "utorrent" "bittorrent" "filezilla" "syncthing" "torrentflux" "plex" "emby"
    "qbittorrent" "transmission" "deluge" "frostwire" "ktorrent" "aria2" "fusee" "freedownloadmanager" "rtorrent" "monsoon" "popcorn-time" "jdownloader"
)
for tool in "${tools[@]}"; do
    if dpkg -l | grep -q "$tool"; then
        apt-get remove --purge -y "$tool"
        log_change "Removed tool: $tool."
    fi
done
progress_bar 5 "Removing Hacking Tools"

# Netcat Backdoor Finder and Removal
task_title "Searching and Removing Netcat Backdoors" "🚨"
if netstat -an | grep -qE ':(4444|1337)'; then
    pkill -f netcat
    apt-get remove --purge -y netcat
    log_change "Netcat backdoor detected and removed."
else
    echo "No Netcat backdoor found."
fi
progress_bar 5 "Removing Netcat Backdoor"

# Run LinPEAS for privilege escalation checks
task_title "Running LinPEAS" "🔍"
if ! command -v curl &> /dev/null; then
    apt-get install -y curl
fi
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee "$LOGS_DIR/linpeas_report.txt"
log_change "LinPEAS report generated: $LOGS_DIR/linpeas_report.txt."

# Run Lynis and chkrootkit for security audits
task_title "Running Lynis and chkrootkit" "🔍"
lynis audit system | tee "$LOGS_DIR/lynis_report.txt"
chkrootkit | tee "$LOGS_DIR/chkrootkit_report.txt"
log_change "Lynis and chkrootkit reports generated: $LOGS_DIR/lynis_report.txt and $LOGS_DIR/chkrootkit_report.txt."

# Backup old crontab before replacing it
task_title "Backing Up Old Crontab" "⏰"
OLD_CRONTAB_FILE="$LOGS_DIR/old_crontab.txt"
crontab -l > "$OLD_CRONTAB_FILE"
log_change "Backed up old crontab to $OLD_CRONTAB_FILE."

# Replace crontab with a secure version
task_title "Replacing Crontab" "⏰"
NEW_CRONTAB_FILE="$HOME/HardFiles/crontab"
if [ -f "$NEW_CRONTAB_FILE" ]; then
    crontab "$NEW_CRONTAB_FILE"
    log_change "Replaced crontab with $NEW_CRONTAB_FILE."
else
    echo "Crontab file not found at $NEW_CRONTAB_FILE."
fi

# Kill all netcat processes
task_title "Killing Netcat Processes" "🚨"
pkill -9 nc
if [ $? -eq 0 ]; then
    log_change "Killed all netcat processes."
else
    echo "No netcat processes found."
fi

# Change user passwords
task_title "Changing User Passwords" "🔑"
new_password="CyberPatr1ot36@#"
read -p "Enter the username to exclude from password change: " excluded_user
cut -f1 -d: /etc/passwd | grep -vE '^(root|nobody|sync|shutdown|halt)$' | while IFS= read -r user; do
    if [ "$user" == "$excluded_user" ]; then
        echo -e "\033[1;33m⚠️ Skipping password change for $user.\033[0m"
        continue
    fi
    echo "$user:$new_password" | chpasswd
    log_change "Changed password for $user."
done
progress_bar 5 "Changing User Passwords"

# Search and delete .mp3 files
task_title "Searching and Deleting .mp3 Files" "🎵"
read -p "Enter the directory to search for .mp3 files (default is /home): " search_dir
search_dir=${search_dir:-/home}
find "$search_dir" -type f -iname "*.mp3" | tee "$LOGS_DIR/mp3_files_list.txt"
read -p "Do you want to delete all .mp3 files listed above? (yes/no): " delete_confirmation
if [ "$delete_confirmation" = "yes" ]; then
    while read -r mp3_file; do
        rm -f "$mp3_file"
        log_change "Deleted .mp3 file: $mp3_file."
    done < "$LOGS_DIR/mp3_files_list.txt"
fi
progress_bar 5 "Deleting .mp3 Files"

# Final success message
echo -e "\033[1;32m🎉 All tasks completed successfully!\033[0m"
echo "Execution completed at $(date)" >> "$LOG_FILE"
