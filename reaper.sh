#!/bin/bash

# Display ASCII Art at the beginning
cat << "EOF"
              ...                            
             ;::::;                          
           ;::::; :;                         
         ;:::::'   :;                        
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
echo "Script created by Traceroute and ChatGPT"


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

# Update and install necessary tools
task_title "Updating and Installing Tools" "🔧"
apt-get update && apt-get upgrade -y
apt-get install -y ufw chkrootkit fail2ban iptables libpam-pwquality gnome-software discover xfce4-taskmanager mate-system-monitor lynis
progress_bar 5 "Installing Packages"

# Disable guest login
task_title "Disabling Guest Login" "🚪"
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
progress_bar 2 "Disabling Guest Login"

# Detect the Desktop Environment (DE)
task_title "Detecting Desktop Environment" "🌐"
desktop_env=$(echo $XDG_CURRENT_DESKTOP | tr '[:upper:]' '[:lower:]')

case "$desktop_env" in
    gnome)
        task_title "Detected GNOME" "🟢"
        ;;
    kde)
        task_title "Detected KDE" "🔵"
        ;;
    xfce)
        task_title "Detected XFCE" "🟡"
        ;;
    mate)
        task_title "Detected MATE" "🟠"
        ;;
    *)
        echo -e "\033[1;33m⚠️ Warning: No known desktop environment detected.\033[0m"
        echo "Skipping automatic update configuration."
        exit 0
        ;;
esac

# Enable automatic updates
echo "Enabling automatic updates for $desktop_env..."
systemctl enable --now apt-daily-upgrade.timer
systemctl enable --now apt-daily.timer
progress_bar 5 "Enabling Automatic Updates"

# Delete unwanted users
task_title "Deleting Unwanted Users" "🧑‍💻"
echo "Available users to delete (numbered):"
awk -F: '{ print NR ": " $1 }' /etc/passwd | grep /bin/bash
echo -n "Enter the numbers of the users you want to delete (space-separated): "
read -a user_numbers

for num in "${user_numbers[@]}"; do
    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        echo "Invalid input '$num'. Please enter only numbers."
        exit 1
    fi
    username=$(awk -F: -v num="$num" 'NR == num { print $1 }' /etc/passwd)
    if [ -z "$username" ]; then
        echo "Invalid number $num. No user found at that number."
        continue
    fi
    echo "You have selected user: $username"
    echo -n "Are you sure you want to delete this user? (yes/no): "
    read confirmation
    if [ "$confirmation" != "yes" ]; then
        echo "User deletion aborted for $username."
        continue
    fi
    userdel -r "$username"
    if [ $? -eq 0 ]; then
        echo -e "\033[1;32m✔️ User $username has been deleted.\033[0m"
    else
        echo -e "\033[1;31m❌ Failed to delete user $username.\033[0m"
    fi
done
progress_bar 5 "Deleting Users"

# Manage services
task_title "Managing Services" "⚙️"
services=("ssh" "vsftp" "apache2" "mysql" "nginx")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        status="running"
    else
        status="not running"
    fi
    echo "Service '$service' is $status."
    if [ "$status" == "running" ]; then
        echo -n "Do you want to stop this service? (yes/no): "
        read response
        if [ "$response" == "yes" ]; then
            systemctl stop "$service"
            if [ $? -eq 0 ]; then
                echo -e "\033[1;32m✔️ Service '$service' has been stopped.\033[0m"
            else
                echo -e "\033[1;31m❌ Failed to stop service '$service'.\033[0m"
            fi
        else
            echo "Service '$service' will continue running."
        fi
    fi
done
progress_bar 5 "Managing Services"

# Change all user passwords
task_title "Changing User Passwords" "🔑"
new_password="CyB3rP@tr1oT2024"
for user in $(cut -f1 -d: /etc/passwd | grep -vE '^(root|nobody|sync|shutdown|halt)$'); do
    echo "Changing password for user: $user"
    echo "$user:$new_password" | chpasswd
done
progress_bar 10 "Changing User Passwords"

# Configure firewall with UFW
task_title "Configuring Firewall" "🛡️"
ufw enable
ufw allow ssh
ufw allow http
ufw deny 23   # Telnet protocol
ufw deny 2049 # NFS
ufw deny 515  # LPD
ufw deny 111  # RPC services
ufw default deny
ufw status verbose
progress_bar 5 "Configuring Firewall"

# Configure Fail2Ban
task_title "Configuring Fail2Ban" "🚨"
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bak
sed -i 's/^bantime[[:space:]]*=.*/bantime = 60m/' /etc/fail2ban/jail.conf
sed -i 's/^findtime[[:space:]]*=.*/findtime = 5m/' /etc/fail2ban/jail.conf
sed -i 's/^maxretry[[:space:]]*=.*/maxretry = 10/' /etc/fail2ban/jail.conf
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl start fail2ban
systemctl enable fail2ban
systemctl restart sshd
progress_bar 6 "Configuring Fail2Ban"

# List users with shell access
task_title "Listing Users with Shell Access" "🧑‍💻"
echo "Users with /bin/bash, /bin/sh, or /bin/zsh shell and their groups:"
while IFS=: read -r user _ _ _ _ _ shell; do
    if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
        groups=$(groups "$user" | cut -d: -f2 | xargs)
        echo "$user | $groups"
    fi
done < /etc/passwd
progress_bar 5 "Listing Users"

# Remove hacking tools
task_title "Removing Hacking Tools" "🧹"
tools=(
    metasploit-framework nmap wireshark aircrack-ng burpsuite john sqlmap hydra maltego nikto openvas netcat ettercap reaver set dnsenum dnsmap hashcat burp sqlninja mitmproxy wpscan theharvester feroxbuster gobuster netdiscover enum4linux
)
for tool in "${tools[@]}"; do
    echo "Removing $tool..."
    sudo apt-get remove --purge -y "$tool"
done
sudo apt-get autoremove -y
progress_bar 10 "Removing Tools"

# Search for vulnerabilities with Lynis
task_title "Searching for Vulnerabilities with Lynis" "🔍"
lynis audit system
progress_bar 10 "Scanning for Vulnerabilities"

# Set up Chroot environment for added security
task_title "Setting up Chroot Environment" "🔒"
mkdir -p /var/chroot/{bin,lib,lib64,etc}
cp /bin/bash /var/chroot/bin/
cp /bin/ls /var/chroot/bin/
progress_bar 5 "Setting up Chroot"

# Search and delete .mp3 files
task_title "Searching and Deleting .mp3 Files" "🎵"
find / -type f -iname "*.mp3" -exec rm -f {} \;
progress_bar 5 "Deleting .mp3 Files"

# Final success message
echo -e "\033[1;32m🎉 All tasks completed successfully!\033[0m"
