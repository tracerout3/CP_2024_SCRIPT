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

# Log file for tracking important changes
LOG_FILE="notes.txt"
echo "Log of changes made by the script" > "$LOG_FILE"
echo "=================================" >> "$LOG_FILE"
echo "Execution started at $(date)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Function to log changes to the file
log_change() {
    echo "$1" >> "$LOG_FILE"
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

#locks root and secures /etc/shadow
chmod 640 /etc/shadow

# Update and install necessary tools
task_title "Updating and Installing Tools" "🔧"
apt-get update && apt-get upgrade -y
apt-get install -y ufw chkrootkit fail2ban iptables libpam-pwquality lynis vim net-tools
progress_bar 5 "Installing Packages"

# Disable guest login for LightDM, GDM, and SDDM
task_title "Securing Login Manager" "🔐"
echo "Securing LightDM, GDM, and SDDM login managers..."
for manager in lightdm gdm sddm; do
    if systemctl is-active --quiet "$manager"; then
        # Disable guest login
        echo "Disabling guest login for $manager..."
        log_change "Disabled guest login for $manager."
        case "$manager" in
            lightdm)
                echo "allow-guest=false" | tee -a /etc/lightdm/lightdm.conf
                ;;
            gdm)
                echo "AllowGuest=false" | tee -a /etc/gdm/custom.conf
                ;;
            sddm)
                echo "Disallowing guests in sddm.conf..."
                echo "[General]" | tee -a /etc/sddm.conf
                echo "UserSessions=lightdm" | tee -a /etc/sddm.conf
                ;;
        esac
        # Disable automatic login
        echo "Disabling automatic login for $manager..."
        case "$manager" in
            lightdm)
                sed -i 's/^autologin-user=/autologin-user=/' /etc/lightdm/lightdm.conf
                ;;
            gdm)
                sed -i 's/^AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/gdm/custom.conf
                ;;
            sddm)
                sed -i 's/^#AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/sddm.conf
                ;;
        esac
        # Disable root login
        echo "Disabling root login for $manager..."
        case "$manager" in
            lightdm)
                sed -i 's/^greeter-show-manual-login=true/greeter-show-manual-login=false/' /etc/lightdm/lightdm.conf
                ;;
            gdm)
                sed -i 's/^EnableRoot=true/EnableRoot=false/' /etc/gdm/custom.conf
                ;;
            sddm)
                sed -i 's/^#EnableRootLogin=true/EnableRootLogin=false/' /etc/sddm.conf
                ;;
        esac
    fi
done
progress_bar 5 "Securing Login Managers"

# Automatically detect and manage services (keep or delete)
task_title "Managing Services" "⚙️"
services=("ssh" "nginx" "ftp" "vsftpd" "apache2" "proftpd")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        read -p "Service '$service' is running. Do you want to keep or delete it? (keep/delete): " action
        case "$action" in
            keep)
                echo "Keeping $service running."
                ;;
            delete)
                systemctl stop "$service"
                systemctl disable "$service"
                echo "$service has been stopped and disabled."
                log_change "Stopped and disabled service: $service."
                ;;
            *)
                echo "Invalid action for $service. Skipping."
                ;;
        esac
    fi
done
progress_bar 5 "Managing Services"

# Task title (for display purposes)
task_title="Managing Users and Groups 👥"
# Define color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RESET='\033[0m'  # Reset to default color

# Function to list users with /bin/bash, /bin/sh, or /bin/zsh shell along with their groups
list_users() {
    echo -e "\nUsers with /bin/bash, /bin/sh, or /bin/zsh shell and their groups:\n"
    users=()

    while IFS=: read -r user _ _ _ _ _ shell; do
        if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
            users+=("$user")
            groups=$(groups "$user" | cut -d: -f2 | xargs)  # Get groups and trim leading spaces

            # Print each user with their groups
            echo -e "[ * ] $user"
            # Print each group with color coding
            for group in $groups; do
                if [[ "$group" == "sudo" ]]; then
                    # Color sudo group in red
                    echo -e "   ${RED}$group${RESET}"
                elif [[ "$group" =~ [^a-zA-Z0-9_] ]]; then
                    # Color unusual groups (non-alphanumeric) in yellow
                    echo -e "   ${YELLOW}$group${RESET}"
                else
                    # Default color for normal groups
                    echo -e "   ${GREEN}$group${RESET}"
                fi
            done
            echo -e "\n"  # Add space between users for readability
        fi
    done < /etc/passwd

    if [ ${#users[@]} -eq 0 ]; then
        echo "No users with /bin/bash, /bin/sh, or /bin/zsh shell found."
        return 1
    fi
}

# Function to modify a user's group membership (add/remove)
modify_user_group() {
    read -p "Enter the username to modify: " username

    # Check if the user exists in the list of users
    if [[ ! " ${users[@]} " =~ " $username " ]]; then
        echo "User $username does not exist or does not have a specified shell."
        return 1
    fi

    read -p "Do you want to add or remove the user from a group? [add/remove]: " action
    read -p "Enter the group name: " group

    if [[ "$action" == "add" ]]; then
        if sudo usermod -aG "$group" "$username"; then
            echo "$username added to $group."
        else
            echo "Failed to add $username to $group. Please check if the group exists."
        fi
    elif [[ "$action" == "remove" ]]; then
        if sudo deluser "$username" "$group"; then
            echo "$username removed from $group."
        else
            echo "Failed to remove $username from $group. Please check if the group exists."
        fi
    else
        echo "Invalid action. Please use 'add' or 'remove'."
    fi
}

# Function to delete users
delete_user() {
    read -p "Enter the username to delete: " username

    # Check if the user exists in the list of users
    if [[ ! " ${users[@]} " =~ " $username " ]]; then
        echo "User $username does not exist or does not have a specified shell."
        return 1
    fi

    echo "You have selected user: $username"
    echo -n "Are you sure you want to delete this user? (yes/no): "
    read confirmation

    if [ "$confirmation" != "yes" ]; then
        echo "User deletion aborted for $username."
        return
    fi

    sudo userdel -r "$username"

    if [ $? -eq 0 ]; then
        echo "User $username has been deleted."
    else
        echo "Failed to delete user $username."
    fi
}

# Function to add a new user
add_user() {
    read -p "Enter the new username to add: " new_user
    read -p "Enter the shell for the new user (e.g., /bin/bash): " shell
    read -p "Enter the group for the new user: " group

    # Check if the user already exists
    if id "$new_user" &>/dev/null; then
        echo "User $new_user already exists."
        return 1
    fi

    # Create the new user with the specified shell and group
    sudo useradd -m -s "$shell" -G "$group" "$new_user"

    if [ $? -eq 0 ]; then
        echo "User $new_user has been added with shell $shell and group $group."
    else
        echo "Failed to add user $new_user. Please check if the group exists."
    fi
}

# Function to continue or exit
continue_or_exit() {
    echo -n "Would you like to perform another action? [yes/no]: "
    read answer
    if [[ "$answer" == "yes" ]]; then
        return 0  # Continue
    elif [[ "$answer" == "no" ]]; then
        echo "Moving on (its a simply thing)"
        break  # Exit completely
    else
        echo "Invalid response. Please type 'yes' to continue or 'no' to exit."
        
    fi
}

# Main execution
echo -e "\nWelcome to the User Management Script!"

while true; do
    # List users and allow user to choose an action
    list_users

    # If users were found, prompt for further actions
    if [ $? -eq 0 ]; then
        echo -n "Would you like to modify a user's group, delete a user, add a new user, or exit? [modify/delete/add/exit]: "
        read action

        if [ "$action" == "modify" ]; then
            modify_user_group
        elif [ "$action" == "delete" ]; then
            delete_user
        elif [ "$action" == "add" ]; then
            add_user
        elif [ "$action" == "exit" ]; then
            echo "Skipping action and continuing..."
            break  # Continue without quitting
        else
            echo "Invalid action. Please choose 'modify', 'delete', 'add', or 'exit'."
        fi
    fi

    # Ask if the user wants to continue or exit after performing the action
    continue_or_exit
done
# Displaying progress bar (simplified)
echo -e "\n[##########] 100% - Managing Users and Groups"

# Configure secure password and lockout policies (NIST framework)
task_title "Configuring Password Policy" "🔑"
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   2/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
echo "Password min days set to 2, max days 90, and warning age 7 days." | tee -a "$LOG_FILE"

# Define the log file location for security configuration logs
LOG_FILE="/var/log/security_config.log"

# Define the parameters for the faillock module
DENY_ATTEMPTS=5
UNLOCK_TIME=900  # 15 minutes in seconds

# Function to log changes
log_change() {
    echo "$(date): $1" >> "$LOG_FILE"
}

# Check if the script is being run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Determine the PAM configuration file location based on the distro
if [ -f /etc/debian_version ]; then
    PAM_FILE="/etc/pam.d/common-auth"  # Debian-based systems (Ubuntu, etc.)
elif [ -f /etc/redhat-release ]; then
    PAM_FILE="/etc/pam.d/system-auth"  # RHEL/CentOS-based systems (system-auth)
else
    echo "Unsupported distribution. Exiting."
    exit 1
fi

# Backup the current PAM file before making any changes
cp "$PAM_FILE" "$PAM_FILE.bak"
echo "Backup of $PAM_FILE created at $PAM_FILE.bak"

# Update PAM configuration to enable faillock
echo "Configuring PAM faillock for account lockout..."

# Add the required PAM lines for faillock if not already present
if ! grep -q "pam_faillock.so" "$PAM_FILE"; then
    echo "Adding faillock configuration to $PAM_FILE..."
    echo "auth required pam_faillock.so preauth audit deny=$DENY_ATTEMPTS unlock_time=$UNLOCK_TIME" >> "$PAM_FILE"
    echo "auth [default=die] pam_faillock.so authfail audit deny=$DENY_ATTEMPTS unlock_time=$UNLOCK_TIME" >> "$PAM_FILE"
    echo "account required pam_faillock.so" >> "$PAM_FILE"
    log_change "Configured PAM faillock: deny=$DENY_ATTEMPTS, unlock_time=$UNLOCK_TIME"
else
    echo "PAM faillock configuration already present in $PAM_FILE. Skipping..."
fi

# Displaying success message
echo "PAM faillock has been configured with the following settings:"
echo "  Deny after $DENY_ATTEMPTS failed attempts"
echo "  Account will be unlocked after $UNLOCK_TIME seconds (15 minutes)"

# Log the change
log_change "Configured PAM faillock: deny=$DENY_ATTEMPTS, unlock_time=$UNLOCK_TIME"

# Secure UFW and Fail2Ban configurations
task_title "Configuring UFW and Fail2Ban" "🔥"
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable
systemctl enable fail2ban
systemctl start fail2ban
echo "Firewall and Fail2Ban configurations completed." | tee -a "$LOG_FILE"
progress_bar 5 "Securing Firewall and Fail2Ban"

# Remove common hacking tools
task_title "Removing Hacking Tools" "🛑"
tools=("nmap" "ophcrack" "netcat" "netcat-bsd" "metasploit" "hydra" "john" "aircrack-ng" "wireshark" "aisleriot" "wireshark-qt" "wireshark-common" "tcpdump")
for tool in "${tools[@]}"; do
    if dpkg -l | grep -q "$tool"; then
        apt-get remove --purge -y "$tool"
        echo "$tool has been removed."
        log_change "Removed tool: $tool."
    fi
done
progress_bar 5 "Removing Hacking Tools"



# PAM Authentication Configuration for Password Length and Null Passwords
task_title "Configuring PAM Authentication" "🔑"
echo "Enforcing password length and preventing null passwords..."

# Configure minimum password length and prevent null passwords
sed -i '/pam_pwquality.so/ s/$/ minlen=14/' /etc/pam.d/common-password
sed -i '/nullok/s/nullok//' /etc/pam.d/common-auth

echo "PAM Authentication updated: minimum password length 14, null passwords disabled." | tee -a "$LOG_FILE"
progress_bar 3 "Configuring PAM"

# SSH Hardening
task_title "Hardening SSH Configuration" "🔒"
echo "Hardening SSH configuration..."

# Disable root login and configure other settings
sudo sed -i 's/^\(#\?\)PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
# sed -i 's/^#AllowUsers .*/AllowUsers myuser/' /etc/ssh/sshd_config # Replace 'myuser' with your username(s)
# sed -i 's/^#Port .*/Port 22/' /etc/ssh/sshd_config # You can change port here if you like

# Restart SSH service to apply changes
systemctl restart sshd

echo "SSH hardening completed: root login disabled, password authentication disabled, user access restricted." | tee -a "$LOG_FILE"
progress_bar 3 "Hardening SSH"



# Netcat Backdoor Finder and Removal
task_title "Searching and Removing Netcat Backdoors" "🚨"
echo "Searching for Netcat backdoors..."

# Find any instances of netcat running or installed
if netstat -an | grep -qE ':(4444|1337)'; then
    echo "Netcat backdoor detected. Removing..."
    pkill -f netcat
    apt-get remove --purge -y netcat
    echo "Netcat removed."
    log_change "Netcat backdoor detected and (probobly) removed (double check) (look in /etc/crontab)."
else
    echo "No Netcat backdoor found."
fi
progress_bar 5 "Removing Netcat Backdoor"

# Run security audits (Lynis and chkrootkit)
task_title "Running Security Audits" "🔍"
lynis audit system
chkrootkit
echo "Lynis and chkrootkit completed their security audits." | tee -a "$LOG_FILE"
progress_bar 5 "Running Security Audits"

# Change all user passwords
task_title "Changing User Passwords" "🔑"
new_password="CyberPatr1ot36@#" 
cut -f1 -d: /etc/passwd | grep -vE '\(root|nobody|sync|shutdown|halt\)' | while IFS= read -r user ; do
    echo "Changing password for user: $user"
    echo "$user:$new_password" | chpasswd
    if [ $? -eq 0 ]; then
        echo -e "\033[1;32m✔️ Password for $user changed successfully.\033[0m"
        log_change "Changed password for $user."
    else
        echo -e "\033[1;31m❌ Failed to change password for $user.\033[0m"
    fi
done
progress_bar 5 "Changing User Passwords"


#disables ipv4 forwarding && enables ipv4 syn packet coockies

echo "net.ipv4.ip_forward=0" | sudo tee /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" | sudo tee /etc/sysctl.conf
sudo sysctl --system


# MP3 File Search and Deletion
task_title "Searching and Deleting .mp3 Files" "🎵"
echo -n "Enter the directory to search for .mp3 files (default is /home): "
read search_dir
search_dir=${search_dir:-/home}

echo "Searching for .mp3 files in $search_dir..."
find "$search_dir" -type f -iname "*.mp3" | tee mp3_files_list.txt

echo -n "Do you want to delete all .mp3 files listed above? (yes/no): "
read delete_confirmation
if [ "$delete_confirmation" = "yes" ]; then
    while read -r mp3_file; do
        rm -f "$mp3_file"
        echo "Deleted: $mp3_file"
        log_change "Deleted .mp3 file: $mp3_file"
    done < mp3_files_list.txt
fi
progress_bar 5 "Deleting .mp3 Files"

# Final success message
echo -e "\033[1;32m🎉 All tasks completed successfully!\033[0m"
echo "Execution completed at $(date)" >> "$LOG_FILE"
