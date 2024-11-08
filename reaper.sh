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

# Update and install necessary tools
task_title "Updating and Installing Tools" "🔧"
apt-get update && apt-get upgrade -y
apt-get install -y ufw chkrootkit fail2ban iptables libpam-pwquality gnome-software discover xfce4-taskmanager mate-system-monitor lynis
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
                sed -i 's/^autologin-user=/autologin-user='"/\n#autologin-user="'" /etc/lightdm/lightdm.conf
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
        log_change "Deleted user $username."
    else
        echo -e "\033[1;31m❌ Failed to delete user $username.\033[0m"
    fi
done
progress_bar 5 "Deleting Users"

# Change all user passwords
task_title "Changing User Passwords" "🔑"
new_password="CyB3rP@tr1oT2024"
for user in $(cut -f1 -d: /etc/passwd | grep -vE '^(root|nobody|sync|shutdown|halt)$'); do
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

# MP3 File Search and Deletion
task_title "Searching and Deleting .mp3 Files" "🎵"
echo -n "Enter the directory to search for .mp3 files (default is /home): "
read search_dir
search_dir=${search_dir:-/home}

echo "Searching for .mp3 files in $search_dir..."
find "$search_dir" -type f -iname "*.mp3" | tee mp3_files_list.txt

echo -n "Do you want to delete all .mp3 files listed above? (yes/no): "
read delete_confirmation
if [ "$delete_confirmation" == "yes" ]; then
    while read -r mp3_file; do
        rm -f "$mp3_file"
        echo "Deleted: $mp3_file"
        log_change "Deleted .mp3 file: $mp3_file"
    done < mp3_files_list.txt
    echo -e "\033[1;32m✔️ All .mp3 files have been deleted.\033[0m"
else
    echo "No files were deleted."
fi
progress_bar 5 "Searching and Deleting .mp3 Files"

# Finish script
echo -e "\033[1;32m✔️ All tasks completed successfully.\033[0m"
echo "Execution completed at $(date)" >> "$LOG_FILE"
