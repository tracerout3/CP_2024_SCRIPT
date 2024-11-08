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

# Disable guest login and improve login manager security
task_title "Securing Login Manager" "🔒"

# Detect which login manager is being used (SDDM, GDM, or LightDM)
login_manager=$(ps aux | grep -E 'sddm|gdm|lightdm' | awk '{print $11}' | head -n 1)

if [ -z "$login_manager" ]; then
    echo -e "\033[1;33m⚠️ Warning: No login manager detected.\033[0m"
else
    case "$login_manager" in
        *sddm*)
            task_title "Detected SDDM" "🔵"
            # Disable guest login in SDDM
            echo "Disabling guest login in SDDM..."
            sed -i 's/^#AllowGuest=false/AllowGuest=false/' /etc/sddm.conf
            sed -i 's/^AllowEmptySession=false/AllowEmptySession=false/' /etc/sddm.conf
            ;;
        *gdm*)
            task_title "Detected GDM" "🟠"
            # Disable guest login in GDM
            echo "Disabling guest login in GDM..."
            gdm_config="/etc/gdm3/custom.conf"
            if grep -q "AllowGuest=false" "$gdm_config"; then
                sed -i 's/^#AllowGuest=true/AllowGuest=false/' "$gdm_config"
            else
                echo "AllowGuest=false" >> "$gdm_config"
            fi
            ;;
        *lightdm*)
            task_title "Detected LightDM" "🟢"
            # Disable guest login in LightDM
            echo "Disabling guest login in LightDM..."
            lightdm_config="/etc/lightdm/lightdm.conf"
            if ! grep -q "allow-guest=false" "$lightdm_config"; then
                echo "allow-guest=false" >> "$lightdm_config"
            fi
            ;;
        *)
            echo -e "\033[1;33m⚠️ Warning: Unknown login manager detected: $login_manager.\033[0m"
            ;;
    esac

    # Disable automatic login (if enabled)
    task_title "Disabling Automatic Login" "🚫"
    case "$login_manager" in
        *sddm*)
            sed -i 's/^#AutoLoginUser=/AutoLoginUser=/' /etc/sddm.conf
            ;;
        *gdm*)
            sed -i 's/^AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
            ;;
        *lightdm*)
            sed -i 's/^autologin-user=/autologin-user=/' /etc/lightdm/lightdm.conf
            ;;
    esac

    # Disable root login at login screen
    task_title "Disabling Root Login" "🔐"
    case "$login_manager" in
        *sddm*)
            sed -i 's/^#DisableDaemon=true/DisableDaemon=true/' /etc/sddm.conf
            ;;
        *gdm*)
            echo "Disabling root login in GDM..."
            gdm_config="/etc/gdm3/custom.conf"
            if ! grep -q "DisallowRoot=true" "$gdm_config"; then
                echo "DisallowRoot=true" >> "$gdm_config"
            fi
            ;;
        *lightdm*)
            sed -i 's/^greeter-show-manual-login=false/greeter-show-manual-login=true/' /etc/lightdm/lightdm.conf
            ;;
    esac

    echo -e "\033[1;32m✔️ Login manager security settings applied successfully.\033[0m"
fi

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
for user in $(cut -f1 -d: /etc/passwd | grep -vE '^(root|nobody|sync|shutdown|halt)'); do
    echo "$user:$new_password" | chpasswd
    if [ $? -eq 0 ]; then
        echo -e "\033[1;32m✔️ Password for $user changed successfully.\033[0m"
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
    done < mp3_files_list.txt
    echo -e "\033[1;32m✔️ All .mp3 files have been deleted.\033[0m"
else
    echo "No files were deleted."
fi
progress_bar 5 "Searching and Deleting .mp3 Files"

# Finish script
echo -e "\033[1;32m✔️ All tasks completed successfully.\033[0m"
