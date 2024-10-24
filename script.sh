#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Put 'sudo' in front of this."
    exit
fi

# Installs tools that are needed
apt-get update && apt-get upgrade && apt-get install ufw chkrootkit fail2ban iptables libpam-pwquality -y

# Function to delete unwanted users not in the readme
delete_users() {
    echo "Available users to delete (numbered):"
    awk -F: '{ print NR ": " $1 }' /etc/passwd | grep /bin/bash

    echo -n "Enter the numbers of the users you want to delete (space-separated): "
    read -a user_numbers

    for num in "${user_numbers[@]}"; do
        if ! [[ "$num" =~ ^[0-9]+$ ]]; then
            echo "Invalid input '$num'. Please enter only numbers."
            return 1
        fi
    done

    for num in "${user_numbers[@]}"; do
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
            echo "User $username has been deleted."
        else
            echo "Failed to delete user $username."
        fi
    done
}

# Function to manage services
manage_services() {
    local services=("ssh" "vsftp" "apache2" "mysql" "nginx" )

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
                    echo "Service '$service' has been stopped."
                else
                    echo "Failed to stop service '$service'."
                fi
            else
                echo "Service '$service' will continue running."
            fi
        else
            echo "Service '$service' is not running; no action needed."
        fi

        echo
    done
}


change_all_user_passwords() {
    local new_password="CyB3rP@tr1oT2024"

    # Change the password for each user except for the system users
    for user in $(cut -f1 -d: /etc/passwd | grep -vE '^(root|nobody|sync|shutdown|halt)$'); do
        echo "Changing password for user: $user"
        echo "$user:$new_password" | chpasswd
    done

    echo "All user passwords have been changed to 'CyB3rP@tr1oT2024'."
}

firewall() {
    echo
    read -p "Configuring firewall (ufw)... [ENTER]"
  
    ufw enable
    ufw allow ssh
    ufw allow http
    ufw deny 23   # Telnet protocol
    ufw deny 2049  # NFS
    ufw deny 515   # LPD
    ufw deny 111   # RPC services
    ufw default deny
  
    ufw status verbose
}




fail2ban() {
      
    #backs up original file  
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bak

    # Modify the parameters in jail.conf
    sed -i 's/^bantime[[:space:]]*=.*/bantime = 60m/' /etc/fail2ban/jail.conf
    sed -i 's/^findtime[[:space:]]*=.*/findtime = 5m/' /etc/fail2ban/jail.conf
    sed -i 's/^maxretry[[:space:]]*=.*/maxretry = 10/' /etc/fail2ban/jail.conf
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    # Restart the fail2ban service to apply changes
    systemctl start fail2ban
    systemctl enable fail2ban
    systemctl restart sshd
    echo "Fail2Ban configuration updated for SSH. Changes applied:"
    echo "bantime = 60m"
    echo "findtime = 5m"
    echo "maxretry = 10"
    
    
}





sudo() {
    # List users with /bin/bash, /bin/sh, or /bin/zsh shell along with their groups
    echo "Users with /bin/bash, /bin/sh, or /bin/zsh shell and their groups:"
    users=()
    
    while IFS=: read -r user _ _ _ _ _ shell; do
        if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
            users+=("$user")
            groups=$(groups "$user" | cut -d: -f2 | xargs)  # Get groups and trim leading spaces
            echo "$user | $groups"
        fi
    done < /etc/passwd

    if [ ${#users[@]} -eq 0 ]; then
        echo "No users with /bin/bash, /bin/sh, or /bin/zsh shell found."
        return
    fi

    # Prompt for user and group action
    read -p "Enter the username to modify: " username
    if [[ ! " ${users[@]} " =~ " $username " ]]; then
        echo "User $username does not exist or does not have a specified shell."
        return
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




killhack() {
    tools=(
        metasploit-framework
        nmap
        wireshark
        aircrack-ng
        burpsuite
        john
        sqlmap
        hydra
        maltego
        nikto
        openvas
        netcat
        ettercap
        reaver
        set
        dnsenum
        dnsmap
        hashcat
        burp
        sqlninja
        mitmproxy
        wpscan
        theharvester
        feroxbuster
        gobuster
        netdiscover
        enum4linux
        gather
        mimikatz
        msfpc
        veil
        wpscan
        dmitry
        fuzzbunch
        dirb
        sublist3r
        osrframework
        cutter
        xspy
    )

    for tool in "${tools[@]}"; do
        echo "Removing $tool..."
        sudo apt-get remove --purge -y "$tool"
    done

    echo "Cleanup unnecessary packages..."
    sudo apt-get autoremove -y
}



passwordgood() {
    

    # Backup the current PAM configuration
    sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.bak

    # Update the PAM configuration for password complexity
    echo "Updating PAM configuration for password policy..."
    sudo bash -c 'cat <<EOL > /etc/pam.d/common-password
# /etc/pam.d/common-password - password-related modules common to all services

password    requisite     pam_pwquality.so retry=3
password    [success=1 default=ignore]      pam_unix.so obscure sha512
password    required      pam_deny.so
EOL'

    # Set password aging policy
    echo "Setting password aging policy..."
    sudo bash -c 'cat <<EOL >> /etc/login.defs
# NIST compliant password aging settings
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_MIN_LEN    12
PASS_WARN_AGE   14
EOL'

    echo "password policy has been set according to cybersecurity bible."
}










# Function to show the menu
show_menu() {
    echo "Please choose an option:"
    echo "1) Delete Users"
    echo "2) Manage Services"
    echo "3) Change bad passwords ("all passwords will be CyB3rP@tr1oT2024")"
    echo "4) Config Firewall"
    echo "5) Secure SSH"
    echo "6) Check sudoers file for unwanted people"
    echo "7) Purgeith thy unholy programs from thy holiest machine"
    echo "q) Quit"
}

# Main loop
while true; do
    show_menu
    read -p "Enter your choice: " choice

    case $choice in
        1)
            delete_users
            ;;
        2)
            manage_services
            ;;
        3)
            change_all_user_passwords
            ;;

        4)
            firewall
            ;;

        5)
            fail2ban
            ;;
        
	6)
            sudo
            ;;

	7)
 	   killhack
     	    ;;


	8)
 	   passwordgood
	   ;;
   
      	
        q)
            echo "Exiting..."
            break
            ;;
        *)
            echo "Invalid choice. Please try again."
            ;;
    esac

    echo ""
done


