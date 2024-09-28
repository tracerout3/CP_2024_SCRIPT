#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Put 'sudo' in front of this."
    exit
fi

# Installs tools that are needed
apt-get install -y ufw chrootkit fail2ban iptables

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








# Function to show the menu
show_menu() {
    echo "Please choose an option:"
    echo "1) Delete Users"
    echo "2) Manage Services"
    echo "3) Change bad passwords ("all passwords will be CyB3rP@tr1oT2024")"
    echo "4) Config Firewall"
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


