#!/bin/bash

#Check if root
if [ "$EUID" -ne 0 ]
  then echo "put sudo infront of this"
  exit
fi











#Function Deletes Unwanted users not in the readme

delete_users() {
    # List users with their numbers
    echo "Available users to delete (numbered):"
    awk -F: '{ print NR ": " $1 }' /etc/passwd

    # Prompt user to select numbers
    echo -n "Enter the numbers of the users you want to delete (space-separated): "
    read -a user_numbers

    # Validate the user input
    for num in "${user_numbers[@]}"; do
        if ! [[ "$num" =~ ^[0-9]+$ ]]; then
            echo "Invalid input '$num'. Please enter only numbers."
            return 1
        fi
    done

    # Process each selected number
    for num in "${user_numbers[@]}"; do
        username=$(awk -F: -v num="$num" 'NR == num { print $1 }' /etc/passwd)

        # Check if the username exists
        if [ -z "$username" ]; then
            echo "Invalid number $num. No user found at that number."
            continue
        fi

        # Confirm the deletion
        echo "You have selected user: $username"
        echo -n "Are you sure you want to delete this user? (yes/no): "
        read confirmation

        if [ "$confirmation" != "yes" ]; then
            echo "User deletion aborted for $username."
            continue
        fi

        # Delete the user
        userdel -r "$username"

        if [ $? -eq 0 ]; then
            echo "User $username has been deleted."
        else
            echo "Failed to delete user $username."
        fi
    done
}


#Checks The services in the machine and shows you them

manage_services() {
    # Define an array of services to check
    local services=("ssh" "vsftp" "apache2" "mysql" )

    # Loop through each service and check its status
    for service in "${services[@]}"; do
        # Check if the service is running
        if systemctl is-active --quiet "$service"; then
            status="running"
        else
            status="not running"
        fi

        # Display the status of the service
        echo "Service '$service' is $status."

        # Prompt user to stop (or delete) the service
        if [ "$status" == "running" ]; then
            echo -n "Do you want to stop this service? (yes/no): "
            read response

            if [ "$response" == "yes" ]; then
                # Stop the service
                sudo systemctl stop "$service"
                
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