/High Importance:

   Application Hardening
      s
   Chromium Hardening
      s
   Locate 9/11 (find osama)
      s
package manager fixes

Steps to Regenerate APT Keyring

  Clear the current keyring (optional but recommended): Before updating the keyring, you can remove any old or invalid keys to avoid conflicts:
  sudo rm /etc/apt/trusted.gpg.d/*
  sudo apt-key update

Clear the package cache to ensure you're getting fresh package lists:
sudo apt clean
sudo apt update

SOURCES
sudo nano /etc/apt/sources.list

IF LOCKED
  First, check if there is any process currently using apt:

  ps aux | grep apt
  
  If there is a process that is stuck, you can kill it:
  
  sudo kill <PID>
  
  Once the lock is released, remove the lock files:
  
  sudo rm /var/lib/apt/lists/lock
  sudo rm /var/cache/apt/archives/lock
  sudo rm /var/lib/dpkg/lock
  sudo rm /var/lib/dpkg/lock-frontend
  
  After this, configure the package manager:
  
  sudo dpkg --configure -a


/Medium Importance:

   Examine INIT Files for Discrepancies
        Inspect systemd unit files in /etc/systemd/system/ and /lib/systemd/system/.
        Review SysVinit scripts in /etc/init.d/ (if applicable).
        Check configuration files in /etc/ for common misconfigurations (e.g., /etc/fstab, /etc/network/interfaces, /etc/hostname).
        Look at system logs (/var/log/syslog, journalctl) for errors and anomalies.
        Ensure correct permissions and ownership for service files.

  Disable Unwanted SUID and SGID Binaries
      #See all set user id files:
      find / -perm +4000
      # See all group id files
      find / -perm +2000
      # Or combine both in a single command
      find / \( -perm -4000 -o -perm -2000 \) -print
      find / -path -prune -o -type f -perm +6000 -ls
  
  Find World-Writable Files
    find / -­‐type d -­‐perm +2 –ls
    chmod 750
    rm
    __________  OR
    find /dir -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print

   Package Manager Fix
   In Firefox/Chrome/Browser - Set the Most Secure Options

/Lower Importance:

  Locate 9/11 (Find Osama)
  
  Unencrypt Techniques (Files etc.)
  
  Analyze Services and Terminate Unnecessary Processes
  
  Remove Unwanted Commands from /etc/rc#.d
  
  Find No-User Files
    find /dir -xdev \( -nouser -o -nogroup \) -print

  SSH key how to
    ls -l /home/username/.ssh  
    ssh-keygen -lf /path/to/public/key
  
  Disable bash history

Easy Points
  sudo sysctl -p
  Disable sharing the screen by going to settings -> sharing then turn it off
  
