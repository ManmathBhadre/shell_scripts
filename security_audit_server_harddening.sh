echo ""
echo -e "\t +++++ Automatic Security Audit and server Hardening on linux server +++++ \t"
echo ""


echo "----------------------------------------------------------"
echo -e "Req. 1: user and group audit"
echo "----------------------------------------------------------"
echo""
#List all users and groups on the server
echo "Users on the server:"
cat /etc/passwd | awk -F: '{print $1}' | sort |xargs
echo""
echo "Groups on the server:"
cat /etc/group | awk -F: '{print $1}' | sort | xargs
echo""
# Check for users with UID 0 (root privileges) and report any non-standard users
echo "Users with UID 0 (root privileges):"
cat /etc/passwd | awk -F: '$3 == 0 {print $1}' | grep -v root
if [ $? -eq 0 ]; then
  echo "Non-standard users with UID 0 found!"
else
  echo "Only standard 'root' user has UID 0."
fi
echo""
# Identify and report any users without passwords or with weak passwords
echo "Users without passwords or with weak passwords:"
for user in $(cat /etc/passwd | awk -F: '{print $1}'); do
  password_status=$(passwd -S $user | awk '{print $2}')
  if [ "$password_status" = "NP" ]; then
    echo "  $user: No password set!"
  elif [ "$password_status" = "L" ]; then
    echo "  $user: Password locked!"
  elif [ "$password_status" = "P" ]; then
    password_strength=$(passwd -S $user | awk '{print $3}')
    if [ "$password_strength" -lt 3 ]; then
      echo "  $user: Weak password!"
    fi
  fi
done

echo "----------------------------------------------------------"
echo -e "Req. 2: file and directries"
echo "----------------------------------------------------------"
echo""
# Scan for files and directories with world-writable permissions
echo "Directories with world-writable permissions:"
find /home -type d -perm -o=w -print| xargs
echo ""
echo "Files with world-writable permissions:"
find /home -type f -perm -o=w -print| xargs
echo""

# Check for the presence of .ssh directories and ensure they have secure permissions
echo "Checking .ssh directories:"
for dir in $(find /home -type d -name .ssh); do
  perms=$(stat -c "%a" "$dir")
  if [ $perms -ne 700 ]; then
    echo "  $dir has insecure permissions ($perms)!"
  fi
done
echo""
# Report any files with SUID or SGID bits set, particularly on executables
echo "Files with SUID bits set:"
find /home -type f -perm -u=s -print| xargs
echo ""

echo "Files with SGID bits set:"
find /home -type f -perm -g=s -print| xargs
echo""
# Check for SUID/SGID bits on executables
echo "SUID bits on executables:"
find /home -type f -perm -u=s -executable -print| xargs
echo ""

echo "SGID bits on executables:"
find /home -type f -perm -g=s -executable -print| xargs
echo""

echo "----------------------------------------------------------"
echo -e "Req. 3: service audit"
echo "----------------------------------------------------------"
echo""
# List all running services
echo "Running Services:"
systemctl --quiet --type=service --state=running
#systemctl --type=service |grep running
echo""
# Check for critical services
CRITICAL_SERVICES=("sshd" "iptables")
for service in "${CRITICAL_SERVICES[@]}"; do
  if systemctl is-active --quiet "$service"; then
    echo "Critical service $service is running"
  else
    echo "Critical service $service is not running"
  fi
done
echo""
# Check for unnecessary or unauthorized services
UNNECESSARY_SERVICES=("telnet" "ftp")
for service in "${UNNECESSARY_SERVICES[@]}"; do
  if systemctl is-active --quiet "$service"; then
    echo "Unnecessary service $service is running"
    echo "Please investigate and disable if necessary"
  fi
done

echo""
# Check for services listening on non-standard or insecure ports
echo "Services listening on non-standard or insecure ports:"
netstat -tulnp | grep -v "ssh" | grep -v "https"
echo""

echo "----------------------------------------------------------"
echo -e "Req. 4: firewall and network security"
echo "----------------------------------------------------------"
echo""
# Check if firewall is active
if [ "$(systemctl is-active firewalld.service)" = "active" ]; then
  echo "Firewall is active"
else
  echo "Firewall is not active"
 
fi
echo""
# Report open ports and associated services
echo "Open Ports and Services:"
netstat -tulnp | grep -v "Proto"
echo ""
# Check for IP forwarding
if [ "$(sysctl net.ipv4.ip_forward)" = "net.ipv4.ip_forward = 1" ]; then
  echo "IP forwarding is enabled"
else
  echo "IP forwarding is disabled"
fi
echo""
# Check for other insecure network configurations
echo "Insecure Network Configurations:"
sysctl -a | grep -E "net.ipv4.tcp_syncookies|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.accept_source_route"

# Check for open ports in iptables
echo "Open Ports in iptables & Firewalld:"
echo "Open ports in iptable: $(iptables -n -L | grep -v 'Chain')"
echo ""
echo -e "Open Ports in Firewalld: $(firewall-cmd --list-ports)"
echo -e "Services allowed in Firewalld: $(firewall-cmd --list-services)"
echo""

echo "----------------------------------------------------------"
echo -e "Req. 5: firewall and network security"
echo "----------------------------------------------------------"
echo""
# Get all IP addresses assigned to the server
IP_ADDRESSES=$(ip addr show | grep "inet " | awk '{print $2}' | sed 's/\/.*//')

# Initialize arrays to store public and private IP addresses
PUBLIC_IPS=()
PRIVATE_IPS=()

# Loop through each IP address
for IP in $IP_ADDRESSES; do
  # Check if IP address is public or private
  if [[ $IP =~ ^10\.|^172\.16\.|^192\.168\. ]]; then
    PUBLIC_IPS+=($IP)
  else
    PRIVATE_IPS+=($IP)
  fi
done

# Print summary of IP addresses
echo "Summary of IP Addresses:"
echo "Public IP Addresses: ${PUBLIC_IPS[@]}"
echo "Private IP Addresses: ${PRIVATE_IPS[@]}"

# Check if sensitive services are exposed on public IPs
SENSITIVE_SERVICES=("ssh" "ftp" "telnet")
for SERVICE in "${SENSITIVE_SERVICES[@]}"; do
  for IP in "${PUBLIC_IPS[@]}"; do
    if netstat -tlnp | grep -q "$SERVICE" && netstat -tlnp | grep -q "$IP"; then
      echo "Warning: $SERVICE is exposed on public IP $IP"
    fi
  done
done


echo "----------------------------------------------------------"
echo -e "Req. 6: security update and paching"
echo "----------------------------------------------------------"
echo""
# Check for available security updates
echo "Checking for available security updates..."
AVAILABLE_UPDATES=$(yum --security check-update)

# If updates are available, report them and install them
if [ -n "$AVAILABLE_UPDATES" ]; then
  echo "Available security updates:"
  echo "$AVAILABLE_UPDATES"
  echo "Installing security updates..."
  yum update -y --security
  echo "Security updates installed successfully."
else
  echo "No security updates available."
fi

# Configure the server to receive and install security updates regularly
echo "Configuring server to receive and install security updates regularly..."

# Enable the yum-cron service to check for update
yum update -y yum-cron*
systemctl status crond.service
systemctl enable crond.service
# Configure yum-cron to install security updates automatically
echo "apply_updates = yes" >> /etc/yum/yum-cron.conf
echo "update_cmd = security" >> /etc/yum/yum-cron.conf

# Restart the yum-cron service to apply the changes
systemctl restart crond.service

echo "Server configured to receive and install security updates regularly."
echo "----------------------------------------------------------"
echo -e "Req. 7: log monitoring"
echo "----------------------------------------------------------"
echo""
# Set the log file to check
LOG_FILE=/var/log/audit/audit.log

# Set the time period to check (e.g. last 24 hours)
TIME_PERIOD="24 hours ago"

# Set the threshold for suspicious login attempts
THRESHOLD=5

# Check for too many login attempts on SSH
echo "Checking for too many login attempts on SSH..."
sudo grep -i "ssh" $LOG_FILE | grep -i "failed" | grep -B1 "$TIME_PERIOD" | awk '{print $11}' | sort | uniq -c | sort -rn | head -n 10

# Check for unknown usernames attempting to login
echo "Checking for unknown usernames attempting to login..."
sudo grep -i "ssh" $LOG_FILE | grep -i "invalid user" | grep -B1 "$TIME_PERIOD" | awk '{print $11}' | sort | uniq -c | sort -rn | head -n 10

# Check for brute-force attacks on SSH
echo "Checking for brute-force attacks on SSH..."
sudo grep -i "ssh" $LOG_FILE | grep -i "password" | grep -B1 "$TIME_PERIOD" | awk '{print $11}' | sort | uniq -c | sort -rn | head -n 10

# Check for root login attempts
echo "Checking for root login attempts..."
sudo grep -i "ssh" $LOG_FILE | grep -i "root" | grep -B1 "$TIME_PERIOD" | awk '{print $11}' | sort | uniq -c | sort -rn | head -n 10
echo""

echo "----------------------------------------------------------"
echo -e "Req. 8: server hardening steps"
echo "----------------------------------------------------------"
echo""
# Set the path to the SSH key file
KEY_FILE="/root/.ssh/id_rsa"

# Generate a new SSH key pair if one doesn't exist
if [ ! -f "$KEY_FILE" ]; then
  ssh-keygen -t rsa -b 4096 -N "" -f "$KEY_FILE"
fi

# Copy the public key to the authorized_keys file
cat "$KEY_FILE.pub" >> /root/.ssh/authorized_keys

# Set the permissions for the SSH key files
chmod 600 "$KEY_FILE"
chmod 600 "$KEY_FILE.pub"
chmod 600 /root/.ssh/authorized_keys

# Disable password-based login for the root user
sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

# Restart the SSH service to apply the changes
systemctl restart sshd

echo "End of SSH authentication check"

# Check if IPv6 is in use
if [ $(ip -6 addr show | grep -c "inet6") -eq 0 ]; then
  # Disable IPv6
  echo "Disabling IPv6..."
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  sysctl -w net.ipv6.conf.default.disable_ipv6=1
  sysctl -w net.ipv6.conf.lo.disable_ipv6=1

  # Update /etc/sysctl.conf to persist the change
  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

  # Restart services that use IPv4
  echo "Restarting services..."
  yum install httpd -y
  yum install postfix -y
#  wget http://downloads.safesquid.net/linux32/safesquid/composite/safesquid-ntlm.RC4.3.2-composite-standard.tar.gz
#  tar -xvzf safesquid-ntlm.RC4.3.2-composite-standard.tar.gz
#  cd safesquid && ./install

#  systemctl restart safesquid.service
  systemctl restart httpd.service
  systemctl restart postfix.service

  # Update SafeSquid configuration to listen on IPv4 addresses
  echo "Updating SafeSquid configuration..."
  sed -i 's/listen_ip = "::"/listen_ip = "0.0.0.0"/' /etc/safesquid/safesquid.conf
  sed -i 's/bind_ip = "::"/bind_ip = "0.0.0.0"/' /etc/safesquid/safesquid.conf

  echo "IPv6 disabled and services updated successfully!"
else
  echo "IPv6 is in use, skipping disablement."
fi

echo""

: '
# Set the GRUB password
echo "Enter a password for GRUB:"
read -s GRUB_PASSWORD
echo "Re-enter the password to confirm:"
read -s GRUB_PASSWORD_CONFIRM

if [ "$GRUB_PASSWORD" == "$GRUB_PASSWORD_CONFIRM" ]; then
  # Generate a hashed password
  GRUB_PASSWORD_HASH=$(echo -n "$GRUB_PASSWORD" | grub2-mkpasswd-pbkdf2)

  # Update the GRUB configuration file
  echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
  echo "password_pbkdf2 root $GRUB_PASSWORD_HASH" >> /etc/grub.d/40_custom

  # Update the GRUB configuration
  grub2-mkconfig -o /boot/grub2/grub.cfg

  echo "GRUB password set successfully!"
else
  echo "Passwords do not match, please try again."
fi
'

# Set default policies
echo "Running Firewall"
firewall-cmd --set-default-zone=trusted
echo "default-zone set"

# Accept incoming traffic on specific ports
firewall-cmd --add-port=22/tcp
firewall-cmd --add-port=80/tcp
firewall-cmd --add-port=443/tcp

# Accept outgoing traffic on specific ports
firewall-cmd --add-port=53/tcp --zone=public
firewall-cmd --add-port=53/udp --zone=public
firewall-cmd --add-port=80/tcp --zone=public
firewall-cmd --add-port=443/tcp --zone=public


# Reload the firewall configuration
firewall-cmd --reload

echo "iptables rules implemented successfully!"

