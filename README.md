# shell_scripts
The first shell script is created with the name "resources_monitoring.sh" which explain

1.Top 10 mostly used applications(CPU and memory)

2.Network monitoring(Concurrent connections, packet drop and number of MB in and out),
Disk usage(system load)
3. Disk Usage:
Display the disk space usage by mounted partitions.
displys partitions using more than 80% of the space.

4. System Load:
Show the current load average for the system.
Includes a breakdown of CPU usage (user, system, idle, etc.).

5. Memory Usage:
Display total, used, and free memory.
Swap memory usage.

6. Process Monitoring:
Display the number of active processes.
Show top 5 processes in terms of CPU and memory usage.

7. Service Monitoring:
Include a section to monitor the status of essential services like sshd, nginx/apache, iptables, etc.

8. Custom Dashboard:
Provide command-line switches to view specific parts of the dashboard, e.g., -cpu, -memory, -network, etc.


######## run the script using below command######
bash resources_monitoring.sh

for calling indivisual part of dashboard taking input from user for
cpu, memory, netowrk sush as

Enter specific part of your Dashboard
cpu
Enter specific part of your Dashboard
momory
Enter specific part of your Dashboard
network


Second script 


1. User and Group Audits:

List all users and groups on the server.
Check for users with UID 0 (root privileges) and report any non-standard users.
Identify and report any users without passwords or with weak passwords.

2. File and Directory Permissions:
Scan for files and directories with world- writable permissions.
Check for the presence of.ssh directories and ensure they have secure permissions.
- Report any files with SUID or SGID bits set, particularly on executables.

3. Service Audits:
List all running services and check for any unnecessary or unauthorized services. Ensure that critical services (e.g., sshd, iptables) are running and properly configured.
Check that no services are listening on non-standard or insecure ports.

4. Firewall and Network Security:
Verify that a firewall (e.g., iptables, ufw) is active and configured to block unauthorized access.
Report any open ports and their associated services.
Check for and report any IP forwarding or other insecure network configurations.

5. IP and Network Configuration Checks:
Public vs. Private IP Checks:
* Identify whether the server's IP addresses are public or private.
* Provide a summary of all IP addresses assigned to the server, specifying which are public and which are private.
* Ensure that sensitive services (e.g., SSH) are not exposed on public IPs unless required.

6. Security Updates and Patching:
Check for and report any available security updates or patches.
Ensure that the server is configured to receive and install security updates regularly.

7. Log Monitoring:
Check for any recent suspicious log entries that may indicate a security breach, such as too many login attempts on SSH.

8. Server Hardening Steps:
SSH Configuration:
* Implement SSH key-based authentication and disable password- based login for root.
* Ensure that SSH keys are securely stored and used.
- Disabling IPv6 (if not required):
* Disable IPv6 if it is not in use, following the provided guidelines.
* Update services like SafeSquid to listen on the correct IPv4 addresses after disabling IPv6.

Securing the Bootloader:
* Set a password for the GRUB bootloader to prevent unauthorized changes to boot parameters.
Firewall Configuration:
* Implement the recommended
* Implement the recommended iptables rules, including default policies, loopback interface acceptance, and specific port allowances.

Automatic Updates:
* Configure unattended-upgrades to automatically apply security updates and remove unused packages, following the provided guidelines.
9. Custom Security Checks:
Allow the script to be easily extended with custom security checks based on specific organizational policies or requirements.
Include a configuration file where custom checks can be defined and managed.

10. Reporting and Alerting:
Generate a summary report of the security audit and hardening process, highlighting any issues that need attention.
Optionally, configure the script to send email alerts or notifications if critical vulnerabilities or misconfigurations are foundr


##################### Run this script using below command #############

bash security_audit_server_harddening.sh
