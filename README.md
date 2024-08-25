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
3/4
Report any open ports and their associated services.
Check for and report any IP forwarding or other insecure network configurations.

5. IP and Network Configuration Checks:
Public vs. Private IP Checks:
* Identify whether the server's IP addresses are public or private.
* Provide a summary of all IP addresses assigned to the server


##################### Run this script using below command #############
bash security_audit_server_harddening.sh
