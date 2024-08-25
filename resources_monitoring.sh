#!/bin/bash

echo ""
echo -e "\t +++++ SCRIPT FOR MONITORING SYSTEM RESOURES +++++ \t"
echo ""

cpu_usage() {
echo "----------------------------------------------------------"
echo -e "Req. 1: Top 10 Most Used Applications"
echo "----------------------------------------------------------"
CPU=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -11)
MEM=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -11)
echo -e "Consumed By CPU = \n $CPU"
echo ""
echo -e "Consumed By MEMORY = \n $MEM"
echo ""
 }

network_usage() {
echo "----------------------------------------------------------"
echo -e "Req. 2: Network Monitoring"
echo "----------------------------------------------------------"
echo ""
echo "Concurrent connections: $(netstat -an | grep ESTABLISHED | wc -l)"
echo ""
echo "Packet drops: $(grep "drop" /proc/net/netstat | awk '{print $1}')"
echo""
echo Number of MB in and out
RX_BYTES=$(cat /proc/net/dev | awk '$1 ~ /ens160|eth0/ {print $2}')
TX_BYTES=$(cat /proc/net/dev | awk '$1 ~ /ens160|eth0/ {print $10}')
RX_MB=$(echo "scale=2; $RX_BYTES / 1024 / 1024" | bc)
TX_MB=$(echo "scale=2; $TX_BYTES / 1024 / 1024" | bc)
echo "in (MB): $RX_MB"
echo "out (MB): $TX_MB"
echo""
}

disk_usage() {
echo "----------------------------------------------------------"
echo -e "Req. 3: disk usage"
echo "----------------------------------------------------------"
ALERT=80

df -h --output=source,pcent | awk '{print $1 " " $2}' | while read line; do

    partition=$(echo $line | awk '{print $1}')
    usage=$(echo $line | awk '{print $2}' | sed 's/%//g')
    if [[ "$usage" -gt "$ALERT" ]]; then
        echo "Critical Disk Found:"
        echo -e "$partition: $usage%"
        echo ""
    fi
done
echo""
}

systems_loads() {
echo "----------------------------------------------------------"
echo -e "Req. 4: system load"
echo "----------------------------------------------------------"
echo""
a=$(uptime | cut -c 32-70)
echo avg.load is $a

a=$(top -bn1 | grep "Cpu(s)" | awk '{print $2,$3,$4,$5,$6,$7,$8,$9}'| cut -c 1-3)
echo cpu usage by user is $a
b=$(top -bn1 | grep "Cpu(s)" | awk '{print $2,$3,$4,$5,$6,$7,$8,$9}'| cut -c 9-11)
echo cpu usage by system is $b
c=$(top -bn1 | grep "Cpu(s)" | awk '{print $2,$3,$4,$5,$6,$7,$8,$9}'| cut -c 17-20)
echo idel cpu uses is $c
echo""
}

memory_usage() {
echo "----------------------------------------------------------"
echo -e "Req. 5: memory usage"
echo "----------------------------------------------------------"
echo""
echo "Memory Usage:"
echo "Total Memory: $(free -m | awk 'NR==2{print $2}') MB"
echo "Used Memory: $(free -m | awk 'NR==2{print $3}') MB"
echo "Free Memory: $(free -m | awk 'NR==2{print $4}') MB"

# Display swap memory usage
echo ""
echo "Swap Memory Usage:"
echo "Total Swap: $(free -m | awk 'NR==3{print $2}') MB"
echo "Used Swap: $(free -m | awk 'NR==3{print $3}') MB"
echo "Free Swap: $(free -m | awk 'NR==3{print $4}') MB"
echo""
}

process_usage() {
echo "----------------------------------------------------------"
echo -e "Req. 6: process monitoring"
echo "----------------------------------------------------------"
echo""
#Display the number of active processes
echo "Number of active processes: $(ps -ef | wc -l)"
echo""

# Display top 5 processes by CPU usage
echo "Top 5 processes by CPU usage:"
ps -eo pcpu,pid,cmd --sort=-pcpu | head -6
echo""
# Display top 5 processes by memory usage
echo "Top 5 processes by memory usage:"
ps -eo pmem,pid,cmd --sort=-pmem | head -6
echo""
}

service_monitoring() {
echo "----------------------------------------------------------"
echo -e "Req. 7: service monitoring"
echo "----------------------------------------------------------"
echo "Essential Services Status:"
echo""
# Check SSHD service
SERVICE="sshd"
if systemctl status $SERVICE | grep -q "active (running)"; then
  echo "  $SERVICE: Running"
else
  echo "  $SERVICE: Not Running"
fi
echo""
# Check Nginx/Apache service
SERVICE="nginx"
if systemctl status $SERVICE | grep -q "active (running)"; then
  echo "  $SERVICE: Running"
else
  SERVICE="apache2"
  if systemctl status $SERVICE | grep -q "active (running)"; then
    echo "  $SERVICE: Running"
  else
    echo "  Web Server: Not Running"
  fi
fi
echo""
# Check Iptables service
SERVICE="iptables"
if systemctl status $SERVICE | grep -q "active (running)"; then
  echo "  $SERVICE: Running"
else
  echo "  $SERVICE: Not Running"
fi
echo""
}

cpu_usage
network_usage
disk_usage
systems_loads
memory_usage
process_usage
service_monitoring

echo "----------------------------------------------------------"
echo -e "Req. 8: custom dashboard"
echo "----------------------------------------------------------"
echo""
echo "Enter specific part of your Dashboard"
read a
echo "Print $a usage to Dashboard"
  case $a in
    cpu) cpu_usage ;;
    memory) memory_usage ;;
    network) network_usage ;;
    disk) disk_usage ;;
    \?) echo "Invalid option: -$OPTARG"; exit 1 ;;
  esac



