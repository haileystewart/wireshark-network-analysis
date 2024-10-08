#!/bin/bash 
pcap_file="C:\\Users\\hailey\\pcap_files\\live_traffic.pcap" 
alert_file="C:\\Users\\hailey\\pcap_files\\alert_dns.txt" 

echo "Starting DNS Alert Script..."
python3 C:\\Users\\hailey\\pcap_files\\analyze_dns.py 

if [ -s $alert_file ]; then 
    echo "Alerts found. Check alert_dns.txt for details."
else 
    echo "No suspicious DNS queries found." 
fi 
