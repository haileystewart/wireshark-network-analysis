#!/bin/bash
echo "Starting DNS Analysis Report Generation..."

if [ -f "analyze_dns.py" ]; then
    python3 analyze_dns.py
else
    echo "analyze_dns.py not found!"
fi

echo "Report generation complete."
