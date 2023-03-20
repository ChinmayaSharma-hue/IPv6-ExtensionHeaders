#!/bin/bash
# Check if 1 argument is passed
if [ $# -ne 1 ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

# Delete the qdisc
sudo tc qdisc del dev $1 clsact