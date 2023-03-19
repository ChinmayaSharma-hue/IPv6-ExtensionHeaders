#!/bin/bash
# Check if 1 argument is passed
if [ $# -ne 1 ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi
sudo tc qdisc add dev $0 clsact
sudo tc filter add dev $0 egress bpf direct-action obj ipv6_drop.o sec classifier
sudo tc filter show dev $0
sudo tc filter show dev $0 egress
