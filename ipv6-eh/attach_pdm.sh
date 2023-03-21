#!/bin/bash

# Check if 1 argument is passed
if [ $# -ne 1 ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

sudo rm -r /sys/fs/bpf/tc/globals

# Delete qdisc if it already exists
sudo tc qdisc del dev $1 clsact || true

# Add a new qdisc of type classact
sudo tc qdisc add dev $1 clsact

# Attach pdm to egress
sudo tc filter add dev $1 egress bpf direct-action obj pdm_kern.o sec pdm_egress

# Attach pdm to eINress

sudo tc filter add dev $1 ingress bpf direct-action obj pdm_kern.o sec pdm_ingress

# Show the device to check if pdm program has been loaded
sudo tc filter show dev $1
sudo tc filter show dev $1 egress
sudo tc filter show dev $1 ingress
