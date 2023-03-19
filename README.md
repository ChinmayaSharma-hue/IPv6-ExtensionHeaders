# IPv6-ExtensionHeaders

This is a demonstration of inserting extension headers into IPv6 packets with the help of eBPF. 

## Getting Started
```
git clone https://github.com/ChinmayaSharma-hue/IPv6-ExtensionHeaders.git
```
### Install dependencies
```
sudo apt-get update && sudo apt-get -y upgrade
```
```
sudo apt-get install -y build-essential clang llvm
```

## Repository Contents

<!-- Link the readme.md file inside directories -->
### [ipv6-drop](https://github.com/ChinmayaSharma-hue/IPv6-ExtensionHeaders/ipv6-drop)
A simple eBPF program that drops all IPv6 packets.
### [ipv6-eh](https://github.com/ChinmayaSharma-hue/IPv6-ExtensionHeaders/ipv6-eh)
An eBPF program that inserts an extension header into all IPv6 packets.

## Tasks

#### Task 1: Drop IPv6 packets
* Use the ipv6-drop program to drop all IPv6 packets.
* Check using wireshark that no IPv6 packets are being sent.
* Try to modify the program to drop only IPv6 packets with a certain destination address.

#### Task 2: Insert an extension header into all IPv6 packets
* Fill in the TODOs in the ipv6-eh program to insert an extension header (as described by [**RFC 8250**](https://datatracker.ietf.org/doc/rfc8250/)) into all IPv6 packets.
* Check using wireshark that the extension header is being inserted into all IPv6 packets.