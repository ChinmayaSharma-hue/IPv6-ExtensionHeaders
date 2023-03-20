# IPv6-ExtensionHeaders

This is a demonstration of inserting extension headers into IPv6 packets with the help of eBPF. 

## Getting Started
```
git clone https://github.com/ChinmayaSharma-hue/IPv6-ExtensionHeaders.git
```
### Install dependencies
```
sudo apt-get update
```
```
sudo apt-get install -y build-essential clang llvm libelf-dev libpcap-dev \
gcc-multilib linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-common \
linux-tools-generic tcpdump wireshark
```

## Repository Contents

<!-- Link the readme.md file inside directories -->
### [ipv6-drop](https://github.com/ChinmayaSharma-hue/IPv6-ExtensionHeaders/tree/main/ipv6-drop)
A simple eBPF program that drops all IPv6 packets.
### [ipv6-eh](https://github.com/ChinmayaSharma-hue/IPv6-ExtensionHeaders/tree/main/ipv6-eh)
An eBPF program that inserts an extension header into all IPv6 packets.

## Tasks

#### Task 1: Drop IPv6 packets
* Use the ipv6-drop program to drop all IPv6 packets.
* Check using wireshark that no IPv6 packets are being sent.
* Try to modify the program to drop only IPv6 packets with a certain destination address.

#### Task 2: Insert an extension header into all IPv6 packets
* Fill in the TODOs in the ipv6-eh program to insert an extension header (as described by [**RFC 8250**](https://datatracker.ietf.org/doc/rfc8250/)) into all IPv6 packets.
* Check using wireshark that the extension header is being inserted into all IPv6 packets.

#### Task 3: Try sending PDM enabled IPv6 packets and analyze
* Atttach the compiled PDM program to your main infterface
  ```
  ./attach_pdm.sh <interface>
  ```
* Send IPv6 packets with PDM to a server which has enabled PDM.
  ```
  ping6 2001:19f0:5:3ce7:5400:04ff:fe31:1527
  ```
* Simulatneously capture packets on the interface using wireshark.
  ```
  sudo wireshark
  ```
* Analyze the PDM packets on wireshark
