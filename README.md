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
* Try to modify the program to drop only IPv6 packets with a certain destination address(`200:4f80:8000:c000::1000`).


#### Task 2: Try sending PDM enabled IPv6 packets and analyze
* Atttach the compiled PDM program to your main infterface
  ```
  ./attach_pdm.sh eno1
  ```
* Send IPv6 packets with PDM to a server which has enabled PDM.
  ```
  ping6 2001:4f80:8000:c000::1000
  ```
* Simulatneously capture packets on the interface using wireshark.
  ```
  sudo wireshark
  ```
* Analyze the PDM packets on wireshark
