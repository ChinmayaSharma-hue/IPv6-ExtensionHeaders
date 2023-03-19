# PDM eBPF

eBPF(TC-BPF) implementation of IPv6 PDM extension header([**RFC8250**](https://www.rfc-editor.org/rfc/rfc8250)).\
The program has two sections, ingress and egress. These are attached to ingress and egress of the interface respectively, so that the respective sections are executed on ingress and egress of the interface.\
The main goal of this task is to fill in the TODOs in the program, as well as figure out the relevance of certain lines of code.

## How to use 
1. [Optional] Creating a virtual network interface pair,
   ```
   sudo ip link add veth0 type veth peer name veth1
   ```
   ```
   sudo ip link set veth0 up
   ```
   ```
   sudo ip link set veth1 up
   ```
2. Running the start.sh script to compile and load the BPF program,
   ```
   ./start.sh <your_interface>
   ```
3. Ping from the source machine to the destination machine,
   ```
   ping6 <destination_ip>%<source_eth_interface> -c5
   ```
4. Check the ICMPv6 packets for PDM extension header using wireshark.



## Unloading the eBPF program

1. Run the stop.sh script to unload the eBPF program,
   ```
   ./stop.sh <your_interface>
   ```