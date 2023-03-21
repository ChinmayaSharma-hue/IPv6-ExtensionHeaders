# Adding PDM extension header to IPv6 packets

eBPF(TC-BPF) implementation of IPv6 PDM extension header([**RFC8250**](https://www.rfc-editor.org/rfc/rfc8250)).\
The program has two sections, ingress and egress. These are attached to ingress and egress of the interface respectively, so that the respective sections are executed on ingress and egress of the interface.\

## How to use 

1. Compile and load the BPF program to a interface.
   ```
   ./start.sh eno1
   ```
2. Start wireshark on eno1 interface
   ```
   sudo wireshark
   ```
3. Ping from the source machine to the destination machine,
   ```
   ping6 2001:4f80:8000:c000::1000%eno1 -c5
   ```
4. Check the ICMPv6 packets for PDM extension header using wireshark.



## Unloading the eBPF program

1. Run the stop.sh script to unload the eBPF program,
   ```
   ./stop.sh eno1
   ```
