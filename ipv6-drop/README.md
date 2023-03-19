# Drop IPv6 packets

## Running the eBPF program

1. Compiling the eBPF program,
   ```
   make
   ```
2. [Optional] Creating a virtual network interface pair,
   ```
   sudo ip link add veth0 type veth peer name veth1
   ```
   ```
   sudo ip link set veth0 up
   ```
   ```
   sudo ip link set veth1 up
   ```

3. Running the load_bpf.sh script to load the eBPF program,
   ```
   ./load_bpf.sh <your_interface>
   ```

4. Ping from the source machine to the destination machine,
   ```
   ping6 <destination_ip>%<source_eth_interface> -c5
   ```
5. Check the ping statistics using wireshark.


## Unloading the eBPF program

1. Run the remove_bpf.sh script to unload the eBPF program,
   ```
   ./remove_bpf.sh <your_interface>
   ```