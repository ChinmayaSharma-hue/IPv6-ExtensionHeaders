# Drop IPv6 packets

## Running the eBPF program

1. Compiling the eBPF program,
   ```
   make
   ```

2. Running the load_bpf.sh script to load the eBPF program,
   ```
   ./load_bpf.sh eno1
   ```
3. Check the ping statistics using wireshark.
   ```
   sudo wireshark
   ```

4. Ping from the source machine to the destination machine,
   ```
   ping6 2001:4f80:8000:c000::1000%<source_eth_interface> -c5
   ```



## Unloading the eBPF program

1. Run the remove_bpf.sh script to unload the eBPF program,
   ```
   ./remove_bpf.sh eno1
   ```
