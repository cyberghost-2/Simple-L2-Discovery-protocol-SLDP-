# Contributing to SLDP

First off, thank you for considering contributing to SLDP! 

## Reporting Bugs

If you find a bug, please open an issue on GitHub. To help me fix it quickly, please include:

1. **Your Environment:** Linux distribution, kernel version, and network interface type.
2. **Steps to Reproduce:** Exactly what commands you ran.
3. **Expected vs. Actual Behavior:** What you thought would happen vs. what actually happened.
4. **Wireshark Capture (Optional):** If you are using the `dissector.lua`, please attach a `.pcap` file showing the problem. Use `sudo tcpdump -i <interface> -w sldp_bug.pcap` to capture the raw frames.
5. **Compile Errors:** If it doesn't compile, paste the exact output of `make`.
