# Network Sniffer
## What This Does
The network sniffer detects the following events occurring on the network you're on:
- NULL scan
- FIN scan
- Xmas scan
- Usernames and passwords sent unencrypted via HTTP basic authentication or FTP
- Nikto scan
- Somebody scanning for Remote Desktop Protocol (RDP)

## Using This Tool
Run the network sniffer by running `python3 network_sniffer.py [args]`. The arguments are as follows:
``` 
-i [INTERFACE]: Sniff on a specified network interface
-r [PCAPFILE]: Read in a PCAP file
-h: Display message on how to use tool
```
If no arguments are given, it will automatically sniff on the network interface `eth0`.

## Dependencies
You will need Python 3, Scapy, and Pcapy.

## Future Improvements
This script **does not work on Windows** at this time. It only works on Linux. I don't know if it works on a Mac because I don't own one. I will add support for Windows in the future. I can't make any promises for Macs, though.