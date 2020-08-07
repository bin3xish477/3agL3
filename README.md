# 3agL3
Sniffing network traffic with Python for real-time or PCAP analysis.

## > Pip Requirements
```
scapy
colored
netaddr
netifaces
```

## Npcap/Tcpdump Installation
- Download Npcap for **Windows**:
    - https://nmap.org/download.html
- Install Tcpdump: **Ubuntu/Debian**:
    - `sudo apt install tcpdump -y`
- Install Tcpdump: **CentOS/RHEL**:
    - `yum install tcpdump -y`

## > Example: Live Mode
![live_mode](images/live_mode.png)

## > Example: Read Mode

## > Example: Write Mode

## > Berkeley Packet Filter Examples
```
dst host 192.168.1.0
src host 192.168.1
dst host 172.16
src host 10
host 192.168.1.0
host 192.168.1.0/24
src host 192.168.1/24

```
For more Berkeley Packet Filters: [Berkeley Packet Filters](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_forensics_bpf.html)
