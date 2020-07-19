#!/usr/bin/env python3

"""
Objectives:
	- sniff network packets and print out to stdout or to a file
	- capture packets for a specified time and write packets to pcap
	- provide the option for tcpdump filtering using the sniff(filter=) method
	- open pcap files and parse data according to the 5 tuple
"""

from scapy.all import sniff
from datetime import datetime
import sys

def main():
	pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"[{str(datetime.now())[11:19]}] : Quitting program")
        sys.exit(1)
