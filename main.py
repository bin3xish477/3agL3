#!/usr/bin/env python3

"""
Objectives:
	- sniff network packets and print out to stdout or to a file
	- capture packets for a specified time and write packets to pcap
	- provide the option for tcpdump filtering using the sniff(filter=) method
	- open pcap files and parse data according to the 5 tuple
"""

from utils.parse_args import _parse_args
from datetime import datetime
from src.net_sniff import NetSniff
import sys

def main():
	args = _parse_args()
	capture = NetSniff(interf="eth0")
	capture.capture()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"[{str(datetime.now())[11:19]}] : Quitting program")
        sys.exit(1)
