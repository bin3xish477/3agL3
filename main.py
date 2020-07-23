#!/usr/bin/env python3

"""
Objectives:
	- sniff network packets and print out to stdout or to a file
	- capture packets for a specified time and write packets to pcap
	- provide the option for tcpdump filtering using the sniff(filter=) method
	- open pcap files and parse data according to the 5 tuple
"""

from utils.parse_args import parse_args
from datetime import datetime
from src.net_sniff import NetSniff
from src.read_pcap import ReadPCAP
from src.write_pcap import WritePCAP
from sys import exit

def main():
	args = parse_args()

	args = {
		"live": args.live_mode,
		"interf": args.interf,
		"filter": args.filter,
		"count": args.count,
		"read": args.read_mode,
		"rfile": args.rfile,
		"write": args.write_mode,
		"wfile": args.wfile,
		"src-ip": args.source_ip,
		"dst-ip": args.destination_ip,
		"src-port": args.source_port,
		"dst-port": args.destination_port,
		"src-mac": args.source_mac,
		"dst-mac": args.destination_mac,
		"tcp": args.filter_tcp,
		"udp": args.filter_udp
	}

	if args["live"]:
		capture = NetSniff(args["interf"], args["filter"], args["count"])
		capture.capture()

	elif args["read"]:
		# read_obj = ReadPCAP(
		# 	args["rfile"], args["interf"], args["filter"], args["count"],
		# 	args["src-ip"], args["dst-ip"], args["src-port"], args["dst-port"],
		# 	args["src-mac"], args["dst-mac"], args["tcp"], args["udp"]
		# )
		pass

	elif args["write"]:
		write_obj = WritePCAP(
			args["wfile"], args["interf"], args["filter"], args["count"],
			args["src-ip"], args["dst-ip"], args["src-port"], args["dst-port"],
			args["src-mac"], args["dst-mac"], args["tcp"], args["udp"]
		)

		write_obj.start()
		if args["src-ip"]:
			write_obj.filter_src_ip()

	else:
		print("[ERROR] Must provide a mode of operation: -live, -read, or -write")
	
if __name__ == "__main__":
	main()
