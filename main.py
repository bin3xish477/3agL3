#!/usr/bin/env python3

from utils.parse_args import parse_args
from datetime import datetime
from src.net_sniff import NetSniff
from src.read_pcap import ReadPCAP
from src.write_pcap import WritePCAP
from colored import fg, attr
from time import sleep
from sys import exit
from os import geteuid
from platform import system

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
		"udp": args.filter_udp,
		"sum": args.summary,
		"le": args.len_less_equal,
		"ge": args.len_greater_equal,
		"equal": args.equal
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

		if args["count"]:
			if args["src-ip"]:
				write_obj.filter_src_ip()
			elif args["dst-ip"]:
				write_obj.filter_dst_ip()
			else:
				print("[%sNOTE%s] No filter has been applied" % (fg(226), attr(0)))
				write_obj.no_filter()

			if args["sum"]:
				sleep(1)
				print("[%sNOTE%s] Generating capture summary" % (fg(226), attr(0)))
				write_obj.summary()
		else:
			print(
				"[%sERROR%s] Must provide `-c` arguments for write mode"
				% (fg(9), attr(0))
			)
	else:
		print(
			"[%sERROR%s] Must provide a mode of operation: -live, -read, or -write"
			% (fg(9), attr(0))
		)
	
if __name__ == "__main__":
	if system() == "Linux" and geteuid != 0:
		print(
			"[%sERROR%s] %s must be ran as user `root`"
			% (fg(9), attr(0), __file__)
		)
		exit(1)
	main()