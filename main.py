#!/usr/bin/env python3

from utils.parse_args import parse_args
from datetime import datetime
from src.net_sniff import NetSniff
from src.read_pcap import ReadPCAP
from src.write_pcap import WritePCAP
from colored import fg, attr
from sys import exit
from platform import system
from subprocess import run, PIPE
	
if __name__ == "__main__":
	if system() == "Linux":
		user = run(["whoami"], stdout=PIPE, stderr=PIPE)
		user = user.stdout.decode("utf-8").replace("\n", "")
		if user != "root":
			print("[%sERROR%s] %s MUST BE RAN AS `root`" % (fg(9), attr(0), __file__))
			exit(1)

	args = parse_args()

	args = {
		"live": args.live_mode,
		"interf": args.interf,
		"filter": args.filter,
		"count": args.count,
		"read": args.read_mode,
		"rfile": args.rfile,
		"pkt-cnt": args.packet_count,
		"no-prn": args.no_print,
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
		"icmp": args.filter_icmp,
		"raw-out": args.show_raw_output,
		"raw-sch": args.raw_search,
		"sum": args.summary,
		"le": args.len_less_equal,
		"ge": args.len_greater_equal,
		"len-equal": args.len_equal,
		"ttl-equal": args.len_equal,
		"json": args.json
	}

	if args["live"]:
		capture = NetSniff(args["interf"], args["filter"], args["count"])
		print("[ %sATTENTION%s ] PLEASE WAIT A SECOND OR TWO FOR A RESPONSE" % (fg(202), attr(0)))
		capture.capture()

	elif args["read"]:
		if args["rfile"]:
			read_obj = ReadPCAP(
				args["rfile"],args["src-ip"], args["dst-ip"], 
				args["src-port"], args["dst-port"], args["src-mac"], 
				args["dst-mac"], args["tcp"], args["udp"], args["icmp"],
				args["pkt-cnt"]
			)
			read_obj.read()

			if args["src-ip"]:
				read_obj.filter_src_ip()
			elif args["dst-ip"]:
				read_obj.filter_dst_ip()
			elif args["src-port"]:
				read_obj.filter_src_port()
			elif args["dst-port"]:
				read_obj.filter_dst_port()
			elif args["src-mac"]:
				read_obj.filter_src_mac()
			elif args["dst-mac"]:
				read_obj.filter_dst_mac()
			elif args["tcp"]:
				read_obj.filter_tcp()
			elif args["udp"]:
				read_obj.filter_udp()
			elif args["icmp"]:
				read_obj.filter_icmp()
			else:
				read_obj.no_filter(args["no-prn"])

			if args["sum"]:
				print("\n[ %sNOTE%s ] GENERATING PCAP SUMMARY" % (fg(226), attr(0)))
				read_obj.summary()

			if args["json"]:
				read_obj.to_json()
				print("[ %sSUCCESS%s ] SUMMARY JSON FILE SUCCESSFULLY CREATED" % (fg(50), attr(0)))
			
			if args["pkt-cnt"]:
				pkt_count = read_obj.packet_count()
				print("[ %s+%s ] Number of packets in PCAP: " % (fg(50), attr(0)), pkt_count)

			if args["raw-out"]:
				read_obj.raw_data_parser.raw_output(read_obj.pcapfile)
			elif args["raw-sch"]:
				read_obj.raw_data_parser.search(read_obj.pcapfile, args["raw-sch"])
		else:
			print(
				"[ %sERROR%s ] MUST PROVIDE `-r` ARGUMENTS FOR READ MODE"
				% (fg(9), attr(0))
			)
			exit(1)

	elif args["write"]:
		if args["wfile"]:
			write_obj = WritePCAP(
				args["wfile"], args["interf"], args["filter"], args["count"],
				args["src-ip"], args["dst-ip"], args["src-port"], args["dst-port"],
				args["src-mac"], args["dst-mac"], args["tcp"], args["udp"], args["icmp"]
			)
		else:
			print(
				"[ %sERROR%s ] MUST PROVIDE `-w` ARGUMENT FOR WRITE MODE"
				% (fg(9), attr(0))
			)
			exit(1)		

		if args["count"]:
			if args["src-ip"]:
				write_obj.filter_src_ip()
			elif args["dst-ip"]:
				write_obj.filter_dst_ip()
			elif args["src-port"]:
				write_obj.filter_src_port()
			elif args["dst-port"]:
				write_obj.filter_dst_port()
			elif args["src-mac"]:
				write_obj.filter_src_mac()
			elif args["dst-mac"]:
				write_obj.filter_dst_mac()
			elif args["tcp"]:
				write_obj.filter_tcp()
			elif args["udp"]:
				write_obj.filter_udp()
			elif args["icmp"]:
				write_obj.filter_icmp()
			else:
				print("[ %sNOTE%s ] NO WRITE FILTERS HAVE BEEN APPLIED" % (fg(226), attr(0)))
				write_obj.no_filter()

			if args["sum"]:
				print("\n[ %sNOTE%s ] GENERATING PCAP SUMMARY" % (fg(226), attr(0)))
				write_obj.summary()
				
			if args["json"]:
				write_obj.to_json()
				print("[ %sSUCCESS%s ] SUMMARY JSON FILE SUCCESSFULLY CREATED" % (fg(50), attr(0)))
		else:
			print(
				"[ %sERROR%s ] MUST PROVIDE `-c` ARGUMENT FOR WRITE MODE"
				% (fg(9), attr(0))
			)
	else:
		print(
			"[ %sERROR%s ] MUST PROVIDE A MODE OF OPERATION: -live, -read, or -write"
			% (fg(9), attr(0))
		)