from argparse import ArgumentParser
from colored import fg, attr
from platform import system
from sys import exit, argv
from colored import fg, attr

def parse_args():
	""" Program arguments """
	parser = ArgumentParser(
		description="There are three modes of operation \u2192 live : read : write ",
		usage=f"\n\t{argv[0]} -live [options..] | -read [options..] | -write [options..]",
		add_help=False
		)
	
	# ---------------- Arguments Groups ------------------
	help_options = parser.add_argument_group("%sFor Help%s" % (fg(226), attr(0)))
	live_capture = parser.add_argument_group("%sLive Capture%s" % (fg(196), attr(0)))
	read_pcap = parser.add_argument_group("%sRead Mode Required Options%s" % (fg(76), attr(0)))
	write_pcap = parser.add_argument_group("%sWrite Mode Required Options%s" % (fg(39), attr(0)))
	write_read_pcap = parser.add_argument_group("%sOptional Arguments for Read/Write Modes%s" % (fg(199), attr(0)))

	help_options.add_argument("-h", "--help",action="help",help="show this help message and exit")

	# -------------- Live Capture Options ---------------
	live_capture.add_argument("-live", "--live-mode",action="store_true",default=False,help="perfrom live capture analysis")

	if system() == "Windows":
		live_capture.add_argument("-i", "--interf",nargs="*",help="the interface to listen on (more than one can be specified)")
	else:
		live_capture.add_argument("-i", "--interf", nargs="*", default="eth0",help="the interface to listen on (more than one is allowed)")

	live_capture.add_argument("-c", "--count",type=int, default=0,help="the number of packets to capture (default = 0 = infinity)")
	live_capture.add_argument("-f", "--filter",type=str, default=None,help="Berkeley packet filter to apply to capture")

	# -------------- Reading PCAP options ---------------
	read_pcap.add_argument("-read", "--read-mode",action="store_true", default=False,help="read a PCAP file for analysis")
	read_pcap.add_argument("-r", "--rfile",type=str, default=False,help="name of PCAP file to read for parsing")
	read_pcap.add_argument("-pc", "--packet-count",action="store_true",default=False,help="returns the number of the packets within a PCAP file")
	read_pcap.add_argument("-no-prn", "--no-print",action="store_true",help="do not print out traffic flow output to console")

	# -------------- Writing PCAP options ---------------
	write_pcap.add_argument("-write", "--write-mode",action="store_true", default=None,help="capture live traffic and write to PCAP file (must specify `-c` option)")
	write_pcap.add_argument("-w", "--wfile",type=str, default=None,help="name of PCAP file to create")

	# -------------- Read/Write Options ----------------
	write_read_pcap.add_argument("-src-ip", "--source-ip",type=str,help="Filter packets based on a specified source IP address")
	write_read_pcap.add_argument("-dst-ip", "--destination-ip",type=str,help="Filter packets based on a specified destination IP address")
	write_read_pcap.add_argument("-src-port", "--source-port",type=str,help="Filter packets based on a specified source port number")
	write_read_pcap.add_argument("-dst-port", "--destination-port",type=str,help="Filter packets based on a specified destination port number")
	write_read_pcap.add_argument("-src-mac", "--source-mac",type=str,help="Filter packets based on a specified source mac address (seperate values by `.`)")
	write_read_pcap.add_argument("-dst-mac", "--destination-mac",type=str,help="Filter packets based on a specified destination mac address (seperate values by `.`)")
	write_read_pcap.add_argument("-tcp", "--filter-tcp",action="store_true",default=False,help="Filter TCP packets only")
	write_read_pcap.add_argument("-udp", "--filter-udp",action="store_true", default=False,help="Filter UDP packets only")
	write_read_pcap.add_argument("-icmp", "--filter-icmp",action="store_true",default=False,help="Filter ICMP packets only")
	write_read_pcap.add_argument("-raw-out", "--show-raw-output",action="store_true",help="print raw load of each packet")
	write_read_pcap.add_argument("-raw-sch", "--raw_search",type=str,help="search the raw payload for specified data")
	write_read_pcap.add_argument("-sum", "--summary",action="store_true",help="summary of the packet capture [for read & write mode]")
	write_read_pcap.add_argument("-le", "--len-less-equal",type=int,help="Filters for packets with a length that is less than or equal to the specified number")
	write_read_pcap.add_argument("-ge", "--len-greater-equal",type=int,help="Filters for packets with a length that is greater than or equal to the specified number")
	write_read_pcap.add_argument("-len-eq", "--len-equal",type=int,help="Filters for packets with a length that is equal to the specified number")
	write_read_pcap.add_argument("-ttl-eq", "--ttl-equal",type=int,help="Filteres for packets with a ttl that is equal to the specified number")
	write_read_pcap.add_argument("-j", "--json", action="store_true", help="Create JSON file containing capture summary (ip:count, port:count, mac:count)")
	
	if len(argv[1:]) == 0:
		parser.print_help()
		exit(1)

	return parser.parse_args()