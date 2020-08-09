from argparse import ArgumentParser
from colored import fg, attr
from platform import system
from sys import exit, argv
from colored import fg, attr

def parse_args():
	""" Program arguments """
	parser = ArgumentParser(
		description="There are three modes of operation \u2192 live : read : write",
		usage=f"\n\t{argv[0]} -live <options> | -read <options> | -write <options>",
		add_help=False
	)
	
	# ---------------- Arguments Groups ------------------
	help_options = parser.add_argument_group("%sFor Help%s" % (fg(226), attr(0)))
	live_capture = parser.add_argument_group("%sLive Capture%s" % (fg(196), attr(0)))
	read_pcap = parser.add_argument_group("%sRead Mode Options%s" % (fg(76), attr(0)))
	write_pcap = parser.add_argument_group("%sWrite Mode Options%s" % (fg(39), attr(0)))
	write_read_pcap = parser.add_argument_group("%sOptional Arguments for Read/Write Modes%s" % (fg(199), attr(0)))
	
	help_options.add_argument("-h", "--help",action="help",help="Show this help message and exit")

	# -------------- Live Capture Options ---------------
	live_capture.add_argument("-live", "--live-mode",action="store_true",default=False,help="Perfrom live capture analysis")

	if system() == "Windows":
		live_capture.add_argument("-i", "--interf",nargs="*",help="The interface to listen on (more than one can be specified)")
	else:
		live_capture.add_argument("-i", "--interf",nargs="*",help="The interface to listen on (more than one is allowed)")

	live_capture.add_argument("-c", "--count",metavar="<NUM>",type=int, default=0,help="The number of packets to capture (default = 0 = infinity)")
	live_capture.add_argument("-f", "--filter",metavar="<BPF FITLER>",type=str, default=None,help="Berkeley packet filter to apply to capture")

	# -------------- Reading PCAP options ---------------
	read_pcap.add_argument("-read", "--read-mode",action="store_true", default=False,help="Read a PCAP file for analysis")
	read_pcap.add_argument("-r", "--rfile",metavar="<FILENAME>",type=str, default=False,help="name of PCAP file to read for parsing")
	read_pcap.add_argument("-rc", "--read-count", metavar="<NUM>",type=int,default=None,help="number of packets to read from pcap file")
	read_pcap.add_argument("-hex", "--hex-dump", action="store_true",help="Print out the hex dump of each packet along with packet flow summary")
	read_pcap.add_argument("-pc", "--packet-count",action="store_true",default=False,help="Prints the number of the packets within a PCAP file")
	read_pcap.add_argument("-no-prn", "--no-print",action="store_true",help="Do not print out traffic flow output to console")

	# -------------- Writing PCAP options ---------------
	write_pcap.add_argument("-write", "--write-mode",action="store_true", default=None,help="capture live traffic and write to PCAP file (must specify `-c` option)")
	write_pcap.add_argument("-w", "--wfile",metavar="<FILENAME>",type=str, default=None,help="name of PCAP file to create")

	# -------------- Read && Write Options ----------------
	write_read_pcap.add_argument("-src-ip", "--source-ip",metavar="<IP>",type=str,help="Filter packets based on a specified source IP address")
	write_read_pcap.add_argument("-not-src-ip", "--not-source-ip",metavar="<IP>",type=str,help="Filter packets that do not contain the specified source IP address")
	write_read_pcap.add_argument("-dst-ip", "--destination-ip",metavar="<IP>",type=str,help="Filter packets based on a specified destination IP address")
	write_read_pcap.add_argument("-not-dst-ip", "--not-destination-ip",metavar="<IP>",type=str,help="Filter packets that do not contain the specified destination IP address")
	write_read_pcap.add_argument("-src-port", "--source-port",metavar="<PORT>",type=str,help="Filter packets based on a specified source port number")
	write_read_pcap.add_argument("-not-src-port", "--not-source-port",metavar="<PORT>",type=str,help="Filter packets that do not contain the specified source port number")
	write_read_pcap.add_argument("-dst-port", "--destination-port",metavar="<PORT>",type=str,help="Filter packets based on a specified destination port number")
	write_read_pcap.add_argument("-not-dst-port", "--not-destination-port",metavar="<PORT>",type=str,help="Filter packets based on a specified destination port number")
	write_read_pcap.add_argument("-src-mac", "--source-mac",metavar="<MAC>",type=str,help="Filter packets based on a specified source mac address")
	write_read_pcap.add_argument("-not-src-mac", "--not-source-mac",metavar="<MAC>",type=str,help="Filter packets that do not contain the specified source mac address.")
	write_read_pcap.add_argument("-dst-mac", "--destination-mac",metavar="<MAC>",type=str,help="Filter packets based on a specified destination mac address")
	write_read_pcap.add_argument("-not-dst-mac", "--not-destination-mac",metavar="<MAC>",type=str,help="Filter packets that do not contain the specified destination mac address")
	write_read_pcap.add_argument("-tcp", "--filter-tcp",action="store_true",default=False,help="Filter TCP packets only")
	write_read_pcap.add_argument("-not-tcp", "--not-filter-tcp",action="store_true",default=False,help="Filter for non-TCP packets only")
	write_read_pcap.add_argument("-udp", "--filter-udp",action="store_true", default=False,help="Filter UDP packets only")
	write_read_pcap.add_argument("-not-udp", "--not-filter-udp",action="store_true", default=False,help="Filter for non-UDP packets only")
	write_read_pcap.add_argument("-icmp", "--filter-icmp",action="store_true",default=False,help="Filter ICMP packets only")
	write_read_pcap.add_argument("-not-icmp", "--not-filter-icmp",action="store_true",default=False,help="Filter for non-ICMP packets only")
	write_read_pcap.add_argument("-arp", "--filter-arp",action="store_true",default=False,help="Filter for ARP packets only")
	write_read_pcap.add_argument("-not-arp", "--not-filter-arp",action="store_true",default=False,help="Filter for non-ARP packets only")
	write_read_pcap.add_argument("-dns", "--filter-dns",action="store_true",default=False,help="Filter for DNS packets only")
	write_read_pcap.add_argument("-not-dns", "--not-filter-dns",action="store_true",default=False,help="Filter for non-DNS packets only")
	write_read_pcap.add_argument("-tf", "--tcp-flags",metavar="<TCP FLAG>",nargs="+",help="Filter packets by TCP flag. Seperate each flag by spaces.")
	write_read_pcap.add_argument("-le", "--len-less-equal",metavar="<NUM>",type=int,help="Filters for packets with a length that is less than or equal to the specified number")
	write_read_pcap.add_argument("-ge", "--len-greater-equal",metavar="<NUM>",type=int,help="Filters for packets with a length that is greater than or equal to the specified number")
	write_read_pcap.add_argument("-len-eq", "--len-equal",metavar="<NUM>",type=int,help="Filters for packets with a length that is equal to the specified number")
	write_read_pcap.add_argument("-ttl-eq", "--ttl-equal",metavar="<NUM>",type=int,help="Filters for packets with a ttl that is equal to the specified number")
	write_read_pcap.add_argument("-sum", "--summary",action="store_true",help="Summary of the packet capture <for read & write mode>")
	write_read_pcap.add_argument("-j", "--json",metavar="<FILENAME>",type=str,help="Create JSON file containing capture summary (ip:count, port:count, mac:count)")
	write_read_pcap.add_argument("-l", "--log",metavar="<FILENAME>",type=str,help="Log pcap traffic flow to a txt file for external parsing")
	
	if len(argv[1:]) == 0:
		parser.print_help()
		exit(1)
	return parser.parse_args()
