from argparse import ArgumentParser
from colored import fg, attr
from platform import system
from sys import exit, argv

def parse_args():
	""" Program arguments """
	parser = ArgumentParser(
		description="There are three modes of operation: live capture, read PCAP, write PCAP",
		usage=f"\n\t{argv[0]} -live (live capture) [options] | -read (read PCAP) [options] | -write (write PCAP) [options]",
		add_help=False
		)
	help_options = parser.add_argument_group("For Help")
	live_capture = parser.add_argument_group("Live Capture")
	read_pcap = parser.add_argument_group("Reading PCAP Required Options")
	write_pcap = parser.add_argument_group("Writing PCAP Required Options")
	write_read_pcap = parser.add_argument_group("Optional Arguments for Read/Write Mode")

	help_options.add_argument(
		"-h", "--help",
		action="help",
		help="show this help message and exit"
	)

	# -------------- Live Capture Options ---------------
	live_capture.add_argument(
		"-live", "--live-mode",
		action="store_true",default=False,
		help="perfrom live capture analysis")

	if system() == "Windows":
		live_capture.add_argument(
			"-i", "--interf",
			type=str, default="eth0",
			help="the interface to listen on"
		)
	else:
		live_capture.add_argument(
			"-i", "--interf", 
			nargs="*", type=str, default="eth0",
			help="the interface to listen on (more than one is allowed)"
		)
	live_capture.add_argument(
		"-c", "--count",
		type=int, default=0,
		help="the number of packets to capture (default = 0 = infinity)"
	)

	live_capture.add_argument(
		"-f", "--filter",
		type=str, default=None,
		help="Berkeley packet filter to apply to capture"
	)

	# -------------- Reading PCAP options ---------------
	read_pcap.add_argument(
		"-read", "--read-mode",
		action="store_true", default=False,
		help="read a PCAP file for analysis"
	)

	read_pcap.add_argument(
		"-r", "--rfile",
		type=str, default=False,
		help="name of PCAP file to read for parsing"
	)
	
	# -------------- Writing PCAP options ---------------
	write_pcap.add_argument(
		"-write", "--write-mode",
		action="store_true", default=None,
		help="capture live traffic and write to PCAP file"
	)

	write_pcap.add_argument(
		"-w", "--wfile",
		type=str, default=None,
		help="name of PCAP file to create"
	)

	# -------------- Read/Write Options ----------------
	write_read_pcap.add_argument(
		"-src-ip", "--source-ip",
		type=str,
		help="Filter packets and write PCAP file based on a specified source IP address"
	)

	write_read_pcap.add_argument(
		"-dst-ip", "--destination-ip",
		type=str,
		help="Filter packets and write PCAP file based on a specified destination IP address"
	)

	write_read_pcap.add_argument(
		"-src-port", "--source-port",
		type=str,
		help="Filter packets and write PCAP file based on a specified source port number"
	)

	write_read_pcap.add_argument(
		"-dst-port", "--destination-port",
		type=str,
		help="Filter packets and write PCAP file based on a specified destination port number"
	)

	write_read_pcap.add_argument(
		"-src-mac", "--source-mac",
		type=str,
		help="Filter packets and write PCAP file based on a specified source mac address"
	)

	write_read_pcap.add_argument(
		"-dst-mac", "--destination-mac",
		type=str,
		help="Filter packets and write PCAP file based on a specified destination mac address"
	)

	write_read_pcap.add_argument(
		"-tcp", "--filter-tcp",
		action="store_true",
		default=False,
		help="Filter TCP packets only"
	)

	write_read_pcap.add_argument(
		"-udp", "--filter-udp",
		action="store_true", default=False,
		help="Filter UDP packets only"
	)

	write_read_pcap.add_argument(
		"-sum", "--summary",
		action="store_true",
		help="provide a summary of the packet capture [for read & write mode]"
	)

	write_read_pcap.add_argument(
		"-le", "--len-less-equal",
		type=int,
		help="Filters for packets with a length that is less than or equal to the specified number."
	)

	write_read_pcap.add_argument(
		"-ge", "--len-greater-equal",
		type=int,
		help="Filters for packets with a length that is greater than or equal to the specified number."
	)

	write_read_pcap.add_argument(
		"-e", "--equal",
		type=int,
		help="Filters for packets with a length that is equal to the specified number."
	)

	if len(argv[1:]) == 0:
		parser.print_help()
		exit(1)

	return parser.parse_args()