from argparse import ArgumentParser
from colored import fg, attr
from platform import system
from sys import exit

def _parse_args():
	""" Program arguments """
	parser = ArgumentParser(
		description="There are three modes of operation: live capture, read PCAP, write PCAP",
		usage="-l: live capture, -r: read PCAP, -w: write PCAP"
		)

	live_capture = parser.add_argument_group("Live Capture")
	read_pcap = parser.add_argument_group("Reading PCAP")
	write_pcap = parser.add_argument_group("Writing PCAP")

	# -------------- Live Capture Options ---------------
	live_capture.add_argument(
		"-live", "--live-mode",
		action="store_true",default=False,
		help="perfrom live capture analysis")

	if system() == "Windows":
		live_capture.add_argument(
			"-i", "--interf", 
			nargs="*", type=str, 
			default="eth0",
			help="the interface to listen on (more than one is allowed)"
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
		help="the number of packets to capture (default=0=infinity)"
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
		action="store_true", default=False,
		help="name of PCAP file to read for parsing"
	)
	# -------------- Writing PCAP options ---------------
	write_pcap.add_argument(
		"-write", "--write-mode",
		type=str, default=None,
		help="capture live traffic and write to PCAP file"
	)

	write_pcap.add_argument(
		"-w", "--wfile",
		default=None,
		help="name of PCAP file to create"
	)

	return parser.parse_args()