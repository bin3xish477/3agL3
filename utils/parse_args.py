from argparse import ArgumentParser
from colored import fg, attr
from platform import system
from sys import exit

def _parse_args():
	""" Program arguments """
	parser = ArgumentParser()

	live_capture = parser.add_argument_group("Live Capture")
	read_pcap = parser.add_argument_group("Reading PCAP")
	write_pcap = parser.add_argument_group("Writing PCAP")

	# -------------- Live Capture Options ---------------
	if system() == "Windows":
		live_capture.add_argument(
			"-i", "--interf", 
			nargs="*", type=str, 
			required=True, default="eth0",
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
		"-r", "--read",
		type=str, default=None,
		help="the pcap file to read"
	)

	# -------------- Writing PCAP options ---------------
	write_pcap.add_argument(
		"-w", "--write",
		type=str, default=None,
		help="name of the pcap file to create from live capture"
	)

	return parser.parse_args()