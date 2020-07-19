from argparse import ArgumentParser
from colored import fg, attr

def _parse_args():
	""" Program arguments """
	parser = ArgumentParser()

	parser.add_argument(
		"-i", "--interf", 
		nargs="*", type=str,
		help="the interface to listen on (more then one is allowed)"
	)

	parser.add_argument(
		"-c", "--count",
		type=int,
		help="the number of packets to capture (default = 0 = infinity)"
	)
	
	return parser.parse_args()