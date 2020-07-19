from argparse import ArgumentParser
from colored import fg, attr
from platform import system
from sys import exit

def _parse_args():
	""" Program arguments """
	parser = ArgumentParser()

	if system() == "Windows":
		parser.add_argument(
			"-i", "--interf", 
			nargs="*", type=str, required=True,
			help="the interface to listen on (more than one is allowed)"
		)
	else:
		parser.add_argument(
			"-i", "--interf", 
			nargs="*", type=str,
			help="the interface to listen on (more than one is allowed)"
		)
	parser.add_argument(
		"-c", "--count",
		type=int,
		help="the number of packets to capture (default=0=infinity)"
	)

	return parser.parse_args()