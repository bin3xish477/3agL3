"""
Real-time network traffic capturing using scapy.all.sniff
"""

from datetime import datetime
from colored import fg, attr
from scapy.all import sniff, ICMP, IP

class NetSniff:
	def __init__(self, interf, berkeley_filter, count):
		"""
		Args:
			interf (str): the infertace to capture packets on.
			apply_filter (str): apply tcpdump filter to live capture.
			count (int): number of packets to capture, 0=infinite.
		"""
		self._interf = interf
		self._berkeley_filter = berkeley_filter
		self._count = count

	@property
	def interf(self):
		""" Returns the specified interface """
		return self._interf

	@property
	def berkeley_filter(self):
		""" Filter (tcpdump) to apply to capture """
		return self._berkeley_filter
	
	@property
	def count(self):
		""" Returns the number of packets to capture """
		return self._count
	
	def echo(self, pkt):
		""" The print message for every captured packet
		Args:
		pkt (scapy.layers.l2.Ether): a scapy captured packet.
		"""
		if pkt.haslayer(ICMP):
			try:
				date = str(datetime.now())
				src_mac = str(pkt[0].src).replace(":", ".")
				dst_mac = str(pkt[0].dst).replace(":", ".")
				proto = str(pkt[1].payload.name).upper()

				icmp_type = ""
				# add more icmp field types
				if pkt[ICMP].type == 0:
					icmp_type = "echo-reply"
				elif pkt[ICMP].type == 8:
					icmp_type = "echo"

				return (
					f"[%s{date[11:13]}%s:%s{date[14:16]}%s:%s{date[17:]}%s]" \
					f" {src_mac} | {dst_mac} %sICMP%s" \
					f" %s{pkt[1].src}%s %s\u2192%s %s{pkt[1].dst}%s" \
					f" (TTL:{pkt[0].ttl} LEN:{pkt[0].len} TYPE:{icmp_type})"
					% (
						fg(39), attr(0),
						fg(39), attr(0),
						fg(39), attr(0),
						fg(118), attr(0),
						fg(209), attr(0),
						fg(9), attr(0),
						fg(171), attr(0)
					)
				)
			except:
				return None
		else:
			try:
				date = str(datetime.now())
				src_mac = str(pkt[0].src).replace(":", ".")
				dst_mac = str(pkt[0].dst).replace(":", ".")
				proto = str(pkt[1].payload.name).upper()
				return (
					f"[%s{date[11:13]}%s:%s{date[14:16]}%s:%s{date[17:]}%s]" \
					f" {src_mac} | {dst_mac}" \
					f" %s{proto}%s" \
					f" {pkt[1].src}%s:{pkt[2].sport}%s %s\u2192%s {pkt[1].dst}%s:{pkt[2].dport}%s" \
					f" (TTL:{pkt[0].ttl} LEN:{pkt[0].len})"
					% (
						fg(39), attr(0),
						fg(39), attr(0),
						fg(39), attr(0),
						fg(118), attr(0),
						fg(209), attr(0),
						fg(9), attr(0),
						fg(171), attr(0)
					)
				)
			except:
				return None

	def capture(self, print_stdout=True):
		""" Begin capturing live packets with scapy.all.sniff 
		Args:
			print (bool): display packets to screen, default=True.
		"""
		if print_stdout:
			sniff(
				iface=self.interf, 
				filter=self.berkeley_filter,
				count=self.count, 
				prn=self.echo
			)
		else:
			capture = sniff(
				iface=self.interf, 
				filter=self.berkeley_filter,
				count=self.count
			)
			return capture