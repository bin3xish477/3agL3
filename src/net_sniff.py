"""
Real-time network traffic capturing using scapy.all.sniff
"""

from datetime import datetime
from colored import fg, attr
from scapy.all import sniff, ICMP, IP, Ether

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
				src_mac = str(pkt[Ether].src)
				dst_mac = str(pkt[Ether].dst)
				proto = str(pkt[IP].payload.name).upper()

				icmp_type = ""
				if pkt[ICMP].type == 0:
					icmp_type = "echo-reply"
				elif pkt[ICMP].type == 8:
					icmp_type = "echo"

				return (
					f"<%s%s{date[11:13]}%s:%s%s{date[14:16]}%s:%s%s{date[17:25]}%s>" \
					f" {src_mac} | {dst_mac} %s%s{str(pkt[IP].payload.name).upper()}%s" \
					f" %s%s{pkt[IP].src}%s %s%s\u2192%s %s%s{pkt[IP].dst}%s" \
					f" (TTL:{pkt[Ether].ttl} LEN:{pkt[Ether].len} TYPE:{icmp_type})"
					% (
						fg(141), attr("bold"), attr("reset"),
						fg(141), attr("bold"), attr("reset"),
						fg(141), attr("bold"), attr("reset"),
						fg(118), attr("bold"), attr("reset"),
						fg(208), attr("bold"), attr("reset"),
						fg(9), attr("bold"), attr("reset"),
						fg(220), attr("bold"), attr("reset"),
					)
				)
			except:
				return None
		else:
			try:
				date = str(datetime.now())
				src_mac = str(pkt[Ether].src)
				dst_mac = str(pkt[Ether].dst)
				proto = str(pkt[IP].payload.name).upper()
				return (
					f"<%s%s{date[11:13]}%s:%s%s{date[14:16]}%s:%s%s{date[17:25]}%s>" \
					f" {src_mac} | {dst_mac}" \
					f" %s%s{proto}%s" \
					f" {pkt[IP].src}%s%s:{pkt[IP].sport}%s %s%s\u2192%s {pkt[IP].dst}%s%s:{pkt[IP].dport}%s" \
					f"  (TTL:{pkt[0].ttl} LEN:{pkt[0].len})"
					% (
						fg(141), attr("bold"), attr("reset"),
						fg(141), attr("bold"), attr("reset"),
						fg(141), attr("bold"), attr("reset"),
						fg(118), attr("bold"), attr("reset"),
						fg(208), attr("bold"), attr("reset"),
						fg(9), attr("bold"), attr("reset"),
						fg(220), attr("bold"), attr("reset"),
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