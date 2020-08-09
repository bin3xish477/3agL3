"""
Real-time network traffic capturing using scapy.all.sniff
"""

from datetime import datetime
from colored import fg, attr
from scapy.all import *

class NetSniff:
	def __init__(self, interf, berkeley_filter, count):
		"""
		Args:
			interf (str): the infertace to capture packets on
			apply_filter (str): apply BP filter to live capture
			count (int): number of packets to capture, 0=infinite
		"""
		self._interf = interf
		self._berkeley_filter = berkeley_filter
		self._count = count
		self.FLAGS = {
			'F': 'FIN',
			'S': 'SYN',
			'R': 'RST',
			'P': 'PSH',
			'A': 'ACK',
			'U': 'URG',
			'E': 'ECE',
			'C': 'CWR',
		}

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
				src_mac = pkt[Ether].src
				dst_mac = pkt[Ether].dst
				proto = str(pkt[IP].payload.name).upper()

				icmp_type = ""
				if pkt[ICMP].type == 0:
					icmp_type = "echo-reply"
				elif pkt[ICMP].type == 8:
					icmp_type = "echo"
				return (
					f"<%s%s{date[:13]}%s:%s%s{date[14:16]}%s:%s%s{date[17:25]}%s>" \
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
		elif pkt.haslayer(ARP):
			date = str(datetime.now())
			proto = "ARP"
			WHO_HAS = 1
			IS_AT = 2
			arp_str = ""
			# matching ARP request
			if pkt[ARP].op == WHO_HAS:
				arp_str = ": REQUEST: %s%sWho Has%s %s%s%s?%s %s%sTell%s %s %s%sAt%s %s" % (
					fg(9), attr("bold"), attr("reset"),
					pkt[Ether].pdst,
					fg(9), attr("bold"), attr("reset"),
					fg(9), attr("bold"), attr("reset"),
					pkt[Ether].psrc,
					fg(9), attr("bold"), attr("reset"),
					pkt[Ether].src
				)
			# matching ARP reply
			if pkt[ARP].op == IS_AT:
				arp_str = ": REPLY  : %s%sTell%s %s %s%sThat%s %s %s%sIs At%s %s" % (
					fg(201), attr("bold"), attr("reset"),
					pkt[Ether].dst,
					fg(201), attr("bold"), attr("reset"),
					pkt[ARP].psrc,
					fg(201), attr("bold"), attr("reset"),
					pkt[Ether].src
				)
			return (
				f"<%s%s{date[:13]}%s:%s%s{date[14:16]}%s:%s%s{date[17:23]}%s>" \
				f" %s%s{proto}%s{arp_str}"
				% (
					fg(141), attr("bold"), attr("reset"),
					fg(141), attr("bold"), attr("reset"),
					fg(141), attr("bold"), attr("reset"),
					fg(118), attr("bold"), attr("reset"),
				)
			)
		elif pkt.haslayer(DNS):
			try:
				date = str(datetime.now())
				qname = str(pkt[DNSQR].qname)[2:-1]
				qtype = dnsqtypes[pkt[DNSQR].qtype]
				qr = pkt[DNSQR]
				qclass = qr.get_field("qclass").i2repr(qr, qr.qclass)
				proto = "DNS"
				return (
					f"<%s%s{date[:13]}%s:%s%s{date[14:16]}%s:%s%s{date[17:23]}%s>" \
					f" ;; {qname} {qclass} {qtype} ;;" \
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
		elif pkt.haslayer(TCP):
			try:
				tcp_flag_str = ",".join([self.FLAGS[x] for x in pkt[TCP].flags if x in self.FLAGS.keys()])
				date = str(datetime.now())
				src_mac = pkt[Ether].src
				dst_mac = pkt[Ether].dst
				proto = str(pkt[IP].payload.name).upper()
				return (
					f"<%s%s{date[:13]}%s:%s%s{date[14:16]}%s:%s%s{date[17:23]}%s>" \
					f" {src_mac} | {dst_mac}" \
					f" %s%s{proto}%s [%s%s{tcp_flag_str}%s]" \
					f" {pkt[IP].src}%s%s:{pkt[IP].sport}%s %s%s\u2192%s {pkt[IP].dst}%s%s:{pkt[IP].dport}%s" \
					f"  (TTL:{pkt[0].ttl} LEN:{pkt[0].len})"
					% (
						fg(141), attr("bold"), attr("reset"),
						fg(141), attr("bold"), attr("reset"),
						fg(141), attr("bold"), attr("reset"),
						fg(118), attr("bold"), attr("reset"),
						fg(226), attr("bold"), attr("reset"),
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
				src_mac = pkt[Ether].src
				dst_mac = pkt[Ether].dst
				proto = str(pkt[IP].payload.name).upper()
				return (
					f"<%s%s{date[:13]}%s:%s%s{date[14:16]}%s:%s%s{date[17:23]}%s>" \
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
