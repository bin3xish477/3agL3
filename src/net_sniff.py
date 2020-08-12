"""
Real-time network traffic capturing using scapy.all.sniff
"""

from datetime import datetime
from colored import fg, attr
from scapy.all import *

class NetSniff:
	def __init__(self, interf, berkeley_filter, count, promiscuous):
		"""
		Args:
			interf (str): the infertace to capture packets on
			apply_filter (str): apply BP filter to live capture
			count (int): number of packets to capture, 0=infinite
			promiscuous (bool): promiscuous mode
		"""
		self._interf = interf
		self._berkeley_filter = berkeley_filter
		self._count = count
		self._promiscuous = promiscuous
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
	
	@property
	def promiscuous(self):
		""" Returns promiscuous boolean value """
		return self._promiscuous

	def ICMPFormatString(self, pkt):
		""" Returns ICMP formatted string to print to console """
		try:
			date = datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S %Y/%m/%d')
			src_mac = pkt[Ether].src
			dst_mac = pkt[Ether].dst
			proto = pkt[IP].payload.name
			icmp_type = ""

			if pkt[ICMP].type == 0:
				icmp_type = "echo-reply"
			elif pkt[ICMP].type == 8:
				icmp_type = "echo"
			return (
				f"%s%s@%s{date}" \
				f" {src_mac} | {dst_mac} %s%s{proto}%s" \
				f" %s%s{pkt[IP].src}%s %s%s\u2192%s %s%s{pkt[IP].dst}%s" \
				f" (TTL:{pkt[Ether].ttl} LEN:{pkt[Ether].len} TYPE:{icmp_type})"
				% (
					fg(118), attr("bold"), attr("reset"),
					fg(208), attr("bold"), attr("reset"),
					fg(9), attr("bold"), attr("reset"),
					fg(220), attr("bold"), attr("reset"),
				)
			)
		except: return None

	def ARPFormatString(self, pkt):
		""" Returns formatted ARP packet string to print to console """
		try:
			date = datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S %Y/%m/%d')
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
				f"%s%s@%s{date}" \
				f" %s%s{proto}%s{arp_str}"
				% (
					fg(165), attr("bold"), attr("reset"),
					fg(118), attr("bold"), attr("reset"),
				)
			)
		except: return None

	def DNSFormatString(self, pkt):
		""" Returns DNS formatted packet string to print to console """
		try:
			date = datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S %Y/%m/%d')
			qname = str(pkt[DNSQR].qname)[2:-1]
			qtype = dnsqtypes[pkt[DNSQR].qtype]
			qr = pkt[DNSQR]
			qclass = qr.get_field("qclass").i2repr(qr, qr.qclass)
			proto = "DNS"
			return (
				f"%s%s@%s{date}" \
				f" ;; {qname} {qclass} %s%s{qtype}%s ;;" \
				f" %s%s{proto}%s" \
				f" {pkt[IP].src}%s%s:{pkt[IP].sport}%s %s%s\u2192%s {pkt[IP].dst}%s%s:{pkt[IP].dport}%s" \
				f" (TTL:{pkt[IP].ttl} LEN:{len(pkt)})"
				% (
					fg(201), attr("bold"), attr("reset"),
					fg(118), attr("bold"), attr("reset"),
					fg(208), attr("bold"), attr("reset"),
					fg(9), attr("bold"), attr("reset"),
					fg(38), attr("bold"), attr("reset"),
				)
			)
		except: return None

	def TCPFormatString(self, pkt):
		""" Returns TCP formatted packet string to print to console """
		try:
			date = datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S %Y/%m/%d')
			tcp_flag_str = ".".join([self.FLAGS[x] for x in pkt[TCP].flags])
			src_mac = pkt[Ether].src
			dst_mac = pkt[Ether].dst
			proto = pkt[IP].payload.name
			return (
				f"%s%s@%s{date}" \
				f" {src_mac} | {dst_mac}" \
				f" %s%s{proto}%s [%s%s{tcp_flag_str}%s]" \
				f" {pkt[IP].src}%s%s:{pkt[IP].sport}%s %s%s\u2192%s {pkt[IP].dst}%s%s:{pkt[IP].dport}%s" \
				f" (TTL:{pkt[IP].ttl} LEN:{len(pkt)})"
				% (
					fg(165), attr("bold"), attr("reset"),
					fg(118), attr("bold"), attr("reset"),
					fg(226), attr("bold"), attr("reset"),
					fg(208), attr("bold"), attr("reset"),
					fg(9), attr("bold"), attr("reset"),
					fg(38), attr("bold"), attr("reset"),
				)
			)
		except: return None

	def OtherProtocol(self, pkt):
		""" Returns formatted packet string for packets that contain protocols
		that do not match the ones defined above (ICMP, ARP, DNS, TCP) """
		try:
			date = datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S %Y/%m/%d')
			src_mac = pkt[Ether].src
			dst_mac = pkt[Ether].dst
			proto = pkt[IP].payload.name
			return (
				f"%s%s@%s{date}" \
				f" {src_mac} | {dst_mac}" \
				f" %s%s{proto}%s" \
				f" {pkt[IP].src}%s%s:{pkt[IP].sport}%s %s%s\u2192%s {pkt[IP].dst}%s%s:{pkt[IP].dport}%s" \
				f" (TTL:{pkt[IP].ttl} LEN:{len(pkt)})"
				% (
					fg(118), attr("bold"), attr("reset"),
					fg(208), attr("bold"), attr("reset"),
					fg(9), attr("bold"), attr("reset"),
					fg(38), attr("bold"), attr("reset"),
				)
			)
		except: return None

	def echo(self, pkt):
		""" The print message for every captured packet
		Args:
			pkt (scapy.layers.l2.Ether): a scapy captured packet.
		"""
		if pkt.haslayer(ICMP):
			icmp_string = self.ICMPFormatString(pkt)
			return icmp_string
		elif pkt.haslayer(ARP):
			arp_string = self.ARPFormatString(pkt)
			return arp_string
		elif pkt.haslayer(DNS):
			dns_string = self.DNSFormatString(pkt)
			return dns_string
		elif pkt.haslayer(TCP):
			tcp_string = self.TCPFormatString(pkt)
			return tcp_string
		else:
			other_proto_string = self.OtherProtocol(pkt)
			return other_proto_string

	def capture(self, print_stdout=True):
		""" Begin capturing live packets with scapy.all.sniff 
		Args:
			print (bool): display packets to screen, default=True.
		"""
		# if promiscuous argument is false, turn off promiscuous mode
		if not self.promiscuous:
			conf.sniff_promisc = 0
			print("[ %s%sWARNING%s ] PROMISCUOUS MODE HAS BEEN TURNED OFF" % (fg(196), attr("bold"), attr("reset")))

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
