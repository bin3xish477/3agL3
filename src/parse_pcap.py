from collections import Counter
from colored import fg, attr
from scapy.all import *

class PCAPParser:
    def filt_src_ip(self, capture, src_ip):
        """ Filter source IP addresses from capture """
        filtered = []
        for cap in capture:
            if cap[1].src == src_ip:
                filtered.append(cap)
        return filtered

    def filt_dst_ip(self, capture, dst_ip):
        """ Filter destination IP addresses from capture """
        filtered = []
        for cap in capture:
            if cap[1].dst == dst_ip:
                filtered.append(cap)
        return filtered

    def filt_src_port(self, capture, src_port):
        """
        """
        filtered = []
        for cap in capture:
            if cap[2].sport == src_port:
                filtered.append(cap)
        return filtered

    def filt_dst_port(self, capture, dst_port):
        """
        """
        filtered = []
        for cap in capture:
            if cap[2].dport == dst_port:
                filtered.append(cap)
        return filtered

    def filt_src_mac(self, capture, src_mac):
        """ """
        filtered = []
        for cap in capture:
            if cap[0].dst == src_mac:
                filtered.append(cap)
        return filtered

    def filt_dst_mac(self, capture, dst_mac):
        """ """
        filtered = []
        for cap in capture:
            if cap[0].src == dst_mac:
                filtered.append(cap)
        return filtered


    def summary(self, capture, *args):
        """ Prints a summary of the data contained in a capture.
        This summary includes:
            - unique IP and the number of times they appear
            - unique port number and the number of time they appear
            - unique mac addresses and the number of times they appear

        Args:
            capture (scapy.plist.PacketList)
            args (any): will not be used but decorator calling this function expects an argument
        """
        print(type(capture))