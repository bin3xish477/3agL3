from collections import Counter
from scapy.all import *

class PCAPParser:
    def __init__(self):
        """
        """
    
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