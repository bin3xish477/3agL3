from src.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import rdpcap

class ReadPCAP(NetSniff):
    def __init__(
        self, rfile, interf, berkeley_filter, count,
        src_ip, dst_ip, src_port, 
        dst_port, src_mac, dst_mac,
        tcp, udp
    ):
        """
        Args:
            rfile (str): name of PCAP file to read as input to program.
            interf (str): interface to use to capture packets.
            berkeley_filter (str): berkeley packet filter to apply to packet capture.
            count (int): number of packets to capture.
            src_ip ():
            dst_ip ():
            src_port ():
            dst_port ():
            src_mac ():
            dst_mac ():
            tcp (bool): 
            udp (bool):
        """
        super().__init__(interf, berkeley_filter, count)

        self.rfile = rfile
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.tcp = tcp
        self.udp = udp

        self.capparser = PCAPParser()

    def read(self):
        """ Read PCAP file """
        pcapfile = rdpcap(self.rfile)