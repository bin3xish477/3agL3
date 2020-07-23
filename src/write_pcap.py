from src.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import wrpcap
from sys import exit

class WritePCAP(NetSniff):
    def __init__(
        self, wfile, interf, berkeley_filter, count,
        src_ip, dst_ip, src_port, dst_port, src_mac,
        dst_mac, tcp , udp
    ):
        """
        Args:
            wfile (str): name of file to create.
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

        self.wfile = wfile
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        # these are booleans v
        self.tcp = tcp
        self.udp = udp

        self.capparser = PCAPParser()

    def start(self):
        """ Starts real-time capture and stores results in `to_parse` """
        self.to_parse = super().capture(print_stdout=False)

    def filter_src_ip(self):
        """ """
        filtered_capture = self.capparser.filt_src_ip(self.to_parse, self.src_ip)
        self.write(filtered_capture)

    def write(self, packets):
        """
        """
        try:
            wrpcap(self.wfile, packets)
        except:
            print("[ERROR] There was an error writing PCAP file. Please try again...")
            exit(1)