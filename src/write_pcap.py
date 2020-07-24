from src.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import wrpcap
from colored import fg, attr
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

    def start(self, func, arg):
        """ Starts real-time capture and passes that capture to `func`
        along with `arg`. 
            Args:
                func (function): function defined in PCAPParser to invoke
                arg (str|int): value to filter from packet capture
        """
        self.to_parse = super().capture(print_stdout=False)
        filtered_capture = func(self.to_parse, arg)
        self.write(filtered_capture)

    def filter_src_ip(self):
        """ """
        self.start(self.capparser.filt_src_ip, self.src_ip)
    
    def filter_dst_ip(self):
        """ """
        self.start(self.capparser.filt_dst_ip, self.dst_ip)

    def filter_src_port(self):
        """ """


    def filter_dst_port(self):
        """ """

    def filter_src_mac(self):
        """ """

    def filter_dst_mac(self):
        """ """

    def filter_tcp(self):
        """ """

    def filter_udp(self):
        """ """
        
    def summary(self):
        """ """
        self.start(self.capparser.summary, None)

    def write(self, packets):
        """
        """
        try:
            wrpcap(self.wfile, packets)
        except:
            print(
                "[%sERROR%s] There was an error writing PCAP file. Please try again..."
            % (fg(9), attr(0))
            )
            exit(1)