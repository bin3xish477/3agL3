from src.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import rdpcap
from colored import fg, attr
from time import sleep

class ReadPCAP:
    def __init__(
        self, rfile,src_ip, dst_ip, src_port,
        dst_port, src_mac, dst_mac, tcp, udp
    ):
        """
        Args:
            rfile (str): name of PCAP file to read as input to program.
            src_ip ():
            dst_ip ():
            src_port ():
            dst_port ():
            src_mac ():
            dst_mac ():
            tcp (bool): 
            udp (bool):
        """

        self._rfile = rfile
        self._src_ip = src_ip
        self._dst_ip = dst_ip
        self._src_port = src_port
        self._dst_port = dst_port
        self._src_mac = src_mac
        self._dst_mac = dst_mac
        self._tcp = tcp
        self._udp = udp

        self.capparser = PCAPParser()

    def read(self):
        """ Read PCAP file """
        self._pcapfile = rdpcap(self._rfile)
    
    def start(self, func, arg):
        """ Starts real-time capture and passes that capture to `func`
        along with `arg`. 
            Args:
                func (function): function defined in PCAPParser to invoke
                arg (str|int): value to filter from packet capture
        """
        filtered_capture = func(self._pcapfile, arg)
        if len(filtered_capture) == 0:
            print("[%sATTENTION%s] NO PACKET CONTAINED TARGET VALUE `%s`" % (fg(202), attr(0), arg))
            exit(1)
        else:
            self.to_stdout(filtered_capture)

    def filter_src_ip(self):
        """ """
        self.start(self.capparser.filt_src_ip, self._src_ip)
    
    def filter_dst_ip(self):
        """ """
        self.start(self.capparser.filt_dst_ip, self._dst_ip)

    def filter_src_port(self):
        """ """
        self.start(self.capparser.filt_src_port, self._src_port)

    def filter_dst_port(self):
        """ """
        self.start(self.capparser.filt_dst_port, self._dst_port)

    def filter_src_mac(self):
        """ """
        self.start(self.capparser.filt_src_mac, self._src_mac)

    def filter_dst_mac(self):
        """ """
        self.start(self.capparser.filt_dst_mac, self._dst_mac)

    def filter_tcp(self):
        """ """
        self.start(self.capparser.filt_tcp, self._tcp)

    def filter_udp(self):
        """ """
        self.start(self.capparser.filt_udp, self._udp)

    def filter_icmp(self):
        """ """

    def no_filter(self):
        """ """
        self.to_stdout(self._pcapfile)
    
    def summary(self):
        """ """
        self.capparser.summary(self._pcapfile)

    def to_json(self):
        """ """
        self.capparser.json_summary(self._pcapfile)

    def to_stdout(self, capture):
        """ """
        obj = NetSniff(None, None, None)
        for cap in capture:
            print_str = obj.echo(cap)
            if not print_str:
                continue
            print(print_str)
