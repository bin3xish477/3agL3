from src.parse_pcap import PCAPParser, RawPCAPAnalyzer
from src.net_sniff import NetSniff
from scapy.all import rdpcap
from colored import fg, attr
from time import sleep

class ReadPCAP:
    def __init__(
        self, rfile,src_ip, dst_ip, src_port,
        dst_port, src_mac, dst_mac, tcp, udp,
        icmp, pkt_cnt
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
        self._pkt_cnt = pkt_cnt
        self._src_ip = src_ip
        self._dst_ip = dst_ip
        self._src_port = src_port
        self._dst_port = dst_port
        self._src_mac = src_mac
        self._dst_mac = dst_mac
        self._tcp = tcp
        self._udp = udp
        self._icmp = icmp

        self.capparser = PCAPParser()
        self.raw_data_parser = RawPCAPAnalyzer()

    def read(self):
        """ Read PCAP file """
        self._pcapfile = rdpcap(self._rfile)

    @property
    def pcapfile(self):
        """ Returns `self._pcapfile` """
        return self._pcapfile
    
    def start(self, func, arg):
        """ Starts real-time capture and passes that capture to `func`
        along with `arg`. 
            Args:
                func (function): function defined in PCAPParser to invoke
                arg (str|int): value to filter from packet capture
        """
        filtered_capture = func(self.pcapfile, arg)
        if len(filtered_capture) == 0 or filtered_capture == None:
            print("[ %sATTENTION%s ] NO PACKETS CONTAINED SPECIFIED FILTER" % (fg(202), attr(0)))
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
        self.start(self.capparser.filt_tcp, _)

    def filter_udp(self):
        """ """
        self.start(self.capparser.filt_udp, _)

    def filter_icmp(self):
        """ """
        self.start(self.capparser.filt_icmp, _)

    def no_filter(self, no_print=False):
        """ """
        if not no_print:
            print("[ %sNOTE%s ] NO READ FILTERS HAVE BEEN APPLIED" % (fg(226), attr(0)))
            self.to_stdout(self.pcapfile)
    
    def packet_count(self):
        """ """
        return len([cap for cap in self.pcapfile])

    def summary(self):
        """ """
        self.capparser.summary(self.pcapfile)

    def to_json(self):
        """ """
        self.capparser.json_summary(self.pcapfile)

    def to_stdout(self, capture):
        """ """
        obj = NetSniff(None, None, None)
        try:
            for cap in capture:
                print_str = obj.echo(cap)
                if not print_str:
                    continue
                print(print_str)
        except KeyboardInterrupt:
            print(
                "\n[ %sATTENTION%s ] SIGINT INVOKED: TERMINATING PROGRAM"
                % (fg(202), attr(0))
            )