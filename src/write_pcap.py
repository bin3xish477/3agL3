from src.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import wrpcap
from colored import fg, attr
from sys import exit
from time import sleep

class WritePCAP(NetSniff):
    def __init__(
        self, wfile, interf, berkeley_filter, count,
        src_ip, not_src_ip, dst_ip, not_dst_ip, src_port,
        not_src_port, dst_port, not_dst_port, src_mac,
        not_src_mac, dst_mac, not_dst_mac, tcp, not_tcp,
        udp, not_udp, icmp, not_icmp
    ):
        super().__init__(interf, berkeley_filter, count)

        self._wfile = wfile
        self._src_ip = src_ip
        self._not_src_ip = not_src_ip
        self._dst_ip = dst_ip
        self._not_dst_ip = not_dst_ip
        self._src_port = src_port
        self._not_src_port = not_src_port
        self._dst_port = dst_port
        self._not_dst_port = not_dst_port
        self._src_mac = src_mac
        self._not_src_mac = not_src_mac
        self._dst_mac = dst_mac
        self._not_dst_mac = not_dst_mac
        self._tcp = tcp
        self._not_tcp = not_tcp
        self._udp = udp
        self._not_udp = not_udp
        self._icmp = icmp
        self._not_icmp = not_icmp

        self.capparser = PCAPParser()
        self.netsniff_obj = NetSniff(None, None, None)

    def execute(self, func, arg):
        """ Executes real-time capture and passes that capture to `func`
        along with `arg`. 
            Args:
                func (function): function defined in PCAPParser to invoke
                arg (str|int): value to filter from packet capture
        """
        try:
            self.to_parse = super().capture(print_stdout=False)
        except:
            print(
				"[%sERROR%s] COULD BEGIN PACKET CAPTURE. PLEASE TRY AGAIN..."
				% (fg(9), attr(0))
			)
        self._filtered_cap = func(self.to_parse, arg)
        self.write(self._filtered_cap)

    def filter_src_ip(self):
        """ """
        self.execute(self.capparser.filt_src_ip, self._src_ip)

    def filter_not_src_ip(self):
        """ """
        self.execute(self.capparser.filt_not_src_ip, self._not_src_ip)
    
    def filter_dst_ip(self):
        """ """
        self.execute(self.capparser.filt_dst_ip, self._dst_ip)

    def filter_not_dst_ip(self):
        """ """
        self.execute(self.capparser.filt_not_dst_ip, self._not_dst_ip)

    def filter_src_port(self):
        """ """
        self.execute(self.capparser.filt_src_port, self._src_port)

    def filter_not_src_port(self):
        """ """
        self.execute(self.capparser.filt_not_src_port, self._not_src_port)

    def filter_dst_port(self):
        """ """
        self.execute(self.capparser.filt_dst_port, self._dst_port)

    def filter_not_dst_port(self):
        """ """
        self.execute(self.capparser.filt_not_dst_port, self._not_dst_port)

    def filter_src_mac(self):
        """ """
        self.execute(self.capparser.filt_src_mac, self._src_mac)

    def filter_not_src_mac(self):
        """ """
        self.execute(self.capparser.filt_not_src_mac, self._not_src_mac)

    def filter_dst_mac(self):
        """ """
        self.execute(self.capparser.filt_dst_mac, self._dst_mac)

    def filter_not_dst_mac(self):
        """ """
        self.execute(self.capparser.filt_not_dst_mac, self._not_dst_mac)

    def filter_tcp(self):
        """ """
        self.execute(self.capparser.filt_tcp, None)

    def filter_not_tcp(self):
        """ """
        self.execute(self.capparser.filt_not_tcp, None)

    def filter_udp(self):
        """ """
        self.execute(self.capparser.filt_udp, None)

    def filter_not_udp(self):
        """ """
        self.execute(self.capparser.filt_not_udp, None)

    def filter_icmp(self):
        """ """
        self.execute(self.capparser.filt_icmp, None)

    def filter_not_icmp(self):
        """ """
        self.execute(self.capparser.filt_not_icmp, None)

    def len_le_eq(self, value):
        """ """

    def len_gr_eq(self, value):
        """ """

    def len_eq(self, value):
        """ """

    def ttl_eq(self, value):
        """ """

    def no_filter(self):
        """ """
        for i in range(2, -1, -1):
            if i != 0:
                print(
                    "[ %sATTENTION%s ] CAPTURE WILL BEGIN IN %s\r" % (fg(202), attr(0), i), end=""
                )
            else:
                print(
                    "[ %sATTENTION%s ] CAPTURE WILL BEGIN IN %s" % (fg(202), attr(0), i)
                )
            sleep(1)
        self._cap = super().capture(print_stdout=False)
        self.write(self._cap)

    def summary(self):
        """ """
        if self._cap:
            self.capparser.summary(self._cap)
        elif self._filtered_cap:
            self.capparser.summary(self._filtered_cap)

    def to_json(self):
        """ """
        if self._cap:
            self.capparser.json_summary(self._cap)
        elif self._filtered_cap:
            self.capparser.json_summary(self._filtered_cap)

    def log(self):
        """ """
        if self._cap:
            with open("capture.log", "w") as log_file:
                for cap in self._cap:
                    flow_statement = self.netsniff_obj.echo(cap)
                    log_file.write(flow_statement + "\n")

        elif self._filtered_cap:
            with open("capture.log", "w") as log_file:
                for cap in self._filtered_cap:
                    flow_statement = self.netsniff_obj.echo(cap)
                    log_file.write(flow_statement + "\n")

    def write(self, packets):
        """
        """
        try:
            wrpcap(self._wfile, packets)
            print("[ %sSUCCESS%s ] PCAP FILE `%s` CREATED" % (fg(50), attr(0), self._wfile))
        except:
            print(
                "[ %sERROR%s ] THERE WAS AN ERROR CREATING PCAP FILE. PLEASE TRY AGAIN..."
                % (fg(9), attr(0))
            )
            exit(1)