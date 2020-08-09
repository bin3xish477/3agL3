from utils.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import rdpcap, hexdump
from colored import fg, attr
from time import sleep
from os.path import exists
from platform import system

SYSTEM = system()

class ReadPCAP:
    def __init__(
        self, rfile, hexdump, src_ip, not_src_ip, dst_ip, not_dst_ip, 
        src_port, not_src_port, dst_port, not_dst_port, src_mac,
        not_src_mac, dst_mac, not_dst_mac, tcp, not_tcp,udp, 
        not_udp, icmp, not_icmp, pkt_cnt
    ):
        self._rfile = rfile
        self._hex = hexdump
        self._pkt_cnt = pkt_cnt
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

    def read(self, count=None):
        """ Read PCAP file """
        if exists(self._rfile):
            temp_pkt_list = []
            i = 0
            try:
                self._pcapfile = rdpcap(self._rfile)
                if count is not None:
                    for cap in self.pcapfile:
                        if i == count:
                            break
                        i += 1
                        temp_pkt_list.append(cap)
                    self._pcapfile = temp_pkt_list
            except:
                print(
                    "[ %sERROR%s ] THERE WAS A PROBLEM READING PCAP FILE"
                    % (fg(9), attr(0))
                )
                exit(1)
        else:
            print("[ %sERROR%s ] FILE %s DOES NOT EXIST" % (fg(9), attr(0), self._rfile))
            exit(1)

    @property
    def pcapfile(self):
        """ Returns `self._pcapfile` """
        return self._pcapfile
    
    def execute(self, func, arg):
        """ Executes real-time capture and passes that capture to `func`
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
        self.execute(self.capparser.filt_src_ip, self._src_ip)
    
    def filter_not_src_ip(self):
        self.execute(self.capparser.filt_not_src_ip, self._not_src_ip)

    def filter_dst_ip(self):
        self.execute(self.capparser.filt_dst_ip, self._dst_ip)

    def filter_not_dst_ip(self):
        self.execute(self.capparser.filt_not_dst_ip, self._not_dst_ip)

    def filter_src_port(self):
        self.execute(self.capparser.filt_src_port, self._src_port)

    def filter_not_src_port(self):
        self.execute(self.capparser.filt_not_src_port, self._not_src_port)

    def filter_dst_port(self):
        self.execute(self.capparser.filt_dst_port, self._dst_port)
    
    def filter_not_dst_port(self):
        self.execute(self.capparser.filt_not_dst_port, self._not_dst_port)

    def filter_src_mac(self):
        self.execute(self.capparser.filt_src_mac, self._src_mac)

    def filter_not_src_mac(self):
        self.execute(self.capparser.filt_not_src_mac, self._not_src_mac)

    def filter_dst_mac(self):
        self.execute(self.capparser.filt_dst_mac, self._dst_mac)

    def filter_not_dst_mac(self):
        self.execute(self.capparser.filt_not_dst_mac, self._not_dst_mac)

    def filter_tcp(self):
        self.execute(self.capparser.filt_tcp, None)

    def filter_not_tcp(self):
        self.execute(self.capparser.filt_not_tcp, None)

    def filter_udp(self):
        self.execute(self.capparser.filt_udp, None)

    def filter_not_udp(self):
        self.execute(self.capparser.filt_not_udp, None)

    def filter_icmp(self):
        self.execute(self.capparser.filt_icmp, None)

    def filter_not_icmp(self):
        self.execute(self.capparser.filt_not_icmp, None)

    def filter_arp(self):
        self.execute(self.capparser.filt_arp, None)

    def filter_not_arp(self):
        self.execute(self.capparser.filt_not_arp, None)

    def filter_dns(self):
        self.execute(self.capparser.filt_dns, None)

    def filter_not_dns(self):
        self.execute(self.capparser.filt_not_dns, None)

    def filter_tcp_flags(self, target_flags):
        self.execute(self.capparser.filt_tcp_flags, target_flags)

    def len_le_eq(self, value:int):
        filtered_capture = self.capparser.len_less_equal(self.pcapfile, value)
        self.to_stdout(filtered_capture)

    def len_gr_eq(self, value:int):
        filtered_capture = self.capparser.len_greater_equal(self.pcapfile, value)
        self.to_stdout(filtered_capture)

    def len_eq(self, value:int):
        filtered_capture = self.capparser.len_equal(self.pcapfile, value)
        self.to_stdout(filtered_capture)

    def ttl_eq(self, value:int):
        filtered_capture = self.capparser.ttl_equal(self.pcapfile, value)
        self.to_stdout(filtered_capture)

    def no_filter(self, no_print=False):
        if not no_print:
            print("[ %sNOTE%s ] NO READ FILTERS HAVE BEEN APPLIED" % (fg(226), attr(0)))
            self.to_stdout(self.pcapfile)
    
    def packet_count(self):
        return len([cap for cap in self.pcapfile])

    def summary(self):
        self.capparser.summary(self.pcapfile)

    def to_json(self, filename):
        self.capparser.json_summary(self.pcapfile, filename)

    def log(self, filename):
        if not filename:
            filename = "capture.log"
        with open(filename, "w", encoding="utf-8") as log_file:
            for cap in self.pcapfile:
                if SYSTEM == "Windows":
                    flow_statement = self.netsniff_obj.echo(cap).replace("\u2192", "->")
                else: flow_statement = self.netsniff_obj.echo(cap)
                log_file.write(flow_statement + "\n")

    def to_stdout(self, capture):
        try:
            for cap in capture:
                print_str = self.netsniff_obj.echo(cap)
                if not print_str:
                    continue
                print(print_str)
                if self._hex:
                    hexdump(cap)
                    print("\n")
        except KeyboardInterrupt:
            print(
                "\n[ %sATTENTION%s ] SIGINT INVOKED: TERMINATING PROGRAM"
                % (fg(202), attr(0))
            )