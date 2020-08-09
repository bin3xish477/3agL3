from utils.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import wrpcap
from colored import fg, attr
from sys import exit
from time import sleep
from random import randint

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
        print("\t\t\t  <[ %sCAPTURE INFO%s ]>" % (fg(60), attr(0)))
        print("-"*71)
        print("INTERFACE \u2192 %s%s%s" % (fg(randint(50, 200)), attr(0), self.interf))
        print("BERKELEY CAPTURE FILTER APPLIED \u2192 %s%s%s" % (fg(randint(50, 200)), attr(0), self.berkeley_filter))
        print("NUMBER OF PACKETS TO CAPTURE \u2192 %s%s%s" % (fg(randint(50, 200)), attr(0), self.count))
        try:
            self.to_parse = super().capture(print_stdout=False)
        except:
            print(
                "[%sERROR%s] COULD BEGIN PACKET CAPTURE. PLEASE TRY AGAIN..."
                % (fg(9), attr(0))
            )
            exit(1)
        self._filtered_capture = func(self.to_parse, arg)
        self.write(self._filtered_capture)

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
        self.execute(self.capparser.filt_not_icmp, None)\

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

    def no_filter(self):
        print("\t\t\t  <[ %sCAPTURE INFO%s ]>" % (fg(60), attr(0)))
        print("-"*71)
        print("INTERFACE \u2192 %s%s%s" % (fg(randint(50, 200)), self.interf, attr(0)))
        print("BERKELEY CAPTURE FILTER APPLIED \u2192 %s%s%s" % (fg(randint(50, 200)), self.berkeley_filter, attr(0)))
        print("NUMBER OF PACKETS TO CAPTURE \u2192  %s%s%s" % (fg(randint(50, 200)), self.count, attr(0)))
        self._capture = super().capture(print_stdout=False)
        self.write(self._capture)

    def len_le_eq(self, value):
        filtered_capture = self.capparser.len_less_equal(self.to_parse, value)
        self.write(filtered_capture)

    def len_gr_eq(self, value):
        filtered_capture = self.capparser.len_greater_equal(self.to_parse, value)
        self.write(filtered_capture)

    def len_eq(self, value):
        filtered_capture = self.capparser.len_equal(self.to_parse, value)
        self.write(filtered_capture)

    def ttl_eq(self, value):
        filtered_capture = self.capparser.ttl_equal(self.to_parse, value)
        self.write(filtered_capture)

    def summary(self):
        """ Prints summary (IP:count,MAC:count,PORT:count) of PCAP file """
        if self._capture:
            self.capparser.summary(self._capture)
        elif self._filtered_capture:
            self.capparser.summary(self._filtered_capture)

    def to_json(self, filename):
        """ Create JSON file PCAP data (IP:count,MAC:count,PORT:count) """
        if self._capture:
            self.capparser.json_summary(self._capture, filename)
        elif self._filtered_capture:
            self.capparser.json_summary(self._filtered_capture, filename)

    def log(self, filename):
        """ Create log file containing the contents of the PCAP file """
        if not filename:
            filename = "capture.log"
        if self._capture:
                with open(filename, "w", encoding="utf-8") as log_file:
                    for cap in self._capture:
                        flow_statement = self.netsniff_obj.echo(cap)
                        log_file.write(flow_statement + "\n")

        elif self._filtered_capture:
                with open(filename, "w", encoding="utf-8") as log_file:
                    for cap in self._filtered_capture:
                        flow_statement = self.netsniff_obj.echo(cap)
                        log_file.write(flow_statement + "\n")

    def write(self, packets):
        """ Create PCAP file
        Args:
            packets (list): a list containing packets to write to PCAP file
        """
        try:
            wrpcap(self._wfile, packets)
            print("\n[ %sSUCCESS%s ] PCAP FILE `%s` CREATED" % (fg(50), attr(0), self._wfile))
        except:
            print(
                "[ %sERROR%s ] THERE WAS AN ERROR CREATING PCAP FILE. PLEASE TRY AGAIN..."
                % (fg(9), attr(0))
            )
            exit(1)
