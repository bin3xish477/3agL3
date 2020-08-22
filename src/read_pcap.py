from utils.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import rdpcap, hexdump, IP
from colored import fg, attr
from time import sleep
from os.path import exists
from platform import system
from re import search
from datetime import datetime

SYSTEM = system()

class ReadPCAP(NetSniff):
    def __init__(
        self, rfile, hexdump, src_ip, not_src_ip, dst_ip, not_dst_ip, 
        src_port, not_src_port, dst_port, not_dst_port, src_mac,
        not_src_mac, dst_mac, not_dst_mac, tcp, not_tcp,udp, 
        not_udp, icmp, not_icmp, pkt_cnt
    ):
        super().__init__(None, None, None, None)
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
        self.filtered_packets = []

    def read(self, count=None):
        """Read PCAP file """
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
        """Returns `self._pcapfile` """
        return self._pcapfile
    
    def execute(self, func, arg):
        """Executes real-time capture and passes that capture to `func`
        along with `arg`. 
            Args:
                func (function): function defined in PCAPParser to invoke
                arg (str|int): value to filter from packet capture
        """
        self.filtered_packets = func(self.pcapfile, arg)
        if len(self.filtered_packets) == 0 or self.filtered_packets == None:
            print("[ %sATTENTION%s ] NO PACKETS CONTAINED SPECIFIED FILTER" % (fg(202), attr(0)))
            exit(1)
        else:
            self.to_stdout(self.filtered_packets)

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

    def no_filter(self, no_print=False):
        if not no_print:
            print("[ %sNOTE%s ] NO READ FILTERS HAVE BEEN APPLIED" % (fg(226), attr(0)))
            self.to_stdout(self.pcapfile)

    def len_le_eq(self, value:int):
        self.filtered_packets = self.capparser.len_less_equal(self.pcapfile, value)
        if not len(self.filtered_packets):
            print(
                "[ %sATTENTION%s ] NO PACKETS CONTAINED A LENGTH LESS THAN OR EQUAL TO %s"
                % (fg(202), attr(0), value)
            )
        self.to_stdout(self.filtered_packets)

    def len_gr_eq(self, value:int):
        self.filtered_packets = self.capparser.len_greater_equal(self.pcapfile, value)
        if not len(self.filtered_packets):
            print(
                "[ %sATTENTION%s ] NO PACKETS CONTAINED A LENGTH GREATER THAN OR EQUAL TO %s"
                % (fg(202), attr(0), value)
            )
        self.to_stdout(self.filtered_packets)

    def len_eq(self, value:int):
        self.filtered_packets = self.capparser.len_equal(self.pcapfile, value)
        if not len(self.filtered_packets):
            print(
                "[ %sATTENTION%s ] NO PACKETS CONTAINED A LENGTH EQUAL TO %s"
                % (fg(202), attr(0), value)
            )
        self.to_stdout(self.filtered_packets)

    def ttl_eq(self, value:int):
        self.filtered_packets = self.capparser.ttl_equal(self.pcapfile, value)
        if not len(self.filtered_packets):
            print(
                "[ %sATTENTION%s ] NO PACKETS CONTAINED A TIME-TO-LIVE VALUE EQUAL TO %s"
                % (fg(202), attr(0), value)
            )
        self.to_stdout(self.filtered_packets)

    def src_ip_count(self, ip):
        for pkt in self.pcapfile:
            if pkt[IP].src == ip:
                self.filtered_packets.append(pkt)
        return len(self.filtered_packets)

    def dst_ip_count(self, ip):
        for pkt in self.pcapfile:
            if pkt[IP].dst == ip:
                self.filtered_packets.append(pkt)
        return len(self.filtered_packets)

    def ip_count(self, ip):
        for pkt in self.pcapfile:
            if pkt[IP].src == ip or pkt[IP].dst == ip:
                self.filtered_packets.append(pkt)
        return len(self.filtered_packets)
    
    def before(self, time):
        """Filter packets with a time value that starts at `time` and onwards"""
        try:
            _ = search(r"(\d{2}:\d{2})", time).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-b` MUST BE IN HOUR:MINUTE FORMAT"
                % (fg(9), attr(0))
            )
            exit(1)

        time = time.strip()
        c = time.find(":")
        hour, minute = int(time[:c].lstrip("0")), int(time[c+1:].lstrip("0"))

        for pkt in self.pcapfile:
            pkt_time = datetime.fromtimestamp(pkt.time).strftime("%H:%M").lstrip("0")
            c = pkt_time.find(":")
            pkt_hour, pkt_minute = int(pkt_time[:c]), int(pkt_time[c+1:])
            if pkt_hour < hour:
                self.filtered_packets.append(pkt)
            elif pkt_hour == hour:
                if pkt_minute <= minute:
                    self.filtered_packets.append(pkt)
        self.to_stdout(self.filtered_packets) 
        
    def after(self, time):
        """Filter packets that contain a time value up to and including the `time` value"""
        try:
            _ = search(r"(\d{2}:\d{2})", time).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-a` MUST BE IN HOUR:MINUTE FORMAT"
                % (fg(9), attr(0))
            )
            exit(1)

        time = time.strip()
        c = time.find(":")
        hour, minute = int(time[:c].lstrip("0")), int(time[c+1:].lstrip("0"))

        for pkt in self.pcapfile:
            pkt_time = datetime.fromtimestamp(pkt.time).strftime("%H:%M").lstrip("0")
            c = pkt_time.find(":")
            pkt_hour, pkt_minute = int(pkt_time[:c]), int(pkt_time[c+1:])
            if pkt_hour > hour:
                self.filtered_packets.append(pkt)
            elif pkt_hour == hour:
                if pkt_minute >= minute:
                    self.filtered_packets.append(pkt)
        self.to_stdout(self.filtered_packets) 
 
    def time_range(self, time_range):
        """Filter packets based on a specified time range"""
        if len(time_range) <= 1 or len(time_range) > 2:
            print(
                "[ %sATTENTION%s ] `-tr` requires a time start and a time end value"
                % (fg(202), attr(0))
            )
            exit(1)

        try:
           _ = search(r"(\d{2}:\d{2})", time_range[0]).group(0)
           _ = search(r"(\d{2}:\d{2})", time_range[1]).group(0)
        except AttributeError:
            print(
               "[ %sERROR%s ] SPECIFIED `-tr` VALUES MUST BE IN HOUR:MINUTE FORMAT"
                % (fg(9), attr(0))
            )
            exit(1)

        c = time_range[0].find(":")
        start_hour, start_min = int(time_range[0][:c].lstrip("0")), \
                int(time_range[0][c+1:].lstrip("0"))
        c = time_range[1].find(":")
        end_hour, end_min = int(time_range[1][:c].lstrip("0")), \
                int(time_range[1][c+1:].lstrip("0"))
 
        for pkt in self.pcapfile:
            pkt_time = datetime.fromtimestamp(pkt.time).strftime("%H:%M").lstrip("0")
            c = pkt_time.find(":")
            pkt_hour, pkt_minute = int(pkt_time[:c]), int(pkt_time[c+1:])
            if pkt_hour > start_hour and pkt_hour < end_hour:
                self.filtered_packets.append(pkt)
            elif pkt_hour == start_hour:
                if pkt_min > start_min:
                    self.filtered_packets.append(pkt)
            elif pkt_hour == end_hour:
                if pkt_min < end_min:
                    self.filtered_packets.append(pkt)
        self.to_stdout(self.filtered_packets)

    def start_date(self, date):
        try:
            _ = search(r"(\d{4}/\d{2}/\d{2})", date).group(0)
        except AttributeError:
          print("start date error...") 

    def end_date(self, date):
        try:
            _ = search(r"(\d{4}/\d{2}/\d{2})", date).group(0)
        except AttributeError:
            print("end date error...")

    def date_range(self, dates):
        if len(dates) <= 1 or len(dates) > 2:
            print(
                "[ %sATTENTION%s ] `-dr` requires a start date and an end date"
                % (fg(202), attr(0))
            )
            exit(1)
        start_date = dates[0]
        end_date = dates[1]
        print(start_date, end_date)

    def packet_count(self):
        """Returns number of packets within a PCAP file"""
        return len([cap for cap in self.pcapfile])

    def summary(self):
        """Prints summary (IP:count,MAC:count,PORT:count) of PCAP file"""
        self.capparser.summary(self.pcapfile)

    def to_json(self, filename):
        """Create JSON file PCAP data (IP:count,MAC:count,PORT:count)"""
        self.capparser.json_summary(self.pcapfile, filename)

    def to_stdout(self, capture):
        """Prints PCAP data to console"""
        try:
            for cap in capture:
                print_str = self.echo(cap)
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
