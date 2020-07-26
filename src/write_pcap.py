from src.parse_pcap import PCAPParser
from src.net_sniff import NetSniff
from scapy.all import wrpcap
from colored import fg, attr
from sys import exit
from time import sleep

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
        try:
            self.to_parse = super().capture(print_stdout=False)
        except:
            print(
				"[%sERROR%s] COULD BEGIN PACKET CAPTURE. PLEASE TRY AGAIN..."
				% (fg(9), attr(0))
			)
        self.filtered_capture = func(self.to_parse, arg)
        self.write(self.filtered_capture)

    def filter_src_ip(self):
        """ """
        self.start(self.capparser.filt_src_ip, self.src_ip)
    
    def filter_dst_ip(self):
        """ """
        self.start(self.capparser.filt_dst_ip, self.dst_ip)

    def filter_src_port(self):
        """ """
        self.start(self.capparser.filt_src_port, self.src_port)

    def filter_dst_port(self):
        """ """
        self.start(self.capparser.filt_dst_port, self.dst_port)

    def filter_src_mac(self):
        """ """
        self.start(self.capparser.filt_src_mac, self.src_mac)

    def filter_dst_mac(self):
        """ """
        self.start(self.capparser.filt_dst_mac, self.dst_mac)

    def filter_tcp(self):
        """ """
        self.start(self.capparser.filt_tcp, self.tcp)

    def filter_udp(self):
        """ """
        self.start(self.capparser.filt_udp, self.udp)

    def no_filter(self):
        """ """
        for i in range(2, -1, -1):
            if i != 0:
                print(
                    "[%sATTENTION%s] CAPTURE WILL BEGIN IN %s\r"
                    % (fg(202), attr(0), i), end=""
                )
            else:
                print(
                    "[%sATTENTION%s] CAPTURE WILL BEGIN IN %s"
                    % (fg(202), attr(0), i)
                )
            sleep(1)
        self.cap = super().capture(print_stdout=False)
        self.write(self.cap)

    def summary(self):
        """ """
        if self.cap:
            self.capparser.summary(self.cap)
        elif self.filtered_capture:
            self.capparser.summary(self.filtered_capture)

    def write(self, packets):
        """
        """
        try:
            wrpcap(self.wfile, packets)
            print("[%sSUCCESS%s] PCAP FILE `%s` CREATED" % (fg(50), attr(0), self.wfile))
        except:
            print(
                "[%sERROR%s] THERE WAS AN ERROR CREATING PCAP FILE. PLEASE TRY AGAIN..."
                % (fg(9), attr(0))
            )
            exit(1)