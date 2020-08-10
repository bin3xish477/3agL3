from collections import Counter
from colored import fg, attr
from json import dump
from sys import exit
from re import search
from scapy.all import *
from random import randint
from src.net_sniff import NetSniff

class PCAPParser(NetSniff):
    def __init__(self):
        super().__init__(None, None , None, None)
        
    def filt_src_ip(self, capture, src_ip):
        """ Filter source IP addresses from capture 
        Args:
            capture (scapy.plist.PacketList): scapy packet capture
            src_ip (str): target source IP address to filter for        
        """
        try:
            src_ip = search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", src_ip).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-src-ip` MUST BE A VALID IP ADDRESSES"
                % (fg(9), attr(0))
            )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt.haslayer(IP) and pkt[IP].src == src_ip:
                filtered.append(pkt)
        return filtered
    
    def filt_not_src_ip(self, capture, src_ip):
        """ Filter source IP addresses from capture that do not match `src_ip`
        Args:
            capture (scapy.plist.PacketList): scapy packet capture
            src_ip (str): target source IP address to not filter for        
        """
        try:
            src_ip = search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", src_ip).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-not-src-ip` MUST BE A VALID IP ADDRESSES"
                % (fg(9), attr(0))
            )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt.haslayer(IP) and pkt[IP].src != src_ip:
                filtered.append(pkt)
        return filtered

    def filt_dst_ip(self, capture, dst_ip):
        """ Filter destination IP addresses from capture 
        
        Args:
            capture (scapy.plist.PacketList): scapy packet capture
            dst_ip (str): target destination IP address to filter for
        """
        try:
            dst_ip = search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", dst_ip).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-dst-ip` MUST BE A VALID IP ADDRESSES"
                % (fg(9), attr(0))
            )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt.haslayer(IP) and pkt[IP].dst == dst_ip:
                filtered.append(pkt)
        return filtered

    def filt_not_dst_ip(self, capture, dst_ip):
        """ Filter destination IP addresses from capture 
        
        Args:
            capture (scapy.plist.PacketList): scapy packet capture
            dst_ip (str): target destination IP address to filter for
        """
        try:
            dst_ip = search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", dst_ip).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-not-dst-ip` MUST BE A VALID IP ADDRESSES"
                % (fg(9), attr(0))
            )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt.haslayer(IP) and pkt[IP].dst != dst_ip:
                filtered.append(pkt)
        return filtered

    def filt_src_port(self, capture, src_port):
        """ Filter for packets with a source port that matches `src_port` """
        filtered = []
        for pkt in capture:
            try:
                if pkt.haslayer(IP) and pkt[IP].sport == int(src_port):
                    filtered.append(pkt)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-src-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_not_src_port(self, capture, src_port):
        """ Filter for packets with a source port that does not match `src_port` """
        filtered = []
        for pkt in capture:
            try:
                if pkt.haslayer(IP) and pkt[IP].sport != int(src_port):
                    filtered.append(pkt)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-not-src-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_dst_port(self, capture, dst_port):
        """ Filter for packets with a destination port that equals `dst_port` """
        filtered = []
        for pkt in capture:
            try:
               if (pkt.haslayer(TCP) or pkt.haslayer(UDP)
                and pkt[TCP].dport == int(dst_port)
                or pkt[UDP].dport == int(dst_port)):
                    filtered.append(pkt)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-dst-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_not_dst_port(self, capture, dst_port):
        """ Filter for packets with destination port's that do not match `dst_port` """
        filtered = []
        for pkt in capture:
            try:
                if (pkt.haslayer(TCP) or pkt.haslayer(UDP)
                and pkt[TCP].dport != int(dst_port)
                or pkt[UDP].dport != int(dst_port)):
                    filtered.append(pkt)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-not-dst-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_src_mac(self, capture, src_mac):
        """ Filter for packets whose source MAC address equals `src_mac` """
        try:
            src_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", src_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-src-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt[Ether].src == src_mac:
                filtered.append(pkt)
        return filtered

    def filt_not_src_mac(self, capture, src_mac):
        """ Filter for packets whose source MAC address does not equal `src_mac` """
        try:
            src_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", src_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-not-src-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt[Ether].src != src_mac:
                filtered.append(pkt)
        return filtered

    def filt_dst_mac(self, capture, dst_mac):
        """ Filter for packets with destination MAC address that is equal to `dst_mac` """
        try:
            dst_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", dst_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-dst-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt[Ether].dst == dst_mac:
                filtered.append(pkt)
        return filtered

    def filt_not_dst_mac(self, capture, dst_mac):
        """ Filter for packets with destination MAC addresses not matching `dst_mac` """
        try:
            dst_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", dst_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-not-dst-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for pkt in capture:
            if pkt[Ether].dst != dst_mac:
                filtered.append(pkt)
        return filtered

    def filt_tcp(self, capture, _):
        """ Filter for TCP packets """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(TCP) and str(pkt[IP].payload.name).upper() == "TCP":
                filtered.append(pkt)
        return filtered

    def filt_not_tcp(self, capture, _):
        """ Filter for non-TCP packets """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(TCP):
                filtered.append(pkt)
        return filtered

    def filt_udp(self, capture, _):
        """ Filter for UDP packets """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(IP) and str(pkt[IP].payload.name).upper() == "UDP":
                filtered.append(pkt)
        return filtered

    def filt_not_udp(self, capture, _):
        """ Filter for non-UDP packets """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(UDP):
                filtered.append(pkt)
        return filtered

    def filt_icmp(self, capture, _):
        """ Filter for ICMP packets """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(ICMP) and str(pkt[IP].payload.name).upper() == "ICMP":
                filtered.append(pkt)
        return filtered

    def filt_not_icmp(self, capture, _):
        """ Filter for non-ICMP packets """
        filtered = []
        for pkt in capture:
            if not pkt.haslayer(ICMP):
                filtered.append(pkt)
        return filtered

    def filt_arp(self, capture, _):
        """ Filter for ARP packets """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(ARP):
                filtered.append(pkt)
        return filtered

    def filt_not_arp(self, capture, _):
        """ Filter for non-ARP packets """
        filtered = []
        for pkt in capture:
            if not pkt.haslayer(ARP):
                filtered.append(pkt)
        return filtered

    def filt_dns(self, capture, _):
        """ Filter for DNS packets """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(DNS):
                filtered.append(pkt)
        return filtered

    def filt_not_dns(self, capture, _):
        """ Filter for non-DNS packets """
        filtered = []
        for pkt in capture:
            if not pkt.haslayer(DNS):
                filtered.append(pkt)
        return filtered

    def filt_tcp_flags(self, capture, target_flags):
        """ Filter for packets with TCP flags in the order specified in the list `target_flags` """
        filtered = []
        target_flags = [flag.upper() for flag in target_flags]
        for pkt in capture:
            if pkt.haslayer(TCP):
                pkt_flags = sorted([self.FLAGS[flag] for flag in pkt[TCP].flags])
                if pkt_flags == sorted(target_flags):
                    filtered.append(pkt)
        return filtered

    def len_less_equal(self, capture, value):
        """ Filter for packets with a length less than or equal to `value` """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(Ether) and len(pkt) <= value:
                filtered.append(pkt)
        return filtered

    def len_greater_equal(self, capture, value):
        """ Filter for packets with a length greater than or equal to `value` """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(Ether) and len(pkt) >= value:
                filtered.append(pkt)
        return filtered

    def len_equal(self, capture, value):
        """ Filter for packets with a length that is equal to `value` """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(Ether) and len(pkt) == value:
                filtered.append(pkt)
        return filtered

    def ttl_equal(self, capture, value):
        """ Filter for packets with time-to-live equal to `value` """
        filtered = []
        for pkt in capture:
            if pkt.haslayer(Ether) and pkt[Ether].ttl == value:
                filtered.append(pkt)
        return filtered

    def summary(self, capture):
        """ Prints a summary of the data contained in a capture.
        This summary includes:
            - unique IP and the number of times they appear
            - unique port number and the number of time they appear
            - unique mac addresses and the number of times they appear

        Args:
            capture (scapy.plist.PacketList): scapy packet capture list
        """
        try:
            # FILTERING IP ADDRESSES
            ip_list = ([pkt[IP].src for pkt in capture if pkt.haslayer(IP)]
            + [pkt[IP].dst for pkt in capture if pkt.haslayer(IP)])
            ip_dict = Counter(ip_list)
            
            print("\n%sIP%s > COUNT" % (fg(randint(1, 254)), attr(0)))
            print("_"*30)
            for ip, count in ip_dict.most_common():
                print("\'%s\' > %s" % (ip, count))

            # FILTERING PORT NUMBERS
            port_list = ([pkt[IP].sport for pkt in capture if pkt.haslayer(TCP) or pkt.haslayer(UDP)]
            + [pkt[IP].dport for pkt in capture if pkt.haslayer(TCP) or pkt.haslayer(UDP)])
            port_dict = Counter(port_list)

            print("\n%sPORT%s > COUNT" % (fg(randint(1, 254)), attr(0)))
            print("_"*20)
            for port, count in port_dict.most_common():
                print("%s > %s" % (port, count))
            print("\n", end="")

            # FILTERING MAC ADDRESSES
            mac_list = ([pkt[Ether].src for pkt in capture if pkt.haslayer(Ether)]
            + [pkt[Ether].dst for pkt in capture if pkt.haslayer(Ether)])
            mac_dict = Counter(mac_list)

            print("%sMAC%s > COUNT" % (fg(randint(1, 254)), attr(0)))
            print("_"*30)
            for mac, count in mac_dict.most_common():
                print("%s > %s" % (mac, count))
            print("\n", end="")

            # FILTERING PACKET LENGTHS
            i = 0
            pkt_len_sum = 0
            for pkt in capture:
                if pkt.haslayer(Ether):
                    i += 1
                    pkt_len_sum += len(pkt)
            average_pkt_len = round(pkt_len_sum / i, 1)
            print("-"*37)
            print("%sAVERAGE PACKET LENGTH%s: %s bytes" % (fg(109), attr(0), average_pkt_len))

            # FILTERING TTL
            i = 0
            pkt_ttl_sum = 0
            for pkt in capture:
                if pkt.haslayer(IP):
                    try:
                        i += 1
                        pkt_ttl_sum += pkt[IP].ttl
                    except AttributeError:
                        continue
            average_pkt_ttl = round(pkt_ttl_sum / i, 1)
            print("%sAVERAGE TTL%s: %s " % (fg(109), attr(0), average_pkt_ttl))
        except:
            print(
                "[ %sERROR%s ] COULDN'T GENERATE COMPLETE CAPTURE SUMMARY"
                % (fg(9), attr(0))
            )
            exit(1)

    def json_summary(self, capture, filename):
        """ Generate JSON file containing summary of packet capture.
        The JSON file will contain:
            - ip: count
            - port: count
            - mac: count
        
        Args:
            capture (scapy.plist.PacketList): scapy packet capture list
            filename (str): name of JSON file to create
        """
        capture_summary = {}

        ip_list = ([pkt[IP].src for pkt in capture if pkt.haslayer(IP)]
        + [pkt[IP].dst for pkt in capture if pkt.haslayer(IP)])
        ip_dict = Counter(ip_list)
        capture_summary["ip_dict"] = ip_dict

        port_list = ([pkt[IP].sport for pkt in capture if pkt.haslayer(TCP) or pkt.haslayer(UDP)]
        + [pkt[IP].dport for pkt in capture if pkt.haslayer(TCP) or pkt.haslayer(UDP)])
        port_dict = Counter(port_list)
        capture_summary["port_dict"] = port_dict

        mac_list = ([pkt[Ether].src for pkt in capture if pkt.haslayer(Ether)]
        + [pkt[Ether].dst for pkt in capture if pkt.haslayer(Ether)])
        mac_dict = Counter(mac_list)
        capture_summary["mac_dict"] = mac_dict
        
        try:
            if filename:
                with open(filename, "w") as cap_sum_file:
                    dump(capture_summary, cap_sum_file, indent=4)
            else:
                with open("capture_summary.json", "w") as cap_sum_file:
                    dump(capture_summary, cap_sum_file, indent=4)
        except:
            print(
                "[ %sERROR%s ] THERE WAS AN ERROR CREATING SUMMARY JSON FILE... PLEASE TRY AGAIN"
                % (fg(9), attr(0))
            )
