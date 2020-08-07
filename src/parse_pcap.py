from collections import Counter
from colored import fg, attr
from json import dump
from sys import exit
from re import search
from scapy.all import Ether, IP, ICMP, Raw
from random import randint

class PCAPParser:
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
        for cap in capture:
            if cap.haslayer(IP) and cap[IP].src == src_ip:
                filtered.append(cap)
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
                "[ %sERROR%s ] SPECIFIED `-src-ip` MUST BE A VALID IP ADDRESSES"
                % (fg(9), attr(0))
            )
            exit(1)

        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and cap[IP].src != src_ip:
                filtered.append(cap)
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
        for cap in capture:
            if cap.haslayer(IP) and cap[IP].dst == dst_ip:
                filtered.append(cap)
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
                "[ %sERROR%s ] SPECIFIED `-dst-ip` MUST BE A VALID IP ADDRESSES"
                % (fg(9), attr(0))
            )
            exit(1)

        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and cap[IP].dst == dst_ip:
                filtered.append(cap)
        return filtered

    def filt_src_port(self, capture, src_port):
        """
        """
        filtered = []
        for cap in capture:
            try:
                if cap.haslayer(IP) and cap[IP].sport == int(src_port):
                    filtered.append(cap)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-src-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_not_src_port(self, capture, src_port):
        """
        """
        filtered = []
        for cap in capture:
            try:
                if cap.haslayer(IP) and cap[IP].sport == int(src_port):
                    filtered.append(cap)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-src-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_dst_port(self, capture, dst_port):
        """
        """
        filtered = []
        for cap in capture:
            try:
                if cap.haslayer(IP) and cap[IP].dport == int(dst_port):
                    filtered.append(cap)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-dst-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_not_dst_port(self, capture, dst_port):
        """
        """
        filtered = []
        for cap in capture:
            try:
                if cap.haslayer(IP) and cap[IP].dport == int(dst_port):
                    filtered.append(cap)
            except ValueError:
                print(
                    "[ %sERROR%s ] SPECIFIED `-dst-port` MUST BE WITHIN RANGE: 1-65535"
                    % (fg(9), attr(0))
                )
                exit(1)
        return filtered

    def filt_src_mac(self, capture, src_mac):
        """ """
        try:
            src_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", src_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-src-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for cap in capture:
            if cap[Ether].src == src_mac:
                filtered.append(cap)
        return filtered

    def filt_not_src_mac(self, capture, src_mac):
        """ """
        try:
            src_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", src_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-src-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for cap in capture:
            if cap[Ether].src == src_mac:
                filtered.append(cap)
        return filtered

    def filt_dst_mac(self, capture, dst_mac):
        """ """
        try:
            dst_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", dst_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-dst-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for cap in capture:
            if cap[Ether].dst == dst_mac:
                filtered.append(cap)
        return filtered

    def filt_not_dst_mac(self, capture, dst_mac):
        """ """
        try:
            dst_mac = search(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", dst_mac).group(0)
        except AttributeError:
            print(
                "[ %sERROR%s ] SPECIFIED `-dst-mac` MUST BE A VALID MAC ADDRESS"
                % (fg(9), attr(0))
                )
            exit(1)

        filtered = []
        for cap in capture:
            if cap[Ether].dst == dst_mac:
                filtered.append(cap)
        return filtered

    def filt_tcp(self, capture, _):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and str(cap[IP].payload.name).upper() == "TCP":
                filtered.append(cap)
        return filtered

    def filt_not_tcp(self, capture, _):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and str(cap[IP].payload.name).upper() == "TCP":
                filtered.append(cap)
        return filtered

    def filt_udp(self, capture, _):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and str(cap[IP].payload.name).upper() == "UDP":
                filtered.append(cap)
        return filtered

    def filt_not_udp(self, capture, _):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and str(cap[IP].payload.name).upper() == "UDP":
                filtered.append(cap)
        return filtered

    def filt_icmp(self, capture, _):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and str(cap[IP].payload.name).upper() == "ICMP":
                filtered.append(cap)
        return filtered

    def filt_not_icmp(self, capture, _):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(IP) and str(cap[IP].payload.name).upper() == "ICMP":
                filtered.append(cap)
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
            print("[ %sATTENTION%s ] THIS MAY TAKE A SECOND OR TWO" % (fg(202), attr(0)))

            # FILTERING IP ADDRESSES
            ip_list = ([cap[IP].src for cap in capture if cap.haslayer(IP)]
            + [cap[IP].dst for cap in capture if cap.haslayer(IP)])
            ip_dict = Counter(ip_list)
            
            print("%sIP%s: COUNT" % (fg(randint(1, 254)), attr(0)))
            for ip, count in ip_dict.most_common():
                print("\'%s\': %s" % (ip, count))

            # FILTERING PORT NUMBERS
            port_list = ([cap[IP].sport for cap in capture if cap.haslayer(IP)]
            + [cap[IP].dport for cap in capture if cap.haslayer(IP)])
            port_dict = Counter(port_list)

            print("\n%sPORT%s: COUNT" % (fg(randint(1, 254)), attr(0)))

            for port, count in port_dict.most_common():
                print("%s: %s" % (port, count))
            print("\n", end="")

            # FILTERING MAC ADDRESSES
            mac_list = ([cap[Ether].src for cap in capture if cap.haslayer(IP)]
            + [cap[Ether].dst for cap in capture if cap.haslayer(IP)])
            mac_dict = Counter(mac_list)

            print("%sMAC%s: COUNT" % (fg(randint(1, 254)), attr(0)))
            for mac, count in mac_dict.most_common():
                print("%s: %s" % (mac, count))
            print("\n", end="")

            # FILTERING PACKETS LENGTHS
            i = 0
            pkt_len_sum = 0
            for cap in capture:
                i += 1
                pkt_len_sum += len(cap)
            average_pkt_len = round(pkt_len_sum / i, 1)
            print("-"*35)
            print("%sAVERAGE PACKET LENGTH%s: %s bytes" % (fg(109), attr(0), average_pkt_len))

            # FILTERING TTL
            i = 0
            pkt_ttl_sum = 0
            for cap in capture:
                if cap.haslayer(Ether):
                    try:
                        i += 1
                        pkt_ttl_sum += cap[Ether].ttl
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

    def len_less_equal(self, capture, value):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(Ether) and cap[Ether].len <= value:
                filtered.append(cap)
        return filtered

    def len_greater_equal(self, capture, value):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(Ether) and cap[Ether].len >= value:
                filtered.append(cap)
        return filtered

    def len_equal(self, capture, value):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(Ether) and cap[Ether].len == value:
                filtered.append(cap)
        return filtered

    def ttl_equal(self, capture):
        """ """
        filtered = []
        for cap in capture:
            if cap.haslayer(Ether) and cap[Ether].ttl == value:
                filtered.append(cap)
        return filtered

    def json_summary(self, capture):
        """ Generate JSON file containing summary of packet capture.
        The JSON file will contain:
            - ip: count
            - port: count
            - mac: count
        
        Args:
            capture (scapy.plist.PacketList): scapy packet capture list
        """
        capture_summary = {}

        ip_list = ([cap[IP].src for cap in capture if cap.haslayer(IP)]
        + [cap[IP].dst for cap in capture if cap.haslayer(IP)])
        ip_dict = Counter(ip_list)
        capture_summary["ip_dict"] = ip_dict

        port_list = ([cap[IP].sport for cap in capture if cap.haslayer(IP)]
        + [cap[IP].dport for cap in capture if cap.haslayer(IP)])
        port_dict = Counter(port_list)
        capture_summary["port_dict"] = port_dict

        mac_list = ([cap[Ether].src for cap in capture if cap.haslayer(Ether)]
        + [cap[Ether].dst for cap in capture if cap.haslayer(Ether)])
        mac_dict = Counter(mac_list)
        capture_summary["mac_dict"] = mac_dict
        
        try:
            with open("capture_summary.json", "w") as cap_sum_file:
                dump(capture_summary, cap_sum_file, indent=4)
        except:
            print(
                "[ %sERROR%s ] THERE WAS AN ERROR CREATING SUMMARY JSON FILE... PLEASE TRY AGAIN"
                % (fg(9), attr(0))
            )
