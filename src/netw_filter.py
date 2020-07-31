from netaddr import IPAddress, EUI
from netifaces import interfaces, ifaddresses
from colored import fg, attr
from platform import system
from random import randint
from pprint import pprint

"""
For network intergace guid resolution
https://stackoverflow.com/questions/29913516/how-to-get-meaningful-network-interface-names-instead-of-guids-with-netifaces-un
"""

class NetworkFilter:
    def list_interfaces(self):
    	""" List network interfaces on system """
    	print("[ %s%sNetwork Interfaces%s ]" % (fg(126), attr("bold"), attr("reset")))
    	print("-"*22)
    	if SYSTEM == "Linux":
    		list_of_interfaces = interfaces()
    		for interface in list_of_interfaces:
    			print(interface)
    	else:
    		print(
    			"[ %sATTENTION%s ] the `-ls-interf` option is only for Linux"
    			% (fg(202), attr(0))
    		)


    def enumerate_interface(self, target_interface):
    	""" Get info of a specified network interface """
    	if SYSTEM == "Linux":
    		inter_info = ifaddresses(target_interface)
    		for section in inter_info.values():
    			for key, val in section[0].items():
    				print(("%s%s"+key+"%s") % (fg(randint(1,254)), attr("bold"), attr("reset")),"\u2192", val)
    	else:
    		print(
    			"[ %sATTENTION%s ] the `-enum-interf` option is only for Linux"
    			% (fg(202), attr(0))
    		)

    def enumerate_ip(self, target_ip):
    	""" Perform enumeration on a specified IP address """
    	ip = IPAddress(target_ip)
    	print("IP Version:", ip.version)
    	print("Binary Representation:", ip.bin[2:])
    	print("Bit Representation:", ip.bits())
    	pprint("Info:\n", ip.info)

    def enumerate_mac(self, target_mac):
    	""" Perform enumeration on a specified MAC address """
    	mac = EUI(target_mac)
    	print("MAC version:", mac.version)
    	print("Binary Representation:", mac.bin)
    	print("Bit Representation:", mac.bits())
    	print("Host Identifier:", mac.ei)
    	print("Info:\n", mac.info)