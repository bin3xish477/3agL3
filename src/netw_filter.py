# from netaddr import 
# from netifaces import 
from colored import fg, attr
from platform import system
if system() == "Windows":
	from winreg import (
	    ConnectRegistry, HKEY_LOCAL_MACHINE, OpenKey, QueryValueEx
	)

"""
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/libraries/netifaces/index.html
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/libraries/netaddr/index.html

For network intergace guid resolution
https://stackoverflow.com/questions/29913516/how-to-get-meaningful-network-interface-names-instead-of-guids-with-netifaces-un
"""

class NetworkFilter:
    pass