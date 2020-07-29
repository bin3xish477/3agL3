from netaddr import *
from netifaces import *
from winreg import (
    ConnectRegistry, HKEY_LOCAL_MACHINE, OpenKey, QueryValueEx
)

"""
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/libraries/netifaces/index.html
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/libraries/netaddr/index.html

FOR OBTAINING WIRELESS ADAPTER NAME FROM REGISTRY INSTEAD OF GUID'S FOR ADAPTERS
--------------------------------------------------------------------------------
import netifaces as ni
import winreg as wr

def get_connection_name_from_guid(iface_guids):
    iface_names = ['(unknown)' for i in range(len(iface_guids))]
    reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
    reg_key = wr.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(len(iface_guids)):
        try:
            reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r'\Connection')
            iface_names[i] = wr.QueryValueEx(reg_subkey, 'Name')[0]
        except FileNotFoundError:
            pass
    return iface_names
"""

class NetworkFilter:
    pass