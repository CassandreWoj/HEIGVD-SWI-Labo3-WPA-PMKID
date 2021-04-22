#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
#from binascii import a2b_hex, b2a_hex
#from pbkdf2 import *
#from numpy import array_split
#from numpy import array
#import hmac, hashlib

wpa=rdpcap("PMKID_handshake.pcap")

packet = wpa[145]
pmkid = raw(packet)[-20:-4]
print(pmkid)