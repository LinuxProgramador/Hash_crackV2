#!/usr/bin/env python3

import sys
from hashlibx.aux_output import auxiliary_crack

def decrypt_cisco_type7(target_hash):
 try:

   wpa_psk = ssid = None
   key = "dsfd;kfoA,.iyewrkldJKD"
   offset = int(target_hash[:2])
   decrypted = ""

   for i in range(2, len(target_hash), 2):
       byte = int(target_hash[i:i+2], 16)
       key_index = (offset + (i - 2) // 2) % len(key)
       decrypted += chr(byte ^ ord(key[key_index]))

   auxiliary_crack(decrypted.strip(), wpa_psk, ssid)

 except Exception as error:
   print(f"[ERROR]: {error}")
   sys.exit(1)
