#!/usr/bin/env python3

import sys

def auxiliary_crack(word, wpa_psk, ssid):
 try:

   print("\n" + "=" * 50)

   if wpa_psk:
     print("[ SSID ]".center(50))
     print("=" * 50)
     print(f">>> ssid: {ssid}".center(50))

   print("=" * 50)
   print("[ PASSWORD FOUND ]".center(50))
   print("=" * 50)
   print(f">>> Recovered Password: {word.strip()}".center(50))
   print("=" * 50 + "\n")

 except Exception as error:
   print(f"[ERROR]: {error}")
   sys.exit(1)
