#!/usr/bin/env python3

import sys

def auxiliary_crack(word, wpa_psk, ssid):
 try:
  if not type(word) is bool:
    print("\n" + "=" * 50)

    if wpa_psk:
      print("[ SSID ]".center(50))
      print("=" * 50)
      print(f">>> ssid: {ssid}".center(50))

    print("=" * 50)
    print("[ PASSWORD FOUND ]".center(50))
    print("=" * 50)
    print(f">>> Recovered Password: {word}".center(50))
    print("=" * 50 + "\n")
    if word != word.strip():
      print("[WARNING:] The password contains leading or trailing whitespace")
    
 except Exception as error:
   print(f"[ERROR]: {error}")
   sys.exit(1)
