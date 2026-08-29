#!/usr/bin/env python3

import sys

def auxiliary_crack(word):
 try:
    print("\n" + "=" * 50)
    print("=" * 50)
    print("[ PASSWORD FOUND ]".center(50))
    print("=" * 50)
    print(f">>> Recovered Password: {word}".center(50))
    print("=" * 50 + "\n")
    if word != word.strip():
      print("[WARNING]: The password contains leading or trailing whitespace")
    
 except Exception as error:
   print(f"[ERROR]: {error}")
   sys.exit(1)
