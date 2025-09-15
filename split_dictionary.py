#!/usr/bin/env python3

import os
from pathlib import Path
from string import ascii_lowercase
import shutil

HOME = Path.home()
DICT_PATH = os.path.join(HOME, 'Hash_crackV2/wordlist.txt')
DIVIDED_DIR = "divided_dictionaries"

def split_dictionary(size):
    os.makedirs(DIVIDED_DIR, exist_ok=True)
    os.system(f"split -C {size}M --additional-suffix=.txt {DICT_PATH} {DIVIDED_DIR}/dic_")

def use_dictionary():
    dic_list = sorted(os.listdir(DIVIDED_DIR))
    if not dic_list:
        print("No split dictionaries found")
        return

    for dic in dic_list:
        for letter in ascii_lowercase:
            if dic.endswith(letter):
                src = os.path.join(DIVIDED_DIR, dic)
                os.rename(src, DICT_PATH)
                print(f"✓ Using {dic} as {DICT_PATH}")
                return

def delete_dictionaries():
    if not os.path.exists(DIVIDED_DIR):
        print("No divided directory found")
        return

    confirm = input("Are you sure you want to delete all divided dictionaries? (y/n): ").strip().lower()
    if confirm == "y":
        shutil.rmtree(DIVIDED_DIR)
        print("All divided dictionaries deleted")
    else:
        print("Deletion canceled")

def main():
    print("=== Dictionary Splitter ===")
    print("=== This is mainly useful for optimized and intelligent cracking ===")
    action = input("Do you want to split (s), use (u), or delete (d) dictionaries? ").strip().lower()

    if action == "s":
        size = input("Enter chunk size in MB: ").strip()
        if size.isdigit():
            split_dictionary(size)
            print("✓ Dictionary successfully split")
        else:
            print("Invalid size")
    elif action == "u":
        use_dictionary()
    elif action == "d":
        delete_dictionaries()
    else:
        print("Invalid option")

if __name__ == "__main__":
    main()
