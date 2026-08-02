#!/usr/bin/env python3

"""
Tool to crack hashes by brute force on Ubuntu and Termux.
Supports multiprocessing, auto-detect of hash types, custom hash definition,
engineered block sizing, and encoding options.
"""

__version__ = "1.0.0"
__license__ = "GPLv3"
__status__ = "Stable"
__author__ = "JP Rojas"

import sys
import time
import os
import argparse
import signal
from base64 import b64decode
from pathlib import Path
from multiprocessing import Pool, cpu_count
from json import loads
from hashlibx.help_menu import show_help
from hashlibx.combine_words import generate_combinations
from hashlibx.password_rules_engine import rules_parameters
from hashlibx.cisco_type7_decryptor import decrypt_cisco_type7
from hashlibx.aux_output import auxiliary_crack
from hashlibx.hash_type_detector import detect_and_crack_hash
from hashlibx.hash_validator import validate_word

MENU_MODULES = {
    '1': 'zcrack.py',
    '2': 'RARNinja.py',
    '3': 'ssh_service_attack.py',
    '4': None,
    '5': None,
    '6': 'Pdf-Crack.py',
    '7': 'Zip-Crack.py',
    '8': 'Rar-Crack.py',
    '9': '7z-Crack.py'
}

HOME = Path.home()
DICT_PATH = os.path.join(HOME, 'Hash_crackV2/wordlist.txt')
start = time.time()

def show_elapsed_time(signum, frame):
    elapsed = time.time() - start
    print(f"\n[-]Time elapsed: {elapsed:.2f} seconds")

def get_encoder(choice):
    return "latin-1" if choice == "1" else "utf-8"

def call_modules(module_chosen, encoder):
    module = MENU_MODULES.get(module_chosen)
    if module_chosen in ['1', '2'] and module:
        time.sleep(1)
        os.system("clear")
        os.system(f"python3 {HOME}/Hash_crackV2/thirdparty_cracktools/{module}")
    elif module_chosen == '3' and module:
        if not os.path.exists("/data/data/com.termux/files/"):
            time.sleep(1)
            os.system("clear")
            os.system("sudo systemctl start tor")
            time.sleep(1)
            os.system(f"proxychains4 python3 {HOME}/Hash_crackV2/config_bundle/{module}")
            os.system("sudo systemctl stop tor")
        else:
            print("Not supported on Termux, Only Ubuntu!")
    elif module_chosen == '4':
        generate_combinations(encoder)
    elif module_chosen == '5':
        if not os.path.exists("/data/data/com.termux/files/"):
            import webbrowser
            try:
               success = webbrowser.open("https://crackstation.net/")
               if not success:
                  print("Could not open the browser.")
            except webbrowser.Error as e:
                  print(f"Error while trying to open the browser: {e}")
        else:
            os.system("am start -a android.intent.action.VIEW -d https://crackstation.net/")
    elif module_chosen == '6' and module:
        if not os.path.exists("/data/data/com.termux/files/"):
            time.sleep(1)
            os.system(f"python3 {HOME}/Hash_crackV2/config_bundle/{module}")
        else:
            time.sleep(1)
            os.system(f"python3 {HOME}/Hash_crackV2/config_bundle/Pdf_Crack_termux.py")
    elif module_chosen in ['7', '8', '9'] and module:
        time.sleep(1)   
        os.system(f"python3 {HOME}/Hash_crackV2/config_bundle/{module}")


def init_worker():
   signal.signal(signal.SIGINT, signal.SIG_IGN)
   signal.signal(signal.SIGTSTP, signal.SIG_IGN)


def hash_cracking_worker(args):
    password_list, ssid, wpa_psk, target_hash, user, rules, encoder, hash_type, wait_time = args
    for word in password_list:
        mutated_words = rules_parameters(word, rules, [])
        for candidate in mutated_words:
            data = candidate.encode(encoder)

            hash_result = validate_word(candidate, data, target_hash, hash_type, encoder, wpa_psk, ssid, user, wait_time)
            if hash_result is None:
                continue
            if type(hash_result) is list:
                return hash_result
            if isinstance(hash_result, bool) and hash_result:
                return candidate


def dict_crack(target_hash, hash_type, wait_time, ssid, wpa_psk, encoder, user, rules, process_count):
    read_block_size = 8 * 1024 * 1024
    result = None
    with Pool(processes=process_count, initializer=init_worker) as pool:
      with open(DICT_PATH, 'r', encoding=encoder, errors='ignore') as keywords_read:
        last_line = ""
        while True:
            chunk = keywords_read.read(read_block_size)
            if not chunk:
                break

            if wait_time == "y" and hash_type not in ["argon2id", "bcrypt", "scrypt" ,"yescrypt"]:
                time.sleep(10)

            buffer = last_line + chunk
            lines = buffer.splitlines()

            if chunk and not chunk.endswith('\n') and lines:
                last_line = lines.pop()
            else:
                last_line = ""

            total_words = len(lines)
            if total_words == 0:
                continue

            chunk_size = (total_words + process_count - 1) // process_count
            chunks = [lines[i:i + chunk_size] for i in range(0, total_words, chunk_size)]

            actual_processes = min(process_count, len(chunks))

            tasks = [
                   [
             chunk,
             ssid,
             wpa_psk,
             target_hash,
             user,
             rules,
             encoder,
             hash_type,
             wait_time
             ]
               for chunk in chunks[:actual_processes]
             ]

            for result in pool.imap_unordered(hash_cracking_worker, tasks):
              if result and not type(result) is list: 
                 candidate = result
                 auxiliary_crack(candidate, wpa_psk, ssid)
                 pool.terminate()
                 return
              elif result and type(result) is list :
                  pool.terminate()
                  return
                  
        if last_line:
          task = [
             [last_line],
             ssid,
             wpa_psk,
             target_hash,
             user,
             rules,
             encoder,
             hash_type,
             wait_time
             ]
          result = hash_cracking_worker(task)
          if result and not type(result) is list:
              candidate = result
              auxiliary_crack(candidate, wpa_psk, ssid)
              return
          elif result and type(result) is list:
              return

    print("[FINISH]>> PASSWORD NOT FOUND")

def local_db(hash_type, target_hash, encoder):
    wpa_psk = ssid = None
    if hash_type in ["ntlm", "ripemd-160", "sm3" ,"mysql5.x" ]:
        db_path = os.path.join(HOME, 'Hash_crackV2/config_bundle/db.json')
        with open(db_path, 'r', encoding=encoder, errors='ignore') as db_read:
            dic_db = loads(db_read.read())
            for db_hash, value in dic_db.items():
                if target_hash.lower() == db_hash.lower():
                    auxiliary_crack(value, wpa_psk, ssid)
                    sys.exit(0)

def main(hash_type, target_hash, wait_time, rules, choice, ct7, cpu_num, external_imports, module_chosen, base64_decode ):
    try:
        if base64_decode:
          target_hash = b64decode(target_hash).hex()
        hash_type = hash_type.strip().lower() if hash_type else hash_type
        target_hash = target_hash.strip() if target_hash else target_hash
        module_chosen = module_chosen.strip() if module_chosen else module_chosen

        print(show_help())
        encoder = get_encoder(choice)

        if ct7:
            if not target_hash:
                print("[-] You must provide a Cisco type 7 key with -i 'KEY'")
                sys.exit(1)
            decrypt_cisco_type7(target_hash)
        elif external_imports:
            if not module_chosen or not encoder:
                print("[-] Missing required options: --module-chosen and/or --encoder")
                sys.exit(1)
            call_modules(module_chosen, encoder)
        else:
            hash_type, ssid, wpa_psk, user, process_count, target_hash = detect_and_crack_hash(target_hash, hash_type, cpu_num, encoder)
            signal.signal(signal.SIGTSTP,show_elapsed_time)
            local_db(hash_type, target_hash, encoder)
            if hash_type == "yescrypt" and sys.platform == "android":
              print("Not supported on Termux, Only Ubuntu!")
              sys.exit(0)

            dict_crack(target_hash, hash_type, wait_time, ssid, wpa_psk, encoder, user, rules, process_count)

        sys.exit(0)

    except KeyboardInterrupt:
        print()
        sys.exit(1)

    except Exception as error:
        print(f"[ERROR]: {error}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=("""
Cracks hashes on Linux and Termux with multiprocessing,
automatic detection, and custom rules.
Supports bcrypt, sha256crypt, wpa, scrypt, argon2id, and more.
        """),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '-i', '--target-hash',
        dest="target_hash", metavar="'HASH'/'CISCO7_KEY'",
        type=str, default=None,
        help="Target hash or Cisco type 7 key in single quotes (e.g. 'HASH')"
    )
    parser.add_argument(
        '-t', '--hash-type',
        metavar="HASH-TYPE", dest='hash_type',
        default=None, type=str,
        help="""
Use the -t option to specify the hash type manually.
[NOTE] This is required for 'shake-128' and 'shake-256'
"""
    )
    parser.add_argument(
        '-e', '--encoder',
        metavar="ENCODER", dest="choice",
        type=str, default='2',
        help="""
Select encoding:
  1) latin-1
  2) utf-8
        """
    )
    parser.add_argument(
        '-w', '--wait',
        metavar="WAIT-TIME", dest='wait_time',
        type=str, default='n',
        help='Prevent CPU overheating: options (y/n)'
    )
    parser.add_argument(
        '-ct7', '--cisco-type7',
        dest="cisco_type_7",
        action="store_true",
        help="\nAttempt to decrypt Cisco Type 7 encrypted passwords"
    )
    parser.add_argument(
        '-r', '--rules',
        dest='rules',
        nargs='*',
        default=[],
        help="""
Apply mutation rules to each word in the dictionary. Available rules:

  1) Add numbers
  2) Add uppercase letters
  3) Add lowercase letters
  4) Add symbols (e.g. @, #, $, %%, etc.)
  5) Capitalize only the first letter
  6) Substitute characters (e.g. S -> $, A -> @)
  7) Combine capitalization, numbers, and symbols
  8) Reverse the word (e.g., hola → aloh)
  9) Duplicate the word (e.g., hola → holahola)
 10) Remove vowels (e.g., hola → hl, secure → scr)
 11) Prepend numbers (e.g., password → 123password, hola → 456hola)
 00) Prepend symbols (e.g., password → @password, hola → #hola)
 HBA) Brute force numbers (1 to 4 digits) at the end 
 appends all possible number combinations from 1 to 4 digits to the end of the word.
 (e.g., password1, password2, password9999)


[INFO] Valid input: single or double-digit combinations, e.g., 1, 12
[INFO] Unsupported combinations detected (14, 23, 35, 25)
[NOTE] Rules '7', '8', '9', '10', '11', 'HBA' and '00' are not valid in combination and are applied individually
        """
    )
    parser.add_argument(
        "-c", "--cpu-num",
        dest="cpu_num",
        metavar="CPU_CORES",
        type=int,
        default=cpu_count(),
        help="Number of CPU cores to use (default: all). For 'argon2id' and 'scrypt' 'yescrypt', only 1 core is used"
    )
    parser.add_argument(
        '-m', '--modules-external-imports',
        dest="external_imports",
        action="store_true",
        help="Trigger loading of external or third-party modules required for advanced operations"
    )
    parser.add_argument(
        '-mc', '--module-chosen',
        metavar="MODULE", dest="module_chosen",
        type=str, default=None,
        help="""
Select the cracking module to use:
   1) ZCrack.py    - ZIP file password cracker
   2) RARNinja.py  - RAR file password cracker
   3) SSHCrack     - SSH brute-force module
   4) MIXED        - Create a new dictionary with mutated password combinations
   5) Crackstation - Search common password database for known hash values
   6) Pdf-Crack    - Decrypt PDF file passwords with a key using dictionary attacks
   7) Zip-Crack    - Module that supports the new zip format encryption method and implements multiprocessing to increase speed 
   8) Rar-Crack    - Module that supports the new rar format encryption method and implements multiprocessing to increase speed 
   9) 7z-Crack     - Decrypt 7Z compressed files with passwords using dictionary attacks
        """
    )
    
    parser.add_argument(
      '-b64', '--base64-decode',
      dest="base64_decode",
      action="store_true",
      help="Automatically decode Base64-encoded hashes before hash identification and cracking"
    )
    
    args = parser.parse_args()

    if not os.path.isfile(DICT_PATH):
        print(f"Wordlist not found: {DICT_PATH}")
        sys.exit(1)

    if args.target_hash and not 1 <= len(args.target_hash) <= 4090:
        print("[-] Invalid length: the hash must be between 1 and 4090 characters")
        sys.exit(1)

    main(
        args.hash_type,
        args.target_hash,
        args.wait_time.strip().lower(),
        args.rules,
        args.choice.strip(),
        args.cisco_type_7,
        args.cpu_num,
        args.external_imports,
        args.module_chosen,
        args.base64_decode
    )
