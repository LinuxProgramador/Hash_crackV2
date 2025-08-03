#!/usr/bin/env python3

import sys
import base64
from hashlibx.cpu_selector import get_cpu_allocation
from hashlibx.hash_prompt_info import cracking_prompt

hash_lengths = {
    'md5': 32,
    'sha1': 40,
    'sha224': 56,
    'sha256': 64,
    'sha384': 96,
    'sha512': 128
}


hash_list = [
    "md5", "sha1", "blake2s", "blake2b", "ripemd-160", "bcrypt",
    "sha256crypt", "sha512crypt", "shake-128", "shake-256", "wpa", "ntlm",
    "mysql5.x", "md5crypt", "apr1", "dcc2", "ssha", "sm3",
    "sha512-256", "phpass", "whirlpool", "sha512sum", "sha256sum",
    "sha3-224", "sha3-256", "sha3-384", "sha3-512", "sha256",
    "sha224", "sha384", "sha512", "pbkdf2-sha256", "argon2id", "scrypt"
]


hash_list_show = [
    "\nmd5", "sha1", "\nblake2s", "blake2b", "\nripemd-160", "bcrypt",
    "\nsha256crypt", "sha512crypt", "\nshake-128", "shake-256", "\nwpa", "ntlm",
    "\nmysql5.x", "md5crypt", "\napr1", "dcc2", "\nssha", "sm3",
    "\nsha512-256", "phpass", "\nwhirlpool", "sha512sum", "sha256sum",
    "\nsha3-224", "sha3-256", "\nsha3-384", "sha3-512", "sha256",
    "\nsha224", "sha384", "\nsha512", "pbkdf2-sha256", "\nargon2id", "scrypt"
]



def ask_user_for_type(prompt, options):
    print(prompt)

    for k, v in options.items():
        print(f"{k}) {v}")

    selection = input(">> ").strip()
    return options.get(selection, None)


def match_length_hashes(target_hash):
    length = len(target_hash)

    if length == hash_lengths['md5']:
        return ask_user_for_type("Select hash type:", {"1": "md5", "2": "ntlm"})

    if length == hash_lengths['sha1']:
        return ask_user_for_type("Select hash type:", {"1": "sha1", "2": "ripemd-160"})

    if length == hash_lengths['sha224']:
        return ask_user_for_type("Select hash type:", {"1": "sha224", "2": "sha3-224"})

    if length == hash_lengths['sha384']:
        return ask_user_for_type("Select hash type:", {"1": "sha384", "2": "sha3-384"})

    if length == hash_lengths['sha256'] or (target_hash.endswith('-') and length == 67):
        return ask_user_for_type("Select hash type:", {
            "1": "sha256",
            "2": "sha3-256",
            "3": "blake2s",
            "4": "sm3",
            "5": "sha512-256",
            "6": "sha256sum"
        })

    if length == hash_lengths['sha512'] or (target_hash.endswith('-') and length == 131):
        return ask_user_for_type("Select hash type:", {
            "1": "sha512",
            "2": "sha3-512",
            "3": "blake2b",
            "4": "whirlpool",
            "5": "sha512sum"
        })

    return None


def auto_detect_type(target_hash):
    if len(target_hash) == 60 and any(v in target_hash[:5] for v in ["2a$", "2b$", "2y$"]):
        return "bcrypt", None, None, None, target_hash

    if target_hash.startswith("$5$"):
        return "sha256crypt", None, None, None, target_hash

    if target_hash.startswith("$6$"):
        return "sha512crypt", None, None, None, target_hash

    if target_hash.startswith("$1$"):
        return "md5crypt", None, None, None, target_hash

    if target_hash.startswith("$apr1"):
        return "apr1", None, None, None, target_hash

    if target_hash.startswith("{SSHA}"):
        return "ssha", None, None, None, target_hash

    if target_hash.count(':') == 1:
        left, right = target_hash.split(':')

        if len(right) == 64:
            target_hash = right
            ssid = left
            wpa_psk = True
            return "wpa", None, ssid, wpa_psk, target_hash

        else:
            target_hash = right
            user = left
            return "dcc2", user, None, None, target_hash

    if target_hash.startswith("$dcc2$"):
            dcc2_split_hash = target_hash.split('$')
            salt_bytes = base64.b64decode(dcc2_split_hash[3])
            try:
               user = salt_bytes.decode("utf-16le")

            except UnicodeDecodeError:
               user = salt_bytes.decode("utf-8")

            return "dcc2", user, None, None, target_hash

    if target_hash.startswith("*"):
        return "mysql5.x", None, None, None, target_hash

    if target_hash.startswith("$P$"):
        return "phpass", None, None, None, target_hash

    if target_hash.startswith("$argon2id$"):
        return "argon2id", None, None, None, target_hash

    if target_hash.startswith("$scrypt$"):
        return "scrypt", None, None, None, target_hash

    if target_hash.startswith("$pbkdf2-sha256"):
        return "pbkdf2-sha256", None, None, None, target_hash

    return None, None, None, None, target_hash


def show_info_cracker(hash_type, cpu_num, encoder):
    process_count = get_cpu_allocation(hash_type, cpu_num)
    print(cracking_prompt(encoder, hash_type, process_count))
    return process_count


def detect_and_crack_hash(target_hash, hash_type, cpu_num, encoder):
  try:

    ssid = wpa_psk = user  = None
    target_hash_mod = target_hash

    if not target_hash:
        print("[ERROR]: No hash input provided.")
        sys.exit(1)

    if not hash_type:
        hash_type = match_length_hashes(target_hash)
        if not hash_type:
            hash_type, user, ssid, wpa_psk, target_hash_mod = auto_detect_type(target_hash)

    if not hash_type:
        print("[ERROR]: Hash type could not be detected.")
        sys.exit(1)

    if hash_type not in hash_list:
        print(f"[!] Unsupported hash type: '{hash_type}'. Please choose a valid type from: {', '.join(hash_list_show[0:])}")
        sys.exit(1)

    process_count = show_info_cracker(hash_type, cpu_num, encoder)

    return hash_type, ssid, wpa_psk, user, process_count, target_hash_mod

  except Exception as error:
    print(f"[ERROR]: {error}")
    sys.exit(1)
