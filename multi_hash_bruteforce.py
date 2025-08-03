#!/usr/bin/env python3

import sys
import time
import binascii
from string import ascii_lowercase, ascii_uppercase, digits
from multiprocessing import Process, Queue, Event
from itertools import product
from base64 import b64encode, b64decode
from hashlib import (
    md5, sha1, sha224, sha256, sha384, sha512,
    sha3_224, sha3_256, sha3_384, sha3_512,
    blake2s, blake2b, shake_128, shake_256,
    pbkdf2_hmac, algorithms_available, new
)
from Crypto.Hash import RIPEMD160, MD4
from passlib.hash import (
    sha256_crypt, sha512_crypt, md5_crypt,
    apr_md5_crypt, msdcc2, phpass
)
from passlib.hash import pbkdf2_sha256 as pbkf_sha2_passlib
from bcrypt import checkpw
from gmssl import sm3, func
from whirlpool import new as wpl


SUPPORTED_HASHES = {
    'md5': md5,
    'sha1': sha1,
    'sha224': sha224,
    'sha256': sha256,
    'sha384': sha384,
    'sha512': sha512,
    'sha3-224': sha3_224,
    'sha3-256': sha3_256,
    'sha3-384': sha3_384,
    'sha3-512': sha3_512,
    'blake2b': blake2b,
    'blake2s': blake2s,
    'sha256crypt': sha256_crypt,
    'sha512crypt': sha512_crypt,
    'md5crypt': md5_crypt,
    'apr1': apr_md5_crypt,
    'phpass': phpass
}


def display_supported_hashes():
    print('''
 ----------------------------------
| Support table for hash selection |
 ----------------------------------
| md5        | sha1         |
| blake2s    | blake2b      |
| ripemd-160 | bcrypt       |
| sha256crypt| sha512crypt  |
| shake-128  | shake-256    |
| wpa        | ntlm         |
| mysql5.x   | md5crypt     |
| apr1       | dcc2         |
| ssha       | sm3          |
| sha512-256 | phpass       |
| whirlpool  | sha512sum    |
| sha256sum  | sha3-224     |
| sha3-384   | sha3-256     |
| sha3-512   | sha256       |
| sha224     | sha384       |
| sha512     | pbkdf2-sha256|
 ---------------------------
''')


def generate_word_blocks(charset, min_len, max_len, block_limit=512 * 1024):
    buffer, buffer_size = [], 0
    for r in range(min_len, max_len + 1):
        for combo in product(charset, repeat=r):
            word = ''.join(combo)
            encoded = word.encode()
            size = len(encoded)

            if buffer_size + size > block_limit:
                yield buffer
                buffer, buffer_size = [], 0

            buffer.append(word)
            buffer_size += size
    if buffer:
        yield buffer


def word_generator(config):
    charset, min_len, max_len = config
    for block in generate_word_blocks(charset, min_len, max_len):
        for word in block:
            yield word


def validate_word(word, target_hash, hash_type, ssid, user):
    data = word.encode()

    if hash_type == "mysql5.x":
        return "*" + sha1(sha1(data).digest()).hexdigest().upper()

    elif hash_type == "whirlpool":
        return wpl(data).hexdigest()

    elif hash_type == "sha256sum":
        return sha256((word + "\n").encode()).hexdigest()

    elif hash_type == "sha512sum":
        return sha512((word + "\n").encode()).hexdigest()

    elif hash_type == "sm3":
        if 'sm3' in algorithms_available:
            h = new('sm3')
            h.update(data)
            return h.hexdigest()
        return sm3.sm3_hash(func.bytes_to_list(data))

    elif hash_type == "ntlm":
        h = MD4.new()
        h.update(word.encode('utf-16le'))
        return h.hexdigest()

    elif hash_type == "sha512-256":
        return new("sha512_256", data).hexdigest()

    elif hash_type == "ssha":
        b64_data = target_hash[6:]
        decoded = b64decode(b64_data)
        digest = decoded[:20]
        salt = decoded[20:]
        h = sha1(data)
        h.update(salt)
        return h.digest(), digest

    elif hash_type == "shake-256":
        return shake_256(data).hexdigest(len(target_hash) // 2)

    elif hash_type == "shake-128":
        s = shake_128()
        s.update(data)
        return s.digest(len(bytes.fromhex(target_hash))).hex()

    elif hash_type == "ripemd-160":
        if 'ripemd160' in algorithms_available:
            return new("ripemd160", data).hexdigest()
        h = RIPEMD160.new()
        h.update(data)
        return h.hexdigest()

    elif hash_type == "bcrypt":
        return checkpw(data, target_hash.encode())

    elif hash_type == "dcc2":
        time.sleep(0.02)
        try:
           from passlib.hash import dcc2
           return dcc2.verify((user, word), target_hash)

        except ImportError:
          try:
             return msdcc2.verify(word, target_hash, user=user)

          except ValueError as value_error:
             print(f"[!] Error verifying DCC2 hash: {value_error}. Please ensure the hash format and username are correct")
             sys.exit(1)

    elif hash_type == "wpa":
        if 8 <= len(word) <= 63:
            derived_key = pbkdf2_hmac('sha1', data, ssid.encode(), 4096, 32)
            return derived_key.hex().lower() == target_hash.lower()

    elif hash_type == "pbkdf2-sha256":
      try:

        algo, iterations, salt_b64, key_b64 = target_hash.split('$')[1:]
        dklen = len(b64decode(key_b64))
        salt = b64decode(salt_b64)
        key = pbkdf2_hmac('sha256', data, salt, int(iterations), dklen)
        return f"pbkdf2-sha256${iterations}${b64encode(salt).decode()}${b64encode(key).decode()}"

      except binascii.Error:
        return pbkf_sha2_passlib.verify(word, target_hash)


    elif hash_type in SUPPORTED_HASHES:
        if hash_type == 'sha512crypt':
            time.sleep(0.02)

        if hash_type in ['sha256crypt', 'sha512crypt', 'md5crypt', 'apr1', 'phpass']:
            return SUPPORTED_HASHES[hash_type].verify(word, target_hash)
        return SUPPORTED_HASHES[hash_type](data).hexdigest()

    return None


def hash_worker(config, target_hash, hash_type, stop_event, result_queue, wait_time, ssid, user):
  try:
    for word in word_generator(config):
        if stop_event.is_set():
            break
        if wait_time == "y":
            time.sleep(0.20)

        try:
            result = validate_word(word.strip(), target_hash, hash_type, ssid, user)

            # Direct match or special cases
            if hash_type == "ssha":
                if result[0].lower() == result[1].lower():
                    stop_event.set()
                    result_queue.put(word)
                    break
            elif result is True or (isinstance(result, str) and result.lower() == target_hash.lower()):
                stop_event.set()
                result_queue.put(word)
                break

        except Exception:
            continue

  except KeyboardInterrupt:
        return


def get_user_config():
    char_sets = {
        "1": digits,
        "2": ascii_uppercase,
        "3": ascii_lowercase,
        "4": "/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°\"\\"
    }
    config_list = []

    print("[1]: Use numbers\n[2]: Use uppercase letters\n[3]: Use lowercase letters\n[4]: Use symbols")
    for num in range(1, 5):
        print(f"\nConfiguration #{num}")
        selection = input("Option(s): ").strip().replace(" ", "")
        charset = ''.join([char_sets[o] for o in selection if o in char_sets]) or ascii_lowercase + ascii_uppercase + digits + char_sets["4"]

        try:
            min_len = int(input("Minimum key length: "))
            max_len = int(input("Maximum key length: "))
        except ValueError:
            min_len, max_len = 8, 9

        if min_len > max_len:
            min_len, max_len = max_len, min_len

        config_list.append([charset, min_len, max_len])


    return config_list


def main():
   try:
     ssid = user = None

     display_supported_hashes()

     target_hash = input("Enter the target hash: ").strip().replace('  -','')
     hash_type = input("Enter the hash type: ").strip().lower()
     wait_time = input("Prevent CPU overheating (y/n): ").strip().lower()

     if not target_hash or hash_type not in SUPPORTED_HASHES and hash_type not in [
        "pbkdf2-sha256", "ripemd-160", "shake-128", "shake-256", "md5",
        "dcc2", "mysql5.x", "whirlpool", "sha256sum", "sha512sum",
        "sm3", "ntlm", "sha512-256", "ssha", "bcrypt", "wpa"
     ]:
        print("Invalid input.")
        sys.exit(1)

     wpa_psk = True if hash_type == "wpa" else None
     ssid = input("Enter SSID: ").strip() if hash_type == "wpa" else ssid

     if target_hash.startswith("$dcc2$") and hash_type == "dcc2":
         dcc2_split_hash = target_hash.split('$')
         salt_bytes = b64decode(dcc2_split_hash[3])
         try:
             user = salt_bytes.decode("utf-16le")
         except UnicodeDecodeError:
             user = salt_bytes.decode("utf-8")
     elif hash_type == "dcc2":
         user = input("Enter username: ").strip()


     print("\nEnter 4 configurations for charset and length:")
     config_list = get_user_config()

     stop_event = Event()
     result_queue = Queue()

     processes = [
        Process(target=hash_worker, args=(cfg, target_hash, hash_type, stop_event, result_queue, wait_time, ssid, user))
        for cfg in config_list
     ]

     try:
        for p in processes:
            p.start()

        while any(p.is_alive() for p in processes):
            if stop_event.is_set() and not result_queue.empty():
                print("\n" + "=" * 50)

                if wpa_psk:
                   print("[ SSID ]".center(50))
                   print("=" * 50)
                   print(f">>> ssid: {ssid}".center(50))

                print("=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {result_queue.get().strip()}".center(50))
                print("=" * 50 + "\n")

                break

     except KeyboardInterrupt:
        print()

     except Exception as error:
        print(f"[ERROR]: {error}")

     finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
        for p in processes:
            p.join()
        sys.exit(0)

   except KeyboardInterrupt:
        print()
        sys.exit(1)

   except Exception as error:
        print(f"[ERROR]: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
