#!/usr/bin/env python3

import sys, signal
import time
import binascii
from string import ascii_lowercase, ascii_uppercase, digits
from multiprocessing import Pool
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
from passlib.hash import pbkdf2_sha1 as pbkf_sha1_passlib
from passlib.hash import pbkdf2_sha512 as pbkf_sha5_passlib
from passlib.context import CryptContext
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
| pbkdf2-sha1| pbkdf2-sha512|
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
        try:       
          if target_hash.startswith("$DCC2$"):
             temp = target_hash.split('#')
             return msdcc2.verify(word, temp[2], user=temp[1])
          else:
             return msdcc2.verify(word, target_hash, user=user)
    
        except ValueError as value_error:
             print(f"[!] Error verifying DCC2 hash: {value_error}. Please ensure the hash format and username are correct")
             return ["_error_"]

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
        return f"$pbkdf2-sha256${iterations}${b64encode(salt).decode()}${b64encode(key).decode()}"

      except binascii.Error:
        return pbkf_sha2_passlib.verify(word, target_hash)

    elif hash_type == "pbkdf2-sha1":
        try:

          algo, iterations, salt_b64, key_b64 = target_hash.split('$')[1:]
          dklen = len(b64decode(key_b64))
          salt = b64decode(salt_b64)
          key = pbkdf2_hmac('sha1', data, salt, int(iterations), dklen)
          return f"$pbkdf2${iterations}${b64encode(salt).decode()}${b64encode(key).decode()}"

        except binascii.Error:
          return pbkf_sha1_passlib.verify(word, target_hash)

    elif hash_type == "pbkdf2-sha512":
         try:

           algo, iterations, salt_b64, key_b64 = target_hash.split('$')[1:]
           dklen = len(b64decode(key_b64))
           salt = b64decode(salt_b64)
           key = pbkdf2_hmac('sha512', data, salt, int(iterations), dklen)
           return f"$pbkdf2-sha512${iterations}${b64encode(salt).decode()}${b64encode(key).decode()}"

         except binascii.Error:
           return pbkf_sha5_passlib.verify(word, target_hash)

    elif hash_type in SUPPORTED_HASHES:
        if hash_type in ['sha256crypt', 'sha512crypt', 'md5crypt', 'apr1', 'phpass']:
            if hash_type in ['sha256crypt', 'sha512crypt', 'md5crypt', 'apr1']:
              try:
                hash_type_sche = hash_type.replace("sha512crypt","sha512_crypt")
                hash_type_sche = hash_type_sche.replace("sha256crypt","sha256_crypt")
                hash_type_sche = hash_type_sche.replace("md5crypt","md5_crypt")
                hash_type_sche = hash_type_sche.replace("apr1","apr_md5_crypt")
                context = CryptContext(schemes=[hash_type_sche])
                return context.verify(word, target_hash)

              except Exception as e:
                 return SUPPORTED_HASHES[hash_type].verify(word, target_hash)
                  
            return SUPPORTED_HASHES[hash_type].verify(word, target_hash)
        return SUPPORTED_HASHES[hash_type](data).hexdigest()

    return None


def init_worker():
   signal.signal(signal.SIGINT, signal.SIG_IGN)
   signal.signal(signal.SIGTSTP, signal.SIG_IGN)


def hash_worker(args):
    config, target_hash, hash_type, wait_time, ssid, user = args    
    for word in word_generator(config):

            if wait_time == "y":
                time.sleep(0.20)

            try:
                result = validate_word(
                    word,
                    target_hash,
                    hash_type,
                    ssid,
                    user
                )

                if isinstance(result, list):
                      return result
                    
                if hash_type == "ssha":
                    if result[0].lower() == result[1].lower():
                        return word

                elif result is True or (
                    isinstance(result, str)
                    and result.lower() == target_hash.lower()
                ):
                    return word

            except Exception as error_:
                print(f"[ERROR]: {error_}")
                return ["_error_"]

    return None




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
     result = ssid = user = None

     display_supported_hashes()

     target_hash = input("Enter the target hash: ").strip().replace('  -','')
     hash_type = input("Enter the hash type: ").strip().lower()
     wait_time = input("Prevent CPU overheating (y/n): ").strip().lower()
     base64_decode = input("Decode Base64-encoded hash? (y/n): ").strip().lower()
     if base64_decode == "y":
         decoded = b64decode(target_hash, validate=True)

         try:
           decoded_text = decoded.decode("ascii")
         except UnicodeDecodeError:
           decoded_text = None

         if decoded_text and (
            decoded_text.startswith((
             "$2a$", "$2b$", "$2y$",
             "$1$", "$5$", "$6$",
             "$apr1",
             "{SSHA}",
             "$P$",
             "$pbkdf2-sha256",
             "$pbkdf2-sha512",
             "$pbkdf2",
             "$DCC2$",
             "*"
           ))) or ":" in decoded_text:

           target_hash = decoded_text
         else:
           target_hash = decoded.hex()
         
     if not target_hash or hash_type not in SUPPORTED_HASHES and hash_type not in [
        "pbkdf2-sha256", "ripemd-160", "shake-128", "shake-256", "md5",
        "dcc2", "mysql5.x", "whirlpool", "sha256sum", "sha512sum",
        "sm3", "ntlm", "sha512-256", "ssha", "bcrypt", "wpa", "pbkdf2-sha1", "pbkdf2-sha512"
     ]:
        print("Invalid input.")
        sys.exit(1)

     wpa_psk = True if hash_type == "wpa" else None
     ssid = input("Enter SSID: ") if hash_type == "wpa" else ssid

     if hash_type == "pbkdf2-sha1":
         target_hash = target_hash.replace("pbkdf2-sha1","pbkdf2")

       
     elif hash_type == "dcc2" and not target_hash.startswith("$DCC2$"):
         user = input("Enter username: ")


     print("\nEnter 4 configurations for charset and length:")
     config_list = get_user_config()

     with Pool(processes=4, initializer=init_worker) as pool:

       tasks = [
        (cfg, target_hash, hash_type, wait_time, ssid, user)
        for cfg in config_list
       ]

       for result in pool.imap_unordered(hash_worker, tasks):

        if result and not isinstance(result, list):
            candidate = result

            print("\n" + "=" * 50)

            if wpa_psk:
                print("[ SSID ]".center(50))
                print("=" * 50)
                print(f">>> ssid: {ssid}".center(50))

            print("=" * 50)
            print("[ PASSWORD FOUND ]".center(50))
            print("=" * 50)
            print(f">>> Recovered Password: {candidate}".center(50))
            print("=" * 50 + "\n")

            pool.terminate()
            sys.exit(0)
        elif result and isinstance(result, list):
             pool.terminate()
             sys.exit(0)
            
     print("[FINISH]>> PASSWORD NOT FOUND")

    
   except KeyboardInterrupt:
        print()
        sys.exit(0)

   except Exception as error:
        print(f"[ERROR]: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
