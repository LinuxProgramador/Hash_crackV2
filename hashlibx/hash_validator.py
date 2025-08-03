#!/usr/bin/env python3

import time
import sys
import binascii
from gmssl import sm3,func
from whirlpool import new as wpl
from argon2 import PasswordHasher
from Crypto.Hash import RIPEMD160,MD4
from hashlib import (
        md5,sha1, sha224, sha384, sha256, sha512,
        sha3_256, sha3_224, sha3_384, sha3_512,
        blake2s, blake2b, shake_128, shake_256,
        pbkdf2_hmac, algorithms_available, new

        )
from hashlib import scrypt as scrypt_hashlib
from passlib.hash import (
       sha256_crypt, sha512_crypt, md5_crypt,
       apr_md5_crypt, msdcc2, phpass, scrypt

       )
from passlib.hash import pbkdf2_sha256 as pbkf_sha2_passlib
from bcrypt import checkpw
from base64 import b64encode, b64decode
from argon2.exceptions import VerifyMismatchError


HASH_ALGORITHMS_INFO = {
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


def validate_word(word, data,  target_hash, hash_type, encoder, wpa_psk, ssid, user, wait_time):
  try:

    generated_hash = ''

    if hash_type == "mysql5.x":
        generated_hash = "*" + sha1(sha1(data).digest()).hexdigest().upper()

    elif hash_type == "whirlpool":
        generated_hash = wpl(data).hexdigest()

    elif hash_type == "sha256sum":
        target_hash = target_hash.replace('  -','')
        generated_hash = sha256((word + "\n").encode(encoder)).hexdigest()

    elif hash_type == "sha512sum":
        target_hash = target_hash.replace('  -','')
        generated_hash = sha512((word + "\n").encode(encoder)).hexdigest()

    elif hash_type == "sm3":
        if 'sm3' in algorithms_available:
            h = new('sm3')
            h.update(data)
            generated_hash = h.hexdigest()

        else:
            generated_hash = sm3.sm3_hash(func.bytes_to_list(data))

    elif hash_type == "ntlm":
        h = MD4.new()
        h.update(word.encode('utf-16le'))
        generated_hash = h.hexdigest()

    elif hash_type == "sha512-256":
        generated_hash = new("sha512_256", data).hexdigest()

    elif hash_type == "ssha":
        b64_data = target_hash[6:]
        decoded = b64decode(b64_data)
        digest = decoded[:20]
        salt = decoded[20:]
        h = sha1(data)
        h.update(salt)
        return h.digest().lower() == digest.lower()

    elif hash_type == "shake-256":
        generated_hash = shake_256(data).hexdigest(len(target_hash) // 2)

    elif hash_type == "shake-128":
        s = shake_128()
        s.update(data)
        generated_hash = s.digest(len(bytes.fromhex(target_hash))).hex()

    elif hash_type == "ripemd-160":
        if 'ripemd160' in algorithms_available:
            generated_hash =  new("ripemd160", data).hexdigest()

        else:
             h = RIPEMD160.new()
             h.update(data)
             generated_hash = h.hexdigest()

    elif hash_type == "bcrypt":
        if wait_time == "y":
           time.sleep(0.20)

        return checkpw(data, target_hash.encode(encoder))

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
            derived_key = pbkdf2_hmac('sha1', data, ssid.encode(encoder), 4096, 32)
            return derived_key.hex().lower() == target_hash.lower()

    elif hash_type == "pbkdf2-sha256":
      try:

        algo, iterations, salt_b64, key_b64 = target_hash.split('$')[1:]
        dklen = len(b64decode(key_b64))
        salt = b64decode(salt_b64)
        key = pbkdf2_hmac('sha256', data, salt, int(iterations), dklen)
        generated_hash = f"pbkdf2-sha256${iterations}${b64encode(salt).decode(encoder)}${b64encode(key).decode(encoder)}"

      except binascii.Error:
        return pbkf_sha2_passlib.verify(word, target_hash)


    elif hash_type in HASH_ALGORITHMS_INFO:
        if hash_type == 'sha512crypt':
            time.sleep(0.02)

        if hash_type in ['sha256crypt', 'sha512crypt', 'md5crypt', 'apr1', 'phpass']:
            return HASH_ALGORITHMS_INFO[hash_type].verify(word, target_hash)
        generated_hash = HASH_ALGORITHMS_INFO[hash_type](data).hexdigest()


    elif hash_type == "argon2id":
         if wait_time == "y":
            time.sleep(0.20)

         ph = PasswordHasher()
         try:
             ph.verify(target_hash, word)
             return True

         except VerifyMismatchError:
              return False


    elif hash_type == "scrypt":
        try:

          if wait_time == "y":
            time.sleep(0.20)

          x = target_hash.split('$')
          params = x[2].split(',')
          salt = b64decode(x[3])
          n = int(params[0].split('=')[1])
          r = int(params[1].split('=')[1])
          p = int(params[2].split('=')[1])
          dklen = len(b64decode(x[4]))
          derived_key = scrypt_hashlib(data, salt=salt, n=n, r=r, p=p, dklen=dklen)
          salt_b64 = b64encode(salt).decode(encoder)
          key_b64 = b64encode(derived_key).decode(encoder)
          hash_str = f"$scrypt$n={n},r={r},p={p}${salt_b64}${key_b64}"
          generated_hash = hash_str

        except binascii.Error:
           return scrypt.verify(word, target_hash)


    if generated_hash.lower() == target_hash.lower():
       return True

    return False

  except Exception as error:
    print(f"[ERROR]: {error}")
    sys.exit(1)
