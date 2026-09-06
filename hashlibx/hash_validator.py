#!/usr/bin/env python3

import time
import sys
import binascii
import ctypes
from gmssl import sm3, func
from whirlpool import new as wpl
from Crypto.Hash import RIPEMD160, MD4

from hashlib import (
    md5,
    sha1,
    sha224,
    sha384,
    sha256,
    sha512,
    sha3_256,
    sha3_224,
    sha3_384,
    sha3_512,
    blake2s,
    blake2b,
    shake_128,
    shake_256,
    pbkdf2_hmac,
    algorithms_available,
    new,
)

from hashlib import scrypt as scrypt_hashlib

from passlib.hash import (
    sha256_crypt,
    sha512_crypt,
    md5_crypt,
    apr_md5_crypt,
    msdcc2,
    phpass,
    scrypt,
    mssql2005,
    ldap_salted_sha512,
    ldap_salted_sha256,
)

from hashward import CryptContext as crypc_bcrypt_sha256
from passlib.hash import pbkdf2_sha256 as pbkf_sha2_passlib
from passlib.hash import pbkdf2_sha1 as pbkf_sha1_passlib
from passlib.hash import pbkdf2_sha512 as pbkf_sha5_passlib

from bcrypt import checkpw
from argon2.exceptions import VerifyMismatchError

is_linux = "yes" if sys.platform == "linux" else None

if is_linux is not None:
    from pyescrypt import WrongPassword, WrongPasswordConfiguration

if is_linux is not None:
    import pyxcrypt

ctx = crypc_bcrypt_sha256(
    schemes=["bcrypt_sha256"],
    default="bcrypt_sha256"
)

try:
    
  libcrypt = ctypes.CDLL("libcrypt.so")

  libcrypt.crypt.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p
  ]
  libcrypt.crypt.restype = ctypes.c_char_p
    
except OSError:
    libcrypt = None

target_hash_g = None

hashlib_ripemd_160 = new if "ripemd160" in algorithms_available else None
hashlib_sm3 = new if "sm3" in algorithms_available else None

lib = None
candidates_apr = (
        "libaprutil-1.so",
        "libaprutil-1.so.0",
        "aprutil-1",
    )

for name_lib in candidates_apr:
        try:
            candidate_lib = ctypes.CDLL(name_lib)
            candidate_lib.apr_md5_encode.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_size_t,
            ]
            candidate_lib.apr_md5_encode.restype = ctypes.c_int
            lib = candidate_lib
            break
        except (OSError, AttributeError):
            continue


if lib is not None:
    result = ctypes.create_string_buffer(128)
    
    

CRYPT_VALIDATOR_SET = {
        "sha256crypt",
        "sha512crypt",
        "md5crypt",
        "apr1",
        "phpass"
    }

CRYPT_VALIDATOR_SET_WITHOUT_PHPASS = {
            "sha256crypt",
            "sha512crypt",
            "md5crypt",
            "apr1"
        }

CRYPT_ALGORITHMS = {
    "sha256crypt": sha256_crypt,
    "sha512crypt": sha512_crypt,
    "md5crypt": md5_crypt,
    "apr1": apr_md5_crypt,
    "phpass": phpass,
}


HASH_ALGORITHMS_INFO = {
    "md5": md5,
    "sha1": sha1,
    "sha224": sha224,
    "sha256": sha256,
    "sha384": sha384,
    "sha512": sha512,
    "sha3-224": sha3_224,
    "sha3-256": sha3_256,
    "sha3-384": sha3_384,
    "sha3-512": sha3_512,
    "blake2b": blake2b,
    "blake2s": blake2s,
}


def convert_target_hash_bytes(target_hash):
      global target_hash_g
      target_hash_g = target_hash.encode()


def mysql5_x_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return sha1(sha1(data).digest()).digest() == target_hash
        

def whirlpool_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return wpl(data).digest() == target_hash
    


def sha256sum_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return bytes.fromhex(word) == target_hash
    

def sha512sum_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):  
     return bytes.fromhex(word) == target_hash



def sm3_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
        if hashlib_sm3 is not None:
           return hashlib_sm3("sm3", data).digest() == target_hash 
        
        return bytes.fromhex(
             sm3.sm3_hash(func.bytes_to_list(data))
             ) == target_hash
  

def ntlm_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return MD4.new(
        word.encode("utf-16le")
        ).digest() == target_hash


    


def sha512_256_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):    
    return new("sha512_256", data).digest() == target_hash
    

def ssha_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    digest = precomputed["digest"]

    h = sha1(data)
    h.update(precomputed["salt"])

    return h.digest() == digest


def shake_256_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    return shake_256(data).digest(len(target_hash)) == target_hash


def shake_128_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    return shake_128(data).digest(len(target_hash)) == target_hash


def ripemd_160_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if hashlib_ripemd_160 is not None:
        return hashlib_ripemd_160("ripemd160", data).digest() == target_hash
    
    return RIPEMD160.new(data).digest() == target_hash



def bcrypt_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    return checkpw(
        data,
        target_hash
    )


def dcc2_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)
        
    return msdcc2.verify(
         word,
         target_hash,
         user=user
         )


def pbkdf2_sha256_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    try:
        if precomputed is not None:
            key = pbkdf2_hmac(
                "sha256",
                data,
                precomputed["salt"],
                precomputed["iterations"],
                precomputed["dklen"]
            )

            return key == precomputed["key"]

        else:
            return pbkf_sha2_passlib.verify(
                word,
                target_hash
            )

    except (
        binascii.Error,
        ValueError,
        TypeError,
        IndexError,
        KeyError
    ):
        return pbkf_sha2_passlib.verify(
            word,
            target_hash
        )

def pbkdf2_sha1_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    try:
        if precomputed is not None:
            key = pbkdf2_hmac(
                "sha1",
                data,
                precomputed["salt"],
                precomputed["iterations"],
                precomputed["dklen"]
            )

            return key == precomputed["key"]

        else:
            return pbkf_sha1_passlib.verify(
                word,
                target_hash
            )

    except (
        binascii.Error,
        ValueError,
        TypeError,
        IndexError,
        KeyError
    ):
        return pbkf_sha1_passlib.verify(
            word,
            target_hash
        )

def pbkdf2_sha512_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    try:
        if precomputed is not None:
            key = pbkdf2_hmac(
                "sha512",
                data,
                precomputed["salt"],
                precomputed["iterations"],
                precomputed["dklen"]
            )

            return key == precomputed["key"]

        else:
            return pbkf_sha5_passlib.verify(
                word,
                target_hash
            )

    except (
        binascii.Error,
        ValueError,
        TypeError,
        IndexError,
        KeyError
    ):
        return pbkf_sha5_passlib.verify(
            word,
            target_hash
        )

def argon2id_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    try:
        ph.verify(
            target_hash,
            word
        )

        return True

    except VerifyMismatchError:
        return False


def scrypt_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    try:
        if precomputed is not None:
            derived_key = scrypt_hashlib(
                data,
                salt=precomputed["salt"],
                n=precomputed["n"],
                r=precomputed["r"],
                p=precomputed["p"],
                dklen=precomputed["dklen"]
            )

            return derived_key == precomputed["key"]

        else:
            return scrypt.verify(
                word,
                target_hash
            )

    except (
        binascii.Error,
        ValueError,
        TypeError,
        IndexError,
        KeyError
    ):
        return scrypt.verify(
            word,
            target_hash
        )


def yescrypt_hash(
    word, data, target_hash, hash_type, 
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    try:
        yescrypt_.compare(
            data,
            target_hash
        )

        return True

    except (
        WrongPassword,
        WrongPasswordConfiguration
    ):
        return False



def mssql2005_hash(
    word, data, target_hash, hash_type,
    user, wait_time, ph,
    yescrypt_, context, precomputed
):

    return mssql2005.verify(word, target_hash)



def ldap_ssha512_hash(
    word, data, target_hash, hash_type,
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
   return ldap_salted_sha512.verify(word, target_hash)



def ldap_ssha256_hash(
    word, data, target_hash, hash_type,
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    return ldap_salted_sha256.verify(word, target_hash)



def bcrypt_sha256_hash(
    word, data, target_hash, hash_type,
    user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)
        
    return ctx.verify(word, target_hash)



def validate_word(
    word,
    data,
    target_hash,
    hash_type,
    user,
    wait_time,
    ph,
    yescrypt_,
    context,
    precomputed
):

    if wait_time == "y" and hash_type in CRYPT_VALIDATOR_SET:
        time.sleep(0.20)

    if hash_type in CRYPT_VALIDATOR_SET:

        if hash_type in CRYPT_VALIDATOR_SET_WITHOUT_PHPASS:

            try:
                if is_linux is not None and target_hash.startswith(("$1$", "$5$", "$6$")):
                   result_pyxcyt = pyxcrypt.crypt(word, target_hash)
                   if result_pyxcyt is not None and not result_pyxcyt.startswith('*'):
                      return result_pyxcyt == target_hash
                   
                elif is_linux is None:
                  if libcrypt is not None and target_hash_g.startswith((b"$1$", b"$5$", b"$6$")):
                     return libcrypt.crypt(data, target_hash_g) == target_hash_g

                if hash_type == "apr1":
                   if lib is not None:
                      ret = lib.apr_md5_encode(
                             data,
                             target_hash_g,
                             result,
                             ctypes.sizeof(result)
                      )

                      if ret == 0:
                         return result.value == target_hash_g

                return context.verify(
                    word,
                    target_hash
                )

            except Exception:
                return CRYPT_ALGORITHMS[
                    hash_type
                ].verify(
                    word,
                    target_hash
                )

        return CRYPT_ALGORITHMS[
            hash_type
        ].verify(
            word,
            target_hash
        )

    return HASH_ALGORITHMS_INFO[hash_type](data).digest() == target_hash



