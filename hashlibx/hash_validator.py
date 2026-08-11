#!/usr/bin/env python3

import time
import sys
import binascii

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
)

from passlib.hash import pbkdf2_sha256 as pbkf_sha2_passlib
from passlib.hash import pbkdf2_sha1 as pbkf_sha1_passlib
from passlib.hash import pbkdf2_sha512 as pbkf_sha5_passlib

from bcrypt import checkpw
from argon2.exceptions import VerifyMismatchError


if sys.platform == "linux":
    from pyescrypt import WrongPassword, WrongPasswordConfiguration



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


def mysql5_x_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return sha1(sha1(data).digest()).digest() == target_hash
        

def whirlpool_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return wpl(data).digest() == target_hash
    


def sha256sum_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return sha256((word + "\n").encode(encoder)).digest() == target_hash
    

def sha512sum_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):  
     return sha512((word + "\n").encode(encoder)).digest() == target_hash



def sm3_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
        if "sm3" in algorithms_available:
           h = new("sm3")
           h.update(data)
           return  h.digest() == target_hash 
        else:
           return bytes.fromhex(
             sm3.sm3_hash(func.bytes_to_list(data))
             ) == target_hash
  

def ntlm_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
     return MD4.new(
        word.encode("utf-16le")
        ).digest() == target_hash


    


def sha512_256_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):    
    return new("sha512_256", data).digest() == target_hash
    

def ssha_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
    digest = precomputed["digest"]

    h = sha1(data)
    h.update(precomputed["salt"])

    return h.digest() == digest


def shake_256_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
    return shake_256(data).digest(len(target_hash)) == target_hash


def shake_128_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
    return shake_128(data).digest(len(target_hash)) == target_hash


def ripemd_160_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if "ripemd160" in algorithms_available:
        return new("ripemd160", data).digest() == target_hash
    else:
        h = RIPEMD160.new()
        h.update(data)
        return h.digest() == target_hash



def bcrypt_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)

    return checkpw(
        data,
        target_hash
    )


def dcc2_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if wait_time == "y":
        time.sleep(0.20)
        
    return msdcc2.verify(
         word,
         target_hash,
         user=user
         )


def wpa_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
    yescrypt_, context, precomputed
):
    if 8 <= len(word) <= 63:
        
        return pbkdf2_hmac(
         "sha1",
         data,
         ssid,
         4096,
         32
         ) == target_hash

    return False


def pbkdf2_sha256_hash(
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
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
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
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
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
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
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
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
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
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
    word, data, target_hash, hash_type, encoder,
    wpa_psk, ssid, user, wait_time, ph,
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


def validate_word(
    word,
    data,
    target_hash,
    hash_type,
    encoder,
    wpa_psk,
    ssid,
    user,
    wait_time,
    ph,
    yescrypt_,
    context,
    precomputed
):

    if wait_time == "y" and hash_type in {
        "sha256crypt",
        "sha512crypt",
        "md5crypt",
        "apr1",
        "phpass"
    }:
        time.sleep(0.20)

    if hash_type in {
        "sha256crypt",
        "sha512crypt",
        "md5crypt",
        "apr1",
        "phpass"
    }:

        if hash_type in {
            "sha256crypt",
            "sha512crypt",
            "md5crypt",
            "apr1"
        }:

            try:
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



