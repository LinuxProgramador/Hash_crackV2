#!/usr/bin/env python3

import sys

def cracking_prompt(encoder, hash_type, process_count):
  try:

    valid_hashes = {
    "shake-128": "shake-128 [SHAKE128 / extensible-output function]",
    "shake-256": "shake-256 [SHAKE256 / extensible-output function]",
    "sha256crypt": "$5$ sha256crypt [Unix SHA-256 password hash]",
    "sha512crypt": "$6$ sha512crypt [Unix SHA-512 password hash]",
    "md5crypt": "$1$ md5crypt [FreeBSD-style MD5-based crypt]",
    "ssha": "{SSHA} Salted SHA-1 [LDAP salted hash]",
    "phpass": "$P$ phpass [WordPress/Drupal/PhpBB]",
    "wpa": "WPA-PSK [Pre-Shared Key, 4096 HMAC-SHA1 iterations]",
    "scrypt": "scrypt [Memory-hard password hash]",
    "pbkdf2-sha256": "PBKDF2-HMAC-SHA256 [Django-style, variable iterations]",
    "argon2id": "Argon2id [Memory-hard, CPU-intensive password hash]",
    "dcc2": "DCC2/MSCash2 [Domain Cached Credentials v2]",
    "apr1": "$apr1$ Apache MD5-based hash [Variant of md5crypt]",
    "bcrypt": "$2a$ bcrypt [Blowfish-based crypt]",
    "mysql5.x": "MySQL5.x [Double SHA1 used in authentication]",
    "pbkdf2-sha1": "PBKDF2-HMAC-SHA1 [Django-style, variable iterations]",
    "pbkdf2-sha512": "PBKDF2-HMAC-SHA512 [Django-style, variable iterations]",
    "yescrypt": "$y$ yescrypt [Memory-hard, ASIC-resistant Linux /etc/shadow password hash]",
    "md5": "MD5 [128-bit message digest]",
    "sha1": "SHA-1 [160-bit secure hash algorithm]",
    "sha224": "SHA-224 [224-bit SHA-2 hash function]",
    "sha256": "SHA-256 [256-bit SHA-2 hash function]",
    "sha384": "SHA-384 [384-bit SHA-2 hash function]",
    "sha512": "SHA-512 [512-bit SHA-2 hash function]",
    "sha3-224": "SHA3-224 [224-bit Keccak-based hash function]",
    "sha3-256": "SHA3-256 [256-bit Keccak-based hash function]",
    "sha3-384": "SHA3-384 [384-bit Keccak-based hash function]",
    "sha3-512": "SHA3-512 [512-bit Keccak-based hash function]",
    "blake2b": "BLAKE2b [Fast cryptographic hash optimized for 64-bit systems]",
    "blake2s": "BLAKE2s [Fast cryptographic hash optimized for 8 to 32-bit systems]",
    "whirlpool": "Whirlpool [512-bit hash function based on AES design principles]",
    "sha256sum": "SHA256SUM [SHA-256 checksum format commonly used for file integrity verification]",
    "sha512sum": "SHA512SUM [SHA-512 checksum format commonly used for file integrity verification]",
    "sm3": "SM3 [Chinese national cryptographic hash standard]",
    "ntlm": "NTLM [Windows NT LAN Manager password hash based on MD4]",
    "sha512-256": "SHA-512/256 [SHA-512 truncated to 256 bits]",
    "ripemd-160": "RIPEMD-160 [160-bit cryptographic hash function]"
    }


    message = f"""
[INFO] Loaded 1 hash ({valid_hashes.get(hash_type, hash_type)})
[INFO] Encoding used: {encoder}
[INFO] CPU cores in use: {process_count}
[INFO] Press Ctrl-C to abort
    """.strip()

    return message

  except Exception as error:
    print(f"[ERROR]: {error}")
    sys.exit(1)
