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
        "mysql5.x": "MySQL5.x [Double SHA1 used in authentication]"
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
