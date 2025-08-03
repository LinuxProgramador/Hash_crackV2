#!/usr/bin/env python3

def show_help():
  return '''

      ' 88  88    db    .dP"Y8 88  88 88888 88""Yb '
      ' 88  88   dPYb   `Ybo." 88  88 88__  88__dP '
      ' 888888  dP__Yb  o.`Y8b 888888 88""  88"Yb  '
      ' 88  88 dP""""Yb 8bodP  88  88 88888 88  Yb '


               Hasher 1.0.0 - Multi Hash Cracker
    --------------------------------------------------
     INFO: Tool for cracking multiple types of hashes
     INFO: Use the help menu for guidance:
                 → python3 Hasher.py -h
    --------------------------------------------------

         ╔════════ Supported Hash Types ════════╗
         ║  md5         sha1        blake2s     ║
         ║  blake2b     ripemd-160  bcrypt      ║
         ║  sha256crypt sha512crypt shake-128   ║
         ║  shake-256   wpa         ntlm        ║
         ║  mysql5.x    md5crypt    apr1        ║
         ║  dcc2        ssha        sm3         ║
         ║  sha512-256  phpass      whirlpool   ║
         ║  sha512sum   sha256sum   sha3-224    ║
         ║  sha3-256    sha3-384    sha3-512    ║
         ║  sha256      sha224      sha384      ║
         ║  sha512      pbkdf2-sha256           ║
         ║  argon2id    scrypt      CiscoType7  ║
         ╚══════════════════════════════════════╝
  '''
