
# Hash_crackV2

## Disclaimer

This tool is intended for educational and research purposes only.  
The author is not responsible for any misuse or illegal activity performed using this software.

## Recommended Platforms

• Linux-based systems (Debian, Ubuntu)

• Android (via Termux)

## Quick Command Usage for Hasher.py

🔓 Decrypt a Cisco Type 7 key

python3 Hasher.py -i 'cisco7_key' -ct7


---

📦 Call external modules

python3 Hasher.py -m -mc [1..9]


---

✅ Directly check a hash (with default values)

python3 Hasher.py -i 'hash'

---

⚙️ Example with common parameters

python3 Hasher.py -i 'hash' -t md5 -c 1 -e 2 -w n -r 1


## Features

1. Multi-processing for optimal performance on multi-core systems  
2. Custom dictionary generation using crunch, including combined rule-based and mask-based attacks   
3. Ability to crack ZIP and RAR archive passwords using integrated third-party tools  
4. Support for hybrid attacks, including rules, masks, and blended password lists  
5. Fast and simple command-line interface  
6. Support for multiple hash algorithms (over 30 supported formats)  
7. Optimized resource usage: 512 KB to 1 MB of RAM per block, with customizable CPU core consumption  
8. Automatic detection of hash types  
9. Supports both dictionary and brute-force attacks on hashes  
10. Dictionary-based attack support for exposed SSH services  

## Included third-party projects

- Whirlpool module:  
  https://github.com/oohlaf/python-whirlpool.git

- zipcrack (ZIP password cracking):  
  https://github.com/machine1337/zipcrack

- RARNinja (RAR password cracking):  
  https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility

- Rockyou dictionary 2023:  
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

- Rockyou dictionary 2024:  
  https://t.me/securixy_kz/908

- Collection of common wordlists:  
  https://github.com/kkrypt0nn/wordlists

- Rainbow tables collection:
  
  CrackStation: https://crackstation.net

  FreeRainbowTables: https://freerainbowtables.com

  PassMark Software: https://www.osforensics.com/tools/rainbow-tables/index.html

  Ophcrack: https://ophcrack.sourceforge.io/tables.php

  RainbowCrackalack: https://github.com/jtesta/rainbowcrackalack

  Hashes: https://hashes.com/

  Md5decrypt: https://md5decrypt.net/

- Hash type recognition:
  
  Dcode: https://www.dcode.fr/identificador-hash
  
  [NOTE] Or pass the hash to the main module Hasher.py and it will show you the hash type or the closest one
  
## Installation

```bash
cd ~
git clone https://github.com/LinuxProgramador/Hash_crackV2
cd Hash_crackV2
bash install.sh
python3 Hasher.py [-i, -t, -e, -r, -w, -m, ...]

To access the help menu and see all available options:

python3 Hasher.py -h

Supported hashes

• MD5
• SHA1
• SHA224
• SHA256
• SHA384
• SHA512
• SHA3-224
• SHA3-256
• SHA3-384
• SHA3-512
• BLAKE2s
• BLAKE2b
• RIPEMD-160
• BCRYPT
• SHA256CRYPT
• SHA512CRYPT
• SHAKE-128
• SHAKE-256
• WPA-PSK
• NTLM
• MySQL 5.x
• MD5CRYPT
• APR1
• CISCO TYPE 7
• DCC2
• SSHA
• SM3
• SHA512-256
• PHPASS
• WHIRLPOOL
• SHA256SUM
• SHA512SUM
• ARGON2ID
• SCRYPT
• PBKDF2-SHA256
• PBKDF2-SHA1
• PBKDF2-SHA512

Important notes

1. If you want to use your own dictionary, name the file wordlist.txt and place it inside the Hash_crackV2 directory.


2. ZCrack and RARNinja tools are better suited for older encryption implementations since they were developed some time ago. For decrypting modern compression formats, we recommend using Zip-Crack and Rar-Crack.


3. For DCC2 and WPA-PSK hashes, include the username or SSID along with the hash. For example:

WPA-PSK: MyNetwork:c5846b79d776cf7c0973edf6e8bb0778da330b1a92d18f6664557b1d9b7498dd  
DCC2: root:e7f9a1ba77b1d0406ab52783b2b9636a


4. In the script multi_hash_bruteforce.py, the user and SSID are requested after entering the hash.


5. Both the old and new implementations of DCC2 are supported.


6. For SHAKE-128 and SHAKE-256 hashes, it is mandatory to specify the hash type using the -t option. Auto-detection is not supported for these formats.


7. To perform brute-force attacks without a dictionary, use the script multi_hash_bruteforce.py.


8. To create custom password dictionaries, use the helper script crunch_manager.sh.


9. In Linux distros (Debian/Ubuntu) the installation of the Whirlpool module is done with 'sudo'

To avoid conflicts, but unlikely, you have the option to install Whirlpool from a virtual environment


10. RECOMMENDATION: If the dictionary is massive, split it with split_dictionary.py

Only if you have enough disk space available


11. This process cleans the dictionary by removing duplicate passwords,

which helps reduce the file size and can speed up cracking time.

However, warning: doing so may also break the original smart ordering of the dictionary.

    sort -u rockyou.txt > wordlist.txt



Check progress

To display elapsed time, press:

CTRL + Z

Quit the program

To stop the tool at any time, press:

CTRL + C
