
# Hash_crackV2

## Disclaimer

This tool is intended for educational and research purposes only.  
The author is not responsible for any misuse or illegal activity performed using this software.

## Recommended Platforms

• Linux-based systems (Debian, Ubuntu)

• Android (via Termux)

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

Important notes

1. If you want to use your own dictionary, name the file wordlist.txt and place it inside the Hash_crackV2 directory.


2. Cracking ZIP and RAR archives depends on the tool used for compression. Success is more likely if the files were compressed using command-line tools such as zip or rar.


3. For DCC2 and WPA-PSK hashes, include the username or SSID along with the hash. For example:

WPA-PSK: MyNetwork:c5846b79d776cf7c0973edf6e8bb0778da330b1a92d18f6664557b1d9b7498dd  
DCC2: root:e7f9a1ba77b1d0406ab52783b2b9636a


4. In the script multi_hash_bruteforce.py, the user and SSID are requested after entering the hash.


5. Both the old and new implementations of DCC2 are supported.


6. For SHAKE-128 and SHAKE-256 hashes, it is mandatory to specify the hash type using the -t option. Auto-detection is not supported for these formats.


7. To perform brute-force attacks without a dictionary, use the script multi_hash_bruteforce.py.


8. To create custom password dictionaries, use the helper script crunch_manager.sh.



Quit the program

To stop the tool at any time, press:

CTRL + C
