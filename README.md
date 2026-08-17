
# Hash_crackV2

## Disclaimer

This tool is intended for educational and research purposes only.  
The author is not responsible for any misuse or illegal activity performed using this software.


## Recommended Platforms

• Ubuntu 24.04.4 LTS and Ubuntu 26.04 LTS

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



## 🛠️ Components

* **`crunch_manager.sh`**: Module that calls the native Linux tool (crunch) to generate custom dictionaries

* **`wordlist_manager.sh`**: Module that allows managing large dictionaries for optimized cracking

* **`multi_hash_bruteforce.py`**: Module that allows brute-force attacks without a dictionary

* **`Hasher.py`**: Main module that performs dictionary attacks, calls to external modules (Crack_Rar, etc.)



##  External resources (dictionaries/rainbow tables/dictionary generator)
1. Elpscrk — Intelligent wordlist generator: https://github.com/D4Vinci/elpscrk⁠
2. CUPP — Custom wordlist generator: https://github.com/mebus/cupp⁠
3. Hashes.com — Hash lookup: https://hashes.com⁠
4. CrackStation — Hash lookup: https://crackstation.net
5. SecLists — Wordlist collection: https://github.com/danielmiessler/seclists⁠



## Features

1. Multi-processing for optimal performance on multi-core systems  
2. Custom dictionary generation using crunch, including combined rule-based and mask-based attacks   
3. Ability to crack ZIP and RAR archive passwords using integrated third-party tools  
4. Support for hybrid attacks, including rules, masks, and blended password lists  
5. Fast and simple command-line interface  
6. Support for multiple hash algorithms (over 30 supported formats)  
7. Optimized resource usage: from 512 KB to (8 MB/16 MB/32 MB/64 MB) of RAM per block depending on system resources, with customizable CPU core consumption
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
  
## Installation

```bash
cd ~
git clone https://github.com/JosePRU24/Hash_crackV2
cd Hash_crackV2
bash install.sh
python3 Hasher.py [-i, -t, -e, -r, -w, -m, ...]

## NOTE

If you encounter installation issues on Ubuntu, it is recommended to use a Python virtual environment.

### Create a virtual environment

    python3 -m venv path/to/venv

### Install the project dependencies

    path/to/venv/bin/python3 -m pip install -r linux_requirements.txt

### Install the Whirlpool dependency

    path/to/venv/bin/python3 -m pip install -e ./thirdparty_cracktools/python-whirlpool --use-pep517

## Usage

   path/to/venv/bin/python3 Hasher.py -i ' your_hash_here '


If you encounter installation issues on Ubuntu, or receive errors such as ModuleNotFoundError, you can activate the virtual environment and run the commands normally.

#### Activate the virtual environment

     python3 -m venv path/to/venv
     source path/to/venv/bin/activate


#### Install the project dependencies

     python3 -m pip install -r linux_requirements.txt


#### Install the Whirlpool dependency

    python3 -m pip install -e ./thirdparty_cracktools/python-whirlpool --use-pep517


#### Run the program

    python Hasher.py -i 'your_hash_here'


#### Deactivate the virtual environment

     deactivate



To access the help menu and see all available options:

python3 Hasher.py -h

Supported hashes:

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
• YESCRYPT


Note: For **WPA-PSK** and **DCC2** hashes, the expected input format is:

   *WPA-PSK: network:hash
   *DCC2: username:hash or
   $DCC2$iterations#username#hash
   Example:

          $DCC2$10240#root#8e8d1cd22a57d975978f1404a58548f3

Note:

      By default, only one CPU is allocated to hashes (`argon2id`/`scrypt`/`yescrypt`). To change this behavior, simply pass the number of CPUs to use with the "-c" parameter.
      For example:

             python3 Hasher.py -i 'hash' -c 5


Note:

     You can use your own dictionaries, but you must rename them to ssh_keys.txt or wordlist.txt


Check progress

To display elapsed time, press:

CTRL + Z

Quit the program

To stop the tool at any time, press:

CTRL + C
