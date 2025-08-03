#!/usr/bin/env bash

crunch_option3() {
    clear
    echo "[*] Crunch: Pattern-based dictionary generation using wildcards (@)"

    read -p "Enter the known and unknown parts of the password using '@' as a placeholder: " password
    read -p "Enter the character set to test (e.g., abc123): " values
    read -p "Enter the total length of the password: " length

    clear
    echo
    echo "[✓] Done! Now copy and paste the following command into your terminal:"
    echo
    echo "crunch $length $length $values -t $password -o ~/Hash_crackV2/wordlist.txt"
    echo
    echo "[*] Once the wordlist is generated, re-run Hasher.py to continue."
    exit 2
}


export -f crunch_option3
