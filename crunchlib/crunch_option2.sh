#!/usr/bin/env bash

crunch_option2() {
    clear

    echo "[*] Crunch: Generate dictionary using custom character set and length"

    read -p "Enter the minimum password length: " minimum
    read -p "Enter the maximum password length: " maximum
    read -p "Enter the character set to use (e.g., abc123!@#): " values

    clear
    echo
    echo "[✓] Done! Now copy and paste the following command into your terminal:"
    echo
    echo "crunch $minimum $maximum $values -o ~/Hash_crackV2/wordlist.txt"
    echo
    echo "[*] Once the wordlist is generated, re-run Hasher.py to continue."
    exit 2
}

export -f crunch_option2
