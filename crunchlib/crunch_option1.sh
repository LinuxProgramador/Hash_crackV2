#!/usr/bin/env bash

crunch_option1() {
    clear
    echo "[*] How many words do you want to concatenate to generate the dictionary?"

    while true; do
        read -p "Enter a number (minimum 2, maximum 10): " count

        # Validation: must be an integer between 2 and 10
        if [[ "$count" =~ ^[0-9]+$ ]] && (( count >= 2 && count <= 10 )); then
            break
        else
            echo "[!] Invalid value. Please enter a number between 2 and 10."
        fi
    done

    words=()  # empty array

    for ((i=1; i<=count; i++)); do
        read -p "Enter word #$i: " word
        words+=("$word")
    done

    clear
    echo "[*] Generating concatenated dictionary with the words:"
    printf ' - %s\n' "${words[@]}"
    echo ""
    sleep 3

    crunch 1 1 -o ~/Hash_crackV2/wordlist.txt -p "${words[@]}"

    sleep 2
    clear
    echo "[✓] Dictionary successfully generated at ~/Hash_crackV2/wordlist.txt"
    echo "[→] Now run the Hasher.py program again"
}


export -f crunch_option1
