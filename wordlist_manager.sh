#!/bin/bash

set -eo pipefail

DICT_DIR="./dictionary_directories"

mkdir -p "$DICT_DIR"

dic_delete() {

    echo ""
    echo "1) Delete a dictionary"
    echo "2) Delete all dictionaries"

    read -p "Option: " op

    case "$op" in
        1)
            dic_list

            read -p "Dictionary name: " file

            if [ -f "$DICT_DIR/$file" ]; then
                rm -f "$DICT_DIR/$file"
                echo "[+] Dictionary deleted."
            else
                echo "[-] Dictionary does not exist."
            fi
            ;;

        2)
            find "$DICT_DIR" -type f -delete
            echo "[+] All dictionaries have been deleted."
            ;;

        *)
            echo "[-] Invalid option."
            ;;
    esac
}

dic_divide() {

    read -p "Dictionary path: " wordlist

    if [ ! -f "$wordlist" ]; then
        echo "[-] File does not exist."
        return
    fi

    echo ""
    echo "Recommended values:"
    echo "  500     = Very slow hashes (Argon2id, yescrypt, scrypt)"
    echo "  1000    = Slow hashes (bcrypt, PBKDF2)"
    echo "  5000    = Balanced"
    echo "  10000   = Fast hashes (SHA256, SHA512)"
    echo "  100000  = Very large blocks"
    echo ""

    read -p "Lines per block (500 - 100000): " size

    if ! [[ "$size" =~ ^[0-9]+$ ]]; then
        echo "[-] You must enter a number."
        return
    fi

    if [ "$size" -lt 500 ] || [ "$size" -gt 100000 ]; then
        echo "[-] Value must be between 500 and 100000."
        return
    fi

    total_lines=$(wc -l < "$wordlist")
    total_files=$(( (total_lines + size - 1) / size ))

    echo ""
    echo "Dictionary lines : $total_lines"
    echo "Lines per block  : $size"
    echo "Files to create  : $total_files"

    if [ "$total_files" -gt 10000 ]; then

        echo ""
        echo "[!] WARNING"
        echo "[!] A large number of files will be generated."
        echo "[!] This may take a long time and consume significant disk space."

        if [ "$total_files" -gt 100000 ]; then
            echo ""
            echo "[!] EXTREME WARNING"
            echo "[!] More than 100000 files will be created."
            echo "[!] This is generally not recommended."
        fi

        echo ""

        read -p "Continue anyway? (y/N): " confirm

        case "$confirm" in
            y|Y|yes|YES)
                ;;
            *)
                echo "[-] Operation cancelled."
                return
                ;;
        esac
    fi

    basename=$(basename "$wordlist")

    if [[ "$basename" == *.* ]]; then
        name="${basename%.*}"
        ext=".${basename##*.}"
    else
        name="$basename"
        ext=""
    fi

    split -l "$size" "$wordlist" "$DICT_DIR/tmp_"

    i=1

    for file in "$DICT_DIR"/tmp_*; do
        mv "$file" "$DICT_DIR/${name}${i}${ext}"
        ((i++))
    done

    echo "[+] Dictionary successfully split."
}

dic_list() {

    echo ""
    echo "===== AVAILABLE DICTIONARIES ====="

    if [ -z "$(ls -A "$DICT_DIR" 2>/dev/null)" ]; then
        echo "No dictionaries stored."
        return
    fi

    find "$DICT_DIR" -maxdepth 1 -type f -printf "%f\n"
}

dic_use() {

    dic_list

    read -p "Dictionary to use: " file

    if [ ! -f "$DICT_DIR/$file" ]; then
        echo "[-] Dictionary does not exist."
        return
    fi

    rm -f ./wordlist.txt

    mv "$DICT_DIR/$file" ./wordlist.txt

    echo "[+] Dictionary assigned as wordlist.txt"
}

main() {

    echo ""
    echo "===== DICTIONARY MANAGER ====="
    echo "1) Delete dictionary(s)"
    echo "2) Split dictionary"
    echo "3) List dictionaries"
    echo "4) Use dictionary"
    echo "5) Exit"
    echo ""

    read -p "Select an option: " option

    case "$option" in
        1)
            dic_delete
            ;;
        2)
            dic_divide
            ;;
        3)
            dic_list
            ;;
        4)
            dic_use
            ;;
        5)
            exit 0
            ;;
        *)
            echo "[-] Invalid option."
            ;;
    esac
}

main
