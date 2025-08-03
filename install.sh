#!/usr/bin/env bash

main() {
    local os
    os=$(uname -o 2>/dev/null || echo "unknown")

    echo "[*] Making scripts in Hash_crackV2/ directory executable"
    find ./ -maxdepth 1 -type f \
        ! -name 'README.md' \
        ! -name 'LICENSE' \
        ! -name 'wordlist.txt' \
        ! -name 'termux_requirements.txt' \
        ! -name 'linux_requirements.txt' \
        -exec chmod u+x {} +

    find config_bundle/ -type f \
        ! -name 'db.json' \
        ! -name 'proxychains4.conf' \
        -exec chmod u+x {} +

    find crunchlib/ -type f \
        -exec chmod u+x {} +

    find hashlibx/ -type f \
        ! -name '__init__.py' \
        -exec chmod u+x {} +

    find thirdparty_cracktools/ \
        -type f -exec chmod u+x {} +


    echo -e "\n[*] Installing dependencies..."
    sleep 1

    if [[ "$os" == "Android" || "$PREFIX" == *"com.termux"* ]]; then
        echo "[+] Environment detected: Termux"
        apt update && apt upgrade -y
        apt install  python rust crunch -y
        python -m pip install -r termux_requirements.txt
    else
        echo "[+] Environment detected: Linux (Debian/Ubuntu)"
        if ! command -v sudo >/dev/null; then
            echo "[!] 'sudo' is not installed. Aborting."
            exit 1
        fi

        sudo apt update && sudo apt upgrade -y
        sudo apt install python3 python3-pip tor proxychains4 crunch -y
        python3 -m pip install --upgrade pip
        python3 -m pip install -r linux_requirements.txt

        # Only if the config file exists
        if [[ -f "$HOME/Hash_crackV2/config_bundle/proxychains4.conf" ]]; then
            echo "[*] Copying proxychains4.conf to the system"
            sudo cp -f "$HOME/Hash_crackV2/config_bundle/proxychains4.conf" /etc/proxychains4.conf
        else
            echo "[!] proxychains4.conf not found in ~/Hash_crackV2/config_bundle/"
        fi
    fi

    python3 -m pip install -e thirdparty_cracktools/python-whirlpool/.
    echo -e "\n[✓] Installation completed."
}

main
