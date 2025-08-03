#!/usr/bin/env bash

crunch_info() {
    echo "[*] Crunch will be used to generate a custom wordlist!"
    sleep 4
    clear
    cat << 'EOF'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1] Concatenate Mode:
    - Generates a wordlist by combining provided words.
    - Example:
        Words: Harry Hermallony Ron
        Result: All combinations like HarryHermallonyRon, etc.
    - Useful for targeting names, aliases, or merged terms.

[2] Length-Specific Mode:
    - Generates a wordlist using a set of characters.
    - Example:
        crunch 4 8 abcdef
        → Will create combinations from 4 to 8 characters long using "abcdef".

[3] Pattern-Based Mode:
    - Generates a wordlist using a fixed part of a password and wildcards (@).
    - Example:
        Known part: hello
        Unknown part: @@@ (e.g., 123)
        Pattern: hello@@@
        → The exact total length must be specified (e.g., 8 in this case).
    - INFO: The '@' wildcard can be placed anywhere in the pattern
            to indicate the position(s) of unknown characters.

⚠️ WARNING:
    Be extremely careful with the number of combinations you generate!
    Crunch can easily create gigabytes of data, which may overload or crash your system!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
}


export -f crunch_info
