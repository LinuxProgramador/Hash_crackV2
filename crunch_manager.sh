#!/usr/bin/env bash

run_crunch() {
   source "$HOME/Hash_crackV2/crunchlib/crunch_info.sh"
   source "$HOME/Hash_crackV2/crunchlib/crunch_option1.sh"
   source "$HOME/Hash_crackV2/crunchlib/crunch_option2.sh"
   source "$HOME/Hash_crackV2/crunchlib/crunch_option3.sh"

   rm -f "$HOME/Hash_crackV2/wordlist.txt"

   crunch_info

   read -p "[?] Choose an option (1, 2, or 3): " option_chosen

   case "$option_chosen" in
        1)
            crunch_option1
            exit 2
            ;;
        2)
            crunch_option2
            ;;
        3)
            crunch_option3
            ;;
        *)
            echo "[✗] Invalid option!"
            exit 2
            ;;
   esac
}

run_crunch
