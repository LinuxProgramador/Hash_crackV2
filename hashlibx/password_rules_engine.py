#!/usr/bin/env python3

import sys

def rules_parameters(word, rules, stored):
  try:

    rule = ''

    numbers = [
    "0", "00", "000", "0000", "00000",
    "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "2", "22", "222", "2222",
    "3", "33", "333", "3333",
    "4", "44", "444", "4444",
    "5", "55", "555", "5555",
    "6", "66", "666", "6666",
    "7", "77", "777", "7777",
    "8", "88", "888", "8888",
    "9", "99", "999", "9999",
    "111", "1111", "11111",
    "321", "4321", "54321", "654321", "987654",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "1990", "1991", "1992", "1995", "1999", "2000", "2001", "2005", "2010"
    ]

    symbols = [
    "!", "@", "#", "$", "%", "&", "*", "(", ")", "_", "-", "+", "=",
    "{", "}", "[", "]", "|", "\\", ":", ";", "'", "\"", "<", ">", ",", ".", "?", "/",
    "~", "`", "^"
    ]

    character_substitution = {"a":"@","A":"4","e":"3","E":"3","i":"1","I":"1","o":"0","O":"0","s":"$","S":"5","t":"7","T":"7","ó":"0","Ó":"0","á":"@","Á":"4","é":"3","É":"3","í":"1","Í":"1","à":"@","À":"4","è":"3","È":"3","ò":"0","Ò":"0","ì":"1","Ì":"1"}

    if rules and len(rules) == 2:
       for option in rules:
            rule += option

    elif rules and len(rules) == 1:
        rule = rules[0]

    elif rules and len(rules) >= 3:
        for option in rules[:2]:
            rule += option

    else:
        rules.append('0')
        rule = rules[0]


    chosen_rules = rule if rule in ['1','2','3','4','5','6','7','8','9','12','13','15','21','31','51','42','24','34','43','54','45','64','46','61','16','56','65','26','62','36','63'] else ''

    if chosen_rules:
        if chosen_rules in ['1']:
           for number in numbers:
              word_number  = word + number
              stored.append(word_number)

        elif chosen_rules in ['4']:
           for symbol in symbols:
              word_symbol  = word + symbol
              stored.append(word_symbol)

        elif chosen_rules in ['3']:
              stored.append(word.lower())

        elif chosen_rules in ['2']:
              stored.append(word.upper())

        elif chosen_rules in ['5']:
              stored.append(word.capitalize())

        elif chosen_rules in ['6']:
               for char in character_substitution:
                  word = word.replace(char,character_substitution[char])
               stored.append(word)

        elif chosen_rules in ['7']:
              word = word.capitalize()
              for number in numbers:
                 word_number = word + number
                 for symbol in symbols:
                    word_symbol  = word_number + symbol
                    stored.append(word_symbol)

        elif chosen_rules in ['8']:
              word = word[::-1]
              stored.append(word)

        elif chosen_rules in ['9']:
              word = word + word
              stored.append(word)

        elif chosen_rules in ['10']:
             for vocal in vocals:
                 word = word.replace(vocal, '')
                 word = word.replace(vocal.upper(), '')
             stored.append(word)

        elif chosen_rules in ['11']:
             for number in numbers:
                 word_number = number + word
                 stored.append(word_number)

        elif chosen_rules in ['00']:
             for symbol in symbols:
                 word_symbol  = symbol + word
                 stored.append(word_symbol)

        elif chosen_rules in ['HBA']:
            for r in range(1, 5):                                                                                  
              for combo in product([0,1,2,3,4,5,6,7,8,9], repeat=r):
                   full_word = word + ''.join(str(digit) for digit in combo)
                   stored.append(full_word)
              

        elif chosen_rules in ['64','46']:
            for char in character_substitution:
               word = word.replace(char,character_substitution[char])
            for symbol in symbols:
               word_symbol  = word + symbol
               stored.append(word_symbol)

        elif chosen_rules in ['61','16']:
               for char in character_substitution:
                  word = word.replace(char,character_substitution[char])
               for number in numbers:
                  word_number  = word + number
                  stored.append(word_number)

        elif chosen_rules in ['56','65']:
               for char in character_substitution:
                  word = word.replace(char,character_substitution[char])
               stored.append(word.capitalize())

        elif chosen_rules in ['26','62']:
              for char in character_substitution:
                  word = word.replace(char,character_substitution[char])
              stored.append(word.upper())

        elif chosen_rules in ['36','63']:
              for char in character_substitution:
                  word = word.replace(char,character_substitution[char])
              stored.append(word.lower())

        elif chosen_rules in ['12','21']:
              word = word.upper()
              for number in numbers:
                 word_number  = word + number
                 stored.append(word_number)

        elif chosen_rules in ['13','31']:
              word = word.lower()
              for number in numbers:
                 word_number = word + number
                 stored.append(word_number)

        elif chosen_rules in ['15','51']:
              word = word.capitalize()
              for number in numbers:
                 word_number  = word + number
                 stored.append(word_number)

        elif chosen_rules in ['42','24']:
              word = word.upper()
              for symbol in symbols:
                 word_symbol  = word + symbol
                 stored.append(word_symbol)

        elif chosen_rules in ['34','43']:
              word = word.lower()
              for symbol in symbols:
                 word_symbol  = word + symbol
                 stored.append(word_symbol)

        elif chosen_rules in ['54','45']:
              word = word.capitalize()
              for symbol in symbols:
                 word_symbol  = word + symbol
                 stored.append(word_symbol)
    else:
       stored.append(word)

    return stored

  except Exception as error:
    print(f"[ERROR]: {error}")
    sys.exit(1)
