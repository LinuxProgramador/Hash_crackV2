#!/usr/bin/env python3

from itertools import product

def rules_parameters(word, rules, numbers, symbols, vocals, character_substitution, digits, translation_table):
    
    if rules and len(rules) == 1:
          rule = rules[0]
    elif rules and len(rules) >= 2:
        rule = "".join(rules[:2])


    chosen_rules = rule if rule in {'HBA','00','1','2','3','4','5','6','7','8','9','10','11','12','13','15','21','31','51','42','24','34','43','54','45','64','46','61','16','56','65','26','62','36','63'} else ''

    if chosen_rules:
        if chosen_rules == '1':
           for number in numbers:
              yield word + number


        elif chosen_rules == '4':
           for symbol in symbols:
              yield word + symbol


        elif chosen_rules == '3':
              yield word.lower()

        elif chosen_rules == '2':
              yield word.upper()

        elif chosen_rules == '5':
              yield word.capitalize()

        elif chosen_rules == '6':
            yield = word.translate(translation_table)

        elif chosen_rules == '7':
              word = word.capitalize()
              for number in numbers:
                 word_number = word + number
                 for symbol in symbols:
                    yield word_number + symbol


        elif chosen_rules == '8':
              yield word[::-1]


        elif chosen_rules == '9':
              yield word + word


        elif chosen_rules == '10':
             temp_word = word
             for vocal in vocals:
                 temp_word = temp_word.replace(vocal, '')
                 temp_word = temp_word.replace(vocal.upper(), '')
             yield temp_word


        elif chosen_rules == '11':
             for number in numbers:
                 yield number + word

        elif chosen_rules == '00':
             for symbol in symbols:
                 yield symbol + word


        elif chosen_rules == 'HBA':
            for r in range(1, 5):
               for combo in product(digits, repeat=r):
                  yield word + "".join(combo)


        elif chosen_rules in ('64','46'):
            word = word.translate(translation_table)
            for symbol in symbols:
               yield  word + symbol


        elif chosen_rules in ('61','16'):
               word = word.translate(translation_table)
               for number in numbers:
                  yield word + number


        elif chosen_rules in ('56','65'):
               word = word.translate(translation_table)
               yield word.capitalize()

        elif chosen_rules in ('26','62'):
              word = word.translate(translation_table)
              yield word.upper()


        elif chosen_rules in ('36','63'):
              word = word.translate(translation_table)
              yield word.lower()


        elif chosen_rules in ('12','21'):
              word = word.upper()
              for number in numbers:
                 yield word + number


        elif chosen_rules in ('13','31'):
              word = word.lower()
              for number in numbers:
                 yield word + number


        elif chosen_rules in ('15','51'):
              word = word.capitalize()
              for number in numbers:
                 yield word + number


        elif chosen_rules in ('42','24'):
              word = word.upper()
              for symbol in symbols:
                 yield word + symbol


        elif chosen_rules in ('34','43'):
              word = word.lower()
              for symbol in symbols:
                 yield word + symbol


        elif chosen_rules in ('54','45'):
              word = word.capitalize()
              for symbol in symbols:
                 yield word + symbol



