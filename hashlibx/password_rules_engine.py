#!/usr/bin/env python3

from itertools import product


RULE_SYMBOL_TRANSLATIONS = {'64', '46'}
RULE_NUMBER_TRANSLATIONS = {'61', '16'}
RULE_CAPITAL_TRANSLATIONS = {'56', '65'}
RULE_UPPER_TRANSLATIONS = {'26', '62'}
RULE_LOWER_TRANSLATIONS = {'36', '63'}

RULE_UPPER_NUMBERS = {'12', '21'}
RULE_LOWER_NUMBERS = {'13', '31'}
RULE_CAPITAL_NUMBERS = {'15', '51'}

RULE_UPPER_SYMBOLS = {'42', '24'}
RULE_LOWER_SYMBOLS = {'34', '43'}
RULE_CAPITAL_SYMBOLS = {'54', '45'}


def rules_parameters(
    word,
    rules,
    numbers,
    symbols,
    vocals,
    digits,
    translation_table,
    valid_rules
):

    if not rules:
        yield word
        return

    rule = rules[0] if len(rules) == 1 else ''.join(rules[:2])


    if rule not in valid_rules:
        yield word
        return

    chosen_rules = rule

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
        yield word.translate(translation_table)

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
                yield word + ''.join(combo)

    elif chosen_rules in RULE_SYMBOL_TRANSLATIONS:
        word = word.translate(translation_table)

        for symbol in symbols:
            yield word + symbol

    elif chosen_rules in RULE_NUMBER_TRANSLATIONS:
        word = word.translate(translation_table)

        for number in numbers:
            yield word + number

    elif chosen_rules in RULE_CAPITAL_TRANSLATIONS:
        word = word.translate(translation_table)
        yield word.capitalize()

    elif chosen_rules in RULE_UPPER_TRANSLATIONS:
        word = word.translate(translation_table)
        yield word.upper()

    elif chosen_rules in RULE_LOWER_TRANSLATIONS:
        word = word.translate(translation_table)
        yield word.lower()

    elif chosen_rules in RULE_UPPER_NUMBERS:
        word = word.upper()

        for number in numbers:
            yield word + number

    elif chosen_rules in RULE_LOWER_NUMBERS:
        word = word.lower()

        for number in numbers:
            yield word + number

    elif chosen_rules in RULE_CAPITAL_NUMBERS:
        word = word.capitalize()

        for number in numbers:
            yield word + number

    elif chosen_rules in RULE_UPPER_SYMBOLS:
        word = word.upper()

        for symbol in symbols:
            yield word + symbol

    elif chosen_rules in RULE_LOWER_SYMBOLS:
        word = word.lower()

        for symbol in symbols:
            yield word + symbol

    elif chosen_rules in RULE_CAPITAL_SYMBOLS:
        word = word.capitalize()

        for symbol in symbols:
            yield word + symbol

    elif chosen_rules == 'lcu':
        yield word[:1].lower() + word[1:].upper()
