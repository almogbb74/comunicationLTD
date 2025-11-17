import json
import os
import re
from django.conf import settings
from project_core.secrets import PASSWORD_CONFIG_FILE_NAME, PASSWORD_DICT_FILE_NAME


def get_dictionary_words():  # Loads the words dictionary
    dict_path = os.path.join(settings.BASE_DIR, PASSWORD_DICT_FILE_NAME)
    try:
        with open(dict_path, 'r') as f:
            return set(word.strip().lower() for word in f)
    except FileNotFoundError:
        return set()  # Return an empty set if the file is missing


def load_password_config():  # Loads the config file
    config_path = os.path.join(settings.BASE_DIR, PASSWORD_CONFIG_FILE_NAME)
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback if config file is missing
        return {
            "PASSWORD_LENGTH": 10,
            "REQUIRE_UPPERCASE": True,
            "REQUIRE_LOWERCASE": True,
            "REQUIRE_DIGITS": True,
            "REQUIRE_SPECIAL_CHARS": True,
            "PREVENT_DICTIONARY_WORDS": True,
        }


def validate_password_rules(password):  # Check the password according the config file
    config = load_password_config()

    # Check Length
    if len(password) < config['PASSWORD_LENGTH']:
        return False

    # Check Uppercase
    if config['REQUIRE_UPPERCASE'] and not re.search(r'[A-Z]', password):
        return False

    # Check Lowercase
    if config['REQUIRE_LOWERCASE'] and not re.search(r'[a-z]', password):
        return False

    # Check Digits
    if config['REQUIRE_DIGITS'] and not re.search(r'\d', password):
        return False

    # Check Special Chars
    if config['REQUIRE_SPECIAL_CHARS'] and not re.search(r'[\W_]', password):  # \W is "non-word" chars
        return False

    # Check Dictionary Words
    if config['PREVENT_DICTIONARY_WORDS']:
        dictionary_words = get_dictionary_words()
        if password.lower() in dictionary_words:
            return False

    # TODO: Implement Password History check

    return True
