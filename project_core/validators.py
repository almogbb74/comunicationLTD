import json
import os
import re

from typing import Set, Any, List
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from enums.password_validation_enum import PasswordValidationEnum
from django.conf import settings
from project_core.models import PreviousPassword
from project_core.secrets import PASSWORD_CONFIG_FILE_NAME, PASSWORD_DICT_FILE_NAME


def get_dictionary_words() -> Set:  # Loads the words dictionary
    dict_path = os.path.join(settings.BASE_DIR, PASSWORD_DICT_FILE_NAME)
    try:
        with open(dict_path, 'r') as f:
            return set(word.strip().lower() for word in f)
    except FileNotFoundError:
        return set()  # Return an empty set if the file is missing


def load_password_config() -> dict[str, Any]:  # Loads the config file
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
            "PASSWORD_HISTORY_COUNT": 3,
            "PREVENT_DICTIONARY_WORDS": True,
            "LOGIN_ATTEMPTS_MAX": 3,
            "LOCKOUT_DURATION_IN_MIN": 15
        }


def validate_password_rules(password: str) -> PasswordValidationEnum:  # Check the password according the config file
    config = load_password_config()

    # Check Length
    if len(password) < config['PASSWORD_LENGTH']:
        return PasswordValidationEnum.PASSWORD_LENGTH_SHORT

    # Check Uppercase
    if config['REQUIRE_UPPERCASE'] and not re.search(r'[A-Z]', password):
        return PasswordValidationEnum.PASSWORD_NO_UPPERCASE

    # Check Lowercase
    if config['REQUIRE_LOWERCASE'] and not re.search(r'[a-z]', password):
        return PasswordValidationEnum.PASSWORD_NO_LOWERCASE

    # Check Digits
    if config['REQUIRE_DIGITS'] and not re.search(r'\d', password):
        return PasswordValidationEnum.PASSWORD_NO_DIGITS

    # Check Special Chars
    if config['REQUIRE_SPECIAL_CHARS'] and not re.search(r'[\W_]', password):  # \W is "non-word" chars
        return PasswordValidationEnum.PASSWORD_NO_SPECIAL_CHARS

    # Check Dictionary Words
    if config['PREVENT_DICTIONARY_WORDS']:
        dictionary_words = get_dictionary_words()
        for w in dictionary_words:
            if w in password.lower():
                return PasswordValidationEnum.PASSWORD_IS_IN_DICTIONARY

    return PasswordValidationEnum.PASSWORD_VALID


def validate_password_history(user: User, new_password: str, history_count: int) -> PasswordValidationEnum:
    previous_passwords: List[PreviousPassword] = (
        list(user.previous_passwords.all().order_by('-created_at')))  # Get existing passwords

    for prev in previous_passwords[:history_count]:  # Check password reuse
        if check_password(new_password, prev.password):
            return PasswordValidationEnum.PASSWORD_PREVIOUSLY_USED  # Password exists in history

    PreviousPassword.objects.create(user=user, password=user.password)  # Save old current password into history

    updated_previous = list(
        user.previous_passwords.all().order_by('-created_at'))  # Refresh the list after adding new entry

    if len(updated_previous) > history_count:  # Enforce history count limit (Using for loop in case the policy changes, and we'll have to delete more than one)
        for pw in updated_previous[history_count:]:
            pw.delete()  # Remove the oldest passwords beyond history count from db

    return PasswordValidationEnum.PASSWORD_VALID
