from enum import Enum, auto


class PasswordValidationEnum(Enum):
    PASSWORD_VALID = auto()
    PASSWORD_LENGTH_SHORT = auto()
    PASSWORD_NO_UPPERCASE = auto()
    PASSWORD_NO_LOWERCASE = auto()
    PASSWORD_NO_DIGITS = auto()
    PASSWORD_NO_SPECIAL_CHARS = auto()
    PASSWORD_IS_IN_DICTIONARY = auto()
    PASSWORD_INVALID_DEFAULT = auto()
