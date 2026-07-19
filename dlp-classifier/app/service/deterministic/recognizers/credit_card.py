from __future__ import annotations

from presidio_analyzer import PatternRecognizer
from presidio_analyzer.predefined_recognizers import CreditCardRecognizer

_TEST_CARD_NUMBERS = {
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "5105105105105100",
    "5555555555554444",
    "371449635398431",
    "378282246310005",
    "6011111111111117",
    "6011000990139424",
    "3530111333300000",
    "3566002020360505",
}

_BIN_PREFIXES = (
    "4",  # Visa
    "51", "52", "53", "54", "55",  # Mastercard
    "34", "37",  # Amex
    "6011", "65",  # Discover
    "35",  # JCB
)


def _luhn_check(number: str) -> bool:
    """Standard Luhn (mod 10) checksum over a digit string."""
    total = 0
    parity = len(number) % 2
    for index, digit_char in enumerate(number):
        digit = int(digit_char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class CreditCardValidator(PatternRecognizer):

    def __init__(self) -> None:
        base = CreditCardRecognizer()
        super().__init__(
            supported_entity=base.supported_entities[0],
            patterns=base.patterns,
            context=base.context,
            name="CreditCardValidator",
        )

    def validate_result(self, pattern_text: str) -> bool:
        digits = "".join(char for char in pattern_text if char.isdigit())

        if not 13 <= len(digits) <= 19:
            return False

        if not any(digits.startswith(prefix) for prefix in _BIN_PREFIXES):
            return False

        if digits in _TEST_CARD_NUMBERS:
            return False

        return _luhn_check(digits)
