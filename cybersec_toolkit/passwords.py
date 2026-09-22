"""Local password generation and transparent, offline strength feedback.

Strength feedback is a heuristic, not a prediction of cracking time. Passwords
are never logged, stored, or transmitted by this module.
"""

from __future__ import annotations

import secrets
import string
from math import log2


AMBIGUOUS_CHARACTERS = frozenset("O0oIl1|")


def _enabled_groups(
    *,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
) -> list[str]:
    choices = (
        (use_lowercase, string.ascii_lowercase),
        (use_uppercase, string.ascii_uppercase),
        (use_digits, string.digits),
        (use_symbols, string.punctuation),
    )
    groups = [alphabet for enabled, alphabet in choices if enabled]
    if not groups:
        raise ValueError("enable at least one character group")
    if exclude_ambiguous:
        groups = [
            "".join(character for character in alphabet if character not in AMBIGUOUS_CHARACTERS)
            for alphabet in groups
        ]
    if any(not alphabet for alphabet in groups):
        raise ValueError("an enabled character group is empty")
    return groups


def estimate_pool_entropy(
    length: int = 20,
    *,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> float:
    """Return a uniform-pool entropy approximation in bits.

    The value is ``length * log2(pool size)``. It is not a cracking-time
    prediction and should not be applied to human-created passwords.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 1:
        raise ValueError("length must be at least 1")
    groups = _enabled_groups(
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous,
    )
    if length < len(groups):
        raise ValueError("length must cover every enabled character group")
    return round(length * log2(len("".join(groups))), 2)


def generate_password(
    length: int = 20,
    *,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generate a cryptographically random password.

    At least one character from each enabled group is guaranteed. The final
    order is shuffled with ``secrets.randbelow``, rather than ``random``.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 1:
        raise ValueError("length must be at least 1")

    groups = _enabled_groups(
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous,
    )
    if length < len(groups):
        raise ValueError("length must cover every enabled character group")

    characters = [secrets.choice(alphabet) for alphabet in groups]
    pool = "".join(groups)
    characters.extend(secrets.choice(pool) for _ in range(length - len(groups)))
    for index in range(len(characters) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        characters[index], characters[other] = characters[other], characters[index]
    return "".join(characters)


def analyze_password(password: str) -> dict[str, object]:
    """Return offline, explainable password feedback without retaining input.

    The score runs from 0 to 4. It is only a rough local heuristic; it cannot
    detect passwords exposed in breaches or determine real cracking time.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    classes = []
    if any(ch.islower() for ch in password):
        classes.append("lowercase")
    if any(ch.isupper() for ch in password):
        classes.append("uppercase")
    if any(ch.isdecimal() for ch in password):
        classes.append("digits")
    if any(not ch.isalnum() for ch in password):
        classes.append("symbols")

    length = len(password)
    score = sum(length >= threshold for threshold in (8, 12, 16))
    score += len(classes) >= 3
    score += len(classes) == 4
    score = min(4, score)

    lower = password.casefold()
    common = lower in {
        "password",
        "password123",
        "admin",
        "admin123",
        "qwerty",
        "qwerty123",
        "123456",
        "12345678",
        "123456789",
        "letmein",
        "welcome",
    }
    repeated = length >= 4 and len(set(password)) <= 2
    sequential = any(
        sequence in lower
        for sequence in ("1234", "2345", "abcd", "bcde", "qwerty", "asdf")
    )

    recommendations = []
    if length < 12:
        recommendations.append("Use at least 12 characters; a longer passphrase is often easier to remember.")
    if len(classes) < 3:
        recommendations.append("Consider adding a different character type or using a longer random passphrase.")
    if common:
        score = 0
        recommendations.append("Avoid widely used passwords and choose a unique secret.")
    if repeated:
        score = min(score, 1)
        recommendations.append("Avoid repeating the same characters.")
    if sequential:
        score = min(score, 2)
        recommendations.append("Avoid keyboard patterns and number or letter sequences.")

    return {
        "length": length,
        "character_classes": classes,
        "score": score,
        "rating": ("very weak", "weak", "fair", "strong", "very strong")[score],
        "recommendations": recommendations,
        "limitations": (
            "This offline heuristic is not a cracking-time estimate and does not "
            "check breach exposure or how the password was generated."
        ),
    }
