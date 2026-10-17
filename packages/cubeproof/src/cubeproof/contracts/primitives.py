"""Primitive types of specification §4.1 and the constants every layer shares.

Predicates (``is_*``) accept any Python object and return a bool; they never raise. An
integer is never a boolean. Patterns match the whole string with ASCII classes only, so a
final LF or a non-ASCII digit never passes.
"""

from __future__ import annotations

import re

from cubeproof.base.errors import ContractError
from cubeproof.base.paths import relpath_problem

INT_MAX = 2**63 - 1
#: Maximum number of split variables W (specification §3.2).
K_MAX = 20
#: The exact, complete checker stdout of an accepted proof (specification §4.8).
SUCCESS_LINE = "s VERIFIED UNSAT\n"

_HASH = re.compile(r"[0-9a-f]{64}")
_ID128 = re.compile(r"[0-9a-f]{32}")
_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_UTC = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z")

_MS_PER_DAY = 86_400_000
#: 0000-01-01T00:00:00.000Z and 9999-12-31T23:59:59.999Z, the range of the UTC form.
_MIN_MS = -62_167_219_200_000
_MAX_MS = 253_402_300_799_999


def _full(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def is_hash(value: object) -> bool:
    return _full(_HASH, value)


def is_id128(value: object) -> bool:
    return _full(_ID128, value)


def is_name(value: object) -> bool:
    return _full(_NAME, value)


def is_relpath(value: object) -> bool:
    return relpath_problem(value) is None


def is_int64(value: object) -> bool:
    return type(value) is int and -INT_MAX <= value <= INT_MAX


def is_nonnegative(value: object) -> bool:
    return type(value) is int and 0 <= value <= INT_MAX


def is_positive(value: object) -> bool:
    return type(value) is int and 1 <= value <= INT_MAX


def is_literal(value: object) -> bool:
    return is_int64(value) and value != 0


def _leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _month_days(year: int, month: int) -> int:
    return (31, 29 if _leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]


def utc_problem(value: object) -> str | None:
    """None for a valid UTC string; ``"schema"`` for a wrong form; ``"utc.calendar"`` for an
    impossible instant (requirement utc.calendar: month, day of month, hour, minute, second)."""
    if not isinstance(value, str):
        return "schema"
    match = _UTC.fullmatch(value)
    if match is None:
        return "schema"
    year, month, day, hour, minute, second = (int(x) for x in match.groups()[:6])
    if not 1 <= month <= 12 or not 1 <= day <= _month_days(year, month):
        return "utc.calendar"
    if hour > 23 or minute > 59 or second > 59:
        return "utc.calendar"
    return None


def is_utc(value: object) -> bool:
    return utc_problem(value) is None


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 in the proleptic Gregorian calendar (H. Hinnant's algorithm)."""
    year -= month <= 2
    era = year // 400
    year_of_era = year - era * 400
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    return era * 146_097 + day_of_era - 719_468


def _civil_from_days(days: int) -> tuple[int, int, int]:
    days += 719_468
    era = days // 146_097
    day_of_era = days - era * 146_097
    year_of_era = (
        day_of_era - day_of_era // 1460 + day_of_era // 36_524 - day_of_era // 146_096
    ) // 365
    day_of_year = day_of_era - (365 * year_of_era + year_of_era // 4 - year_of_era // 100)
    shifted = (5 * day_of_year + 2) // 153
    day = day_of_year - (153 * shifted + 2) // 5 + 1
    month = shifted + (3 if shifted < 10 else -9)
    return year_of_era + era * 400 + (month <= 2), month, day


def format_utc(milliseconds: int) -> str:
    """The UTC string ``YYYY-MM-DDTHH:MM:SS.mmmZ`` of milliseconds since the Unix epoch."""
    if type(milliseconds) is not int:
        raise TypeError("milliseconds must be an int")
    if not _MIN_MS <= milliseconds <= _MAX_MS:
        raise ValueError(f"{milliseconds} ms is outside years 0000-9999")
    days, rest = divmod(milliseconds, _MS_PER_DAY)
    year, month, day = _civil_from_days(days)
    seconds, ms = divmod(rest, 1000)
    minutes, second = divmod(seconds, 60)
    hour, minute = divmod(minutes, 60)
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.{ms:03d}Z"


def parse_utc(text: str) -> int:
    """Milliseconds since the Unix epoch of a valid UTC string (ContractError otherwise)."""
    problem = utc_problem(text)
    if problem is not None:
        raise ContractError(problem, f"{text!r} is not a valid UTC string")
    match = _UTC.fullmatch(text)
    assert match is not None
    year, month, day, hour, minute, second, ms = (int(x) for x in match.groups())
    days = _days_from_civil(year, month, day)
    return ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + ms
