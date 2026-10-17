"""The typed error vocabulary of cubeproof (specification §2.3, §4.1, §12.2).

Library code raises these; only the command-line boundary turns them into messages and exit
codes. Every error names the violated rule: the identifier of the requirement matrix
``schemas/cubeproof/v1/requirements.json`` where one exists (``schema``, ``cube.range``,
``limit.depth`` ...), otherwise a dotted name of the condition (``settings.reader_depth``).

The same contract violation has different consequences in different contexts (requirements
matrix, column ``violation``): a malformed value is a plain rejection when a document is
checked on its own, an input error in a campaign, an integrity error in a journal. Readers
of single values therefore raise :class:`ContractError`; the code that knows the context
converts it with :func:`contextualize`. Hitting a reader limit is always a
:class:`ResourceError`, never an integrity or input verdict.
"""

from __future__ import annotations

from typing import ClassVar, TypeVar


class CubeproofError(Exception):
    """Base class of every error cubeproof raises deliberately."""

    kind: ClassVar[str] = "error"

    def __init__(self, rule: str, detail: str = "", *, location: str | None = None) -> None:
        self.rule = rule
        self.detail = detail
        self.location = location
        where = f" at {location}" if location is not None else ""
        text = f"{self.kind}: {rule}{where}"
        super().__init__(f"{text}: {detail}" if detail else text)


class ConfigurationError(CubeproofError):
    """A setting or request is unusable (usage/configuration, exit 3 at the CLI)."""

    kind: ClassVar[str] = "configuration"


class ToolError(CubeproofError):
    """A required external tool is missing, changed or unusable (exit 5 at the CLI)."""

    kind: ClassVar[str] = "tool"


class ResourceError(CubeproofError):
    """A reader limit or another resource bound was reached; never permission to ignore input."""

    kind: ClassVar[str] = "resource"


class ContractError(CubeproofError):
    """A value violates a contract rule; the context decides the consequence."""

    kind: ClassVar[str] = "reject"


class InputError(ContractError):
    """A malformed input of a command (campaign, bundle, explicit file); exit 4 for certify."""

    kind: ClassVar[str] = "input"


class IntegrityError(ContractError):
    """Committed evidence disagrees with itself or with the regenerated formula (exit 4)."""

    kind: ClassVar[str] = "integrity"


_Contextual = TypeVar("_Contextual", bound=ContractError)


def contextualize(error: CubeproofError, cls: type[_Contextual]) -> CubeproofError:
    """``error`` as seen in a context whose violations are ``cls`` (input or integrity).

    A plain :class:`ContractError` becomes ``cls`` with the same rule, detail and location
    (chained to the original). Resource errors and errors already classified (input,
    integrity, tool, configuration) are returned unchanged.
    """
    if type(error) is not ContractError:
        return error
    converted = cls(error.rule, error.detail, location=error.location)
    converted.__cause__ = error
    return converted
