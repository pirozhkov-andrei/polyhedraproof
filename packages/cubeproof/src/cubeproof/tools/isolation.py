"""Isolation wrappers and pinned binaries (specification §4.6, §5, §6.2; writer.machinery).

Every tool runs as ``setpriv --pdeathsig KILL -- prlimit --as=N [--fsize=M] --core=0 --
<binary> <args>``: both util-linux programs execute the next program in place, so the tool
keeps the process (and the process group/session the supervisor created), the kernel kills
it when the thread that started it dies, and its address space, file size and core dumps
are capped. :meth:`Isolation.probe` runs the complete chain once at startup.

A :class:`PinnedBinary` is the actual regular file behind a configured absolute path
(symlinks resolved once, at measurement) with its SHA-256. The supervisor re-hashes it
before every spawn and after every exit; a difference is ``binary_changed``. Tool paths
come from the CLI/API configuration and must match the campaign hashes
(:meth:`PinnedBinary.pinned`); they are never inferred from PATH or from artifacts.

Limits (specification §5 threat model): a same-UID writer that swaps the file between the hash and
the exec is excluded; the hash after exit detects ordinary replacement during a run.
``setpriv`` sets the parent-death signal only once it runs, and it does not look at its
parent: alone it would leave a tool running whose coordinator died while ``setpriv`` was
starting. The supervisor therefore sets the signal in the forked child before any exec and
checks the parent there (``tools.process``); ``setpriv`` repeats the setting. The startup
rules of the coordinator (never delete files of a surviving old process) remain for
processes that leave on their own, such as a descendant that a tool started.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from cubeproof.base.errors import ConfigurationError, ToolError

DEFAULT_SETPRIV = "/usr/bin/setpriv"
DEFAULT_PRLIMIT = "/usr/bin/prlimit"
#: The environment of every tool: nothing inherited (no CADICAL_* options, no PATH lookups).
TOOL_ENVIRONMENT: dict[str, str] = {"LC_ALL": "C"}
_PROBE_TIMEOUT_S = 30.0
_CHUNK = 1 << 20


def _absolute(name: str, path: object) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise ConfigurationError(f"tools.{name}", f"{path!r} is not an absolute local path")
    return path


def _regular_executable(path: str, rule: str) -> os.stat_result:
    try:
        info = os.stat(path)
    except FileNotFoundError:
        raise ToolError(f"{rule}.missing", path) from None
    except OSError as error:
        raise ToolError(f"{rule}.unreadable", f"{path}: {error}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ToolError(f"{rule}.not_regular", path)
    if not os.access(path, os.X_OK):
        raise ToolError(f"{rule}.not_executable", path)
    return info


def file_sha256(path: str) -> str | None:
    """SHA-256 of the regular file at ``path`` (no symlink followed), or None if unusable."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        digest = hashlib.sha256()
        while chunk := os.read(fd, _CHUNK):
            digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


@dataclass(frozen=True)
class PinnedBinary:
    """A tool binary: resolved absolute path of a regular executable file and its SHA-256."""

    path: str
    sha256: str

    @classmethod
    def measure(cls, path: str) -> PinnedBinary:
        """Resolve ``path`` once and hash the actual regular file (ToolError if unusable)."""
        real = os.path.realpath(_absolute("binary", path))
        _regular_executable(real, "tool")
        digest = file_sha256(real)
        if digest is None:
            raise ToolError("tool.unreadable", real)
        return cls(real, digest)

    @classmethod
    def pinned(cls, path: str, expected_sha256: str) -> PinnedBinary:
        """:meth:`measure`, then require the configured campaign hash."""
        binary = cls.measure(path)
        if binary.sha256 != expected_sha256:
            raise ToolError(
                "tool.hash_mismatch",
                f"{binary.path} has SHA-256 {binary.sha256}, the campaign pins {expected_sha256}",
            )
        return binary

    def changed(self) -> bool:
        """True unless the file at ``path`` is still a regular file with the pinned hash."""
        return file_sha256(self.path) != self.sha256

    def verify(self) -> None:
        if self.changed():
            raise ToolError("binary_changed", f"{self.path} is missing or no longer {self.sha256}")


@dataclass(frozen=True)
class Isolation:
    """Absolute paths of ``setpriv`` and ``prlimit`` that passed :meth:`probe`."""

    setpriv: str
    prlimit: str

    def wrap(
        self,
        executable: str,
        args: Sequence[str],
        *,
        memory_bytes: int,
        file_bytes: int | None,
    ) -> list[str]:
        """The complete command line of a tool under the parent-death signal and the caps."""
        limits = [f"--as={memory_bytes}"]
        if file_bytes is not None:
            limits.append(f"--fsize={file_bytes}")
        limits.append("--core=0")
        return [
            self.setpriv,
            "--pdeathsig",
            "KILL",
            "--",
            self.prlimit,
            *limits,
            "--",
            executable,
            *args,
        ]

    @classmethod
    def probe(cls, setpriv: str = DEFAULT_SETPRIV, prlimit: str = DEFAULT_PRLIMIT) -> Isolation:
        """Check that the whole wrapper chain runs here (util-linux >= 2.33 for pdeathsig)."""
        isolation = cls(_absolute("setpriv", setpriv), _absolute("prlimit", prlimit))
        _regular_executable(isolation.setpriv, "isolation.setpriv")
        _regular_executable(isolation.prlimit, "isolation.prlimit")
        command = isolation.wrap(
            isolation.setpriv, ("--version",), memory_bytes=1 << 30, file_bytes=1 << 20
        )
        try:
            probe = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=TOOL_ENVIRONMENT,
                timeout=_PROBE_TIMEOUT_S,
                start_new_session=True,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ToolError("isolation.probe", f"{command}: {error}") from error
        if probe.returncode != 0 or not probe.stdout.startswith(b"setpriv"):
            said = (probe.stderr or probe.stdout)[-2000:].decode("utf-8", "replace").strip()
            raise ToolError(
                "isolation.probe",
                f"the wrapper chain exited {probe.returncode} (util-linux 2.33 or later with "
                f"setpriv --pdeathsig and prlimit is required): {said}",
            )
        return isolation
