"""Import and boundary rules of the packages (specification §2.1 and §2.3).

Static analysis with the standard library only: every runtime module of the three packages
is parsed, its imports are resolved to modules, and the rules below are checked on the
direct edges *and* on the transitive closure, so a forbidden dependency cannot be hidden
behind another module. Importing a submodule executes the ``__init__`` of every parent
package, so parent packages are part of every closure.

Rules (the code of a finding is in brackets):

- [DIST] a package imports only the standard library, itself and the distributions its
  ``pyproject.toml`` declares (cubeproof and neighbourly: none; faces12-campaign: the two).
- [UNKNOWN] every module belongs to a named layer; a new subsystem is listed here first.
- [LAYER] a direct import goes to the same subsystem, to an allowed lower layer, or to a
  package root (which itself imports nothing of the package).
- [TRANSITIVE] the same rule on the transitive closure, including parent packages.
- [PURE] the certifier, the evidence readers, CNF and contracts reach no process,
  thread, signal, socket or resource module, and no process function of ``os``
  (``os.fork``, ``os.system``, ``os.exec*`` ...), through any chain ("pure base helpers").
- [CYCLE] no import cycle between modules of a package.
- [DYNAMIC] no import, code execution or module loading from computed strings.
- [IMPORT] no relative import beyond the top-level package.
- [ENV] only the command-line boundary reads the environment or the process arguments.
- [OUTPUT] only the command-line boundary prints, writes to the standard streams, exits or
  raises SystemExit.
- [SEALED] ``neighbourly.cnf`` reaches only itself and the standard library.
- [DATA] ``neighbourly.cnf`` reads no package data (no importlib.resources, pkgutil,
  ``__file__``).
- [INDEPENDENT] the independent certifier and the spec-vector generator import only the
  standard library and their own files.

Run ``python3 tools/checks/archcheck.py [ROOT]`` to print the findings of a checkout.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - CPython 3.10
    import tomli as tomllib

STDLIB: frozenset[str] = frozenset(sys.stdlib_module_names)

#: Standard-library modules that start or control processes, threads, signals, sockets or
#: resource limits. "Pure" layers must not reach them through any chain of imports.
PROCESS_STDLIB: frozenset[str] = frozenset(
    {
        "subprocess",
        "multiprocessing",
        "concurrent",
        "signal",
        "resource",
        "socket",
        "ctypes",
        "asyncio",
        "threading",
        "_thread",
        "selectors",
        "pty",
    }
)

#: Functions of ``os`` that start, replace, wait for or signal processes without importing a
#: PROCESS_STDLIB module. Any reference counts, not only a call (``run = os.system``).
PROCESS_NAMES: frozenset[str] = frozenset(
    {
        "os.fork",
        "os.forkpty",
        "os.system",
        "os.popen",
        "os.kill",
        "os.killpg",
        "os.wait",
        "os.wait3",
        "os.wait4",
        "os.waitid",
        "os.waitpid",
        "os.pidfd_open",
        "os.register_at_fork",
        "os.startfile",
        "os.posix_spawn",
        "os.posix_spawnp",
    }
)
#: Families of such functions: ``os.execv``, ``os.execlpe``, ``os.spawnl`` ...
PROCESS_PREFIXES: tuple[str, ...] = ("os.exec", "os.spawn")

#: Qualified names that read the process environment or arguments.
ENV_NAMES: frozenset[str] = frozenset(
    {
        "os.environ",
        "os.environb",
        "os.getenv",
        "os.getenvb",
        "os.putenv",
        "os.unsetenv",
        "posix.environ",
        "nt.environ",
        "sys.argv",
        "sys.orig_argv",
    }
)

#: Calls that print or end the process.
OUTPUT_CALLS: frozenset[str] = frozenset(
    {"print", "exit", "quit", "sys.exit", "os._exit", "os.abort", "builtins.print"}
)
#: Calls on the standard streams (``sys.stdout.write``, ``sys.stderr.flush`` ...).
OUTPUT_PREFIXES: tuple[str, ...] = (
    "sys.stdout.",
    "sys.stderr.",
    "sys.__stdout__.",
    "sys.__stderr__.",
)


def is_process_name(name: str) -> bool:
    """A qualified name of PROCESS_NAMES or of a PROCESS_PREFIXES family."""
    return name in PROCESS_NAMES or name.startswith(PROCESS_PREFIXES)


#: Calls that import, load or execute code named by a runtime value.
DYNAMIC_CALLS: frozenset[str] = frozenset(
    {
        "importlib.import_module",
        "importlib.__import__",
        "__import__",
        "exec",
        "eval",
        "runpy.run_module",
        "runpy.run_path",
        "importlib.util.spec_from_file_location",
        "importlib.util.module_from_spec",
        "importlib.machinery.SourceFileLoader",
    }
)

#: Modules and names through which code reads files shipped inside its package.
DATA_MODULES: tuple[str, ...] = (
    "importlib.resources",
    "importlib_resources",
    "pkgutil",
    "pkg_resources",
)
DATA_NAMES: frozenset[str] = frozenset({"__file__", "__spec__", "__loader__"})


@dataclass(frozen=True, order=True)
class Violation:
    rule: str
    module: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.module}: {self.detail}"


@dataclass(frozen=True)
class Layer:
    """A named subsystem: module prefixes and the layers it may import.

    ``exact`` layers match only the module itself (a package ``__init__``). ``root`` layers
    are package roots: everyone may import them and they may import nothing of the package.
    ``pure`` layers must not reach PROCESS_STDLIB. ``boundary`` layers may read the
    environment, print and exit.
    """

    name: str
    prefixes: tuple[str, ...]
    allowed: frozenset[str] = frozenset()
    exact: bool = False
    root: bool = False
    pure: bool = False
    boundary: bool = False

    def match_length(self, module: str) -> int:
        """Length of the matching prefix, or -1."""
        best = -1
        for prefix in self.prefixes:
            if module == prefix or (not self.exact and module.startswith(prefix + ".")):
                best = max(best, len(prefix))
        return best


@dataclass
class Module:
    name: str
    path: Path
    is_package: bool
    imports: list[tuple[str, int]] = field(default_factory=list)
    dynamic: list[tuple[str, int]] = field(default_factory=list)
    env_reads: list[tuple[str, int]] = field(default_factory=list)
    outputs: list[tuple[str, int]] = field(default_factory=list)
    data_reads: list[tuple[str, int]] = field(default_factory=list)
    process_refs: list[tuple[str, int]] = field(default_factory=list)
    problems: list[tuple[str, int]] = field(default_factory=list)


@dataclass(frozen=True)
class Distribution:
    """One package: where its sources are and which rules apply."""

    name: str
    top: str
    src: Path
    requires: frozenset[str]
    layers: tuple[Layer, ...]
    sealed: tuple[str, ...] = ()


# -- layer tables ------------------------------------------------------------------------------


def _layer(
    name: str,
    prefixes: str | Sequence[str],
    allowed: Iterable[str] = (),
    **flags: bool,
) -> Layer:
    pre = (prefixes,) if isinstance(prefixes, str) else tuple(prefixes)
    return Layer(name, pre, frozenset(allowed), **flags)


_CP_BELOW_ENTRY = (
    "commands",
    "coordinator",
    "leaf",
    "split",
    "certify",
    "schema",
    "journal",
    "tools",
    "cnf",
    "contracts",
    "base",
)

#: cubeproof, specification §2.3. "Evidence storage" for leaf and split is read
#: as the journal and its storage/recovery primitives (evidence.journal); a separate
#: evidence storage subsystem would be a layer of its own here.
CUBEPROOF_LAYERS: tuple[Layer, ...] = (
    _layer("root", "cubeproof", exact=True, root=True),
    _layer("evidence-root", "cubeproof.evidence", exact=True, root=True),
    _layer("cli", ("cubeproof.cli", "cubeproof.__main__"), _CP_BELOW_ENTRY, boundary=True),
    _layer("api", "cubeproof.api", _CP_BELOW_ENTRY),
    _layer("commands", "cubeproof.commands", _CP_BELOW_ENTRY[1:]),
    _layer("coordinator", "cubeproof.coordinator", _CP_BELOW_ENTRY[2:]),
    _layer("leaf", "cubeproof.leaf", ("schema", "journal", "tools", "cnf", "contracts", "base")),
    _layer("split", "cubeproof.split", ("schema", "journal", "tools", "cnf", "contracts", "base")),
    _layer(
        "certify",
        "cubeproof.evidence.certify",
        ("schema", "journal", "cnf", "contracts", "base"),
        pure=True,
    ),
    _layer("schema", "cubeproof.evidence.schema", ("contracts", "base"), pure=True),
    _layer("journal", "cubeproof.evidence.journal", ("contracts", "base"), pure=True),
    # The stream relay runs as its own isolated process (python -I -S, specification §6.4):
    # it reads its arguments and exits with a status, so it is a boundary; it imports only
    # the standard library (an empty allowed set within the package).
    _layer("tools", "cubeproof.tools.relay", (), exact=True, boundary=True),
    _layer("tools", "cubeproof.tools", ("cnf", "contracts", "base")),
    _layer("cnf", "cubeproof.cnf", ("contracts", "base"), pure=True),
    _layer("contracts", "cubeproof.contracts", ("base",), pure=True),
    _layer("base", "cubeproof.base"),
)

_NB_GENERIC = ("encoding", "enumeration", "exact", "maps", "cnf")

#: neighbourly, specification §2.1, §2.3 and §13.2. "exact/geometry" is one
#: subsystem under either name. Pure helpers of the lowest layer have no named layer.
NEIGHBOURLY_LAYERS: tuple[Layer, ...] = (
    _layer("root", "neighbourly", exact=True, root=True),
    _layer("cnf", "neighbourly.cnf"),
    _layer("data", "neighbourly.data"),
    _layer("maps", "neighbourly.maps", ("cnf",)),
    _layer("exact", ("neighbourly.exact", "neighbourly.geometry"), ("maps", "cnf")),
    _layer("enumeration", "neighbourly.enumeration", ("maps", "cnf")),
    _layer("encoding", "neighbourly.encoding", ("maps", "cnf")),
    _layer("interpret", "neighbourly.interpret", _NB_GENERIC),
    _layer("checks", "neighbourly.checks", _NB_GENERIC),
    _layer("corpus12", "neighbourly.corpus12", (*_NB_GENERIC, "data")),
)

_FC_ADAPTERS = ("release", "campaign", "claim", "formulas", "model")

#: faces12_campaign, specification §2.3 (adapters: release/campaign/claim, plus
#: the formulas and model adapters). The libraries are distributions. ``pins`` holds the
#: hashes of the release tools, constants that the campaign and claim adapters share; it
#: imports nothing of the application.
CAMPAIGN_LAYERS: tuple[Layer, ...] = (
    _layer("root", "faces12_campaign", exact=True, root=True),
    _layer(
        "cli",
        ("faces12_campaign.cli", "faces12_campaign.__main__"),
        ("commands", *_FC_ADAPTERS, "pins"),
        boundary=True,
    ),
    _layer("api", "faces12_campaign.api", ("commands", *_FC_ADAPTERS, "pins")),
    _layer("commands", "faces12_campaign.commands", (*_FC_ADAPTERS, "pins")),
    *(_layer(name, f"faces12_campaign.{name}", ("pins",)) for name in _FC_ADAPTERS),
    _layer("pins", "faces12_campaign.pins"),
)

LAYER_TABLES: Mapping[str, tuple[Layer, ...]] = {
    "cubeproof": CUBEPROOF_LAYERS,
    "neighbourly": NEIGHBOURLY_LAYERS,
    "faces12_campaign": CAMPAIGN_LAYERS,
}
SEALED: Mapping[str, tuple[str, ...]] = {"neighbourly": ("neighbourly.cnf",)}

#: Standalone tools that must not import the project.
INDEPENDENT_TOOLS: tuple[str, ...] = ("tools/certify_min.py", "tools/spec_vectors")


# -- scanning ----------------------------------------------------------------------------------


def import_name(distribution: str) -> str:
    """Import name of one of our distributions (``faces12-campaign`` -> ``faces12_campaign``)."""
    return distribution.replace("-", "_").lower()


def requirement_name(requirement: str) -> str:
    """The project name of a PEP 508 requirement string."""
    name = requirement.strip()
    for stop in "<>=!~;[ (@":
        name = name.split(stop, 1)[0]
    return name.strip()


def _module_name(root: Path, path: Path) -> tuple[str, bool]:
    parts = list(path.relative_to(root).with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


class _Visitor(ast.NodeVisitor):
    def __init__(self, module: Module) -> None:
        self.module = module
        self.aliases: dict[str, str] = {}
        package = module.name.split(".")
        self.package = package if module.is_package else package[:-1]

    # name resolution
    def qualname(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qualname(node.value)
            return None if base is None else f"{base}.{node.attr}"
        return None

    def _absolute(self, level: int, name: str | None, line: int) -> str | None:
        if level == 0:
            return name
        up = level - 1
        if up >= len(self.package):
            self.module.problems.append(("relative import beyond the top-level package", line))
            return None
        base = self.package[: len(self.package) - up]
        return ".".join([*base, name] if name else base)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.module.imports.append((alias.name, node.lineno))
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                self.aliases[top] = top
            self._check_imported(alias.name, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        target = self._absolute(node.level, node.module, node.lineno)
        if target is None:
            return
        # Only the full names are recorded: `from p import m` depends on the submodule p.m
        # when it exists and on p otherwise (resolve() picks the longest known prefix).
        # The package p itself runs as a parent of p.m and is added by closure_paths().
        for alias in node.names:
            if alias.name == "*":
                self.module.imports.append((target, node.lineno))
                self._check_imported(target, node.lineno)
                continue
            full = f"{target}.{alias.name}"
            self.module.imports.append((full, node.lineno))
            self.aliases[alias.asname or alias.name] = full
            self._check_imported(full, node.lineno)

    def _check_imported(self, name: str, line: int) -> None:
        if name in ENV_NAMES:
            self.module.env_reads.append((name, line))
        if name.startswith(DATA_MODULES):
            self.module.data_reads.append((name, line))
        if is_process_name(name):
            self.module.process_refs.append((name, line))

    def visit_Call(self, node: ast.Call) -> None:
        name = self.qualname(node.func)
        if name in DYNAMIC_CALLS:
            first = node.args[0] if node.args else None
            constant = isinstance(first, ast.Constant) and isinstance(first.value, str)
            if (
                name in {"importlib.import_module", "__import__", "importlib.__import__"}
                and constant
            ):
                assert isinstance(first, ast.Constant)
                text = str(first.value)
                if text.startswith("."):
                    self.module.dynamic.append((f"{name}({text!r}) relative", node.lineno))
                else:
                    self.module.imports.append((text, node.lineno))
            else:
                self.module.dynamic.append((name, node.lineno))
        if name is not None and (name in OUTPUT_CALLS or name.startswith(OUTPUT_PREFIXES)):
            self.module.outputs.append((name, node.lineno))
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        if exc is not None and self.qualname(exc) in {"SystemExit", "builtins.SystemExit"}:
            self.module.outputs.append(("raise SystemExit", node.lineno))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = self.qualname(node)
        if name in ENV_NAMES:
            self.module.env_reads.append((name, node.lineno))
        if name is not None and name.startswith(DATA_MODULES):
            self.module.data_reads.append((name, node.lineno))
        if name is not None and is_process_name(name):
            self.module.process_refs.append((name, node.lineno))
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in DATA_NAMES:
            self.module.data_reads.append((node.id, node.lineno))
        name = self.aliases.get(node.id)
        if name in ENV_NAMES and isinstance(node.ctx, ast.Load):
            self.module.env_reads.append((name, node.lineno))
        self.generic_visit(node)


def parse_module(name: str, path: Path, is_package: bool) -> Module:
    module = Module(name, path, is_package)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    _Visitor(module).visit(tree)
    return module


def scan(src: Path, top: str) -> dict[str, Module]:
    """All modules of package ``top`` below the source root ``src``."""
    modules: dict[str, Module] = {}
    base = src / top
    if not base.is_dir():
        return modules
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        name, is_package = _module_name(src, path)
        modules[name] = parse_module(name, path, is_package)
    return modules


# -- graph helpers -----------------------------------------------------------------------------


def resolve(name: str, modules: Mapping[str, Module]) -> str | None:
    """The most specific known module for a dotted import target."""
    parts = name.split(".")
    for cut in range(len(parts), 0, -1):
        candidate = ".".join(parts[:cut])
        if candidate in modules:
            return candidate
    return None


def parents(name: str) -> Iterator[str]:
    parts = name.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        yield ".".join(parts[:cut])


def explicit_edges(modules: Mapping[str, Module]) -> dict[str, dict[str, int]]:
    """module -> {imported internal module: first line}."""
    edges: dict[str, dict[str, int]] = {}
    for name, module in modules.items():
        out: dict[str, int] = {}
        for target, line in module.imports:
            resolved = resolve(target, modules)
            if resolved is not None and resolved != name:
                out.setdefault(resolved, line)
        edges[name] = out
    return edges


def closure_paths(
    start: str, edges: Mapping[str, Mapping[str, int]], modules: Mapping[str, Module]
) -> dict[str, list[str]]:
    """Every module reached from ``start`` (parents included) with one shortest path."""
    paths: dict[str, list[str]] = {start: [start]}
    queue = [start]
    while queue:
        current = queue.pop(0)
        nexts = list(edges.get(current, {}))
        nexts += [p for p in parents(current) if p in modules]
        for target in nexts:
            if target not in paths:
                paths[target] = [*paths[current], target]
                queue.append(target)
    return paths


def cycles(edges: Mapping[str, Mapping[str, int]]) -> list[list[str]]:
    """Strongly connected components with more than one module (Tarjan, iterative)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    found: list[list[str]] = []
    counter = 0
    for root in sorted(edges):
        if root in index:
            continue
        work: list[tuple[str, Iterator[str]]] = [(root, iter(sorted(edges[root])))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in edges:
                    continue
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(edges[child]))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    component.append(item)
                    if item == node:
                        break
                if len(component) > 1:
                    found.append(sorted(component))
    return sorted(found)


# -- rules -------------------------------------------------------------------------------------


def layer_of(module: str, layers: Sequence[Layer]) -> Layer | None:
    best: tuple[int, Layer] | None = None
    for layer in layers:
        length = layer.match_length(module)
        if length >= 0 and (best is None or length > best[0]):
            best = (length, layer)
    return None if best is None else best[1]


def _permitted(source: Layer, target: Layer) -> bool:
    return target.name == source.name or target.root or target.name in source.allowed


def _in_sealed(module: str, sealed: Sequence[str]) -> str | None:
    for prefix in sealed:
        if module == prefix or module.startswith(prefix + "."):
            return prefix
    return None


def check_distribution(dist: Distribution) -> list[Violation]:
    """Every finding for one package."""
    modules = scan(dist.src, dist.top)
    found: list[Violation] = []
    edges = explicit_edges(modules)
    layers = {name: layer_of(name, dist.layers) for name in modules}

    for name, module in sorted(modules.items()):
        layer = layers[name]
        sealed = _in_sealed(name, dist.sealed)
        for text, line in module.problems:
            found.append(Violation("IMPORT", name, f"line {line}: {text}"))
        # [DIST]
        for target, line in module.imports:
            top = target.split(".")[0]
            if top in STDLIB or top == dist.top:
                continue
            if top in dist.requires and sealed is None:
                continue
            found.append(
                Violation(
                    "DIST", name, f"line {line}: imports {target}, not declared by {dist.name}"
                )
            )
        if layer is None:
            found.append(
                Violation("UNKNOWN", name, "module is in no layer of the architecture rules")
            )
        # [DYNAMIC]
        for text, line in module.dynamic:
            found.append(Violation("DYNAMIC", name, f"line {line}: {text}"))
        boundary = layer is not None and layer.boundary
        # [ENV]
        if not boundary:
            for text, line in module.env_reads:
                found.append(Violation("ENV", name, f"line {line}: reads {text} outside the CLI"))
            # [OUTPUT]
            for text, line in module.outputs:
                found.append(Violation("OUTPUT", name, f"line {line}: {text} outside the CLI"))
        if sealed is not None:
            for text, line in module.data_reads:
                found.append(Violation("DATA", name, f"line {line}: {text} reads package data"))
        if layer is None:
            continue
        # [LAYER] direct edges (sealed packages are covered by [SEALED])
        for target, line in sorted(edges[name].items()):
            target_layer = layers[target]
            if sealed is not None:
                if _in_sealed(target, (sealed,)) is None and not _is_parent(target, name):
                    found.append(
                        Violation("SEALED", name, f"line {line}: imports {target} outside {sealed}")
                    )
                continue
            if target_layer is not None and not _permitted(layer, target_layer):
                found.append(
                    Violation(
                        "LAYER",
                        name,
                        f"line {line}: layer {layer.name} may not import {target} "
                        f"(layer {target_layer.name})",
                    )
                )
        # closure rules; a layer already imported directly is reported once, by [LAYER]
        paths = closure_paths(name, edges, modules)
        direct_layers = {
            target_layer.name
            for target_layer in (layers[t] for t in edges[name])
            if target_layer is not None
        }
        for target, path in sorted(paths.items()):
            if target == name:
                continue
            target_layer = layers[target]
            chain = " -> ".join(path)
            direct = target in edges[name]
            if sealed is not None:
                if _in_sealed(target, (sealed,)) is None:
                    if not _is_parent(target, name):
                        if not direct:
                            found.append(Violation("SEALED", name, f"reaches {target}: {chain}"))
                    elif edges.get(target):
                        found.append(
                            Violation(
                                "SEALED",
                                name,
                                f"parent package {target} imports "
                                f"{', '.join(sorted(edges[target]))}: {chain}",
                            )
                        )
                continue
            if direct or target_layer is None or target_layer.name in direct_layers:
                continue
            if not _permitted(layer, target_layer):
                found.append(
                    Violation(
                        "TRANSITIVE",
                        name,
                        f"reaches {target} (layer {target_layer.name}): {chain}",
                    )
                )
        if layer.pure:
            for target, path in sorted(paths.items()):
                impure = sorted(
                    {(line, imported.split(".")[0]) for imported, line in modules[target].imports}
                )
                for line, top in impure:
                    if top in PROCESS_STDLIB:
                        found.append(
                            Violation(
                                "PURE",
                                name,
                                f"reaches {top} ({target} line {line}): {' -> '.join(path)}",
                            )
                        )
                for text, line in modules[target].process_refs:
                    found.append(
                        Violation(
                            "PURE",
                            name,
                            f"reaches {text} ({target} line {line}): {' -> '.join(path)}",
                        )
                    )
    # [CYCLE]
    for component in cycles(edges):
        found.append(Violation("CYCLE", component[0], "import cycle: " + ", ".join(component)))
    return sorted(set(found))


def _is_parent(candidate: str, module: str) -> bool:
    return module.startswith(candidate + ".")


def check_standalone(path: Path, label: str) -> list[Violation]:
    """A tool that may import only the standard library and its own files.

    ``path`` is one script or a directory. In a directory, the tool's own modules are the
    directory as a package and its top-level files run as scripts.
    """
    if path.is_dir():
        files = sorted(p for p in path.rglob("*.py") if "__pycache__" not in p.parts)
        local = {path.name} | {p.stem for p in path.glob("*.py")}
    else:
        files, local = [path], set()
    found: list[Violation] = []
    for file in files:
        name = f"{label}/{file.relative_to(path).as_posix()}" if path.is_dir() else label
        module_name, is_package = _module_name(path.parent, file)
        module = parse_module(module_name, file, is_package)
        for target, line in module.imports:
            top = target.split(".")[0]
            if top in STDLIB or top in local:
                continue
            found.append(
                Violation(
                    "INDEPENDENT",
                    name,
                    f"line {line}: imports {target}; only the standard library is allowed",
                )
            )
        for text, line in module.dynamic:
            found.append(Violation("DYNAMIC", name, f"line {line}: {text}"))
        for text, line in module.problems:
            found.append(Violation("IMPORT", name, f"line {line}: {text}"))
    return sorted(set(found))


# -- the repository ----------------------------------------------------------------------------


def load_pyproject(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        data: dict[str, object] = tomllib.load(handle)
    return data


def package_dirs(root: Path) -> list[Path]:
    return sorted(p.parent for p in (root / "packages").glob("*/pyproject.toml"))


def distribution(package_dir: Path) -> Distribution:
    data = load_pyproject(package_dir / "pyproject.toml")
    project = data["project"]
    assert isinstance(project, dict)
    name = str(project["name"])
    top = import_name(name)
    requires = frozenset(import_name(requirement_name(r)) for r in project.get("dependencies", []))
    return Distribution(
        name=name,
        top=top,
        src=package_dir / "src",
        requires=requires,
        layers=LAYER_TABLES.get(top, ()),
        sealed=SEALED.get(top, ()),
    )


def check_repository(root: Path) -> list[Violation]:
    found: list[Violation] = []
    for package_dir in package_dirs(root):
        dist = distribution(package_dir)
        if dist.top not in LAYER_TABLES:
            found.append(Violation("UNKNOWN", dist.top, "package has no layer table"))
        found += check_distribution(dist)
    for relative in INDEPENDENT_TOOLS:
        path = root / relative
        if path.exists():
            found += check_standalone(path, relative)
    return found


def main(argv: Sequence[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    found = check_repository(root)
    for violation in found:
        print(violation)
    print(f"{len(found)} architecture findings")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
