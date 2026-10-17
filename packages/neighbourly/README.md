# neighbourly

Neighbourly maps, exact geometry and their CNF encodings.

`neighbourly` holds the mathematics that turns a combinatorial map into a formula: map
validation and enumeration, exact rational geometry, the S/H/A/B/I encoding and the gauge,
interpretation of models, controls, and the corpus of the 59 maps with twelve faces. Its
subpackage `neighbourly.cnf` is a problem-independent CNF emission module: deterministic
variables and clauses, witness checks, encodings, DIMACS and bundle writing.

The 59 base formulas are pinned by their SHA-256 hashes, and the exact geometric controls,
the comparison with a reference encoder in the tests and the stored structural fixtures
support the encoding. They do not prove the mathematical reduction, which is the article's,
and nothing here asserts a theorem for every `n`: the residue condition
`n mod 12 in {0, 3, 4, 7}` that the encoding entry checks is necessary, not asserted
sufficient, and the census of twelve faces is not a generic theorem.

## Install

```sh
python3 -m pip install packages/neighbourly
```

Python 3.10 or newer; no third-party dependency.

## Usage

```python
from neighbourly import corpus12

cmap = corpus12.load_map(1)  # map 1 of the 59 maps with twelve faces
encoder = corpus12.base_encoder(1)  # every layer S,H,A,B,I, gauge at face 1
print(encoder.variables, len(encoder.clauses))  # 5257 52177
formula = corpus12.base_formula(1)  # emits the formula and hashes its bytes
print(formula.sha256 == corpus12.formula_hashes()[1].sha256)  # True
```

The last line compares the emitted formula with the pinned hash of the package data.
`neighbourly.encoding.build_encoder(cmap, layers, gauge_face)` builds the formula of any
encodable map with a chosen selection of layers.

## Modules

`maps`, `enumeration`, `exact` and `geometry`, `encoding` (chirotope S/H/A, faces B/I, gauge,
formula), `interpret`, `checks`, `corpus12` (the 59 matrices, golden counts and hashes) and
`cnf` (builder, witness, encodings, DIMACS, bundle). The `faces12-campaign` package writes the
bundles of the 59 formulas from them and `cubeproof` reads those bundles.

## Boundaries

- Runtime dependencies: the Python standard library only.
- `neighbourly` never imports `cubeproof` or `faces12_campaign`.
- `neighbourly.cnf` imports only the standard library and its own submodules, never another
  `neighbourly` module, and reads no package data, so it is separable from the rest of the
  distribution.
- Generic modules do not import the twelve-face corpus. The library does not read the
  environment, print or exit.

The architecture tests of the repository check these rules, including transitive imports.

## Documentation

In the [repository](https://github.com/pirozhkov-andrei/polyhedraproof):
the article `paper/faces12-en.tex` (the mathematics of record), the
[theory map](../../docs/THEORY_MAP.md) from its statements to the code, the
[specification](../../docs/SPECIFICATION.md) (§3 and §13 for the formula bytes and this
package) and the [design decisions](../../docs/decisions/README.md).

## License

MIT, see `LICENSE`.
