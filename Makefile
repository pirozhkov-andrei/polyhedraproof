# The things anybody needs.
#
# Standard checks (one stable meaning each; see docs/CONTRIBUTING.md):
#
#   make install-dev        the three packages and the meta-package, editable, with the pinned development tools
#   make lint               style and types (mypy --strict), and that the claims documents are consistent
#   make test-architecture  the package boundaries, import rules, configuration, claims documents and release list
#   make test-release-view  the release view (RELEASE_FILES.txt) passes its own fast suites
#   make test-fast          every fast test of the packages and the shared suites, except tests/architecture (run by test-architecture) and tests/release (run by test-installed); no slow or image tests
#   make test-installed     wheels and sdists in clean environments outside the checkout
#   make test-all           every supported test; only inside the declared Linux test image
#
# Other targets:
#
#   make docs        regenerate the generated blocks of docs/CLAIMS.md and docs/THEORY_MAP.md
#   make maps        recompute the census of the maps with twelve faces (paper: thm:59)
#   make image       build the release image
#   make paper       rebuild the article twice and check the PDF
#   make bundle      the deterministic source archive, under dist/
#   make format      apply the formatter and the automatic lint fixes
#   make clean       remove tool caches, __pycache__ directories and LaTeX build files
#
.PHONY: install-dev lint test-architecture test-release-view test-fast test-installed test-all \
	format docs maps image paper bundle clean

PYTHON  ?= python3
PYTEST  ?= $(PYTHON) -m pytest
VERSION := $(shell sed -n 's/^version = "\(.*\)"$$/\1/p' packages/cubeproof/pyproject.toml)
IMAGE   ?= faces12-campaign:$(VERSION)

PACKAGES      := packages/cubeproof packages/neighbourly packages/faces12-campaign
PACKAGE_SRC   := $(addsuffix /src,$(PACKAGES))
PACKAGE_TESTS := $(addsuffix /tests,$(PACKAGES))
SHARED_TESTS  := tests/architecture tests/fakes tests/image $(wildcard tests/contracts) $(wildcard tests/independent) $(wildcard tests/reference) $(wildcard tests/endtoend)
# tests/architecture already runs in `make test-architecture`; its nested release-view test re-runs every package fast suite.
FAST_SHARED_TESTS := $(filter-out tests/architecture,$(SHARED_TESTS))
LINT_CODE     := $(PACKAGES) tests/architecture tests/release tests/contracts tests/fakes tests/image \
                 tests/endtoend \
                 docker/test docker/release tools conftest.py
STRICT_CODE   := $(PACKAGE_SRC) $(PACKAGE_TESTS) tests/architecture tests/release tests/contracts \
                 tests/fakes tests/image tests/endtoend docker/test/pinned_tools.py docker/release/release_artifacts.py docker/release/release_entrypoint.py tools/checks tools/spec_vectors tools/neighbourly_fixtures conftest.py
CONSTRAINTS   := constraints/dev.txt
FAST          := not slow and not image
NO_CACHE      := -p no:cacheprovider
# Parallel workers for the package suites; tests marked serial (conftest.py) run afterwards
# without workers so that their wall-clock limits keep their meaning. Without
# pytest-xdist (an environment from before `make install-dev`) the first pass runs serially.
WORKERS       ?= auto
PARALLEL      := $(shell $(PYTHON) -c "import xdist" 2>/dev/null && echo "-n $(WORKERS)")

# -- standard checks ------------------------------------------------------------------------------

install-dev:
	$(PYTHON) -m pip install -c $(CONSTRAINTS) setuptools
	$(PYTHON) -m pip install --no-build-isolation -c $(CONSTRAINTS) -e ".[dev]" \
		$(addprefix -e ,$(PACKAGES))

lint:
	$(PYTHON) -m ruff check $(LINT_CODE)
	$(PYTHON) -m ruff format --check $(LINT_CODE)
	$(PYTHON) -m mypy --strict $(STRICT_CODE)
	$(PYTHON) -m ruff check tests scripts
	$(PYTHON) -m ruff format --check tests scripts
	$(PYTHON) -m mypy
	$(PYTHON) tools/checks/claims_docs.py --check

test-architecture:
	$(PYTEST) tests/architecture -m "not release_view" -q $(NO_CACHE)

test-release-view:
	$(PYTEST) tests/architecture -m release_view -q $(NO_CACHE)

test-fast:
	$(PYTEST) $(PACKAGE_TESTS) $(FAST_SHARED_TESTS) -m "$(FAST) and not serial" $(PARALLEL) -q $(NO_CACHE)
	$(PYTEST) $(PACKAGE_TESTS) $(FAST_SHARED_TESTS) -m "$(FAST) and serial" -q $(NO_CACHE)

test-installed:
	$(PYTEST) tests/release --run-slow -q $(NO_CACHE)

test-all:
	$(PYTHON) tools/checks/require_image.py
	$(PYTEST) $(PACKAGE_TESTS) $(SHARED_TESTS) tests/release --run-slow --run-image $(NO_CACHE)

# -- other targets --------------------------------------------------------------------------------

format:
	$(PYTHON) -m ruff format tests scripts $(LINT_CODE)
	$(PYTHON) -m ruff check --fix tests scripts $(LINT_CODE)

docs:
	$(PYTHON) tools/checks/claims_docs.py

maps:
	$(PYTHON) -m faces12_campaign maps

image:
	docker build --platform linux/amd64 -f docker/release/Dockerfile -t $(IMAGE) .

paper:
	$(PYTHON) scripts/build_paper.py

bundle:
	$(PYTHON) -m faces12_campaign release bundle --root . \
		--output dist/polyhedraproof-$(VERSION)-source.tar.gz --author "Andrei Pirozhkov"

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	$(MAKE) -C paper clean
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
