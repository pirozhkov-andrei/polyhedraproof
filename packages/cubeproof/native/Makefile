# Build and install the optional native lookahead helper (specification §9.3, §14).
#
#   make                       build/cubeproof-look and its build record, warnings are errors
#   make install PREFIX=/opt   PREFIX/bin/cubeproof-look and PREFIX/bin/cubeproof-look.provenance.json
#   make clean
#
# The path of the installed binary is then configured explicitly (ToolPaths.helper); the
# library never searches PATH. Without the helper the Python reference is used.
PYTHON ?= python3
CC     ?= cc
PREFIX ?= /usr/local

.PHONY: all install clean

all:
	$(PYTHON) build.py --cc $(CC) --out build

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 build/cubeproof-look $(DESTDIR)$(PREFIX)/bin/cubeproof-look
	install -m 0644 build/cubeproof-look.provenance.json \
		$(DESTDIR)$(PREFIX)/bin/cubeproof-look.provenance.json

clean:
	rm -rf build
