# The development/test image: pinned CaDiCaL and cake_lpr, util-linux, and the pinned
# development tools, without any project code (specification §14).
#
# It exists before, and independently of, the installed release image: the checkout is
# mounted at run time, so one image serves every commit with the same pins.
#
#   docker build --platform linux/amd64 -f docker/test/Dockerfile -t polyhedraproof-test .
#   docker run --rm --init --network none -v "$PWD:/src:ro" polyhedraproof-test make test-all
#
# docker/test/run.sh wraps both; docker/test/validate.sh builds twice from clean state and
# compares the recorded provenance. Every pin (base digest, Debian snapshot, tool commits,
# cake_lpr source checksums, arena defaults, SOURCE_DATE_EPOCH, apt package lists) is in
# docker/test/tools.json; the tests in tests/image/test_tool_manifest.py fail if this file,
# the release Dockerfile and the manifest drift apart.

# --- tools: build the two pinned binaries -------------------------------------------------
FROM debian@sha256:2bc5c236e9b262645a323e9088dfa3bb1ecb16cc75811daf40a23a824d665be9 AS tools

ENV DEBIAN_FRONTEND=noninteractive \
    SOURCE_DATE_EPOCH=1700000000 \
    TZ=UTC \
    LC_ALL=C

COPY docker/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates git python3 \
    && rm -rf /var/lib/apt/lists/*

COPY docker/normalize_cadical_build.py /build/docker/normalize_cadical_build.py
COPY docker/test/pinned_tools.py docker/test/tools.json /build/docker/test/
RUN python3 /build/docker/test/pinned_tools.py build \
        --root /build --prefix /opt/polyhedraproof-test --work /build/src --jobs 4 \
    && dpkg-query -W '-f=${Package}=${Version}\n' > /opt/polyhedraproof-test/provenance/tools-stage-packages.txt

# --- test: the environment the tests run in -----------------------------------------------
FROM debian@sha256:2bc5c236e9b262645a323e9088dfa3bb1ecb16cc75811daf40a23a824d665be9 AS test

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LC_ALL=C

COPY docker/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates coreutils gcc git libc6-dev make procps python3 python3-venv \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /opt/polyhedraproof-test /opt/polyhedraproof-test
COPY constraints/dev.txt /opt/polyhedraproof-test/share/constraints/dev.txt
COPY docker/test/pinned_tools.py docker/test/tools.json /opt/polyhedraproof-test/share/

# The development tools at the versions of constraints/dev.txt, and an offline wheelhouse of
# the same files: the containers run with --network none, and the installed-artifact tests
# build fresh virtual environments from it (PIP_NO_INDEX/PIP_FIND_LINKS below).
RUN python3 -m venv /opt/polyhedraproof-test/venv \
    && /opt/polyhedraproof-test/venv/bin/python -m pip download --no-cache-dir \
        --dest /opt/polyhedraproof-test/wheelhouse \
        -c /opt/polyhedraproof-test/share/constraints/dev.txt \
        build coverage mypy pytest ruff setuptools \
    && /opt/polyhedraproof-test/venv/bin/python -m pip install --no-cache-dir --no-index \
        --find-links /opt/polyhedraproof-test/wheelhouse \
        -c /opt/polyhedraproof-test/share/constraints/dev.txt \
        build coverage mypy pytest ruff setuptools \
    && (cd /opt/polyhedraproof-test/wheelhouse && sha256sum * > ../provenance/wheelhouse.sha256) \
    && /opt/polyhedraproof-test/venv/bin/python /opt/polyhedraproof-test/share/pinned_tools.py \
        environment --output /opt/polyhedraproof-test/provenance/environment.json \
    && /opt/polyhedraproof-test/venv/bin/python /opt/polyhedraproof-test/share/pinned_tools.py \
        verify --prefix /opt/polyhedraproof-test \
    && git config --system --add safe.directory '*'

ENV PATH=/opt/polyhedraproof-test/venv/bin:/opt/polyhedraproof-test/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    POLYHEDRAPROOF_TEST_TOOLS=/opt/polyhedraproof-test \
    PIP_NO_INDEX=1 \
    PIP_FIND_LINKS=/opt/polyhedraproof-test/wheelhouse \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

# Nothing needs root; pass --user "$(id -u):$(id -g)" to match a host's ownership instead.
RUN groupadd --gid 1000 tester && useradd --uid 1000 --gid 1000 --create-home tester
USER tester
WORKDIR /src
CMD ["make", "test-all"]
