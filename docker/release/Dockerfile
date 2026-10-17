# The installed release image (specification §14).
#
#   docker build --platform linux/amd64 -f docker/release/Dockerfile -t faces12-campaign:1.0.0rc1 .
#   docker run --rm --init --network none faces12-campaign:1.0.0rc1 selfcheck
#
# The image installs built artifacts, never the checkout: the `artifacts` stage builds an
# sdist of each package, the wheel from that sdist and the deterministic source archive of
# the release list; the final stage installs only those wheels, with --no-index, into a
# virtual environment, and every Python process starts isolated (-I), so no PYTHONPATH or
# working directory can put other code in front of them. docker/release/validate.sh builds
# twice from clean state and compares what must be identical (tool, helper, wheel, source
# archive and formula hashes; image metadata and timestamps are not compared).
#
# Pins: the `tools` stage is the `tools` stage of docker/test/Dockerfile instruction for
# instruction (same base digest, Debian snapshot, CaDiCaL and cake_lpr pins of
# docker/test/tools.json), so the release binaries are the binaries the image tests use;
# tests/release/test_release_image.py fails if the two drift apart.

# --- tools: the pinned solver and checker (identical to docker/test/Dockerfile) -------------
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

# --- helper: the native lookahead helper and the exact tool sources -----------------------
FROM tools AS helper

COPY packages/cubeproof/native/build.py packages/cubeproof/native/cubeproof-look.c /build/native/
RUN python3 /build/native/build.py --cc gcc --out /opt/faces12-helper \
    && mkdir -p /opt/faces12-sources \
    && cadical=$(git -C /build/src/cadical rev-parse HEAD) \
    && git -C /build/src/cadical archive --format=tar --prefix="cadical-$cadical/" "$cadical" \
        | gzip -n -9 > "/opt/faces12-sources/cadical-$cadical.tar.gz" \
    && cake=$(git -C /build/src/cake_lpr rev-parse HEAD) \
    && git -C /build/src/cake_lpr archive --format=tar --prefix="cake_lpr-$cake/" "$cake" \
        basis_ffi.c cake_lpr.S LICENSE \
        | gzip -n -9 > "/opt/faces12-sources/cake_lpr-$cake.tar.gz" \
    && cp /build/native/build.py /build/native/cubeproof-look.c /opt/faces12-sources/ \
    && (cd /opt/faces12-sources && sha256sum -- * > /opt/faces12-sources.sha256) \
    && mv /opt/faces12-sources.sha256 /opt/faces12-sources/SHA256SUMS

# --- artifacts: sdists, wheels from the sdists, the source archive ------------------------
FROM debian@sha256:2bc5c236e9b262645a323e9088dfa3bb1ecb16cc75811daf40a23a824d665be9 AS artifacts

ENV DEBIAN_FRONTEND=noninteractive \
    SOURCE_DATE_EPOCH=1700000000 \
    TZ=UTC \
    LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

COPY docker/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# the build tools at the versions of constraints/dev.txt (network at build time only)
COPY constraints/dev.txt /build/constraints/dev.txt
RUN python3 -m venv /build/env \
    && /build/env/bin/python -m pip install --no-cache-dir -c /build/constraints/dev.txt \
        build setuptools

COPY . /src
RUN umask 0022 \
    && /build/env/bin/python -I /src/docker/release/release_artifacts.py \
        --source /src --out /artifacts --python /build/env/bin/python > /build/artifacts.log

# --- release: what users run ----------------------------------------------------------------
FROM debian@sha256:2bc5c236e9b262645a323e9088dfa3bb1ecb16cc75811daf40a23a824d665be9 AS release

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

COPY docker/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends \
        coreutils procps python3 python3-venv tar util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --from=helper /opt/polyhedraproof-test/bin/ /opt/faces12/bin/
COPY --from=helper /opt/faces12-helper/ /opt/faces12/bin/
COPY --from=helper /opt/polyhedraproof-test/provenance/ /opt/faces12/provenance/
COPY --from=helper /opt/polyhedraproof-test/licenses/ /opt/faces12/licenses/
COPY --from=helper /opt/faces12-sources/ /opt/faces12/sources/
COPY --from=artifacts /artifacts/ /opt/faces12/artifacts/
COPY docker/release/release_entrypoint.py /opt/faces12/entrypoint.py

# Install the wheels only (no index, no checkout), compile them with hash-checked .pyc files
# (reproducible, unlike timestamped ones), record the installation, then hand the volume
# mount points to the non-root user. Docker copies this ownership into a new named volume.
RUN python3 -m venv /opt/faces12/venv \
    && /opt/faces12/venv/bin/python -m pip install --no-cache-dir --no-index --no-compile \
        --find-links /opt/faces12/artifacts/wheels -r /opt/faces12/artifacts/requirements.txt \
    && /opt/faces12/venv/bin/python -m compileall -q --invalidation-mode checked-hash \
        /opt/faces12/venv/lib \
    && cp /opt/faces12/artifacts/artifacts.json /opt/faces12/artifacts/requirements.txt \
        /opt/faces12/provenance/ \
    && dpkg-query -W '-f=${Package}=${Version}\n' | sort > /opt/faces12/provenance/image-packages.txt \
    && /opt/faces12/venv/bin/python -I /opt/faces12/entrypoint.py record \
    && groupadd --gid 1000 faces12 \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /work faces12 \
    && mkdir -p /work/results /work/scratch /io \
    && chown faces12:faces12 /work/results /work/scratch \
    && chmod 0750 /work/results /work/scratch

ENV PATH=/opt/faces12/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

USER faces12
WORKDIR /work
ENTRYPOINT ["/opt/faces12/venv/bin/python", "-I", "/opt/faces12/entrypoint.py"]
CMD ["help"]
