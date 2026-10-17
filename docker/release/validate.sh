#!/usr/bin/env bash
# Build the release image twice from clean state, compare what must be identical, and run the
# image's checks, the release-image test tier and the installed two-worker run against the
# first build (specification §14).
#
#   bash docker/release/validate.sh OUTPUT_DIR [TAG]
#
#   OUTPUT_DIR  where the evidence goes; must lie outside the checkout
#   TAG         the tag given to the first build when everything holds
#               (default faces12-campaign:VERSION, VERSION of packages/cubeproof)
#
# Environment:
#
#   VALIDATE_RUN_ID=ID       the name of this run in the tags of the two builds,
#                            faces12-release-validate:ID-1 and :ID-2 (letters, digits, "_", "."
#                            and "-", at most 100 characters, not starting with "." or "-").
#                            Default: UTC time, process ID and the name of OUTPUT_DIR, so two
#                            runs never share a tag. A tag that exists already is refused.
#   VALIDATE_KEEP_IMAGES=1   keep the two intermediate tags. By default both are removed when
#                            the script ends, whatever the result; the image of the first
#                            build stays under TAG when everything held.
#   VALIDATE_SKIP_CLUSTER=1  do not run the installed two-worker run (three to five minutes)
#
# Needs Docker on x86-64 with network access to Docker Hub, snapshot.debian.org, GitHub and
# PyPI (build time only; every container started here runs with --network none), and
# python3 (3.10 or later) with pytest on the host for the test tier. Writes, in OUTPUT_DIR:
#
#   build-{1,2}.log          the two build logs (docker build --no-cache --pull)
#   image-{1,2}.id           the image IDs (metadata; not expected to be equal)
#   provenance-{1,2}/        /opt/faces12/provenance of each build: tool and helper records,
#                            artifacts.json (wheel, sdist and source archive hashes),
#                            formulas.json, installed.json, release-provenance.json, Debian
#                            package lists
#   reproduced-{1,2}.sha256  the hashes a second build must reproduce, one per line
#   compare.diff             diff of the two reproduced-*.sha256 (empty when identical)
#   selfcheck.log            `selfcheck` in build 1
#   tests.log                pytest of tests/release/test_release_image.py and
#                            test_wrappers.py with --run-slow --run-image and
#                            POLYHEDRAPROOF_RELEASE_IMAGE set to build 1 (the wrapper procedure with
#                            host paths containing spaces)
#   cluster.log              tests/endtoend/cluster/cluster_installed.py against build 1: two
#   cluster-installed/       workers of one campaign in containers of the image, driven by
#                            pipeline/faces12-worker.sh, with a handoff, crashes, a clean stop
#                            and a recreated container, then certified, audited and its
#                            retained proofs verified in the image (transcript.log,
#                            result.json). The directory is replaced by each run.
#   summary.txt              the run ID and tags, what matched and what passed, and the
#                            hashes of the logs
#
# Compared (must be identical): the cadical and cake_lpr binaries (tools.json), the helper
# binary (cubeproof-look.provenance.json), the exact tool and helper sources (SHA256SUMS),
# every wheel and the source archive (artifacts.json "reproducible"), the 59 formula hashes
# (formulas.json), every installed file (installed.json) and the release provenance document
# without its time of recording (release-provenance.json without "recorded_utc": package
# digests, Python runtime, operating system, architecture and C library, tool paths and
# hashes). Not compared: image IDs, layer timestamps and sdists (their gzip header carries the
# build time; artifacts.json lists them as informational).
#
# Exit status 0 only if every compared hash is identical, selfcheck passed, the test tier
# passed and the two-worker run passed or was skipped with VALIDATE_SKIP_CLUSTER=1. The release
# tag is given only when the two-worker run passed: a skipped run validates nothing to tag.
#
# The file can be sourced for its functions (run_id, intermediate_tag, remove_intermediate);
# nothing runs then.
set -euo pipefail

REPOSITORY=faces12-release-validate

# a tag-safe name of this run: VALIDATE_RUN_ID, or UTC time, process ID and the directory name
run_id() {
  local name id
  if [ -n "${VALIDATE_RUN_ID:-}" ]; then
    id=$VALIDATE_RUN_ID
  else
    name=$(basename "$1" | tr -c 'A-Za-z0-9_.\n' '-' | cut -c1-40)
    id="$(date -u +%Y%m%dT%H%M%SZ)-$$-$name"
  fi
  case "$id" in
    "" | .* | -* | *[!A-Za-z0-9_.-]*)
      echo "error: run ID '$id': letters, digits, '_', '.' and '-', not starting with '.' or '-'" >&2
      return 2 ;;
  esac
  if [ "${#id}" -gt 100 ]; then
    echo "error: run ID '$id' is longer than 100 characters" >&2
    return 2
  fi
  printf '%s\n' "$id"
}

# intermediate_tag RUN_ID N: the tag of build N of a run
intermediate_tag() {
  printf '%s:%s-%s\n' "$REPOSITORY" "$1" "$2"
}

# remove_intermediate TAG...: remove the tags that exist (an image that has another tag, such
# as the validated one, keeps it and stays); prints one summary line per tag
remove_intermediate() {
  local image
  for image in "$@"; do
    if ! docker image inspect "$image" > /dev/null 2>&1; then
      continue
    elif docker image rm "$image" > /dev/null 2>&1; then
      echo "removed intermediate tag $image"
    else
      echo "intermediate tag $image could NOT be removed"
    fi
  done
}

# the hashes a second build must reproduce, as "name sha256" lines (sorted)
reproduced() {
  python3 - "$1" <<'PY'
import hashlib, json, sys
from pathlib import Path

base = Path(sys.argv[1])
lines = []
tools = json.loads((base / "tools.json").read_text(encoding="utf-8"))
for name, entry in sorted(tools["tools"].items()):
    lines.append(f"tool/{name} {entry['sha256']}")
helper = json.loads((base / "cubeproof-look.provenance.json").read_text(encoding="utf-8"))
lines.append(f"helper/cubeproof-look {helper['binary_sha256']}")
for line in (base / "sources.sha256").read_text(encoding="utf-8").splitlines():
    digest, name = line.split(maxsplit=1)
    lines.append(f"tool-source/{name} {digest}")
artifacts = json.loads((base / "artifacts.json").read_text(encoding="utf-8"))
for kind in artifacts["reproducible"]:
    for name, digest in sorted(artifacts[kind].items()):
        lines.append(f"{kind}/{name} {digest}")
formulas = json.loads((base / "formulas.json").read_text(encoding="utf-8"))
for entry in formulas["formulas"]:
    lines.append(f"formula/{entry['key']} {entry['formula_sha256']}")
for name, dropped in (("installed.json", ()), ("release-provenance.json", ("recorded_utc",))):
    document = json.loads((base / name).read_text(encoding="utf-8"))
    for key in dropped:
        del document[key]
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    lines.append(f"{name} {hashlib.sha256(canonical).hexdigest()}")
print("\n".join(sorted(lines)))
PY
}

main() {
  if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: docker/release/validate.sh OUTPUT_DIR [TAG]" >&2
    exit 2
  fi
  local root out version tag id n image status
  root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
  mkdir -p "$1"
  out=$(cd "$1" && pwd -P)
  case "$out/" in
    "$root"/*) echo "error: OUTPUT_DIR must be outside the checkout" >&2; exit 2 ;;
  esac
  if [ "$(uname -m)" != "x86_64" ]; then
    echo "error: the release image and cake_lpr.S target x86-64" >&2
    exit 2
  fi
  version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/packages/cubeproof/pyproject.toml")
  tag=${2:-faces12-campaign:$version}
  id=$(run_id "$out") || exit 2
  images=("$(intermediate_tag "$id" 1)" "$(intermediate_tag "$id" 2)")
  for image in "${images[@]}"; do
    if docker image inspect "$image" > /dev/null 2>&1; then
      echo "error: $image exists; remove it or choose another VALIDATE_RUN_ID" >&2
      exit 2
    fi
  done
  summary="$out/summary.txt"
  : > "$summary"
  container=""
  trap finish EXIT

  for n in 1 2; do
    image=${images[n - 1]}
    echo "== build $n (no cache): $image"
    docker build --no-cache --pull --platform linux/amd64 -f "$root/docker/release/Dockerfile" \
      -t "$image" "$root" > "$out/build-$n.log" 2>&1
    docker image inspect --format '{{.Id}}' "$image" > "$out/image-$n.id"
    rm -rf "$out/provenance-$n"
    container=$(docker create "$image")
    docker cp "$container:/opt/faces12/provenance" "$out/provenance-$n"
    docker cp "$container:/opt/faces12/bin/cubeproof-look.provenance.json" "$out/provenance-$n/"
    docker cp "$container:/opt/faces12/sources/SHA256SUMS" "$out/provenance-$n/sources.sha256"
    docker rm "$container" > /dev/null
    container=""
    reproduced "$out/provenance-$n" > "$out/reproduced-$n.sha256"
  done

  status=0
  {
    echo "release image validation $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "source $(git -C "$root" rev-parse HEAD 2>/dev/null || echo 'no git')"
    echo "version $version"
    echo "run $id: ${images[0]} ${images[1]}"
    echo "compared hashes: $(wc -l < "$out/reproduced-1.sha256")"
  } >> "$summary"

  if diff "$out/reproduced-1.sha256" "$out/reproduced-2.sha256" > "$out/compare.diff"; then
    echo "reproduced hashes: identical across the two builds" >> "$summary"
  else
    echo "reproduced hashes: DIFFER between the two builds (compare.diff)" >> "$summary"
    status=1
  fi

  if docker run --rm --init --network none "${images[0]}" selfcheck \
      > "$out/selfcheck.log" 2>&1; then
    echo "selfcheck: passed" >> "$summary"
  else
    echo "selfcheck: FAILED (selfcheck.log)" >> "$summary"
    status=1
  fi

  if (cd "$root" && POLYHEDRAPROOF_RELEASE_IMAGE=${images[0]} python3 -m pytest \
      -p no:cacheprovider tests/release/test_release_image.py tests/release/test_wrappers.py \
      --run-slow --run-image -v -rs) \
      > "$out/tests.log" 2>&1; then
    echo "release image test tier: passed" >> "$summary"
  else
    echo "release image test tier: FAILED (tests.log)" >> "$summary"
    status=1
  fi

  logs=(build-1.log build-2.log image-1.id image-2.id reproduced-1.sha256 reproduced-2.sha256
    compare.diff selfcheck.log tests.log provenance-1/artifacts.json)
  if [ "${VALIDATE_SKIP_CLUSTER:-}" = "1" ]; then
    echo "installed two-worker run: SKIPPED (VALIDATE_SKIP_CLUSTER=1)" >> "$summary"
  else
    logs+=(cluster.log)
    if (cd "$root" && python3 tests/endtoend/cluster/cluster_installed.py "${images[0]}" \
        "$out/cluster-installed") > "$out/cluster.log" 2>&1; then
      echo "installed two-worker run: passed" >> "$summary"
    else
      echo "installed two-worker run: FAILED (cluster.log, cluster-installed/)" >> "$summary"
      status=1
    fi
    if [ -f "$out/cluster-installed/result.json" ]; then
      logs+=(cluster-installed/result.json cluster-installed/transcript.log)
    fi
  fi

  if [ "$status" -eq 0 ] && [ "${VALIDATE_SKIP_CLUSTER:-}" = "1" ]; then
    echo "not tagged $tag: the installed two-worker run was skipped" >> "$summary"
  elif [ "$status" -eq 0 ]; then
    docker tag "${images[0]}" "$tag"
    echo "tagged $tag: $(docker image inspect --format '{{.Id}}' "$tag")" >> "$summary"
  fi
  (cd "$out" && sha256sum "${logs[@]}" >> "$summary")
  exit "$status"
}

# on every exit after the builds began: drop a leftover container, remove or keep the two
# intermediate tags, print the summary; the exit status is kept
finish() {
  local code=$?
  trap - EXIT
  if [ -n "$container" ]; then
    docker rm -f "$container" > /dev/null 2>&1 || true
  fi
  if [ "${VALIDATE_KEEP_IMAGES:-}" = "1" ]; then
    echo "kept intermediate tags ${images[*]} (VALIDATE_KEEP_IMAGES=1)" >> "$summary"
  else
    remove_intermediate "${images[@]}" >> "$summary"
  fi
  if [ "$code" -ne 0 ] && ! grep -q "FAILED\|DIFFER" "$summary"; then
    echo "validation did not finish (exit $code)" >> "$summary"
  fi
  cat "$summary"
  exit "$code"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
