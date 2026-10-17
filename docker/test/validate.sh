#!/usr/bin/env bash
# Build the development/test image twice from clean state, compare what must be identical,
# and run the test tiers inside the first build (specification §14).
#
#   bash docker/test/validate.sh OUTPUT_DIR
#
# Environment:
#
#   VALIDATE_RUN_ID=ID      the name of this run in the tags of the two builds,
#                           polyhedraproof-test-validate:ID-1 and :ID-2 (letters, digits, "_",
#                           "." and "-", at most 100 characters, not starting with "." or "-").
#                           Default: UTC time, process ID and the name of OUTPUT_DIR, so two
#                           runs never share a tag. A tag that exists already is refused.
#   VALIDATE_KEEP_IMAGES=1  keep the two tags. By default both are removed when the script
#                           ends, whatever the result: the test image for daily use is the one
#                           `docker/test/run.sh build` tags.
#   TEST_SHM_SIZE=SIZE      /dev/shm of the test container (default 4g)
#
# Needs Docker on x86-64 with network access to Docker Hub, snapshot.debian.org, GitHub and
# PyPI (build time only; the test containers run with --network none). Writes, in OUTPUT_DIR
# (create it outside the checkout):
#
#   build-{1,2}.log        the two build logs
#   provenance-{1,2}/      /opt/polyhedraproof-test/provenance of each build: tool commits,
#                          source and binary SHA-256, compilers, Debian packages, Python
#                          distributions, wheelhouse checksums
#   compare.log            pinned_tools.py compare provenance-1 provenance-2
#   image-{1,2}.id         the image IDs (metadata; not expected to be equal)
#   test-all.log           `make test-all` in build 1, the checkout mounted read-only
#   summary.txt            the run ID and tags, what matched and what passed
#
# Exit status 0 only if the two provenance records are identical (tool binaries, packages,
# wheelhouse) and `make test-all` passed. Image IDs and timestamps are not compared.
#
# The file can be sourced for its functions (run_id, intermediate_tag, remove_intermediate);
# nothing runs then.
set -euo pipefail

REPOSITORY=polyhedraproof-test-validate

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

# remove_intermediate TAG...: remove the tags that exist; prints one summary line per tag
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

# on every exit after the builds began: drop a leftover container, remove or keep the two
# tags, print the summary; the exit status is kept
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

main() {
  if [ $# -ne 1 ]; then
    echo "usage: docker/test/validate.sh OUTPUT_DIR" >&2
    exit 2
  fi
  local root out id n image status file
  root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  mkdir -p "$1"
  out=$(cd "$1" && pwd)
  case "$out/" in
    "$root"/*) echo "error: OUTPUT_DIR must be outside the checkout" >&2; exit 2 ;;
  esac
  if [ "$(uname -m)" != "x86_64" ]; then
    echo "error: the test image and cake_lpr.S target x86-64" >&2
    exit 2
  fi

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
    docker build --no-cache --pull --platform linux/amd64 -f "$root/docker/test/Dockerfile" \
      -t "$image" "$root" > "$out/build-$n.log" 2>&1
    docker image inspect --format '{{.Id}}' "$image" > "$out/image-$n.id"
    rm -rf "$out/provenance-$n"
    container=$(docker create "$image")
    docker cp "$container:/opt/polyhedraproof-test/provenance" "$out/provenance-$n"
    docker rm "$container" > /dev/null
    container=""
  done

  status=0
  {
    echo "test image validation $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "source $(git -C "$root" rev-parse HEAD 2>/dev/null || echo 'no git')"
    echo "manifest sha256 $(sha256sum "$root/docker/test/tools.json" | cut -d' ' -f1)"
    echo "run $id: ${images[0]} ${images[1]}"
  } >> "$summary"

  if docker run --rm --network none -v "$out:/out:ro" --entrypoint python3 \
      "${images[0]}" /opt/polyhedraproof-test/share/pinned_tools.py \
      compare /out/provenance-1 /out/provenance-2 > "$out/compare.log" 2>&1; then
    echo "provenance: identical across the two builds" >> "$summary"
  else
    echo "provenance: DIFFERS between the two builds (compare.log)" >> "$summary"
    status=1
  fi
  for file in tools-stage-packages.txt wheelhouse.sha256; do
    if cmp -s "$out/provenance-1/$file" "$out/provenance-2/$file"; then
      echo "$file: identical" >> "$summary"
    else
      echo "$file: DIFFERS" >> "$summary"
      status=1
    fi
  done

  # /dev/shm above the 2 GiB disk reserve for the cross-device tests, as in run.sh
  if docker run --rm --init --network none --shm-size "${TEST_SHM_SIZE:-4g}" \
      -v "$root:/src:ro" "${images[0]}" \
      make test-all > "$out/test-all.log" 2>&1; then
    echo "make test-all: passed" >> "$summary"
  else
    echo "make test-all: FAILED (test-all.log)" >> "$summary"
    status=1
  fi
  (cd "$out" && sha256sum build-*.log compare.log test-all.log image-*.id \
    provenance-*/tools.json provenance-*/environment.json >> "$summary")
  exit "$status"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
