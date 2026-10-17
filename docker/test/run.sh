#!/usr/bin/env bash
# Build the development/test image, or run a command in it with this checkout mounted.
#
#   bash docker/test/run.sh build               build the image (tag below)
#   bash docker/test/run.sh run [COMMAND...]    run COMMAND in it (default: make test-all)
#
# The checkout is mounted read-only at /src and the container has no network (--network
# none) and an init process (--init). Mount a full clone, not a `git worktree`: a worktree's
# .git file points to a path of the host that does not exist inside the container, and the
# release-list check needs `git ls-files`. Set TEST_IMAGE to use another tag.
#
# /dev/shm is the second file system of the cross-device tests (the retain run puts its
# work directory there). Docker's default of 64 MiB is below the coordinator's 2 GiB disk
# reserve, so the run would be refused before the crash the test needs;
# TEST_SHM_SIZE (default 4g) sets its size.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
image=${TEST_IMAGE:-polyhedraproof-test:dev}
shm=${TEST_SHM_SIZE:-4g}
action=${1:-run}
[ $# -gt 0 ] && shift

case "$action" in
  build)
    if [ "$(uname -m)" != "x86_64" ]; then
      echo "error: the test image and cake_lpr.S target x86-64" >&2
      exit 2
    fi
    docker build --platform linux/amd64 -f "$root/docker/test/Dockerfile" -t "$image" "$root"
    ;;
  run)
    if [ $# -eq 0 ]; then
      set -- make test-all
    fi
    docker run --rm --init --network none --shm-size "$shm" -v "$root:/src:ro" "$image" "$@"
    ;;
  *)
    echo "usage: bash docker/test/run.sh build | run [COMMAND...]" >&2
    exit 2
    ;;
esac
