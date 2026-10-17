#!/usr/bin/env bash
# One faces12-campaign worker in Docker on a Linux host (specification §14).
#
#   bash pipeline/faces12-worker.sh COMMAND --worker NAME [OPTIONS] [-- RUN_OPTIONS...]
#
# Commands:
#   launch     create the worker's volumes if missing, give empty ones to the worker's user,
#              then create and start the container (refused if the container exists)
#   stop       docker stop -t 120: the worker ends cleanly and keeps its journal
#   start      docker start the stopped container: the run resumes from its journal
#   recreate   remove the container (never a volume) and launch it again with the given inputs
#   status     the container's state and the worker's status document (-- --json: as JSON)
#   logs       the container's log (docker logs; extra words are passed to it)
#   capacity   size and free space of the volumes and the container layer, and which share a disk
#   example    write the example campaign (minutes of work, not the article's) into --io
#   backup     archive the results volume of a stopped worker into --to DIR (tar + sha256)
#   restore    fill an EMPTY results volume from --from ARCHIVE (refused if it holds files)
#   names      print the container and volume names
#
# Options:
#   --worker NAME    a-z, 0-9, _ and - (first a letter or digit, at most 48 characters); the
#                    worker name of the journal, and the names PREFIX-NAME (container),
#                    PREFIX-results-NAME and PREFIX-work-NAME (volumes)
#   --io DIR         host directory mounted at /io: campaign, shards, inbox, outbox, export
#   --image IMAGE    default $POLYHEDRAPROOF_IMAGE, else faces12-campaign:1.0.0rc1
#   --campaign FILE  below --io (default campaign.json); --shard FILE below --io (optional)
#   --inbox DIR --outbox DIR --export DIR   below --io (defaults inbox, outbox, export)
#   --user UID:GID   the user the worker runs as (default: the caller's ids; never 0)
#   --prefix P       name prefix (default faces12)
#   --to DIR / --from ARCHIVE               for backup / restore
#   -- RUN_OPTIONS   further `run` options, e.g. -- --jobs 8 --memory 24G --disk 200G
#
# The results volume holds the authoritative journal; the work volume is disposable; /io holds
# immutable inputs and the exchange directories only. Nothing here deletes a volume. Both
# volumes and the container layer normally share one disk: `capacity` shows it, and --disk
# must budget them together. The paths given to the worker are the explicit /io, /work/results
# and /work/scratch paths of the container, so host paths with spaces need no quoting inside.
set -euo pipefail

usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }
die() { echo "error: $*" >&2; exit 2; }

[ $# -ge 1 ] || { usage; exit 2; }
command=$1
shift
case "$command" in
  -h|--help|help) usage; exit 0 ;;
  launch|stop|start|recreate|status|logs|capacity|example|backup|restore|names) ;;
  *) die "unknown command '$command' (see --help)" ;;
esac

worker= io= campaign=campaign.json shard= inbox=inbox outbox=outbox export=export
image=${POLYHEDRAPROOF_IMAGE:-faces12-campaign:1.0.0rc1}
user= prefix=faces12 to= from=
extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; extra=("$@"); break ;;
    --worker|--io|--image|--campaign|--shard|--inbox|--outbox|--export|--user|--prefix|--to|--from)
      [ $# -ge 2 ] || die "$1 needs a value"
      value=$2
      case "$1" in
        --worker) worker=$value ;; --io) io=$value ;; --image) image=$value ;;
        --campaign) campaign=$value ;; --shard) shard=$value ;; --inbox) inbox=$value ;;
        --outbox) outbox=$value ;; --export) export=$value ;; --user) user=$value ;;
        --prefix) prefix=$value ;; --to) to=$value ;; --from) from=$value ;;
      esac
      shift 2 ;;
    *)
      if [ "$command" = logs ]; then extra+=("$1"); shift; else die "unexpected '$1'"; fi ;;
  esac
done

[[ "$prefix" =~ ^[a-z0-9][a-z0-9_-]{0,15}$ ]] || die "--prefix: a-z, 0-9, _ and -, at most 16"
if [ "$command" != example ]; then
  [ -n "$worker" ] || die "--worker is required"
  [[ "$worker" =~ ^[a-z0-9][a-z0-9_-]{0,47}$ ]] \
    || die "--worker '$worker': a-z, 0-9, _ and - (first a letter or digit), at most 48"
fi
container="$prefix-$worker"
results_volume="$prefix-results-$worker"
work_volume="$prefix-work-$worker"
label="org.polyhedraproof.worker=$worker"

# the user a new container runs as; asked for only by the commands that start one
need_user() {
  if [ -z "$user" ]; then
    user="$(id -u):$(id -g)"
  fi
  [[ "$user" =~ ^[0-9]{1,9}:[0-9]{1,9}$ ]] || die "--user must be UID:GID"
  [ "$((10#${user%%:*}))" -ne 0 ] || die "the worker never runs as root; pass --user UID:GID"
}
case "$command" in
  names|stop|start|logs|status) ;;
  *) need_user ;;
esac

# below IO: a relative path without '..', or die
inside() {
  local name=$1 value=$2
  case "/$value/" in
    *"/../"*|*"/./"*|//*) die "$name '$value' must be a relative path below --io without . or .." ;;
  esac
  [ -n "$value" ] || die "$name is empty"
}

# docker -v separates its fields with ':'
no_colon() {
  case "$2" in *:*) die "$1 '$2': a host path with ':' cannot be mounted by this wrapper" ;; esac
}

host_io() {
  [ -n "$io" ] || die "--io DIR is required for $command"
  [ -d "$io" ] || die "--io '$io' is not a directory"
  local resolved
  resolved=$(cd "$io" && pwd -P)
  no_colon --io "$resolved"
  echo "$resolved"
}

container_state() {  # running | exited | created | ... | absent
  local state
  if state=$(docker container inspect --format '{{.State.Status}}' "$container" 2>/dev/null) \
      && [ -n "$state" ]; then
    echo "$state"
  else
    echo absent
  fi
}

volume_exists() {
  docker volume inspect "$1" > /dev/null 2>&1
}

# both volumes must exist (a read-only mount of a missing name would create an unlabelled one)
require_volumes() {
  volume_exists "$results_volume" || die "no volume $results_volume (launch the worker first)"
  volume_exists "$work_volume" || die "no volume $work_volume (launch the worker first)"
}

ensure_volume() {
  if ! volume_exists "$1"; then
    docker volume create --label "$label" --label "org.polyhedraproof.role=$2" "$1" > /dev/null
    echo "created volume $1"
  fi
}

init_volumes() {
  ensure_volume "$results_volume" results
  ensure_volume "$work_volume" work
  docker run --rm --init --network none --user 0:0 \
    -v "$results_volume:/work/results" -v "$work_volume:/work/scratch" \
    "$image" init-volumes "$user"
}

launch() {
  local state hostio
  state=$(container_state)
  [ "$state" = absent ] || die "container $container exists ($state): use start, or recreate"
  inside --campaign "$campaign"; inside --inbox "$inbox"; inside --outbox "$outbox"
  inside --export "$export"
  hostio=$(host_io)
  [ -f "$hostio/$campaign" ] || die "no campaign file '$campaign' below --io"
  local args=(run --campaign "/io/$campaign")
  if [ -n "$shard" ]; then
    inside --shard "$shard"
    [ -f "$hostio/$shard" ] || die "no shard file '$shard' below --io"
    args+=(--shard "/io/$shard")
  fi
  mkdir -p "$hostio/$inbox" "$hostio/$outbox" "$hostio/$export"
  args+=(--results /work/results --work /work/scratch --worker "$worker"
         --inbox "/io/$inbox" --outbox "/io/$outbox" --export "/io/$export")
  init_volumes
  docker run -d --name "$container" --init --network none --user "$user" \
    --label "$label" --label "org.polyhedraproof.io=$hostio" \
    -v "$results_volume:/work/results" -v "$work_volume:/work/scratch" \
    -v "$hostio:/io" \
    "$image" "${args[@]}" ${extra[@]+"${extra[@]}"}
  echo "launched $container (results $results_volume, work $work_volume, io $hostio)"
}

case "$command" in
  names)
    printf 'container %s\nresults %s\nwork %s\n' "$container" "$results_volume" "$work_volume" ;;
  launch)
    launch ;;
  stop)
    docker stop -t 120 "$container" ;;
  start)
    [ "$(container_state)" != absent ] || die "no container $container: use launch or recreate"
    docker start "$container" ;;
  recreate)
    state=$(container_state)
    if [ "$state" != absent ]; then
      [ "$state" != running ] || docker stop -t 120 "$container" > /dev/null
      docker rm "$container" > /dev/null   # the container only; its volumes are kept
      echo "removed container $container; volumes kept"
    fi
    launch ;;
  status)
    state=$(container_state)
    echo "container $container: $state"
    if [ "$state" = running ]; then
      docker exec "$container" /opt/faces12/venv/bin/python -I /opt/faces12/entrypoint.py \
        status --results /work/results ${extra[@]+"${extra[@]}"} || true
    elif volume_exists "$results_volume"; then
      need_user
      docker run --rm --init --network none --user "$user" -v "$results_volume:/work/results:ro" \
        "$image" status --results /work/results ${extra[@]+"${extra[@]}"} || true
    else
      echo "no results volume $results_volume"
    fi ;;
  logs)
    docker logs ${extra[@]+"${extra[@]}"} "$container" ;;
  capacity)
    require_volumes
    docker run --rm --init --network none --user "$user" \
      -v "$results_volume:/work/results:ro" -v "$work_volume:/work/scratch:ro" \
      "$image" capacity ;;
  example)
    hostio=$(host_io)
    docker run --rm --init --network none --user "$user" -v "$hostio:/io" \
      "$image" example-campaign /io ${extra[@]+"${extra[@]}"} ;;
  backup)
    [ "$(container_state)" != running ] || die "stop the worker before a backup"
    { [ -n "$to" ] && [ -d "$to" ]; } || die "--to DIR must be an existing directory"
    volume_exists "$results_volume" || die "no volume $results_volume"
    dest=$(cd "$to" && pwd -P)
    no_colon --to "$dest"
    docker run --rm --init --network none --user "$user" \
      -v "$results_volume:/work/results:ro" -v "$dest:/backup" \
      "$image" backup-results /backup "$results_volume-$(date -u +%Y%m%dT%H%M%SZ).tar" ;;
  restore)
    [ "$(container_state)" != running ] || die "stop the worker before a restore"
    { [ -n "$from" ] && [ -f "$from" ]; } || die "--from ARCHIVE must be a file"
    source_dir=$(cd "$(dirname "$from")" && pwd -P)
    no_colon --from "$source_dir"
    init_volumes
    docker run --rm --init --network none --user "$user" \
      -v "$results_volume:/work/results" -v "$source_dir:/backup:ro" \
      "$image" restore-results "/backup/$(basename "$from")" ;;
esac
