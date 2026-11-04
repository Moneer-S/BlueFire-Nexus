#!/bin/sh
# Fixed process-custody boundary for the hosted Strix preparation job.
set -eu

mode=${1-}
shift || true
if [ "$#" -ne 9 ]; then
  echo "invalid Strix preparation boundary arguments" >&2
  exit 2
fi

workspace=$1
stage_root=$2
python=$3
tool_path=$4
revision=$5
threat_review_ref=$6
bundle_ref_output=$7
run_id=$8
run_attempt=$9
boundary_uid=65534
boundary_gid=65534

case "$workspace:$stage_root:$python:$bundle_ref_output" in
  /*:/*:/*:/*) ;;
  *) echo "Strix preparation boundary paths must be absolute" >&2; exit 2 ;;
esac
case "$revision" in
  *[!0-9a-f]*|'') echo "invalid BlueFire revision" >&2; exit 2 ;;
esac
[ "${#revision}" -eq 40 ] || { echo "invalid BlueFire revision" >&2; exit 2; }
case "$threat_review_ref" in
  sha256:*) ;;
  *) echo "invalid threat-review ref" >&2; exit 2 ;;
esac
[ "${#threat_review_ref}" -eq 71 ] || { echo "invalid threat-review ref" >&2; exit 2; }
case "${threat_review_ref#sha256:}" in
  *[!0-9a-f]*|'') echo "invalid threat-review ref" >&2; exit 2 ;;
esac
case "$run_id:$run_attempt" in
  *[!0-9:]*|'') echo "invalid numeric boundary identity" >&2; exit 2 ;;
esac
case "$stage_root" in
  */bluefire-strix-preparation-stage) ;;
  *) echo "preparation stage path is not fixed" >&2; exit 2 ;;
esac
case "$bundle_ref_output" in
  "$stage_root"/*) ;;
  *) echo "bundle-ref output escaped the preparation stage" >&2; exit 2 ;;
esac

script=$workspace/tools/strix_runtime_preparation_boundary.sh
home=$stage_root/bluefire-strix-preparation-boundary-home
host_runner_temp=${stage_root%/bluefire-strix-preparation-stage}

if [ "$mode" = "--outside" ]; then
  [ "$(id -u)" -eq 0 ] || { echo "boundary controller must be root" >&2; exit 2; }
  [ -d "$stage_root" ] || { echo "preparation stage is absent" >&2; exit 2; }
  [ ! -e "$home" ] || { echo "boundary home must be new" >&2; exit 2; }
  chown -R -h "$boundary_uid:$boundary_gid" "$stage_root"
  mkdir -m 0700 "$home"
  chown "$boundary_uid:$boundary_gid" "$home"
  mount --make-rprivate /
  mount --bind /home /home
  mount -o remount,bind,ro,nosuid,nodev /home
  mount --bind /opt /opt
  mount -o remount,bind,ro,nosuid,nodev /opt
  mount --bind "$host_runner_temp" "$host_runner_temp"
  mount -o remount,bind,ro,nosuid,nodev "$host_runner_temp"
  mount --bind "$stage_root" "$stage_root"
  mount -o remount,bind,rw,nosuid,nodev "$stage_root"
  resolver_target=$(readlink -f -- /etc/resolv.conf)
  case "$resolver_target" in
    /run/*|/etc/resolv.conf) ;;
    *) echo "unsupported hosted resolver target" >&2; exit 2 ;;
  esac
  [ "$(stat -c %s -- "$resolver_target")" -le 65536 ] || {
    echo "hosted resolver file is oversized" >&2
    exit 2
  }
  find "$resolver_target" -maxdepth 0 -type f -uid 0 ! -perm /022 | grep -q . || {
    echo "hosted resolver file is not a protected root-owned regular file" >&2
    exit 2
  }
  awk '$1 == "nameserver" { count += 1 } END { if (count == 0) exit 2 }' \
    "$resolver_target" || {
    echo "hosted resolver file has no resolver" >&2
    exit 2
  }
  exec 9<"$resolver_target"
  mount -t tmpfs -o nosuid,nodev,noexec,mode=755,size=1m,nr_inodes=256 tmpfs /run
  private_resolver=/run/bluefire-resolv.conf
  cat <&9 > "$private_resolver"
  exec 9<&-
  chown 0:0 "$private_resolver"
  chmod 0444 "$private_resolver"
  if [ ! -e "$resolver_target" ]; then
    mkdir -p -- "$(dirname -- "$resolver_target")"
    : > "$resolver_target"
  fi
  mount --bind "$private_resolver" "$resolver_target"
  mount -o remount,bind,ro,nosuid,nodev "$resolver_target"
  mount -t tmpfs -o nosuid,nodev,noexec,mode=1777,size=64m,nr_inodes=8192 tmpfs /tmp
  mount -t tmpfs -o nosuid,nodev,noexec,mode=1777,size=64m,nr_inodes=8192 tmpfs /var/tmp
  mount -t tmpfs -o nosuid,nodev,noexec,mode=1777,size=64m,nr_inodes=8192 tmpfs /dev/shm
  mount -t tmpfs -o nosuid,nodev,noexec,mode=000,size=1m,nr_inodes=64 tmpfs /dev/mqueue
  exec /usr/bin/setpriv \
    --reuid="$boundary_uid" --regid="$boundary_gid" --clear-groups --no-new-privs \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    /usr/bin/prlimit --nproc=512 --nofile=1024 --core=0 \
    /usr/bin/env -i \
    "PATH=$tool_path" "HOME=$home" "TMPDIR=/tmp" "TMP=/tmp" "TEMP=/tmp" \
    "XDG_CONFIG_HOME=$home/config" "XDG_CACHE_HOME=$home/cache" \
    "PYTHONPATH=$workspace" PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
    PYTHONDONTWRITEBYTECODE=1 LC_ALL=C.UTF-8 LANG=C.UTF-8 \
    /bin/sh "$script" --inside "$workspace" "$stage_root" "$python" "$tool_path" \
    "$revision" "$threat_review_ref" "$bundle_ref_output" "$run_id" \
    "$run_attempt"
fi

[ "$mode" = "--inside" ] || { echo "invalid boundary mode" >&2; exit 2; }
[ "$(id -u)" -eq "$boundary_uid" ] || { echo "boundary UID drifted" >&2; exit 2; }
[ "$(id -g)" -eq "$boundary_gid" ] || { echo "boundary GID drifted" >&2; exit 2; }
cd "$workspace"

"$python" -P -m tools.build_strix_engine_candidate \
  --work-root "$stage_root/bluefire-strix-candidate-work" \
  --output-root "$stage_root/bluefire-strix-candidate-output" \
  --bluefire-source-revision "$revision"

"$python" -P -m tools.qualify_strix_runtime_candidate \
  --candidate-root "$stage_root/bluefire-strix-candidate-output" \
  --source-root "$stage_root/bluefire-strix-candidate-work/source" \
  --work-root "$stage_root/bluefire-strix-qualification-work" \
  --output-root "$stage_root/bluefire-strix-qualification-output" \
  --bluefire-source-revision "$revision"

"$python" -P -m tools.package_strix_runtime_admission_input \
  --candidate-root "$stage_root/bluefire-strix-candidate-output" \
  --source-root "$stage_root/bluefire-strix-candidate-work/source" \
  --preparation-root "$stage_root/bluefire-strix-qualification-output" \
  --preparation-work-root "$stage_root/bluefire-strix-qualification-work" \
  --output-file "$stage_root/bluefire-strix-admission-input-$run_id-$run_attempt.tar" \
  --bluefire-source-revision "$revision" \
  --threat-review-ref "$threat_review_ref" \
  --github-output "$bundle_ref_output"

rm -rf -- "$home"
[ ! -e "$home" ] || { echo "boundary home remains" >&2; exit 2; }
