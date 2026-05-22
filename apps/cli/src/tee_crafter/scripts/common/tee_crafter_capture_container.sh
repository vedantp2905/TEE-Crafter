#!/usr/bin/env bash
# tee_crafter_capture_container.sh
#
# Run as ExecStopPost for batch container services.  Captures everything the
# user image wrote during the batch run by diffing the container's writable
# layer and copying out only the changed/added paths.  Output is bundled into
# /var/lib/tee_crafter/output.tar.gz with a sidecar .sha256 so the orchestrator
# can verify integrity after pulling the file off the TEE host.
#
# Arguments:
#   $1  container name (e.g. tee-crafter-batch)
#   $2  capture staging directory (must exist and be empty)
#
# Exit codes:
#   0   capture produced an output bundle (even if user image failed)
#   1   container did not exist when we ran (very early failure); a bundle
#       recording that fact was still written
#   2   the bundle itself could not be written -- there is no output at all
#
# The unit file runs this WITHOUT a leading `-`, so every non-zero exit above
# fails the batch unit.  That is deliberate: this script is the only thing that
# produces `output.tar.gz`, so "the hook ran" and "the operator has output" have
# to be the same claim.  They used to differ in both directions -- systemd
# ignored the status, and the script exited 0 even when `tar` failed.

set -uo pipefail

container="${1:?container name required}"
out="${2:?capture dir required}"

bundle=/var/lib/tee_crafter/output.tar.gz

# Bundle the staging dir and prove it landed.  Both exits from this script go
# through here so neither can report success without an artefact behind it.
write_bundle() {
  if ! ( cd "$out" && tar czf "$bundle" . ); then
    echo "[capture] FATAL: tar failed writing $bundle" >&2
    return 1
  fi
  if [ ! -s "$bundle" ]; then
    echo "[capture] FATAL: $bundle is missing or empty after tar" >&2
    return 1
  fi
  if ! sha256sum "$bundle" | awk '{print $1}' > "${bundle}.sha256"; then
    echo "[capture] FATAL: could not write ${bundle}.sha256" >&2
    return 1
  fi
  if [ ! -s "${bundle}.sha256" ]; then
    echo "[capture] FATAL: ${bundle}.sha256 is empty" >&2
    return 1
  fi
  # Ownership/permissions are conveniences for the downloader, not the
  # post-condition -- a bundle the orchestrator can still read via sudo beats
  # failing the run over a missing `tee_enclave` user.
  chown tee_enclave:tee_enclave "$bundle" "${bundle}.sha256" 2>/dev/null || true
  chmod 0644 "$bundle" "${bundle}.sha256" 2>/dev/null || true
  return 0
}

mkdir -p "$out/_meta" "$out/_logs" "$out/files"

if ! docker inspect "$container" >/dev/null 2>&1; then
  echo "[capture] container '$container' not found; nothing to capture" >&2
  echo "1" > "$out/_logs/exit_code.txt"
  echo "container-not-found" > "$out/_meta/error.txt"
  write_bundle || exit 2
  exit 1
fi

# Logs + container metadata first, before the diff/cp loop, so partial captures
# still surface what the user image actually printed.
docker logs "$container" >"$out/_logs/stdout.log" 2>"$out/_logs/stderr.log" || true
docker inspect -f '{{.State.ExitCode}}' "$container" >"$out/_logs/exit_code.txt" 2>/dev/null \
  || echo "?" >"$out/_logs/exit_code.txt"
docker inspect "$container" >"$out/_meta/inspect.json" 2>/dev/null || true
docker diff "$container" >"$out/_meta/diff.txt.raw" 2>/dev/null || : > "$out/_meta/diff.txt.raw"

# ---------------------------------------------------------------------------
# Filter pass 1: drop noisy system paths that distros write to on every
# container start (resolv.conf, ld cache, apt lists, dpkg locks, machine-id,
# python __pycache__, etc.) AND drop the bare top-level system directories
# (/usr, /usr/local, /var, /lib*, /etc, /opt, /srv, /bin, /sbin, /boot, /run)
# that show up as `C` entries.  Recursive `docker cp` on those would pull
# tens of MB of OS files and is also where absolute symlinks like
# /usr/bin/nawk -> /usr/bin/gawk come from.  Original diff kept for audit.
# ---------------------------------------------------------------------------
grep -Ev " (/dev|/proc|/sys|/run|/tmp/\.X|/var/cache/(apt|ldconfig|debconf)|/var/log/apt|/var/lib/apt|/var/lib/dpkg|/var/lib/ucf|/var/lib/systemd/random-seed|/etc/ld\.so\.cache|/etc/machine-id|/etc/mtab|/etc/resolv\.conf|/etc/hostname|/etc/hosts|/etc/nsswitch\.conf|/etc/ssl/certs/java|/usr(/bin|/sbin|/lib|/libexec|/share|/include|/local|/games)?|/lib(32|64)?(/.*)?|/lib/x86_64-linux-gnu|/etc|/var|/opt|/srv|/bin|/sbin|/boot|/root/\.cache|/root/\.bash_history|/root)(/|$)" \
  "$out/_meta/diff.txt.raw" > "$out/_meta/diff.txt.filtered" \
  || cp "$out/_meta/diff.txt.raw" "$out/_meta/diff.txt.filtered"

# Re-allow common writable user-output locations that the broad filter above
# would otherwise eat (e.g. /var/log/myapp.log, /etc/myapp/conf, /opt/myapp).
# We keep the line if any *child* of these prefixes appears.  The narrow
# system-file filters in pass 1 already dropped truly noisy /var/{cache,lib}
# entries, so what remains here is user content.
grep -E " (/var/log/[a-zA-Z0-9_.-]+|/var/tmp|/var/run|/opt/[a-zA-Z0-9_.-]+|/etc/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+|/srv/[a-zA-Z0-9_.-]+|/root/[a-zA-Z0-9_.-]+)" \
  "$out/_meta/diff.txt.raw" >> "$out/_meta/diff.txt.filtered" 2>/dev/null || true

# Dedup + stable sort the filtered list.
sort -u "$out/_meta/diff.txt.filtered" > "$out/_meta/diff.txt"
rm -f "$out/_meta/diff.txt.filtered"

# ---------------------------------------------------------------------------
# Filter pass 2: strip parent-of-child entries.  docker diff routinely emits
# both `C /app` (parent) and `A /app/report.md` (leaf).  If we copied both,
# `docker cp` would recursively pull /app first (creating files/app/...) and
# then copy /app/report.md on top, leading to duplicates like
# files/app/per_cohort/per_cohort/placebo.json.  We only copy *leaf* paths:
# any path that no other diff entry strictly contains as a prefix.
# ---------------------------------------------------------------------------
awk '{
  tag=$1; sub(/^[^ ]+ /, "", $0); path=$0;
  if (path=="" || path=="/") next;
  paths[NR]=path; tags[NR]=tag;
}
END {
  for (i in paths) {
    pi = paths[i] "/";
    is_parent = 0;
    for (j in paths) {
      if (i == j) continue;
      if (index(paths[j], pi) == 1) { is_parent = 1; break; }
    }
    if (!is_parent) print tags[i] " " paths[i];
  }
}' "$out/_meta/diff.txt" > "$out/_meta/diff.txt.leaves"

# diff lines look like:  A /path/to/added   C /path/to/modified   D /path/to/removed
# We capture A and C; we ignore D (deleted paths cannot be docker-cp'd).
while IFS= read -r line; do
  [ -z "$line" ] && continue
  tag="${line%% *}"
  path="${line#* }"
  case "$tag" in
    A|C)
      dest="$out/files$path"
      mkdir -p "$(dirname "$dest")"
      docker cp "$container:$path" "$dest" 2>/dev/null || true
      ;;
    D|*)
      ;;
  esac
done < "$out/_meta/diff.txt.leaves"

# Defense-in-depth: drop any absolute symlinks that slipped through (the
# extractor refuses them; even if it did not, they would point at host
# paths after extract).  We log them for transparency.
if [ -d "$out/files" ]; then
  find "$out/files" -type l -lname '/*' -print >"$out/_meta/dropped_abs_symlinks.txt" 2>/dev/null || true
  find "$out/files" -type l -lname '/*' -delete 2>/dev/null || true
fi

docker rm -f "$container" >/dev/null 2>&1 || true

write_bundle || exit 2

echo "[capture] wrote $bundle ($(stat -c%s "$bundle" 2>/dev/null || stat -f%z "$bundle") bytes)" >&2
exit 0
