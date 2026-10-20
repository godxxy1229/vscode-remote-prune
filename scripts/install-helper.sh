#!/bin/sh
# Explicit operator action only. The extension never launches this script.
set -eu
test "$(id -u)" = 0 || { echo 'Run as root after reviewing this script.'; exit 1; }
test "$#" = 2 || { echo 'Usage: install-helper.sh USER EXPECTED_INSPECTOR_SHA256'; exit 1; }
prune_user=$1
prune_expected=$2
printf '%s\n' "$prune_user" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || exit 1
test "$(id -u "$prune_user")" -gt 0 || exit 1
printf '%s\n' "$prune_expected" | grep -Eq '^[a-f0-9]{64}$' || exit 1
case "$(uname -m)" in aarch64) prune_arch=arm64;; x86_64) prune_arch=x64;; *) echo 'Unsupported architecture'; exit 1;; esac
prune_base=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
prune_source=$prune_base/bin/linux-$prune_arch/inspector
test ! -L "$prune_source" && test -f "$prune_source" || exit 1
prune_actual=$(sha256sum -- "$prune_source"); prune_actual=${prune_actual%% *}
test "$prune_actual" = "$prune_expected" || { echo 'Checksum mismatch'; exit 1; }
prune_target=/usr/local/libexec/remote-prune-inspect
prune_rule=/etc/sudoers.d/remote-prune-$prune_user
for prune_dir in / /usr /usr/local /etc /etc/sudoers.d; do
 test ! -L "$prune_dir" && test "$(stat -c %u "$prune_dir")" = 0 || exit 1
 test "$((0$(stat -c %a "$prune_dir") & 022))" = 0 || exit 1
done
if test ! -e /usr/local/libexec; then install -d -o root -g root -m 0755 /usr/local/libexec; fi
test ! -L /usr/local/libexec && test "$(stat -c %u /usr/local/libexec)" = 0 || exit 1
test "$((0$(stat -c %a /usr/local/libexec) & 022))" = 0 || exit 1
prune_temp=$(mktemp /etc/sudoers.d/.remote-prune-XXXXXXXX)
prune_bin_temp=$(mktemp /usr/local/libexec/.remote-prune-XXXXXXXX)
prune_new_target=0
prune_new_rule=0
prune_done=0
cleanup() {
 rm -f -- "$prune_temp" "$prune_bin_temp"
 if test "$prune_done" = 0; then
  if test "$prune_new_rule" = 1; then rm -f -- "$prune_rule"; fi
  if test "$prune_new_target" = 1; then rm -f -- "$prune_target"; fi
 fi
}
trap cleanup EXIT HUP INT TERM
printf '%s ALL=(root) NOPASSWD: /usr/local/libexec/remote-prune-inspect ""\n' "$prune_user" > "$prune_temp"
chmod 0440 "$prune_temp"
/usr/sbin/visudo -cf "$prune_temp" >/dev/null
for prune_path in "$prune_target" "$prune_rule"; do
 if test -e "$prune_path" || test -L "$prune_path"; then
  test ! -L "$prune_path" && test "$(stat -c %u "$prune_path")" = 0 || exit 1
  test "$((0$(stat -c %a "$prune_path") & 022))" = 0 || exit 1
  if test "$prune_path" = "$prune_target"; then cmp -s "$prune_source" "$prune_path" || { echo 'Existing helper differs; review required'; exit 1; }
  else cmp -s "$prune_temp" "$prune_path" || { echo 'Existing policy differs; review required'; exit 1; }; fi
 fi
done
if test ! -e "$prune_target"; then
 install -o root -g root -m 0755 "$prune_source" "$prune_bin_temp"
 prune_actual=$(sha256sum "$prune_bin_temp"); prune_actual=${prune_actual%% *}
 test "$prune_actual" = "$prune_expected" || exit 1
 sync -f "$prune_bin_temp"
 mv -T -- "$prune_bin_temp" "$prune_target"; prune_new_target=1
 sync -f /usr/local/libexec
fi
if test ! -e "$prune_rule"; then
 sync -f "$prune_temp"
 mv -T -- "$prune_temp" "$prune_rule"; prune_new_rule=1
 sync -f /etc/sudoers.d
fi
/usr/sbin/visudo -c >/dev/null
prune_done=1
echo 'Read-only inspector and exact no-argument sudo rule installed.'
