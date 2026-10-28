#!/bin/sh
# check-apk-pins.sh - refresh the pinned APK versions in a Containerfile.
#
# Alpine keeps only the newest build of each package in a release branch,
# so exact pins (pkg=1.2.3-r0) break as soon as an update ships.  This
# script reads the package list straight out of the Containerfile's
# `apk add` block (so it can never drift from what the build installs),
# asks the Containerfile's own pinned base image what the repo has now,
# and prints:
#
#   1. each pin: unchanged, or old -> new
#   2. packages already installed in the base image that the repo has
#      upgraded (e.g. musl).  `apk add` won't upgrade those on its own, so
#      a new -dev package that needs the newer base version fails with
#      "breaks: musl-dev-…[musl=…]".  Add these to the pin list too (or
#      bump the base image digest).
#   3. a ready-to-paste `RUN apk add` block.
#
# Usage:  scripts-bash/building-only/check-apk-pins.sh [Containerfile.build]
# Env:    RUNTIME=docker to use docker instead of podman.

# shellcheck disable=SC1003,SC2016,SC2020,SC2086  # intentional: literal tr sets, scripts run inside the container, word-split lists
set -eu

CF=${1:-Containerfile.build}
RUNTIME=${RUNTIME:-podman}

[ -f "$CF" ] || { echo "no such file: $CF" >&2; exit 1; }

# Base image: the first FROM line (the pinned alpine@sha256 digest).
IMAGE=$(sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' "$CF" | head -n 1)
[ -n "$IMAGE" ] || { echo "no FROM line in $CF" >&2; exit 1; }

# Current pins: every "name=version" token of the first `RUN ... apk add` block,
# which runs from the "apk add" line through the first line that doesn't
# end in a backslash.
PINS=$(awk '/^[[:space:]]*RUN[[:space:]].*apk add/ { f = 1 } f { print } f && !/\\[[:space:]]*$/ { exit }' "$CF" \
	| tr ' \t\\' '\n\n\n' | grep '=' | sort -u)
[ -n "$PINS" ] || { echo "no pinned packages found in the apk add block of $CF" >&2; exit 1; }
NAMES=$(printf '%s\n' "$PINS" | sed 's/=.*//')

echo "Containerfile : $CF"
echo "Base image    : $IMAGE"
echo

# One container run: refresh the index, then print
#   AVAIL name-version   for each pinned package (exact-name search)
#   UPGRADE name-version for installed packages the repo has newer builds of
# shellcheck disable=SC2086
OUT=$("$RUNTIME" run --rm "$IMAGE" sh -c '
	apk update -q >/dev/null 2>&1 || apk update >&2
	for p in "$@"; do
		r=$(apk search -x "$p" 2>/dev/null | head -n 1)
		if [ -n "$r" ]; then echo "AVAIL $r"; else echo "MISSING $p"; fi
	done
	apk version -l "<" 2>/dev/null | awk "NR > 1 { print \"UPGRADE \" \$1 }"
' sh $NAMES)

# "name-1.2.3-r4" -> "name=1.2.3-r4".  Alpine versions never contain "-"
# except before the -rN release suffix, and always start with a digit.
to_pin() { sed -E 's/^(.+)-([0-9][^-]*-r[0-9]+)$/\1=\2/'; }

AVAIL=$(printf '%s\n' "$OUT" | sed -n 's/^AVAIL //p' | to_pin)
MISSING=$(printf '%s\n' "$OUT" | sed -n 's/^MISSING //p')
# `apk version` prints "name-oldversion"; look up the repo's version.
UPGRADES=$(printf '%s\n' "$OUT" | sed -n 's/^UPGRADE //p' | to_pin | sed 's/=.*//')

echo "== Pinned packages"
changed=0
for name in $NAMES; do
	old=$(printf '%s\n' "$PINS" | sed -n "s/^$name=//p")
	new=$(printf '%s\n' "$AVAIL" | sed -n "s/^$name=//p")
	if [ -z "$new" ]; then
		printf '  %-22s %-16s NOT IN REPO (renamed or dropped?)\n' "$name" "$old"
		changed=1
	elif [ "$old" = "$new" ]; then
		printf '  %-22s %s\n' "$name" "$old"
	else
		printf '  %-22s %-16s -> %s\n' "$name" "$old" "$new"
		changed=1
	fi
done
[ -z "$MISSING" ] || { echo; echo "Not found by exact name:"; printf '  %s\n' $MISSING; }

# Base-image packages with newer repo builds that aren't pinned yet.
EXTRA=""
if [ -n "$UPGRADES" ]; then
	BASEUP=$("$RUNTIME" run --rm "$IMAGE" sh -c '
		apk update -q >/dev/null 2>&1
		for p in "$@"; do apk search -x "$p" 2>/dev/null | head -n 1; done
	' sh $UPGRADES | to_pin)
	for line in $BASEUP; do
		name=${line%%=*}
		printf '%s\n' "$NAMES" | grep -qx "$name" || EXTRA="$EXTRA $line"
	done
fi
echo
echo "== Installed in the base image, newer in the repo"
if [ -n "$EXTRA" ]; then
	for e in $EXTRA; do printf '  %s\n' "$e"; done
	echo "  -> pin these too (apk add won't upgrade them on its own),"
	echo "     or update the base image digest."
	changed=1
else
	echo "  none"
fi

echo
echo "== Paste-ready block"
echo "RUN apk add --no-cache \\"
{ printf '%s\n' "$AVAIL"; for e in $EXTRA; do printf '%s\n' "$e"; done; } \
	| sort -t= -k1,1 -u | sed 's/^/    /; $!s/$/ \\/'

[ "$changed" -eq 0 ] && { echo; echo "All pins are current."; }
exit 0
