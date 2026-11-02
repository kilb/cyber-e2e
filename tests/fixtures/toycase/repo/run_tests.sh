#!/bin/sh
# Row 3 "upstream" regression suite for the toy case: asserts process() still
# computes the right checksum on benign records. A fix that clamps `len` to the
# buffer size keeps these identical; a fix that breaks functionality fails here.
# NOTE: runs under /bin/sh (dash) -- use bare-octal \ddd escapes, not \xHH.
set -e
BIN=.rrg-build/bin/prog
[ -x "$BIN" ] || sh build.sh
d=$(mktemp -d ./.t3.XXXXXX)
trap 'rm -rf "$d"' EXIT
check() { # name expected   (record bytes already written to $d/$1.bin)
  got=$("$BIN" "$d/$1.bin")
  [ "$got" = "$2" ] || { echo "REGRESSION $1: expected $2 got $got"; exit 1; }
}
printf '\003\000\000\000abc'              > "$d/len3.bin";  check len3  38
printf '\000\000\000\000'                 > "$d/empty.bin"; check empty 0
printf '\020\000\000\0000123456789abcdef' > "$d/len16.bin"; check len16 98
echo "ok: 3/3 upstream tests passed"
