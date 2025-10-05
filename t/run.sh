#!/bin/sh
# pcapd test suite.
#
# Every assertion compares pcapd against something pcapd did not produce:
# tshark, tcpdump, capinfos, or a parser written in Python that knows the
# container format and nothing else. An assertion that compares pcapd to
# pcapd is not an assertion.
#
# The last line is exactly "N passed, M failed", which the collection's
# tooling parses.
set -u
cd "$(dirname "$0")/.." || exit 2
PCAPD=./pcapd
[ -x "$PCAPD" ] || { echo "pcapd binary missing: run make" >&2; exit 2; }

# The binary must be newer than its sources, or an edit is tested against
# whatever was lying around. Three mutations elsewhere in this collection were
# each recorded as surviving for exactly this reason.
for f in *.go go.mod; do
	if [ "$f" -nt "$PCAPD" ]; then
		echo "$f is newer than $PCAPD: run make, not t/run.sh" >&2
		exit 2
	fi
done

pass=0
fail=0
ok()  { pass=$((pass+1)); echo "ok   $*"; }
bad() { fail=$((fail+1)); echo "FAIL $*"; }

# eq NAME EXPECTED ACTUAL. Prints both sides on a mismatch, because a failure
# that does not say what it saw costs a reproduction run.
eq() {
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1"
		echo "       expected: $2"
		echo "       actual:   $3"
	fi
}

# status NAME WANT CMD... -- exit status of a command.
status() {
	name=$1; want=$2; shift 2
	"$@" >/dev/null 2>&1
	eq "$name" "$want" "$?"
}

echo "--- cli surface ---"
status "no args is a usage error"    2 $PCAPD
status "unknown command is usage"    2 $PCAPD frobnicate
status "--help exits clean"          0 $PCAPD --help

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
