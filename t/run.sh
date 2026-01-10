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

# A missing oracle is a refusal, not a reduced run. tshark is the authority
# for every field value and every reassembled byte here; without it the suite
# would report a number having checked nothing.
for tool in tshark tcpdump capinfos editcap python3; do
	command -v $tool >/dev/null 2>&1 || {
		echo "pcapd: $tool is not installed and is the oracle for most of this suite" >&2
		exit 2
	}
done

W=$(mktemp -d "${TMPDIR:-/tmp}/pcapd.XXXXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

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

echo "--- corpus ---"
sh t/corpus.sh || { echo "corpus build failed" >&2; exit 2; }
LIVE=$(ls t/corpus/live/*.pcap 2>/dev/null | wc -l)
CONV=$(ls t/corpus/conv/* 2>/dev/null | wc -l)
HAND=$(ls t/corpus/hand/* 2>/dev/null | wc -l)
echo "live captures: $LIVE   conversions: $CONV   hand-built: $HAND"
if [ "$LIVE" -eq 0 ]; then
	echo "SKIP live capture unavailable: every packet below was written by us."
	echo "     See t/corpus/live.log. This needs unshare -rn to work."
fi

# Files pcapd is expected to read. The -mod.pcap conversions are excluded
# here and checked as refusals further down.
corpus_ok() {
	ls t/corpus/live/*.pcap t/corpus/hand/*.pcap t/corpus/hand/*.pcapng \
	   t/corpus/conv/*.pcapng 2>/dev/null
	ls t/corpus/conv/*.pcap 2>/dev/null | grep -v -- '-mod\.pcap$'
}

echo
echo "--- file-level facts against capinfos ---"
# capinfos -M -T -r prints one tab-separated row: name, type, encapsulation,
# timestamp precision, snaplen, ..., packet count, file size, data size.
facts=0
files=0
for f in $(corpus_ok); do
	$PCAPD info "$f" > "$W/info" 2>"$W/err" || { bad "info $f: $(cat "$W/err")"; continue; }
	get() { sed -n "s/^$1: //p" "$W/info"; }
	mine="$(get filetype)|$(get packets)|$(get datasize)"
	ci=$(capinfos -M -T -r "$f" 2>/dev/null)
	theirs="$(echo "$ci" | cut -f2)|$(echo "$ci" | cut -f8)|$(echo "$ci" | cut -f10)"
	eq "capinfos $(basename "$f")" "$theirs" "$mine"
	facts=$((facts+3))
	files=$((files+1))
done
echo "     $facts file-level facts over $files files"

echo
echo "--- what the corpus actually contains ---"
# A test for overlapping segments run over a corpus with no overlapping
# segments passes and proves nothing. Every construct the suite claims to
# exercise is counted here and asserted non-zero. An empty capture file is
# a valid capture of nothing that every tool in the suite reads happily and
# agrees about, and this is what notices.
$PCAPD counts $(corpus_ok) > "$W/counts" || { echo "counts failed" >&2; exit 2; }
sed 's/^/     /' "$W/counts"
has() {
	n=$(awk -F"\t" -v k="$1" '$1==k{print $2}' "$W/counts")
	[ -n "$n" ] || n=0
	if [ "$n" -ge "${2:-1}" ]; then
		ok "corpus has $1 ($n)"
	else
		bad "corpus has $1: $n, want at least ${2:-1}"
	fi
}
for k in file.pcap file.pcapng file.bigendian file.nanosecond \
         link.ether link.linux-sll link.linux-sll2 link.raw link.null link.loop \
         ip4 ip4.df ip4.fragment ip6 ip6.fragment ip6.exthdr.chain \
         ip6.exthdr.0 ip6.exthdr.43 ip6.exthdr.44 ip6.exthdr.60 \
         vlan.tpid.8100 vlan.tpid.88a8 vlan.stacked vlan.dei.set \
         tcp udp tcp.withdata packet.snapped \
         tcp.flag.syn tcp.flag.fin tcp.flag.rst tcp.flag.psh \
         tcp.option.1 tcp.option.2 tcp.option.3 tcp.option.4 tcp.option.8 \
         ng.block.shb ng.block.idb ng.block.epb; do
	has "$k"
done

# Every live capture must hold packets. Three separate scenarios silently
# produced a 24-byte header and nothing else before tcpdump was told to
# flush, and the whole suite stayed green through it.
for f in t/corpus/live/*.pcap; do
	[ -e "$f" ] || continue
	n=$($PCAPD info "$f" | sed -n 's/^packets: //p')
	if [ "$n" -ge 4 ]; then
		ok "live capture $(basename "$f") has $n packets"
	else
		bad "live capture $(basename "$f") has $n packets"
	fi
done

echo
echo "--- per-field values against tshark ---"
# Per field and per packet, never per file. The totals line is what the
# README quotes; the per-file lines only appear when something disagrees.
fc=$(PCAPD=$PCAPD python3 t/fieldcmp.py $(corpus_ok))
echo "$fc" | grep -v '^TOTAL'
eval "$(echo "$fc" | sed -n 's/^TOTAL //p')"
eq "tshark fields: nothing disagrees" "differ=0 broken=0" "differ=$differ broken=$broken"
echo "     $compared values compared over $files files: $same same, $differ differ,"
echo "     $refused refused (tshark had a value), $declined declined (neither did)"

echo
echo "--- refusals ---"
status "no args is a usage error"    2 $PCAPD
status "unknown command is usage"    2 $PCAPD frobnicate
status "--help exits clean"          0 $PCAPD --help
status "missing file is refused"     1 $PCAPD info "$W/nope.pcap"
: > "$W/empty.pcap"
status "empty file is refused"       1 $PCAPD info "$W/empty.pcap"
printf 'not a capture at all\n' > "$W/text.pcap"
status "text file is refused"        1 $PCAPD info "$W/text.pcap"
for m in t/corpus/conv/*-mod.pcap; do
	[ -e "$m" ] || continue
	status "modified-format pcap refused ($(basename "$m"))" 1 $PCAPD info "$m"
	break
done


echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
