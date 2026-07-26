#!/bin/sh
# Build the test corpus into t/corpus.
#
# Three sources, in decreasing order of how much we control them:
#
#   live/    real packets from the kernel's own TCP stack, captured with
#            tcpdump inside a user+network namespace. We chose the traffic;
#            we did not choose the bytes.
#   conv/    the live captures run through editcap into pcapng, nanosecond
#            pcap, and a few deliberately awkward shapes. Wireshark's own
#            writer, so the container bytes are not ours either.
#   hand/    packets written byte by byte in Python, for the cases no
#            generator will produce: an overlapping retransmission with a
#            different payload, a fragment with a gap, a big-endian file.
#   bad/     the named malformed files, one per defect, with the name
#            saying what is wrong. The sweep in t/hostile.py builds many
#            thousands more in a scratch directory and deletes them; these
#            are the ones worth looking at by hand.
#
# Nothing here is committed. The whole directory is in .gitignore, because a
# capture file in git is a binary blob nobody will ever re-derive.
set -u
cd "$(dirname "$0")/.." || exit 2
C=t/corpus
mkdir -p "$C/live" "$C/conv" "$C/hand" "$C/bad" || exit 2

if [ "${1:-}" != "-f" ] && [ -f "$C/.stamp" ] \
   && [ "$C/.stamp" -nt t/live.sh ] && [ "$C/.stamp" -nt t/traffic.py ] \
   && [ "$C/.stamp" -nt t/mkcorpus.py ] && [ "$C/.stamp" -nt t/hostile.py ]; then
	exit 0
fi
rm -f "$C"/live/* "$C"/conv/* "$C"/hand/* "$C"/bad/* "$C/.stamp"

# Live. A failure here is a loud skip, not a silent one: the hand-built
# corpus alone is a decoder tested against its author's idea of a packet,
# and the suite says so in its output rather than quietly reporting fewer
# assertions.
if unshare -rn sh t/live.sh "$C/live" >"$C/live.log" 2>&1; then
	:
else
	echo "corpus: live capture failed, see $C/live.log" >&2
fi

# Conversions. editcap is Wireshark's writer, so these exercise container
# bytes that pcapd's own generator never produced.
for f in "$C"/live/*.pcap; do
	[ -e "$f" ] || continue
	b=$(basename "$f" .pcap)
	editcap -F pcapng   "$f" "$C/conv/$b.pcapng"   >/dev/null 2>&1
	editcap -F nsecpcap "$f" "$C/conv/$b-ns.pcap"  >/dev/null 2>&1
	editcap -F modpcap  "$f" "$C/conv/$b-mod.pcap" >/dev/null 2>&1
done
# One capture with a snaplen that truncates every frame, so caplen and
# origlen differ everywhere instead of nowhere.
if [ -e "$C/live/tcp-bulk.pcap" ]; then
	editcap -F pcap -s 96 "$C/live/tcp-bulk.pcap" "$C/conv/tcp-bulk-snap96.pcap" >/dev/null 2>&1
	editcap -s 96 -F pcapng "$C/live/tcp-bulk.pcap" "$C/conv/tcp-bulk-snap96.pcapng" >/dev/null 2>&1
fi

python3 t/mkcorpus.py "$C/hand" || exit 2

# The named malformed files, one per defect, written out so that they can
# be looked at. The sweep builds them in memory and does not need them on
# disk; a person reading a refusal in the Go source does.
python3 t/hostile.py --dump "$C/bad" >/dev/null || exit 2
touch "$C/.stamp"
