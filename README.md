# pcapd

Reads a packet capture file in classic pcap or pcapng format, decodes the
link layer, IPv4, IPv6, TCP and UDP, reassembles IP fragments, and
reassembles TCP byte streams. Go, standard library only, no `require` block
in `go.mod`.

```
pcapd info FILE                     format, byte order, interfaces, packets
pcapd fields -e NAME ... FILE       one line per packet, tab separated
pcapd counts FILE ...               how many of each construct the files hold
pcapd blocks FILE                   the container layout: offset, length, kind
pcapd streams FILE                  one line per TCP conversation
pcapd follow [--overlap=first|last] [--tshark] N FILE
pcapd check FILE ...                decode fully; print ok or the refusal
```

`make test` builds and runs the suite. It needs `tshark`, `tcpdump`,
`capinfos`, `editcap` and `python3`, and refuses to run without any of them
rather than reporting a smaller number having checked less.

## What it is measured against

Nothing here is checked against a value worked out by hand. Every assertion
compares pcapd with a program it does not control.

`tshark` 4.4.19 is the main oracle, for per-field values (`-T fields -e ...`)
and for reassembled stream bytes (`-z follow,tcp,raw,N`).

`tcpdump` 4.99.5 with libpcap 1.10.5 is the second decoder, and for classic
pcap it reads the container through libpcap rather than through Wireshark's
own reader, so on the container the two are genuinely independent.

`capinfos` and `editcap` give file-level facts and write the pcapng and
nanosecond conversions, so a good part of the corpus has container bytes
that Wireshark wrote rather than bytes this project wrote.

`t/container.py` is a third parser for the container format, in Python with
`struct` and no protocol knowledge at all, compared against `pcapd blocks`
line for line.

`t/overlapcmp.py` is a second reassembler, in Python, built from the segment
list tshark reports. It exists because tshark implements one overlap policy
and so cannot be the oracle for the other one.

The corpus generator is the weakest of these, because we wrote it.

## Numbers

Measured on 20 October 2026. `make test` prints all of them.

| what | measured |
|---|---|
| assertions | 210 passed, 0 failed |
| field values against tshark | 54,480 compared, 54,480 same, 0 differ |
| of those, refused by pcapd where tshark had a value | 0 |
| of those, declined by both | 600 |
| TCP streams reassembled against `follow,tcp,raw` | 78 streams, 1,386,129 bytes, 78 identical |
| second reassembler, both policies | 156 stream and policy pairs, 2,772,258 bytes |
| packet fields against tcpdump | 5,968 compared, 5,968 same, 0 differ |
| container units against the Python parser | 803 units over 96 files, 0 differ |
| file-level facts against capinfos | 288 over 96 files |
| malformed files (`make hostile`) | 41,630 built, 8,981 refused, 32,649 read, 0 crashed, 0 hung |
| of those put to the oracles | 1,700 |

Refusals are counted apart from disagreements everywhere, because the two
need different work. A disagreement is a bug. A refusal where tshark has a
value is a feature that is not written yet, and there are none of those
left in the field comparison. "Declined" is a third count, for a cell where
pcapd has no value and tshark has none either, which is not evidence about
anything.

On the malformed sweep the same split is kept in the other direction: a
file pcapd reads and the oracles refuse is a hole, a file the oracles read
and pcapd refuses is an over-refusal, and both are zero. Over-refusal is
treated as a defect here and not as caution; five refusals were removed
after measurement showed Wireshark reads the files they rejected.

Three files in the full sweep are refused by Wireshark and read by libpcap.
They are counted apart from both, named in the output every run, and
described under "where the oracles disagree" below.

## The overlap policy

The policy implemented is FIRST WINS: for any octet covered by more than
one segment, the bytes that arrived first are the bytes in the stream, and
a later segment disagreeing about them is recorded as a conflict and
otherwise ignored.

Two reasons for that choice. It is what Wireshark does, which is the only
reason the two can be compared byte for byte at all. And it is what the
BSD-derived stacks do, so it is the commonest answer on the wire.

It is not a safe answer, and no answer is. Linux, Windows and the BSDs do
not all resolve an overlap the same way, so a monitor that picks one of
them reassembles a stream the endpoint may never have read. An attacker who
knows which stack the endpoint runs can write a pair of overlapping
segments whose conflicting bytes give the monitor one message and the
endpoint another. That is a real class of intrusion-detection evasion and
it is the reason the choice is in the output rather than buried:

```
$ pcapd follow 0 t/corpus/hand/re-overlap-conflict.pcap
stream 0: 10.0.0.1:40000 <-> 10.0.0.2:80
overlap policy: first
bytes: 12 from node 0, 0 from node 1
conflicts: 1
conflict: direction 0 offset 3 length 3 packet 5 earlier 414141 later 787878 kept earlier
held-undelivered: 0 bytes
0: 4141414141417979795a5a5a
1:
```

`--overlap=last` gives `4141417878787979795a5a5a` for the same file. The
conflict line carries both readings whichever policy is in force, so the
output says what the other policy would have produced rather than making
the reader run it again.

`pcapd follow --tshark` reproduces the block tshark prints, for the diff,
and refuses to run with `--overlap=last`. The per-segment format says which
bytes each segment contributed, and under last-wins a segment can change
bytes another segment already contributed, which that format cannot express
honestly.

IP fragment reassembly uses first-wins too and records conflicts the same
way, but it does not follow `--overlap`: the flag changes TCP only.

## What the corpus holds

96 readable files and 37 named malformed ones, all generated by `make
test`; none are committed, because a capture file in git is a binary blob
nobody will re-derive.

Nine live captures of real loopback traffic, taken with `tcpdump -w` inside
a `unshare -rn` user and network namespace, so the packets come from the
kernel's own TCP stack. 29 conversions of those through `editcap` into
pcapng, nanosecond pcap, Kuznetzov modified pcap, and a 96-byte snaplen.
67 hand-written files for the cases no generator produces.

The counts below come from `pcapd counts` and the suite asserts every one
of them is non-zero. The reason is that an overlap test run over a corpus
with no overlaps passes and proves nothing. Writing the counter found three
capture files that were empty, which every tool in the suite read happily
and agreed about.

```
file.pcap 76   file.pcapng 20   file.bigendian 3   file.nanosecond 10
link.ether 584  link.null 28  link.raw 21  link.loop 14
link.linux-sll 14  link.linux-sll2 19
ip4 561  ip4.df 238  ip4.options 1  ip4.fragment 46
ip4.fragment.offset13bit 2  ip4.dsfield.nonzero 1
ip6 112  ip6.fragment 18  ip6.exthdr.chain 1  ip6.tclass.nonzero 1
ip6.exthdr.0 2  ip6.exthdr.43 2  ip6.exthdr.44 18  ip6.exthdr.60 2
vlan.tpid.8100 21  vlan.tpid.88a8 7  vlan.stacked 7  vlan.dei.set 7
tcp 535  udp 90  tcp.withdata 189  packet.snapped 24
tcp.flag.syn 130  fin 74  rst 7  psh 166  ack 467  urg 1  ece 1  cwr 1  ns 1
tcp.option.0 1  .1 411  .2 37  .3 37  .4 37  .5 1  .8 223
tcp.window.zero 18  udp.checksum.zero 1
ng.block.shb 21  idb 22  epb 182  spb 7  nrb 1  isb 1  dsb 1
ng.block.unknown-0x12345678 1
ng.sections.multiple 2  ng.interfaces.multiple 2
ng.tsresol.unusual 2  ng.tsoffset 1  ng.nameresolution.records 3
tcp.overlap 10  tcp.overlap.conflict 5  tcp.retransmission 6
tcp.outoforder 6  tcp.nohandshake 11  tcp.beforeorigin 1  tcp.snapped 24
tcp.keepalive 1  tcp.zerowindowprobe 2  tcp.seqwrap 2
tcp.data.atfin 1  tcp.data.afterfin 1  tcp.data.afterrst 1
ipfrag.reassembled 17  ipfrag.overlap 4  ipfrag.conflict 1
ipfrag.gap 4  ipfrag.oversize 1
```

The counter is produced by the same decoder the tests use, which is a real
weakness: a construct the decoder cannot see is one the counter cannot
count either, and the pair would agree that the corpus is missing something
it holds. Two of the counts are put beside tshark's own analysis for the
same files as a check on that, `tcp.keepalive` against
`tcp.analysis.keep_alive` and `tcp.zerowindowprobe` against
`tcp.analysis.zero_window_probe`. The rest are not, and tshark has no
equivalent field for most of them.

The malformed corpus is built three ways by `t/hostile.py`: 37 named files,
one per defect, with the name saying what is wrong; every prefix of every
valid capture at a stride; and single bytes of valid captures overwritten
with 0xFF, 0x7F and 0x80 across the file header and the first few records,
which is where a length field becomes an index. The whole sweep is 41,630
files. `make hostile` runs it over the whole corpus; `make test` samples
5,124 of them so that it does not spend six minutes there.

## Where the oracles disagree

Three places, all measured, none averaged away.

A fragmented datagram. tcpdump does not reassemble, so it reads the
transport header off the FIRST fragment and prints ports for it. tshark
reassembles and attributes the transport header to the LAST fragment, where
the datagram is complete, and prints nothing for the first. pcapd follows
tshark. The tcpdump comparison leaves out 39 transport cells on fragments
for this reason, and which packets are fragments is asked of tshark rather
than of pcapd.

Two pcapng files libpcap will not open at all, each named in the output
with what libpcap said. `ng-twoifaces.pcapng` has two interfaces with
different link types. `ng-twosections.pcapng` changes byte order at its
second section, and libpcap reads the new section header with the old order
and reports a block size of 469762048. tshark reads both and so does pcapd.

A microsecond field out of range in the second record of a classic pcap.
tcpdump reads the file; tshark refuses it. What tshark prints before giving
up shows why it is not simply right: the frames it does decode have their
fields 8 bytes later in the file than they were written, which is the
difference between pcap's 16-byte record header and the 24-byte header of
the variants that share the standard magic. One bad field has sent it to a
different record layout for the whole file. pcapd is with tcpdump here.
Three files in the full sweep land in this group.

## Mutation testing

`make mutants` applies 31 single edits to the decoders and the reassembler,
one at a time, rebuilds, and runs the whole suite for each. The results and
the survivors are in `t/mutants.py` and reprinted here.

```
TOTAL mutants=31 killed=26 survived=2 equivalent=3 unusable=0
```

The target exits non-zero while a survivor stands, so this is a red gate
rather than a number in a document.

Three are equivalent, each checked rather than argued. Two are length
bounds on a block that the cursor already enforces: `take()` refuses
wherever the removed check would have, so the only difference is the
wording of the refusal, and the accept-or-refuse verdict was diffed over
all 40 named malformed files and the whole hand-built corpus without one
changing. The third reorders a switch whose two cases cannot both match,
because a sequence number cannot be both `nseq` and `nseq - 1`.

Two survive, and both are in the reassembler:

- **data below the stream origin is delivered anyway.** A segment whose
  sequence number falls before the point the stream began is accepted
  instead of dropped. The corpus reaches the branch, so this is a missing
  assertion and not a missing case: nothing currently checks what comes
  out when a capture starts mid-connection and an older segment arrives.
- **an ack releases a held segment whose start it covers.** The hold
  queue lets a segment out one ack too early. tshark's own reassembly
  agrees with both behaviours on this corpus, which is the reason it
  survives: the oracle is not sensitive to the difference, so a case
  where it becomes observable has to be built by hand.

Both are PLAN items rather than entries in a table of excuses. What they
have in common is worth saying: the mutants that die here are killed by
tshark disagreeing, and these two are places where tshark cannot see the
difference, so the suite has to grow its own assertion.

## What does not work

**No checksum verification.** `ip.checksum`, `tcp.checksum` and
`udp.checksum` are printed as the file holds them and never computed. A
capture full of wrong checksums reads exactly like a correct one. This is a
stated non-goal and not an oversight, but it is the first thing a reader
will assume is there.

**No protocol above TCP and UDP.** No HTTP, no TLS, no DNS, no ICMP. On
ICMP in particular, tshark dissects it and pcapd stops at the IP header,
which is why the field comparison has 600 declined cells: for those tshark
also has no value for the fields being asked about, so they are counted as
declined rather than as refused, but a wider field list would turn some of
them into refusals.

**The whole file is read into memory.** A capture larger than RAM cannot be
read at all. The upgrade is an iterator over an `io.ReaderAt`; nothing above
the `Capture` struct needs the byte slice.

**`--overlap` changes TCP only.** IP fragment reassembly is first-wins and
has no flag, so the fragment conflicts it records cannot be re-run the other
way. The TCP policy flag has a second implementation checking it and the
fragment one would not.

**Held segments are capped at 4 MB per direction.** A stream whose hole
never fills and which keeps receiving data stops holding at that point and
sets a flag. tshark's own limit is different, so a capture engineered to sit
between the two would disagree. Nothing in the corpus reaches either.

**No IPv4 options are interpreted.** The length is honoured so the header
is the right size, and `ip.options` is counted, but no individual option is
decoded or compared. tshark decodes them.

**One sequence-number space per direction, tracked as a 32-bit position.**
Wraparound is handled with serial arithmetic and there is a capture for it,
in order and out of order. A stream that wraps more than once within a
capture is not tested and the absolute offset is an `int64`, so it would
work, but that is an argument and not a measurement.

**The construct counter can only count what the decoder sees.** Stated
above, repeated here because it is the weakest link in the vacuous-pass
guard.

**The live corpus is loopback traffic only.** No real network interface, no
retransmissions caused by real loss, no path MTU discovery, no window
scaling in anger. The hard reassembly cases are all hand-written, which
means they are all cases somebody thought of.

**Only one machine, one Wireshark, one libpcap.** Every number here comes
from tshark 4.4.19 and libpcap 1.10.5 on one Linux box. Several of the
measured behaviours are version-specific: which pcapng versions Wireshark
accepts, which link-type bits it rejects, and the record-variant guess that
produces the third oracle disagreement above. A different Wireshark may
move them.
