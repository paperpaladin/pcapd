# pcapd

## Contract

Read a capture file in classic pcap or pcapng format, decode the link layer,
IPv4 and IPv6 (including extension headers and fragment reassembly), TCP and
UDP, and reassemble TCP byte streams. Print per-packet field values in a form
that can be diffed field by field against `tshark -T fields`, and print
reassembled stream bytes in a form that can be diffed against
`tshark -z follow,tcp,raw,N`.

Refuse a malformed file rather than guessing at it. A length that points past
the end of the file, a block that overlaps its own header, an option list
longer than the block that holds it: all of these are errors with a message,
never a best effort.

## Hard invariant

No field value pcapd prints may disagree with tshark's value for the same
field of the same packet, and no reassembled stream byte may disagree with
tshark's. Where pcapd cannot produce a value it must say so, and a refusal is
counted separately from a disagreement in every report. A run that cannot tell
the two apart has measured nothing.

## Oracle

Ranked by how little of it we control.

1. `tshark` for field values (`-T fields -e ...`) and for stream reassembly
   (`-z follow,tcp,raw,N`). It is a different codebase, a different language,
   and it has been read by more people than anything here.
2. `tcpdump` as a second, independent packet decoder. libpcap's own reader for
   the container, tcpdump's own printers for the protocols.
3. `capinfos` and `editcap` for file-level facts: packet count, byte count,
   encapsulation, snaplen, and for converting between pcap and pcapng so the
   two readers can be checked against the same packets.
4. Python's standard library as a third parser for the container format
   alone: `struct` over the block structure, with no protocol knowledge.
5. The corpus generator, which is the weakest of the five because we wrote it.
   Captures taken with `tcpdump -w` inside a user namespace are real packets
   produced by the kernel's TCP stack; the hand-written ones are not.

## Non-goals

- Live capture. pcapd reads files.
- Protocols above TCP and UDP. No HTTP, no TLS, no DNS.
- Writing capture files. The corpus generator writes pcap bytes from Python;
  pcapd itself never writes a capture.
- gopacket, or any third-party module. `go.mod` has no require block.
- Checksum verification. We print the checksum field; we do not validate it.

## Overlap policy

Decided up front because the choice has to be visible, not discovered later.
pcapd keeps the bytes that arrived FIRST for any octet covered by more than
one segment, and records every conflict it saw. The policy is selectable with
`--overlap` and the chosen policy is printed in the `follow` header, so a
reader of the output never has to guess which of the two possible streams they
are looking at.

## Commit sequence

### Milestone 1: the container

- [x] repository skeleton: go.mod, Makefile, .gitignore, LICENSE, this plan
      why: the collection's gate runs make, so make has to exist first.
- [x] byte cursor with a sticky error flag and one bounds check
      why: every length in this format comes out of the file, so there must be
      exactly one place where a length becomes a slice.
- [x] classic pcap file header, both byte orders, nanosecond variant
      why: the smallest complete unit of the format.
- [x] classic pcap packet records, with caplen/origlen
      why: packet iteration is what everything above depends on.
- [x] `pcapd info`, compared against capinfos
      why: the first external oracle, on the smallest surface.
- [x] corpus generator: real loopback traffic captured in a user namespace
      why: hand-written packets cannot be the only input, or the decoder is
      only ever tested against the author's idea of a packet.
- [x] t/run.sh with the pass/fail protocol and the construct counter
      why: an overlap test on a corpus with no overlaps passes vacuously, so
      the counts come before the tests that need them.
- [x] refuse truncated records, caplen > snaplen, caplen past EOF
      why: this is the attack on a parser like this one.
      measured: caplen above snaplen is NOT refused. Wireshark reads a pcap
      whose snaplen is 0, 1, 32 or 60 with 60-byte records, so refusing it
      would be an over-refusal, which this plan counts as a defect of the
      same kind as the opposite. Truncated records and caplen past EOF are
      refused, and caplen above the ORIGINAL length is refused in classic
      pcap and read in pcapng, which is what each oracle does.

### Milestone 2: pcapng

- [x] pcapng block framing, trailing length, byte-order magic
      why: the block structure is the whole format; everything else is a body.
- [x] section header block, option list, multiple sections
      why: a second section can change byte order mid-file.
- [x] interface description blocks, link type, snaplen, if_tsresol
      why: timestamps are meaningless without the per-interface resolution.
- [x] enhanced packet blocks, per-packet interface id
      why: the normal packet carrier.
- [x] simple packet blocks and their inferred length
      why: an SPB has no caplen, which is a different shape of bug.
- [x] name resolution blocks
      why: named in the contract, and a record list with its own lengths.
- [x] interface statistics blocks and unknown block types skipped by length
      why: a reader that stops at an unknown block cannot read real files.
- [x] pcapng refusals: block length lies, option overruns, odd padding
      why: the same attack again, against a more complicated container.

### Milestone 3: the packet

- [x] Ethernet II, including the length/type ambiguity
      why: the link layer the corpus is captured on.
- [x] `pcapd fields`, per-field comparison harness against tshark
      why: the measurement that the rest of the project is judged by.
- [x] IPv4 header, options, header length
      why: the common case.
- [x] TCP header, flags, options, data offset
      why: the point of the project.
- [x] UDP header
      why: cheap, and it shares the pseudo-header shape with TCP.
- [x] 802.1Q VLAN tags, including stacked tags
      why: changes where the network layer starts.
- [x] Linux cooked capture v1 and v2, raw IP, null/loopback link types
      why: `tcpdump -i any` produces SLL2 and nothing else does.
- [x] IPv6 base header
      why: the second half of the network layer.
- [x] IPv6 extension header chain, including an unknown next header
      why: the chain is where a length error becomes an infinite loop.
- [x] IPv4 fragment reassembly
      why: named in the contract, and the first place state crosses packets.
- [x] IPv6 fragment header and reassembly
      why: a different header, the same state machine.
- [x] fragment refusals: overlapping fragments, gaps, oversized reassembly
      why: a 64 KB limit that is not enforced is a memory bug.

### Milestone 4: the stream

- [x] stream identity and numbering, matched against tcp.stream
      why: every later comparison is indexed by this number.
- [x] in-order reassembly, compared byte for byte against follow,tcp,raw
      why: the base case has to be right before the hard cases mean anything.
- [x] out-of-order segments held and released in sequence order
      why: the first case where arrival order is not byte order.
- [x] exact retransmissions discarded
      why: the common case of duplicate data, and the easy half of overlap.
- [x] overlapping segments with identical bytes
      why: separates "overlap handled" from "conflict handled".
- [x] overlapping segments with conflicting bytes, first-wins, conflict record
      why: the case the project exists for.
- [x] `--overlap=last` as a second policy, and the two outputs differing
      why: a policy flag that produces the same bytes either way is decoration.
- [ ] sequence number wraparound across 2^32
      why: a comparison written with `<` instead of serial arithmetic is wrong
      only here, and a capture rarely reaches it by accident.
- [x] streams with no handshake in the capture
      why: the capture starting late is the normal case on a busy link.
- [ ] zero-window probes and keep-alives not counted as data
      why: a one-byte probe inserted into the stream corrupts it silently.
- [ ] FIN and RST, and data after FIN
      why: where the stream ends decides what the last bytes are.
- [x] `pcapd follow` output matching tshark's format byte for byte
      why: a comparison that normalises both sides measures the normaliser.

### Milestone 5: measurement

- [x] hand-built corpus: overlapping retransmission with different payload
      why: no generator produces this, and it is the headline case.
- [x] hand-built corpus: fragments with a gap, out of order, overlapping
      why: likewise.
- [x] hand-built corpus: big-endian pcap, big-endian pcapng, odd snaplens
      why: the byte-order path is dead code on this machine otherwise.
- [x] malformed corpus: length fields pointing past the end, at least 200
      why: stated in the contract as the obvious attack.
- [x] construct counter printed by the suite, asserted non-zero per construct
      why: the vacuous-pass guard.
- [ ] tcpdump cross-check on the packet layer
      why: a second decoder disagreeing with the first is worth knowing about.
- [ ] Python container parser as a third opinion on block boundaries
      why: tshark and tcpdump share libpcap for classic pcap, so they are not
      fully independent there.
- [ ] mutation run over the decoders, survivors recorded
      why: the suite is only worth the mutants it kills.
- [ ] mutation run over the reassembler, survivors recorded
      why: separately, because the corpus for it is the hand-built one.
- [x] fuzz sweep: random mutations of valid files, no crash, no hang
      why: a panic is a refusal that did not happen.
- [ ] README with the measured numbers and what does not work
      why: a README that only lists successes is not finished.
