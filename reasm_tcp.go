package main

import (
	"fmt"
	"net"
)

// TCP stream reassembly.
//
// The overlap policy is FIRST WINS: for any octet covered by more than one
// segment, the bytes that arrived first are the bytes in the stream, and a
// later segment disagreeing about them is recorded as a conflict and
// otherwise ignored. --overlap=last is the other way round.
//
// Why first: it is what Wireshark does, which is the only reason the two can
// be compared byte for byte at all, and it is also what the BSD-derived
// stacks do, so it is the commonest answer on the wire. It is NOT a safe
// answer. Linux, Windows and the BSDs do not all agree, and an attacker who
// knows which stack the endpoint runs can write a stream that a monitor
// reassembles one way and the endpoint reads the other. That is the whole
// point of the policy being named in the output of every follow and every
// conflict being listed, rather than one of the two readings being presented
// as the content of the connection.
//
// Everything here is measured against tshark -z follow,tcp,raw,N. Six
// behaviours were read off the oracle rather than guessed:
//
//  1. One output line per segment that contributed bytes, in the order the
//     bytes belong in the stream, not the order the segments arrived.
//  2. A segment contributes only the bytes at or after the next expected
//     sequence number. The overlapping part is dropped, not re-emitted.
//  3. The base sequence comes from the SYN when there is one, and from the
//     first segment carrying data when there is not. Without a SYN, data
//     below the first data segment's sequence number is discarded.
//  4. A FIN does not consume a sequence number for this purpose, so data at
//     the FIN's own sequence number is delivered.
//  5. A RST does not end the stream.
//  6. Data that never becomes contiguous is never delivered.

type endpoint struct {
	addr string
	port uint16
}

func (e endpoint) String() string {
	if ip := net.ParseIP(e.addr); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", e.addr, e.port)
	}
	return fmt.Sprintf("%s:%d", e.addr, e.port)
}

// Conflict records one disagreement about the content of a stream octet.
// Both readings are kept, and which one the stream ends up holding is
// decided by the policy, so the record does not say "kept" and "lost": a
// reader of the output can see what the other policy would have given.
type Conflict struct {
	Dir     int
	Offset  int64
	Len     int
	Earlier []byte
	Later   []byte
	Packet  int
}

type heldSeg struct {
	abs    int64
	wire   int64 // sequence numbers the segment occupies
	data   []byte
	packet int
}

type dirState struct {
	haveBase bool
	base     uint32
	nextSeq  uint32
	nextAbs  int64
	out      []byte
	held     []heldSeg
	heldByte int
	// exact is false once a segment has been delivered with fewer bytes
	// captured than it occupies in sequence space. After that out is no
	// longer indexed by stream offset and cannot be used to decide
	// whether an overlapping segment disagrees.
	exact bool
	// nseq is the highest sequence number this direction has reached,
	// counting the SYN and the FIN, which is what tshark means by
	// nextseq. It is kept apart from nextSeq above because that one is
	// the reassembler's position in the byte stream and does not move
	// for a segment carrying no data.
	nseq     uint32
	haveNseq bool
	win      uint16
	haveWin  bool
	// finSeq is the sequence number a FIN was seen at in this
	// direction, which is the number of the octet after the last one
	// the sender means to send.
	finSeq  uint32
	haveFin bool
}

// Chunk is one emission: the bytes one segment contributed, and which way
// they were going. The follow output is this list in order.
type Chunk struct {
	Dir    int
	Data   []byte
	Packet int
}

type Stream struct {
	Index     int
	Nodes     [2]endpoint
	dirs      [2]dirState
	Chunks    []Chunk
	Conflicts []Conflict
	Packets   int
	// Stats for the construct report.
	Retrans   int
	OutOfOrd  int
	Overlaps  int
	NoHand    bool
	Dropped   int // bytes held at the end that never became contiguous
	Missing   int // bytes a hole swallowed that the far end acknowledged
	heldLimit bool
	sawRST    bool
}

const heldLimitBytes = 4 << 20

type streamKey struct {
	a, b endpoint
}

func normKey(a, b endpoint) (streamKey, bool) {
	// The conversation is the unordered pair. Which of the two is node 0
	// is decided by which was the source of the first packet, so the key
	// is ordered deterministically and the node order is recorded apart
	// from it.
	if a.addr < b.addr || (a.addr == b.addr && a.port <= b.port) {
		return streamKey{a, b}, true
	}
	return streamKey{b, a}, false
}

// tcpStream returns the stream for a frame, creating it on first sight. The
// index is assigned in order of first appearance, which is how tshark
// numbers tcp.stream.
func (s *Session) tcpStream(f *Frame) (*Stream, int) {
	if s.tcpIdx == nil {
		s.tcpIdx = map[streamKey]*Stream{}
	}
	src := endpoint{net.IP(f.Src).String(), f.SPort}
	dst := endpoint{net.IP(f.Dst).String(), f.DPort}
	k, _ := normKey(src, dst)
	st := s.tcpIdx[k]
	if st == nil {
		st = &Stream{Index: len(s.Streams), Nodes: [2]endpoint{src, dst}}
		s.tcpIdx[k] = st
		s.Streams = append(s.Streams, st)
	}
	dir := 0
	if src != st.Nodes[0] {
		dir = 1
	}
	return st, dir
}

// udpStream numbers UDP conversations the same way, which tshark calls
// udp.stream and keeps in a separate numbering space from tcp.stream.
func (s *Session) udpStream(f *Frame) int {
	if s.udpIdx == nil {
		s.udpIdx = map[streamKey]int{}
	}
	src := endpoint{net.IP(f.Src).String(), f.SPort}
	dst := endpoint{net.IP(f.Dst).String(), f.DPort}
	k, _ := normKey(src, dst)
	if i, ok := s.udpIdx[k]; ok {
		return i
	}
	i := s.UDPCount
	s.udpIdx[k] = i
	s.UDPCount++
	return i
}

// feedTCP gives one segment to its stream.
func (s *Session) feedTCP(f *Frame) *Stream {
	st, dir := s.tcpStream(f)
	st.Packets++
	d := &st.dirs[dir]
	st.classify(s, dir, f)
	if f.TFlags&0x10 != 0 { // ACK
		st.ackRelease(s, 1-dir, f.AckNum, f.Pkt.Num)
	}
	if !d.haveBase {
		if f.TFlags&0x02 != 0 { // SYN: the stream starts one past it
			d.haveBase = true
			d.exact = true
			d.base = f.Seq + 1
			d.nextSeq = f.Seq + 1
		} else if f.TCPLen > 0 {
			// No handshake in the capture. The first segment with data
			// defines the origin, and anything below it is unreachable.
			d.haveBase = true
			d.exact = true
			d.base = f.Seq
			d.nextSeq = f.Seq
			st.NoHand = true
			s.stat("tcp.nohandshake")
		}
	}
	if f.TCPLen == 0 || !d.haveBase {
		return st
	}
	abs := d.nextAbs + int64(int32(f.Seq-d.nextSeq))
	// The sequence numbers a segment occupies come from the network
	// header, not from how much of it the capture holds. tshark advances
	// its stream position by the former and writes the latter, so a
	// capture with a short snaplen produces a stream that is shorter than
	// the connection and still in the right order. Using the captured
	// length for both turns every segment after the first into an
	// out-of-order one and delivers nothing.
	wire := int64(f.TCPLen)
	if wire < int64(len(f.Payload)) {
		wire = int64(len(f.Payload))
	}
	st.deliver(s, dir, abs, wire, f.Payload, f.Pkt.Num)
	return st
}

// classify names the two one-byte segments that look like data and are
// not the same thing as each other, and keeps the sequence and window
// state they are recognised by. The definitions are tshark's, in tshark's
// order, so that the counts can be compared with tcp.analysis.keep_alive
// and tcp.analysis.zero_window_probe rather than with an idea of what a
// probe is.
//
// The difference matters to the stream and not only to the count. A
// zero-window probe carries one byte AT the next expected sequence
// number, so it is new data and tshark delivers it; a keep-alive repeats
// the last octet already delivered, one BELOW the next expected number,
// so it is not. Reassembly gets both right through the ordinary overlap
// path, which is why neither needed a special case to be correct, only
// to be counted.
func (st *Stream) classify(s *Session, dir int, f *Frame) {
	d := &st.dirs[dir]
	rev := &st.dirs[1-dir]
	seglen := uint32(0)
	if f.TCPLen > 0 {
		seglen = uint32(f.TCPLen)
	}
	probe := false
	if d.haveNseq {
		switch {
		case seglen == 1 && f.Seq == d.nseq && rev.haveWin && rev.win == 0:
			probe = true
			s.stat("tcp.zerowindowprobe")
		case (seglen == 0 || seglen == 1) && f.Seq == d.nseq-1 &&
			f.TFlags&0x07 == 0: // not SYN, FIN or RST
			s.stat("tcp.keepalive")
		}
	}
	next := f.Seq + seglen
	if f.TFlags&0x02 != 0 { // SYN occupies one sequence number
		next++
	}
	if f.TFlags&0x01 != 0 { // and so does FIN
		next++
	}
	// A zero-window probe does not move the next expected sequence
	// number. The receiver advertised no room, so the byte is not
	// accepted and the next probe is at the same place; without this the
	// second probe of a pair reads as a keep-alive, which is what this
	// code did until the counts were put beside tshark's. Note that the
	// byte IS delivered into the reassembled stream, by tshark and by
	// us: analysis position and stream position are different things.
	if !probe && (!d.haveNseq || int32(next-d.nseq) > 0) {
		d.nseq = next
		d.haveNseq = true
	}
	d.win = f.Window
	d.haveWin = true

	// Where the stream ends decides what its last bytes are, so the
	// three arrangements are counted apart. A FIN does not consume a
	// sequence number for reassembly, so data AT the FIN's own number
	// is still delivered, by tshark and by us; data above it is not,
	// because nothing ever fills the hole the FIN left. An RST does not
	// end the stream at all and data after one is delivered normally.
	if seglen > 0 {
		if d.haveFin {
			switch {
			case f.Seq == d.finSeq:
				s.stat("tcp.data.atfin")
			case int32(f.Seq-d.finSeq) > 0:
				s.stat("tcp.data.afterfin")
			}
		}
		if st.sawRST {
			s.stat("tcp.data.afterrst")
		}
	}
	if f.TFlags&0x01 != 0 && !d.haveFin {
		d.finSeq = f.Seq + seglen
		d.haveFin = true
	}
	if f.TFlags&0x04 != 0 {
		st.sawRST = true
	}
}

// ackRelease handles the one case where bytes that were never captured
// still have to be accounted for in the stream.
//
// A hole in a direction is normally permanent: nothing fills it and
// nothing after it is ever delivered. But if the OTHER direction
// acknowledges past the hole, the bytes did arrive at the far end, and
// the only thing wrong is that this capture missed them. tshark fills
// the hole with a marker reading "[N bytes missing in capture file]" and
// releases everything the acknowledgement covers, and so does this.
//
// The rule was measured on seven hand-built files, because the first
// guess (release at the end of the capture) is wrong and the second
// (release on any acknowledgement past the next expected byte) is wrong
// too:
//
//   an ack at the start of the hole or inside it releases nothing;
//   an ack at or past the END of a held segment releases that segment;
//   two holes and one ack covering both produce two markers;
//   a segment arriving later to fill the hole is dropped, because the
//     position has already moved past it.
//
// The marker is a chunk of the follow output and is NOT part of the
// reassembled bytes. The position moves forward without bytes being
// added, which is the same thing a snapped capture does, so exact goes
// false and overlapping segments stop being compared.
func (st *Stream) ackRelease(s *Session, dir int, ack uint32, pkt int) {
	d := &st.dirs[dir]
	if !d.haveBase {
		return
	}
	ackAbs := d.nextAbs + int64(int32(ack-d.nextSeq))
	for len(d.held) > 0 {
		best := -1
		for i := range d.held {
			if best < 0 || d.held[i].abs < d.held[best].abs {
				best = i
			}
		}
		h := d.held[best]
		if h.abs+h.wire > ackAbs {
			return
		}
		d.held = append(d.held[:best], d.held[best+1:]...)
		d.heldByte -= len(h.data)
		if h.abs > d.nextAbs {
			gap := h.abs - d.nextAbs
			st.Chunks = append(st.Chunks, Chunk{
				Dir:    dir,
				Data:   []byte(fmt.Sprintf("[%d bytes missing in capture file]\x00", gap)),
				Packet: pkt,
			})
			st.Missing += int(gap)
			s.stat("tcp.gap.acked")
			d.nextSeq += uint32(gap)
			d.nextAbs = h.abs
			d.exact = false
		}
		st.place(s, dir, h.abs, h.wire, h.data, h.packet)
		st.drain(s, dir)
	}
}

// deliver places one segment, emits whatever became contiguous, and then
// drains anything held that the new bytes unblocked.
func (st *Stream) deliver(s *Session, dir int, abs, wire int64, data []byte, pkt int) {
	d := &st.dirs[dir]
	if abs < 0 {
		// Bytes before the origin of the stream. With no handshake in
		// the capture the origin is the first segment that carried
		// data, so a segment that arrives later with a LOWER sequence
		// number describes bytes no reader of this capture can place.
		// tshark discards them and so do we. Before this check the
		// negative offset reached a slice expression and panicked,
		// which is a refusal that did not happen.
		s.stat("tcp.beforeorigin")
		if abs+wire <= 0 {
			return
		}
		if -abs < int64(len(data)) {
			data = data[-abs:]
		} else {
			data = nil
		}
		wire += abs
		abs = 0
	}
	if abs > d.nextAbs {
		// Out of order: hold it until the hole in front of it fills.
		if d.heldByte+len(data) > heldLimitBytes {
			st.heldLimit = true
			s.stat("tcp.heldlimit")
			return
		}
		st.OutOfOrd++
		s.stat("tcp.outoforder")
		d.held = append(d.held, heldSeg{abs: abs, wire: wire, data: data, packet: pkt})
		d.heldByte += len(data)
		return
	}
	st.place(s, dir, abs, wire, data, pkt)
	st.drain(s, dir)
}

// place writes one segment that starts at or before the next expected
// offset, keeping whichever bytes the policy says.
func (st *Stream) place(s *Session, dir int, abs, wire int64, data []byte, pkt int) {
	d := &st.dirs[dir]
	end := abs + wire
	if abs < d.nextAbs {
		// The front of this segment covers sequence numbers already
		// delivered.
		n := d.nextAbs - abs
		if n > wire {
			n = wire
		}
		cmp := n
		if cmp > int64(len(data)) {
			cmp = int64(len(data))
		}
		if d.exact && cmp > 0 {
			old := d.out[abs : abs+cmp]
			if !bytesEqual(old, data[:cmp]) {
				st.Conflicts = append(st.Conflicts, Conflict{
					Dir: dir, Offset: abs, Len: int(cmp),
					Earlier: append([]byte(nil), old...),
					Later:   append([]byte(nil), data[:cmp]...),
					Packet:  pkt,
				})
				s.stat("tcp.overlap.conflict")
				if s.OverlapLast {
					copy(old, data[:cmp])
				}
			}
		}
		st.Overlaps++
		s.stat("tcp.overlap")
		if end <= d.nextAbs {
			st.Retrans++
			s.stat("tcp.retransmission")
			return
		}
		if cmp < int64(len(data)) {
			data = data[cmp:]
		} else {
			data = nil
		}
		wire -= n
		abs = d.nextAbs
	}
	if wire <= 0 {
		return
	}
	if int64(len(data)) < wire {
		d.exact = false
		s.stat("tcp.snapped")
	}
	d.out = append(d.out, data...)
	d.nextAbs = abs + wire
	if d.nextSeq+uint32(wire) < d.nextSeq {
		// The stream position crossed 2^32. Counted here rather than
		// inferred from the sequence numbers in the file, because this
		// is the one place the arithmetic that has to be serial
		// actually runs.
		s.stat("tcp.seqwrap")
	}
	d.nextSeq += uint32(wire)
	if len(data) > 0 {
		st.Chunks = append(st.Chunks, Chunk{Dir: dir, Data: append([]byte(nil), data...), Packet: pkt})
	}
}

// drain repeatedly takes the lowest held segment that now starts at or
// before the next expected offset.
func (st *Stream) drain(s *Session, dir int) {
	d := &st.dirs[dir]
	for {
		best := -1
		for i := range d.held {
			if d.held[i].abs > d.nextAbs {
				continue
			}
			if best < 0 || d.held[i].abs < d.held[best].abs {
				best = i
			}
		}
		if best < 0 {
			return
		}
		h := d.held[best]
		d.held = append(d.held[:best], d.held[best+1:]...)
		d.heldByte -= len(h.data)
		st.place(s, dir, h.abs, h.wire, h.data, h.packet)
	}
}

// finish accounts for whatever is still held when the file ends. tshark
// never delivers it either, so this is a count rather than an output.
func (st *Stream) finish() {
	for dir := range st.dirs {
		for _, h := range st.dirs[dir].held {
			st.Dropped += len(h.data)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Bytes returns the reassembled stream in one direction.
func (st *Stream) Bytes(dir int) []byte { return st.dirs[dir].out }
