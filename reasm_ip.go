package main

import "sort"

// IP fragment reassembly.
//
// Fragments are held per datagram, keyed by the pair of addresses, the
// identification and, for IPv4, the protocol. A datagram is complete when
// the last fragment has been seen and the pieces cover every byte from zero
// to the end with no hole. Completion is reported on the fragment that
// completes it, which is the arrival order rather than the offset order,
// and which is where tshark reports it too.
//
// Overlapping fragments are kept, not merged: the first arrival wins for any
// byte covered twice, and a second copy with different bytes is recorded as
// a conflict. That is the same rule the TCP reassembler uses, for the same
// reason, and the same reason it is a policy and not a fact.

type fragKey struct {
	src   [16]byte
	dst   [16]byte
	ident uint32
	proto uint8
	v6    bool
}

type fragPiece struct {
	off  int
	data []byte
}

type fragSet struct {
	pieces   []fragPiece
	last     bool
	end      int // total length, known once the last fragment has arrived
	done     bool
	overlap  bool
	conflict bool
	nxt      uint8
	count    int
}

// Session carries the state that spans packets. A decoder with no session
// refuses anything that needs one, which keeps the single-packet path
// honest: it says it cannot do this rather than guessing.
type Session struct {
	frags map[fragKey]*fragSet
	// Counters for the construct report.
	Stats map[string]int

	// TCP streams, in order of first appearance, which is how tshark
	// numbers tcp.stream.
	tcpIdx  map[streamKey]*Stream
	Streams []*Stream
	// udpIdx numbers UDP conversations the same way.
	udpIdx   map[streamKey]int
	UDPCount int

	// OverlapLast selects the other overlap policy: a later segment
	// replaces bytes already delivered instead of being discarded.
	OverlapLast bool
}

func NewSession() *Session {
	return &Session{frags: map[fragKey]*fragSet{}, Stats: map[string]int{}}
}

func (s *Session) stat(k string) {
	if s.Stats != nil {
		s.Stats[k]++
	}
}

func key16(b []byte) [16]byte {
	var k [16]byte
	copy(k[16-len(b):], b)
	return k
}

// addFragment records one fragment and returns the reassembled datagram if
// this fragment completed it.
func (s *Session) addFragment(f *Frame, off int, more bool, ident uint32, nxt uint8, data []byte) ([]byte, uint8, bool) {
	k := fragKey{src: key16(f.Src), dst: key16(f.Dst), ident: ident, v6: f.IPVer == 6}
	if f.IPVer == 4 {
		k.proto = f.IPProto
	}
	fs := s.frags[k]
	if fs == nil {
		fs = &fragSet{}
		s.frags[k] = fs
	}
	fs.count++
	fs.nxt = nxt
	if off+len(data) > 65535 {
		// The reassembly buffer an IP header can describe is bounded by
		// its own 16-bit length field. A fragment claiming more is a
		// memory request dressed up as a packet.
		s.stat("ipfrag.oversize")
		f.refuse("fragment ends at %d, past the 65535-byte limit on a reassembled datagram", off+len(data))
		return nil, 0, false
	}
	for _, p := range fs.pieces {
		if overlaps(p.off, len(p.data), off, len(data)) {
			fs.overlap = true
			s.stat("ipfrag.overlap")
			if !sameBytes(p, off, data) {
				fs.conflict = true
				s.stat("ipfrag.conflict")
			}
		}
	}
	fs.pieces = append(fs.pieces, fragPiece{off: off, data: data})
	if !more {
		fs.last = true
		fs.end = off + len(data)
	}
	if fs.done || !fs.last {
		return nil, 0, false
	}
	// Lay the pieces down in arrival order and let the first writer of
	// each byte keep it. A later fragment covering the same offset with
	// different bytes is the conflict recorded above.
	buf := make([]byte, fs.end)
	filled := make([]bool, fs.end)
	for _, p := range fs.pieces {
		for i := 0; i < len(p.data) && p.off+i < fs.end; i++ {
			if !filled[p.off+i] {
				buf[p.off+i] = p.data[i]
				filled[p.off+i] = true
			}
		}
	}
	for i := range filled {
		if !filled[i] {
			s.stat("ipfrag.gap")
			return nil, 0, false
		}
	}
	fs.done = true
	s.stat("ipfrag.reassembled")
	return buf, fs.nxt, true
}

func overlaps(aOff, aLen, bOff, bLen int) bool {
	return aOff < bOff+bLen && bOff < aOff+aLen
}

// sameBytes reports whether the part of the new fragment that overlaps an
// existing piece carries the same bytes.
func sameBytes(p fragPiece, off int, data []byte) bool {
	lo := off
	if p.off > lo {
		lo = p.off
	}
	hi := off + len(data)
	if p.off+len(p.data) < hi {
		hi = p.off + len(p.data)
	}
	for i := lo; i < hi; i++ {
		if p.data[i-p.off] != data[i-off] {
			return false
		}
	}
	return true
}

// sortedOffsets is used only by the report, so the fragment list can be
// printed in a stable order.
func (fs *fragSet) sortedOffsets() []int {
	out := make([]int, len(fs.pieces))
	for i, p := range fs.pieces {
		out[i] = p.off
	}
	sort.Ints(out)
	return out
}
