package main

import "fmt"

// Frame is one packet, decoded as far as we could get. Where a layer could
// not be decoded, Refuse says why and every field at or above that layer is
// reported as refused rather than as absent. The distinction is the whole
// point: a missing value that means "this packet has no TCP header" and one
// that means "we did not manage to read the TCP header" are different facts,
// and a comparison that cannot tell them apart is measuring nothing.
type Frame struct {
	Pkt  *Packet
	Link uint32

	HasEth  bool
	EthDst  []byte
	EthSrc  []byte
	EthType uint16

	HasSLL     bool
	SLLv2      bool
	SLLPktType uint16
	SLLHatype  uint16
	SLLHalen   uint16
	SLLAddr    []byte
	SLLIfindex uint32
	SLLEtype   uint16

	HasNull bool
	NullAF  uint32

	Tags []VLANTag

	IPVer int // 4, 6, or 0 for neither

	// IPv4
	IHL      int
	DSField  uint8
	TotalLen uint16
	ID       uint16
	Flags    uint8
	FragOff  uint16 // raw 13-bit field, in units of 8 bytes
	TTL      uint8
	IPProto  uint8
	IPCksum  uint16
	IPOpts   []byte

	// IPv6
	TClass   uint8
	Flow     uint32
	PLen     uint16
	NextHdr  uint8
	HopLimit uint8

	// IPv6 extension headers, in the order they appeared.
	ExtHdrs []ExtHdr

	Src []byte
	Dst []byte

	L4     uint8 // transport protocol actually reached
	HasTCP bool
	HasUDP bool

	SPort   uint16
	DPort   uint16
	Seq     uint32
	AckNum  uint32
	DataOff int // TCP header length in bytes
	TFlags  uint16
	Window  uint16
	TCksum  uint16
	UrgPtr  uint16
	TOpts   []byte
	TCPLen  int // segment length from the network header, not from the capture

	// TCP options, decoded. Kinds lists every option kind in the order
	// they appeared, including the ones we do not interpret, because the
	// corpus construct counter needs to know which ones were exercised.
	TOptKinds []uint8
	MSS       []uint16
	WScale    []uint8
	SACKPerm  bool
	SACKEdges []uint32
	TSval     []uint32
	TSecr     []uint32

	ULen   uint16
	UCksum uint16

	Payload []byte // transport payload, as much of it as was captured

	Refuse string
}

// VLANTag is one 802.1Q or 802.1ad tag. TPID is the ethertype that
// introduced it, which is what decides whether Wireshark dissects it as
// vlan or as ieee8021ad, and so which field names it answers to.
type VLANTag struct {
	TPID  uint16
	PCP   uint8
	DEI   uint8
	VID   uint16
	Inner uint16
}

// ExtHdr is one IPv6 extension header. Len is the raw length field, whose
// units differ between header types; LenOct is the whole header in bytes.
type ExtHdr struct {
	Proto   uint8
	Nxt     uint8
	Len     uint8
	LenOct  int
	RtType  uint8
	SegLeft uint8
	FragOff uint16
	More    bool
	Ident   uint32
}

func (f *Frame) refuse(format string, a ...any) {
	if f.Refuse == "" {
		f.Refuse = fmt.Sprintf(format, a...)
	}
}

// Link type numbers we decode.
const (
	dltNull  = 0
	dltEther = 1
	dltRaw   = 101
	dltSLL   = 113
	dltLoop  = 108
	dltRaw4  = 228
	dltRaw6  = 229
	dltSLL2  = 276
)

func decode(p *Packet) *Frame {
	f := &Frame{Pkt: p, Link: p.LinkType}
	c := newCursor(p.Data, true)
	switch p.LinkType {
	case dltEther:
		f.decodeEther(c)
	case dltSLL:
		f.decodeSLL(c)
	case dltSLL2:
		f.decodeSLL2(c)
	case dltRaw, dltRaw4, dltRaw6:
		f.decodeRawIP(c)
	case dltNull, dltLoop:
		f.decodeNull(c, p.LinkType == dltLoop)
	default:
		f.refuse("link type %d (%s) is not decoded", p.LinkType, linkName(p.LinkType))
	}
	return f
}

func (f *Frame) decodeEther(c *cursor) {
	f.HasEth = true
	f.EthDst = c.take(6)
	f.EthSrc = c.take(6)
	f.EthType = c.u16()
	if !c.ok() {
		f.refuse("ethernet header: %v", c.err)
		return
	}
	f.decodeEtherType(c, f.EthType)
}

// decodeSLL reads Linux cooked capture v1: 16 bytes, with the protocol
// last. tcpdump writes this for "-i any" on older kernels and for a few
// device types that have no link header of their own.
func (f *Frame) decodeSLL(c *cursor) {
	f.HasSLL = true
	f.SLLPktType = c.u16()
	f.SLLHatype = c.u16()
	f.SLLHalen = c.u16()
	addr := c.take(8)
	f.SLLEtype = c.u16()
	if !c.ok() {
		f.refuse("linux cooked header: %v", c.err)
		return
	}
	f.sllAddr(addr)
	f.decodeEtherType(c, f.SLLEtype)
}

// decodeSLL2 reads Linux cooked capture v2: 20 bytes, protocol first, with
// an interface index that v1 does not carry. This is what "tcpdump -i any"
// produces on a current kernel and nothing else on this machine writes it.
func (f *Frame) decodeSLL2(c *cursor) {
	f.HasSLL = true
	f.SLLv2 = true
	f.SLLEtype = c.u16()
	c.u16() // reserved
	f.SLLIfindex = c.u32()
	f.SLLHatype = c.u16()
	f.SLLPktType = uint16(c.u8())
	f.SLLHalen = uint16(c.u8())
	addr := c.take(8)
	if !c.ok() {
		f.refuse("linux cooked v2 header: %v", c.err)
		return
	}
	f.sllAddr(addr)
	f.decodeEtherType(c, f.SLLEtype)
}

// The address field is always eight bytes and the length says how much of
// it is real. Wireshark only names it sll.src.eth when the length is six.
func (f *Frame) sllAddr(addr []byte) {
	if f.SLLHalen <= 8 && int(f.SLLHalen) <= len(addr) {
		f.SLLAddr = addr[:f.SLLHalen]
	}
}

// decodeRawIP reads a bare IP packet with no link header at all. The
// version nibble is the only thing that says which one it is.
func (f *Frame) decodeRawIP(c *cursor) {
	if c.left() < 1 {
		f.refuse("raw IP link type with an empty packet")
		return
	}
	switch c.b[c.pos] >> 4 {
	case 4:
		f.decodeIPv4(c)
	case 6:
		f.decodeIPv6(c)
	default:
		f.refuse("raw IP link type with version nibble %d", c.b[c.pos]>>4)
	}
}

// decodeNull reads the four-byte address family of DLT_NULL and DLT_LOOP.
// DLT_NULL writes it in the host byte order of whatever captured the file,
// which is not recoverable from the file, so the value is read both ways
// and the one that names a known family wins. DLT_LOOP is always network
// byte order and needs no guessing.
func (f *Frame) decodeNull(c *cursor, loop bool) {
	raw := c.take(4)
	if !c.ok() {
		f.refuse("null/loopback header: %v", c.err)
		return
	}
	f.HasNull = true
	v := be32(raw)
	if !loop {
		le := swap32(v)
		if !knownAF(v) && knownAF(le) {
			v = le
		}
	}
	f.NullAF = v
	switch v {
	case 2:
		f.decodeIPv4(c)
	case 24, 28, 30:
		// AF_INET6 is 24 on OpenBSD, 28 on FreeBSD and 30 on macOS, and
		// those are the three Wireshark accepts. It is 10 on Linux and
		// 23 on Windows, and Wireshark decodes neither, so neither do
		// we: a corpus file with family 10 is in t/corpus/hand and both
		// tools stop at the link layer on it.
		f.decodeIPv6(c)
	default:
		f.refuse("null/loopback address family %d is not decoded", v)
	}
}

func knownAF(v uint32) bool {
	switch v {
	case 2, 24, 28, 30:
		return true
	}
	return false
}

func (f *Frame) decodeEtherType(c *cursor, et uint16) {
	switch et {
	case 0x0800:
		f.decodeIPv4(c)
	case 0x86DD:
		f.decodeIPv6(c)
	case 0x8100, 0x88A8, 0x9100:
		// A tag is four bytes: three bits of priority, one drop-eligible
		// bit, twelve of VLAN id, then the ethertype of whatever is
		// inside. Tags stack, and the loop is bounded only by the frame
		// running out, which is the bound that matters.
		if len(f.Tags) >= 16 {
			f.refuse("more than 16 stacked VLAN tags")
			return
		}
		tci := c.u16()
		inner := c.u16()
		if !c.ok() {
			f.refuse("vlan tag: %v", c.err)
			return
		}
		f.Tags = append(f.Tags, VLANTag{
			TPID: et, PCP: uint8(tci >> 13), DEI: uint8(tci>>12) & 1,
			VID: tci & 0x0fff, Inner: inner,
		})
		f.decodeEtherType(c, inner)
	default:
		if et <= 1500 {
			f.refuse("ethernet length field %d, not a type: 802.3 framing is not decoded", et)
		} else {
			f.refuse("ethertype %#04x is not decoded", et)
		}
	}
}

func (f *Frame) decodeIPv4(c *cursor) {
	start := c.pos
	b0 := c.u8()
	if !c.ok() {
		f.refuse("ipv4 header: %v", c.err)
		return
	}
	if b0>>4 != 4 {
		f.refuse("ipv4 header says version %d", b0>>4)
		return
	}
	f.IPVer = 4
	f.IHL = int(b0&0x0f) * 4
	if f.IHL < 20 {
		f.refuse("ipv4 header length %d is below the 20-byte minimum", f.IHL)
		return
	}
	f.DSField = c.u8()
	f.TotalLen = c.u16()
	f.ID = c.u16()
	ff := c.u16()
	f.Flags = uint8(ff >> 13)
	f.FragOff = ff & 0x1fff
	f.TTL = c.u8()
	f.IPProto = c.u8()
	f.IPCksum = c.u16()
	f.Src = c.take(4)
	f.Dst = c.take(4)
	if !c.ok() {
		f.refuse("ipv4 header: %v", c.err)
		return
	}
	if f.IHL > 20 {
		f.IPOpts = c.take(f.IHL - 20)
		if !c.ok() {
			f.refuse("ipv4 options: %v", c.err)
			return
		}
	}
	if int(f.TotalLen) < f.IHL {
		f.refuse("ipv4 total length %d is below its own header length %d", f.TotalLen, f.IHL)
		return
	}
	// The network layer, not the capture, decides how long the payload is.
	// A snapped capture has fewer bytes than this and tshark still reports
	// the full length, so the two have to be tracked separately.
	wire := int(f.TotalLen) - f.IHL
	avail := c.left()
	if start+int(f.TotalLen) < len(c.b) {
		// Trailing bytes after the IP datagram (ethernet padding, or a
		// capture of a frame with an FCS). Not an error.
		avail = start + int(f.TotalLen) - c.pos
	}
	if avail > wire {
		avail = wire
	}
	if f.Flags&0x01 != 0 || f.FragOff != 0 {
		f.refuse("fragmented ipv4 datagram: reassembly not implemented")
		return
	}
	f.decodeTransport(c, f.IPProto, wire, avail)
}

func (f *Frame) decodeIPv6(c *cursor) {
	w := c.u32()
	if !c.ok() {
		f.refuse("ipv6 header: %v", c.err)
		return
	}
	if w>>28 != 6 {
		f.refuse("ipv6 header says version %d", w>>28)
		return
	}
	f.IPVer = 6
	f.TClass = uint8((w >> 20) & 0xff)
	f.Flow = w & 0xfffff
	f.PLen = c.u16()
	f.NextHdr = c.u8()
	f.HopLimit = c.u8()
	f.Src = c.take(16)
	f.Dst = c.take(16)
	if !c.ok() {
		f.refuse("ipv6 header: %v", c.err)
		return
	}
	wire := int(f.PLen)
	avail := c.left()
	if avail > wire {
		avail = wire
	}
	proto := f.NextHdr
	// Walk the extension header chain. Each step must consume at least
	// eight bytes, so the loop cannot spin, and the chain is capped at a
	// length no real packet reaches because an attacker-supplied chain is
	// otherwise bounded only by the MTU.
	for len(f.ExtHdrs) < 32 && isChainHdr(proto) {
		e := ExtHdr{Proto: proto}
		switch proto {
		case 44: // fragment: fixed eight bytes, no length field
			e.Nxt = c.u8()
			c.u8()
			ff := c.u16()
			e.Ident = c.u32()
			e.FragOff = ff >> 3
			e.More = ff&1 != 0
			e.LenOct = 8
		case 51: // authentication header: length in four-byte units, plus two
			e.Nxt = c.u8()
			e.Len = c.u8()
			e.LenOct = (int(e.Len) + 2) * 4
			c.skip(e.LenOct - 2)
		default: // hop-by-hop, routing, destination options, mobility
			e.Nxt = c.u8()
			e.Len = c.u8()
			e.LenOct = (int(e.Len) + 1) * 8
			if proto == 43 {
				e.RtType = c.u8()
				e.SegLeft = c.u8()
				c.skip(e.LenOct - 4)
			} else {
				c.skip(e.LenOct - 2)
			}
		}
		if !c.ok() {
			f.refuse("ipv6 extension header %d: %v", proto, c.err)
			return
		}
		if e.LenOct > wire {
			f.refuse("ipv6 extension header %d claims %d bytes with %d left in the payload", proto, e.LenOct, wire)
			return
		}
		f.ExtHdrs = append(f.ExtHdrs, e)
		wire -= e.LenOct
		avail -= e.LenOct
		if avail < 0 {
			avail = 0
		}
		if proto == 44 && (e.FragOff != 0 || e.More) {
			f.refuse("fragmented ipv6 datagram: reassembly not implemented")
			return
		}
		proto = e.Nxt
	}
	if isChainHdr(proto) {
		f.refuse("ipv6 extension header chain longer than 32 headers")
		return
	}
	f.decodeTransport(c, proto, wire, avail)
}

// isChainHdr reports whether a next-header value introduces another header
// we can walk past. ESP is deliberately absent: what follows it is
// encrypted, so the chain genuinely stops there.
func isChainHdr(p uint8) bool {
	switch p {
	case 0, 43, 44, 51, 60, 135:
		return true
	}
	return false
}

// decodeTransport reads the transport header. wire is the number of payload
// bytes the network header says follow; avail is how many of them the
// capture actually holds.
func (f *Frame) decodeTransport(c *cursor, proto uint8, wire, avail int) {
	f.L4 = proto
	switch proto {
	case 6:
		f.decodeTCP(c, wire, avail)
	case 17:
		f.decodeUDP(c, wire, avail)
	default:
		// An extension header hides the real transport behind it, so not
		// decoding one is a refusal. Any other protocol number is
		// terminal: it is genuinely not TCP and not UDP, and reporting
		// the transport fields as absent is the true answer rather than
		// an evasion.
		if isExtHdr(proto) {
			f.refuse("ipv6 extension header %d is not decoded", proto)
		}
		f.Payload = clamp(c, avail)
	}
}

// isExtHdr reports whether a next-header value introduces another header
// rather than a payload. ESP (50) is on the list because what follows it is
// encrypted, which is a refusal of a different kind but still a refusal.
func isExtHdr(p uint8) bool {
	switch p {
	case 0, 43, 44, 50, 51, 60, 135, 139, 140:
		return true
	}
	return false
}

func (f *Frame) decodeTCP(c *cursor, wire, avail int) {
	f.SPort = c.u16()
	f.DPort = c.u16()
	f.Seq = c.u32()
	f.AckNum = c.u32()
	off := c.u8()
	f.TFlags = uint16(off&0x01)<<8 | uint16(c.u8())
	f.DataOff = int(off>>4) * 4
	f.Window = c.u16()
	f.TCksum = c.u16()
	f.UrgPtr = c.u16()
	if !c.ok() {
		f.refuse("tcp header: %v", c.err)
		return
	}
	if f.DataOff < 20 {
		f.refuse("tcp data offset %d is below the 20-byte minimum", f.DataOff)
		return
	}
	if f.DataOff > wire {
		f.refuse("tcp data offset %d exceeds the %d payload bytes the network header allows", f.DataOff, wire)
		return
	}
	if f.DataOff > 20 {
		n := f.DataOff - 20
		if n > c.left() {
			f.refuse("tcp options: %d bytes claimed, %d captured", n, c.left())
			return
		}
		f.TOpts = c.take(n)
		f.decodeTCPOptions(f.TOpts)
	}
	f.HasTCP = true
	f.TCPLen = wire - f.DataOff
	f.Payload = clamp(c, avail-f.DataOff)
}

// decodeTCPOptions walks the option list. Kinds 0 and 1 are one byte; every
// other kind carries its own length, and a length below two would not
// advance, so it ends the list rather than looping. A malformed option list
// is not an error for the packet: tshark reports what it could read and so
// do we.
func (f *Frame) decodeTCPOptions(b []byte) {
	for i := 0; i < len(b); {
		kind := b[i]
		f.TOptKinds = append(f.TOptKinds, kind)
		if kind == 0 { // end of option list
			return
		}
		if kind == 1 { // no-op
			i++
			continue
		}
		if i+1 >= len(b) {
			return
		}
		l := int(b[i+1])
		if l < 2 || i+l > len(b) {
			return
		}
		v := b[i+2 : i+l]
		switch kind {
		case 2:
			if len(v) == 2 {
				f.MSS = append(f.MSS, be16(v))
			}
		case 3:
			if len(v) == 1 {
				f.WScale = append(f.WScale, v[0])
			}
		case 4:
			f.SACKPerm = true
		case 5:
			for j := 0; j+4 <= len(v); j += 4 {
				f.SACKEdges = append(f.SACKEdges, be32(v[j:j+4]))
			}
		case 8:
			if len(v) == 8 {
				f.TSval = append(f.TSval, be32(v[0:4]))
				f.TSecr = append(f.TSecr, be32(v[4:8]))
			}
		}
		i += l
	}
}

func (f *Frame) decodeUDP(c *cursor, wire, avail int) {
	f.SPort = c.u16()
	f.DPort = c.u16()
	f.ULen = c.u16()
	f.UCksum = c.u16()
	if !c.ok() {
		f.refuse("udp header: %v", c.err)
		return
	}
	f.HasUDP = true
	n := int(f.ULen) - 8
	if n < 0 || n > avail-8 {
		n = avail - 8
	}
	f.Payload = clamp(c, n)
}

func clamp(c *cursor, n int) []byte {
	if n < 0 {
		n = 0
	}
	if n > c.left() {
		n = c.left()
	}
	return c.take(n)
}
