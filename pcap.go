package main

import "fmt"

// Classic pcap. A 24-byte file header followed by records, each a 16-byte
// header and then caplen bytes of packet.
//
// The four magic numbers below are the ones libpcap writes. Three more exist
// (Kuznetzov's modified format, Francisco Mesquita's, Navtel's) and are
// refused by name rather than guessed at, because each of them changes the
// record header and reading one as a standard record silently shifts every
// packet.
const (
	magicUsec      = 0xa1b2c3d4
	magicNsec      = 0xa1b23c4d
	magicKuznetzov = 0xa1b2cd34
	magicMesquita  = 0xa1b234cd
	magicNavtel    = 0xa12b3c4d
)

// Packet is one record, after the container has been peeled off. Times are
// kept as seconds plus nanoseconds rather than as a single integer so that a
// pcapng interface with an exotic if_tsresol does not lose precision on the
// way through.
type Packet struct {
	Num      int
	TsSec    int64
	TsNsec   uint32
	CapLen   uint32
	OrigLen  uint32
	LinkType uint32
	Iface    int
	Data     []byte
	// HasTS is false for a pcapng simple packet block, which carries no
	// timestamp at all. Reporting zero for it would be a timestamp of
	// 1 January 1970 presented as a fact.
	HasTS bool
}

// Iface is a capture interface. Classic pcap has exactly one, implied by the
// file header; pcapng has a list.
type Iface struct {
	LinkType uint32
	SnapLen  uint32
	Name     string
	TsResol  uint8  // pcapng if_tsresol, as stored
	TsDiv    uint64 // units per second derived from TsResol
	TsOffset uint64
}

// Capture is a whole file, read into memory. shortcut: everything is held at
// once, so a capture larger than RAM cannot be read. Upgrade path is an
// iterator over an io.ReaderAt; nothing above this struct needs the slice.
type Capture struct {
	Format   string // "pcap" or "pcapng"
	BigEnd   bool
	Nanos    bool
	Major    uint16
	Minor    uint16
	TZOffset int32
	SnapLen  uint32
	Ifaces   []Iface
	Packets  []Packet
	// Sections counts pcapng section header blocks; classic pcap has none.
	Sections int
	// BlockCounts records how many of each pcapng block type were seen,
	// including the ones we skip, so info can report them.
	BlockCounts map[uint32]int
	// Names holds pcapng name resolution records.
	Names []NameRecord
}

// readPcap decodes a classic pcap file. The byte order is decided by the
// magic and then never reconsidered: a file whose records disagree with its
// header is a corrupt file, not a file with mixed endianness.
func readPcap(b []byte) (*Capture, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("pcap: file header truncated: %d bytes, need 24", len(b))
	}
	var be, nanos bool
	m := be32(b[0:4])
	switch m {
	case magicUsec:
		be = true
	case magicNsec:
		be, nanos = true, true
	case swap32(magicUsec):
		be = false
	case swap32(magicNsec):
		be, nanos = false, true
	case magicKuznetzov, swap32(magicKuznetzov):
		return nil, fmt.Errorf("pcap: Kuznetzov modified format (magic %#08x): record headers carry 8 extra bytes, not supported", m)
	case magicMesquita, swap32(magicMesquita):
		return nil, fmt.Errorf("pcap: Mesquita modified format (magic %#08x) not supported", m)
	case magicNavtel, swap32(magicNavtel):
		return nil, fmt.Errorf("pcap: Navtel format (magic %#08x) not supported", m)
	default:
		return nil, fmt.Errorf("pcap: bad magic %#08x", m)
	}

	c := newCursor(b, be)
	c.skip(4)
	f := &Capture{Format: "pcap", BigEnd: be, Nanos: nanos, BlockCounts: map[uint32]int{}}
	f.Major = c.u16()
	f.Minor = c.u16()
	f.TZOffset = int32(c.u32())
	c.u32() // sigfigs, always zero in practice and ignored by libpcap too
	f.SnapLen = c.u32()
	link := c.u32()
	if !c.ok() {
		return nil, fmt.Errorf("pcap: %w", c.err)
	}
	if f.Major != 2 || f.Minor != 4 {
		return nil, fmt.Errorf("pcap: unsupported version %d.%d, only 2.4 is defined", f.Major, f.Minor)
	}
	f.Ifaces = []Iface{{LinkType: link, SnapLen: f.SnapLen, TsDiv: 1000000, Name: ""}}
	if nanos {
		f.Ifaces[0].TsDiv = 1000000000
	}

	n := 0
	for c.left() > 0 {
		if c.left() < 16 {
			return nil, fmt.Errorf("pcap: record %d: header truncated at offset %d, %d bytes left", n+1, c.offset(), c.left())
		}
		sec := c.u32()
		frac := c.u32()
		inclLen := c.u32()
		origLen := c.u32()
		if frac >= uint32(f.Ifaces[0].TsDiv) {
			return nil, fmt.Errorf("pcap: record %d: fractional timestamp %d is not below %d", n+1, frac, f.Ifaces[0].TsDiv)
		}
		if inclLen > origLen {
			return nil, fmt.Errorf("pcap: record %d: captured length %d exceeds original length %d", n+1, inclLen, origLen)
		}
		if int64(inclLen) > int64(c.left()) {
			return nil, fmt.Errorf("pcap: record %d: captured length %d runs past end of file at offset %d, %d bytes left", n+1, inclLen, c.offset(), c.left())
		}
		data := c.take(int(inclLen))
		if !c.ok() {
			return nil, fmt.Errorf("pcap: record %d: %w", n+1, c.err)
		}
		n++
		ns := frac
		if !nanos {
			ns = frac * 1000
		}
		f.Packets = append(f.Packets, Packet{
			Num: n, TsSec: int64(sec), TsNsec: ns,
			CapLen: inclLen, OrigLen: origLen, LinkType: link, Iface: 0, Data: data,
			HasTS: true,
		})
	}
	return f, nil
}

func swap32(v uint32) uint32 {
	return v<<24 | (v&0xff00)<<8 | (v>>8)&0xff00 | v>>24
}
