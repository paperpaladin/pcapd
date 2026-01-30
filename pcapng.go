package main

import (
	"fmt"
	"math"
	"math/bits"
)

// pcapng. Everything in the file is a block: a type, a length, a body, and
// the same length again at the end. The trailing copy is what lets a reader
// walk the file backwards, and it is also a free consistency check, so a
// block whose two lengths disagree is refused here rather than trusted on
// the strength of whichever one is read first.
const (
	blkSHB  = 0x0A0D0D0A
	blkIDB  = 0x00000001
	blkSPB  = 0x00000003
	blkNRB  = 0x00000004
	blkISB  = 0x00000005
	blkEPB  = 0x00000006
	blkDSB  = 0x0000000A
	blkCB1  = 0x00000BAD
	blkCB2  = 0x40000BAD
	bomMark = 0x1A2B3C4D
)

// NameRecord is one entry of a name resolution block: an address and the
// names recorded for it.
type NameRecord struct {
	V6    bool
	Addr  []byte
	Names []string
}

func readPcapng(b []byte) (*Capture, error) {
	f := &Capture{Format: "pcapng", BlockCounts: map[uint32]int{}}
	pos := 0
	be := false
	n := 0
	for pos < len(b) {
		if len(b)-pos < 12 {
			return nil, fmt.Errorf("pcapng: %d trailing bytes at offset %d, smallest block is 12", len(b)-pos, pos)
		}
		btype := be32(b[pos : pos+4])
		// A section header block resets the byte order for everything that
		// follows it. Its own type reads the same either way, which is the
		// only reason a reader can find it without already knowing the
		// order.
		if btype == blkSHB {
			if len(b)-pos < 16 {
				return nil, fmt.Errorf("pcapng: section header block at offset %d is %d bytes, need 16", pos, len(b)-pos)
			}
			switch be32(b[pos+8 : pos+12]) {
			case bomMark:
				be = true
			case swap32(bomMark):
				be = false
			default:
				return nil, fmt.Errorf("pcapng: section header at offset %d has byte-order magic %#08x, want %#08x",
					pos, be32(b[pos+8:pos+12]), uint32(bomMark))
			}
		} else if f.Sections == 0 {
			return nil, fmt.Errorf("pcapng: block type %#08x at offset %d before any section header", btype, pos)
		}
		var total uint32
		if be {
			total = be32(b[pos+4 : pos+8])
		} else {
			total = swap32(be32(b[pos+4 : pos+8]))
			btype = swap32(btype)
			if btype == swap32(blkSHB) {
				btype = blkSHB
			}
		}
		if total < 12 {
			return nil, fmt.Errorf("pcapng: block at offset %d claims total length %d, minimum is 12", pos, total)
		}
		if total%4 != 0 {
			return nil, fmt.Errorf("pcapng: block at offset %d claims total length %d, which is not a multiple of 4", pos, total)
		}
		if int64(total) > int64(len(b)-pos) {
			return nil, fmt.Errorf("pcapng: block at offset %d claims total length %d but only %d bytes remain", pos, total, len(b)-pos)
		}
		trail := be32(b[pos+int(total)-4 : pos+int(total)])
		if !be {
			trail = swap32(trail)
		}
		if trail != total {
			return nil, fmt.Errorf("pcapng: block at offset %d says length %d at the front and %d at the back", pos, total, trail)
		}
		body := newCursor(b[pos+8:pos+int(total)-4], be)
		body.base = pos + 8
		f.BlockCounts[btype]++
		if err := f.block(btype, body, be, &n); err != nil {
			return nil, err
		}
		pos += int(total)
	}
	if f.Sections == 0 {
		return nil, fmt.Errorf("pcapng: no section header block")
	}
	return f, nil
}

func (f *Capture) block(btype uint32, c *cursor, be bool, n *int) error {
	switch btype {
	case blkSHB:
		f.Sections++
		c.u32() // byte-order magic, already read
		f.Major = c.u16()
		f.Minor = c.u16()
		if f.Major != 1 {
			return fmt.Errorf("pcapng: section header version %d.%d, only 1.x is defined", f.Major, f.Minor)
		}
		c.u64() // section length, -1 when unknown; we walk blocks instead
		if _, err := readOptions(c, "section header"); err != nil {
			return err
		}
		f.BigEnd = be
		// A second section restarts interface numbering. Packets already
		// read keep the interface they were decoded with, because the
		// Packet carries its own link type.
		f.Ifaces = nil
	case blkIDB:
		in := Iface{TsDiv: 1000000}
		in.LinkType = uint32(c.u16())
		c.u16() // reserved
		in.SnapLen = c.u32()
		opts, err := readOptions(c, "interface description")
		if err != nil {
			return err
		}
		for _, o := range opts {
			switch o.code {
			case 2: // if_name
				in.Name = string(o.val)
			case 9: // if_tsresol
				if len(o.val) != 1 {
					return fmt.Errorf("pcapng: if_tsresol option is %d bytes, must be 1", len(o.val))
				}
				in.TsResol = o.val[0]
				d, err := tsDiv(o.val[0])
				if err != nil {
					return err
				}
				in.TsDiv = d
			case 14: // if_tsoffset
				if len(o.val) != 8 {
					return fmt.Errorf("pcapng: if_tsoffset option is %d bytes, must be 8", len(o.val))
				}
				if be {
					in.TsOffset = be64(o.val)
				} else {
					in.TsOffset = le64(o.val)
				}
			}
		}
		f.Ifaces = append(f.Ifaces, in)
		if f.SnapLen == 0 {
			f.SnapLen = in.SnapLen
		}
	case blkEPB:
		id := c.u32()
		hi := c.u32()
		lo := c.u32()
		capLen := c.u32()
		origLen := c.u32()
		if !c.ok() {
			return fmt.Errorf("pcapng: enhanced packet block: %w", c.err)
		}
		if int64(capLen) > int64(c.left()) {
			return fmt.Errorf("pcapng: enhanced packet block at offset %d: captured length %d exceeds %d bytes of block body",
				c.offset(), capLen, c.left())
		}
		if capLen > origLen {
			return fmt.Errorf("pcapng: enhanced packet block at offset %d: captured length %d exceeds original length %d",
				c.offset(), capLen, origLen)
		}
		data := c.take(int(capLen))
		c.align4()
		if _, err := readOptions(c, "enhanced packet"); err != nil {
			return err
		}
		return f.addPacket(int(id), uint64(hi)<<32|uint64(lo), capLen, origLen, data, n, true)
	case blkSPB:
		origLen := c.u32()
		if !c.ok() {
			return fmt.Errorf("pcapng: simple packet block: %w", c.err)
		}
		// An SPB carries no captured length. It is the block length minus
		// the 16 bytes of framing and the original-length field, less any
		// padding, and the padding is only recoverable from origLen.
		capLen := uint32(c.left())
		if origLen < capLen {
			capLen = origLen
		}
		data := c.take(int(capLen))
		if !c.ok() {
			return fmt.Errorf("pcapng: simple packet block: %w", c.err)
		}
		return f.addPacket(0, 0, capLen, origLen, data, n, false)
	case blkNRB:
		return f.nameRecords(c)
	case blkISB, blkDSB, blkCB1, blkCB2:
		// Read but not interpreted. Skipping by length is the whole point
		// of the block structure, and a reader that stops at a block it
		// does not know cannot read a real file.
	default:
		// Likewise for a type that did not exist when this was written.
	}
	return nil
}

func (f *Capture) addPacket(iface int, ts uint64, capLen, origLen uint32, data []byte, n *int, hasTS bool) error {
	if iface >= len(f.Ifaces) {
		return fmt.Errorf("pcapng: packet names interface %d, but only %d have been described", iface, len(f.Ifaces))
	}
	in := f.Ifaces[iface]
	*n++
	sec := int64(ts/in.TsDiv) + int64(in.TsOffset)
	frac := ts % in.TsDiv
	// Scale the fraction to nanoseconds. Dividing 1e9 by the resolution
	// first loses the remainder, which for a power-of-two resolution is
	// most of the answer: at 2^-10 seconds one tick is 976562.5 ns and
	// truncating the scale factor makes every timestamp slightly early.
	// The 128-bit multiply keeps it exact. frac is always below TsDiv, so
	// the quotient is below 1e9 and Div64 cannot overflow.
	var ns uint64
	if in.TsDiv <= 1000000000 {
		hi, lo := bits.Mul64(frac, 1000000000)
		ns, _ = bits.Div64(hi, lo, in.TsDiv)
	} else {
		ns = frac / (in.TsDiv / 1000000000)
	}
	f.Packets = append(f.Packets, Packet{
		Num: *n, TsSec: sec, TsNsec: uint32(ns), HasTS: hasTS,
		CapLen: capLen, OrigLen: origLen, LinkType: in.LinkType, Iface: iface, Data: data,
	})
	return nil
}

type ngOption struct {
	code uint16
	val  []byte
}

// readOptions walks an option list to opt_endofopt or to the end of the
// block. An option whose length runs past the block is an error: the list is
// the one place in this format where a length is not cross-checked by a
// second copy of itself.
func readOptions(c *cursor, where string) ([]ngOption, error) {
	var out []ngOption
	for c.left() >= 4 {
		code := c.u16()
		l := c.u16()
		if !c.ok() {
			return nil, fmt.Errorf("pcapng: %s options: %w", where, c.err)
		}
		if code == 0 {
			if l != 0 {
				return nil, fmt.Errorf("pcapng: %s: opt_endofopt has length %d, must be 0", where, l)
			}
			return out, nil
		}
		if int(l) > c.left() {
			return nil, fmt.Errorf("pcapng: %s: option %d claims %d bytes with %d left in the block",
				where, code, l, c.left())
		}
		v := c.take(int(l))
		c.align4()
		if !c.ok() {
			return nil, fmt.Errorf("pcapng: %s options: %w", where, c.err)
		}
		out = append(out, ngOption{code, v})
	}
	return out, nil
}

// nameRecords reads a name resolution block. Each record is a type, a
// length, an address and then a run of NUL-terminated names filling the rest
// of the record.
func (f *Capture) nameRecords(c *cursor) error {
	for c.left() >= 4 {
		typ := c.u16()
		l := c.u16()
		if !c.ok() {
			return fmt.Errorf("pcapng: name resolution: %w", c.err)
		}
		if typ == 0 {
			break
		}
		if int(l) > c.left() {
			return fmt.Errorf("pcapng: name resolution record type %d claims %d bytes with %d left", typ, l, c.left())
		}
		v := c.take(int(l))
		c.align4()
		if !c.ok() {
			return fmt.Errorf("pcapng: name resolution: %w", c.err)
		}
		alen := 4
		v6 := typ == 2
		if v6 {
			alen = 16
		}
		if typ != 1 && typ != 2 {
			continue // a record type we do not know, skipped by its length
		}
		if len(v) < alen+1 {
			return fmt.Errorf("pcapng: name resolution record type %d is %d bytes, need at least %d", typ, len(v), alen+1)
		}
		rec := NameRecord{V6: v6, Addr: v[:alen]}
		for _, nm := range splitNUL(v[alen:]) {
			rec.Names = append(rec.Names, nm)
		}
		f.Names = append(f.Names, rec)
	}
	return nil
}

func splitNUL(b []byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

// tsDiv turns an if_tsresol byte into units per second. The high bit selects
// a power of two instead of a power of ten.
func tsDiv(v uint8) (uint64, error) {
	if v&0x80 != 0 {
		e := v & 0x7f
		if e > 63 {
			return 0, fmt.Errorf("pcapng: if_tsresol 2^-%d is finer than a 64-bit count can express", e)
		}
		return uint64(1) << e, nil
	}
	if v > 19 {
		return 0, fmt.Errorf("pcapng: if_tsresol 10^-%d is finer than a 64-bit count can express", v)
	}
	d := uint64(1)
	for i := uint8(0); i < v; i++ {
		if d > math.MaxUint64/10 {
			return 0, fmt.Errorf("pcapng: if_tsresol 10^-%d overflows", v)
		}
		d *= 10
	}
	return d, nil
}

func be64(b []byte) uint64 {
	var v uint64
	for _, c := range b[:8] {
		v = v<<8 | uint64(c)
	}
	return v
}

func le64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}
