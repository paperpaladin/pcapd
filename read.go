package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// cursor is the only thing in this program that turns an offset and a length
// into a slice. Every length in a capture file comes out of the file itself,
// so a reader that indexes its buffer in twenty places has twenty chances to
// read past the end; this one has a single bounds check and a sticky error.
//
// Sticky means a caller can decode a whole structure and check once at the
// end. After the first failure every read returns a zero value and the
// position stops moving, so the later reads cannot turn an error into a
// different error.
type cursor struct {
	b    []byte
	pos  int
	be   bool // byte order of multi-byte integers in this region
	err  error
	base int // file offset of b[0], for error messages only
}

var errShort = errors.New("read past end of data")

func newCursor(b []byte, be bool) *cursor { return &cursor{b: b, be: be} }

// sub returns a cursor over n bytes starting at the current position and
// advances past them. The child shares the parent's byte order and reports
// file offsets relative to the same origin.
func (c *cursor) sub(n int) *cursor {
	b := c.take(n)
	return &cursor{b: b, be: c.be, base: c.base + c.pos - len(b)}
}

func (c *cursor) fail(format string, a ...any) {
	if c.err == nil {
		c.err = fmt.Errorf(format, a...)
	}
}

func (c *cursor) ok() bool    { return c.err == nil }
func (c *cursor) left() int   { return len(c.b) - c.pos }
func (c *cursor) offset() int { return c.base + c.pos }

// take advances by n and returns the bytes. On a short read it sets the error
// and returns an empty slice, never a partial one: a caller that forgot to
// check would otherwise see a truncated structure as a valid shorter one.
func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > c.left() {
		c.fail("%w: want %d bytes at offset %d, have %d", errShort, n, c.offset(), c.left())
		return nil
	}
	s := c.b[c.pos : c.pos+n]
	c.pos += n
	return s
}

func (c *cursor) skip(n int) { c.take(n) }

// align4 advances to the next multiple of four relative to the start of this
// cursor. pcapng pads every option and every block body this way.
func (c *cursor) align4() {
	if r := c.pos % 4; r != 0 {
		c.skip(4 - r)
	}
}

func (c *cursor) u8() uint8 {
	s := c.take(1)
	if s == nil {
		return 0
	}
	return s[0]
}

func (c *cursor) u16() uint16 {
	s := c.take(2)
	if s == nil {
		return 0
	}
	if c.be {
		return binary.BigEndian.Uint16(s)
	}
	return binary.LittleEndian.Uint16(s)
}

func (c *cursor) u32() uint32 {
	s := c.take(4)
	if s == nil {
		return 0
	}
	if c.be {
		return binary.BigEndian.Uint32(s)
	}
	return binary.LittleEndian.Uint32(s)
}

func (c *cursor) u64() uint64 {
	s := c.take(8)
	if s == nil {
		return 0
	}
	if c.be {
		return binary.BigEndian.Uint64(s)
	}
	return binary.LittleEndian.Uint64(s)
}

// be16 and be32 read network byte order regardless of the container's byte
// order. Packet contents are always big-endian; only the file's own fields
// follow the byte-order mark.
func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
