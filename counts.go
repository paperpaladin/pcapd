package main

import (
	"fmt"
	"os"
	"sort"
)

// The construct counter. A test for overlapping segments run over a corpus
// with no overlapping segments passes, prints a green line and proves
// nothing, so every construct the suite claims to exercise is counted here
// and the suite asserts the count is not zero.
//
// Counting is done by the same decoder the tests use. That is a real
// weakness and is worth stating: if the decoder cannot see a construct, the
// counter cannot see it either, and the pair agree that the corpus is
// missing something it actually contains. The defence is that the counts
// are reported next to tshark's numbers for the same corpus, so a construct
// tshark dissects and we count zero of is visible.
type counter struct {
	n map[string]int
}

func newCounter() *counter { return &counter{n: map[string]int{}} }

func (c *counter) add(k string, v int) { c.n[k] += v }
func (c *counter) hit(k string)        { c.n[k]++ }

func (c *counter) print(w *os.File) {
	keys := make([]string, 0, len(c.n))
	for k := range c.n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%d\n", k, c.n[k])
	}
}

func (c *counter) countFile(path string) {
	cap := load(path)
	c.hit("file." + cap.Format)
	if cap.BigEnd {
		c.hit("file.bigendian")
	} else {
		c.hit("file.littleendian")
	}
	if cap.Nanos {
		c.hit("file.nanosecond")
	}
	if cap.Sections > 1 {
		c.add("ng.sections.multiple", cap.Sections)
	}
	for t, n := range cap.BlockCounts {
		c.add(fmt.Sprintf("ng.block.%s", blockName(t)), n)
	}
	if len(cap.Ifaces) > 1 {
		c.add("ng.interfaces.multiple", len(cap.Ifaces))
	}
	for _, in := range cap.Ifaces {
		if in.TsResol != 0 && in.TsResol != 6 {
			c.hit("ng.tsresol.unusual")
		}
		if in.TsOffset != 0 {
			c.hit("ng.tsoffset")
		}
	}
	c.add("ng.nameresolution.records", len(cap.Names))
	sess := NewSession()
	for i := range cap.Packets {
		p := &cap.Packets[i]
		c.hit("packet")
		if p.CapLen < p.OrigLen {
			c.hit("packet.snapped")
		}
		f := decodeIn(sess, p)
		c.countFrame(f)
	}
	for k, v := range sess.Stats {
		c.add(k, v)
	}
}

func (c *counter) countFrame(f *Frame) {
	c.hit("link." + linkName(f.Link))
	if f.Refuse != "" {
		c.hit("refused")
	}
	for _, t := range f.Tags {
		c.add(fmt.Sprintf("vlan.tpid.%04x", t.TPID), 1)
		if t.PCP != 0 {
			c.hit("vlan.priority.nonzero")
		}
		if t.DEI != 0 {
			c.hit("vlan.dei.set")
		}
	}
	if len(f.Tags) > 1 {
		c.hit("vlan.stacked")
	}
	switch f.IPVer {
	case 4:
		c.hit("ip4")
		if f.IHL > 20 {
			c.hit("ip4.options")
		}
		if f.Flags&0x02 != 0 {
			c.hit("ip4.df")
		}
		if f.Flags&0x01 != 0 || f.FragOff != 0 {
			c.hit("ip4.fragment")
			if f.FragOff >= 0x1000 {
				c.hit("ip4.fragment.offset13bit")
			}
		}
		if f.DSField != 0 {
			c.hit("ip4.dsfield.nonzero")
		}
	case 6:
		c.hit("ip6")
		if f.TClass != 0 {
			c.hit("ip6.tclass.nonzero")
		}
		if f.Flow != 0 {
			c.hit("ip6.flow.nonzero")
		}
		for _, e := range f.ExtHdrs {
			c.add(fmt.Sprintf("ip6.exthdr.%d", e.Proto), 1)
			if e.Proto == 44 && (e.FragOff != 0 || e.More) {
				c.hit("ip6.fragment")
			}
		}
		if len(f.ExtHdrs) > 1 {
			c.hit("ip6.exthdr.chain")
		}
	}
	if f.HasTCP {
		c.hit("tcp")
		for name, bit := range tcpFlagBits {
			if f.TFlags&bit != 0 {
				c.hit("tcp.flag." + name)
			}
		}
		if f.Window == 0 {
			c.hit("tcp.window.zero")
		}
		for _, k := range f.TOptKinds {
			c.add(fmt.Sprintf("tcp.option.%d", k), 1)
		}
		if f.TCPLen > 0 {
			c.hit("tcp.withdata")
		}
	}
	if f.HasUDP {
		c.hit("udp")
		if f.UCksum == 0 {
			c.hit("udp.checksum.zero")
		}
	}
}

var tcpFlagBits = map[string]uint16{
	"fin": 0x001, "syn": 0x002, "rst": 0x004, "psh": 0x008,
	"ack": 0x010, "urg": 0x020, "ece": 0x040, "cwr": 0x080,
	"ns": 0x100,
}

func blockName(t uint32) string {
	switch t {
	case blkSHB:
		return "shb"
	case blkIDB:
		return "idb"
	case blkSPB:
		return "spb"
	case blkNRB:
		return "nrb"
	case blkISB:
		return "isb"
	case blkEPB:
		return "epb"
	case blkDSB:
		return "dsb"
	case blkCB1, blkCB2:
		return "custom"
	}
	return fmt.Sprintf("unknown-%#08x", t)
}

func cmdCounts(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: pcapd counts FILE [FILE ...]")
		os.Exit(exitUsage)
	}
	c := newCounter()
	for _, p := range args {
		c.countFile(p)
	}
	c.print(os.Stdout)
}
