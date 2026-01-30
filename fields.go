package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// The field table. Every entry produces a string formatted the way tshark
// formats the same field, because the comparison is a diff of two columns
// and normalising both sides would measure the normaliser.
//
// Three outcomes are possible for every field of every packet:
//
//	a value   the field is present and we decoded it
//	""        the field is absent from this packet, which is what tshark
//	          prints for a field its dissector never reached
//	"?"       we refused: the packet has the layer, and we did not decode
//	          it. Counted separately from a disagreement, always.
const refusedMark = "?"

type fieldFn func(f *Frame) string

var fields = map[string]fieldFn{}

func init() {
	reg := func(name string, fn fieldFn) { fields[name] = fn }

	reg("frame.number", func(f *Frame) string { return fmt.Sprint(f.Pkt.Num) })
	reg("frame.len", func(f *Frame) string { return fmt.Sprint(f.Pkt.OrigLen) })
	reg("frame.cap_len", func(f *Frame) string { return fmt.Sprint(f.Pkt.CapLen) })
	reg("frame.time_epoch", func(f *Frame) string {
		// A simple packet block has no timestamp. Printing zero would be
		// 1 January 1970 presented as a measurement.
		if !f.Pkt.HasTS {
			return ""
		}
		return fmt.Sprintf("%d.%09d", f.Pkt.TsSec, f.Pkt.TsNsec)
	})
	reg("frame.interface_id", func(f *Frame) string { return fmt.Sprint(f.Pkt.Iface) })

	reg("eth.src", func(f *Frame) string { return mac(f, f.EthSrc) })
	reg("eth.dst", func(f *Frame) string { return mac(f, f.EthDst) })
	reg("eth.type", func(f *Frame) string {
		if !f.HasEth {
			return absent(f)
		}
		return fmt.Sprintf("0x%04x", f.EthType)
	})

	// Wireshark's IPv6 dissector registers the same ip.version field as
	// the IPv4 one, so an IPv6 packet has ip.version 6 and not an empty
	// cell. Found by the comparison, not by reading the source.
	// Wireshark gives the 802.1ad tag a different dissector from the
	// 802.1Q one, so the outer tag of a stacked pair answers to
	// ieee8021ad.id and not to vlan.id. Found by building a stacked
	// capture and seeing one id where two were expected.
	reg("vlan.id", tag(0x8100, func(t VLANTag) string { return fmt.Sprint(t.VID) }))
	reg("vlan.priority", tag(0x8100, func(t VLANTag) string { return fmt.Sprint(t.PCP) }))
	reg("vlan.dei", tag(0x8100, func(t VLANTag) string { return boolStr(t.DEI) }))
	reg("vlan.etype", tag(0x8100, func(t VLANTag) string { return fmt.Sprintf("0x%04x", t.Inner) }))
	reg("ieee8021ad.id", tag(0x88A8, func(t VLANTag) string { return fmt.Sprint(t.VID) }))
	reg("ieee8021ad.priority", tag(0x88A8, func(t VLANTag) string { return fmt.Sprint(t.PCP) }))
	reg("ieee8021ad.dei", tag(0x88A8, func(t VLANTag) string { return fmt.Sprint(t.DEI) }))

	reg("sll.pkttype", sl(func(f *Frame) string { return fmt.Sprint(f.SLLPktType) }))
	reg("sll.hatype", sl(func(f *Frame) string { return fmt.Sprint(f.SLLHatype) }))
	reg("sll.halen", sl(func(f *Frame) string { return fmt.Sprint(f.SLLHalen) }))
	reg("sll.etype", sl(func(f *Frame) string { return fmt.Sprintf("0x%04x", f.SLLEtype) }))
	reg("sll.ifindex", sl(func(f *Frame) string {
		if !f.SLLv2 {
			return ""
		}
		return fmt.Sprint(f.SLLIfindex)
	}))
	reg("sll.src.eth", sl(func(f *Frame) string {
		if f.SLLHalen != 6 {
			return ""
		}
		return hexcolon(f.SLLAddr)
	}))
	reg("null.family", func(f *Frame) string {
		if !f.HasNull {
			return absent(f)
		}
		return fmt.Sprint(f.NullAF)
	})

	reg("ip.version", func(f *Frame) string {
		if f.IPVer == 0 {
			return absent(f)
		}
		return fmt.Sprint(f.IPVer)
	})
	reg("ip.hdr_len", v4(func(f *Frame) string { return fmt.Sprint(f.IHL) }))
	reg("ip.dsfield", v4(func(f *Frame) string { return fmt.Sprintf("0x%02x", f.DSField) }))
	reg("ip.len", v4(func(f *Frame) string { return fmt.Sprint(f.TotalLen) }))
	reg("ip.id", v4(func(f *Frame) string { return fmt.Sprintf("0x%04x", f.ID) }))
	reg("ip.flags", v4(func(f *Frame) string { return fmt.Sprintf("0x%02x", f.Flags) }))
	reg("ip.frag_offset", v4(func(f *Frame) string { return fmt.Sprint(f.FragOff) }))
	reg("ip.ttl", v4(func(f *Frame) string { return fmt.Sprint(f.TTL) }))
	reg("ip.proto", v4(func(f *Frame) string { return fmt.Sprint(f.IPProto) }))
	reg("ip.checksum", v4(func(f *Frame) string { return fmt.Sprintf("0x%04x", f.IPCksum) }))
	reg("ip.src", v4(func(f *Frame) string { return net.IP(f.Src).String() }))
	reg("ip.dst", v4(func(f *Frame) string { return net.IP(f.Dst).String() }))

	reg("ipv6.version", v6(func(f *Frame) string { return "6" }))
	reg("ipv6.tclass", v6(func(f *Frame) string { return fmt.Sprintf("0x%08x", f.TClass) }))
	reg("ipv6.flow", v6(func(f *Frame) string { return fmt.Sprintf("0x%06x", f.Flow) }))
	reg("ipv6.plen", v6(func(f *Frame) string { return fmt.Sprint(f.PLen) }))
	reg("ipv6.nxt", v6(func(f *Frame) string { return fmt.Sprint(f.NextHdr) }))
	reg("ipv6.hlim", v6(func(f *Frame) string { return fmt.Sprint(f.HopLimit) }))
	reg("ipv6.src", v6(func(f *Frame) string { return net.IP(f.Src).String() }))
	reg("ipv6.dst", v6(func(f *Frame) string { return net.IP(f.Dst).String() }))

	reg("ipv6.hopopts.nxt", ext(0, func(e ExtHdr) string { return fmt.Sprint(e.Nxt) }))
	reg("ipv6.hopopts.len", ext(0, func(e ExtHdr) string { return fmt.Sprint(e.Len) }))
	reg("ipv6.hopopts.len_oct", ext(0, func(e ExtHdr) string { return fmt.Sprint(e.LenOct) }))
	reg("ipv6.dstopts.nxt", ext(60, func(e ExtHdr) string { return fmt.Sprint(e.Nxt) }))
	reg("ipv6.dstopts.len", ext(60, func(e ExtHdr) string { return fmt.Sprint(e.Len) }))
	reg("ipv6.dstopts.len_oct", ext(60, func(e ExtHdr) string { return fmt.Sprint(e.LenOct) }))
	reg("ipv6.routing.nxt", ext(43, func(e ExtHdr) string { return fmt.Sprint(e.Nxt) }))
	reg("ipv6.routing.len", ext(43, func(e ExtHdr) string { return fmt.Sprint(e.Len) }))
	reg("ipv6.routing.len_oct", ext(43, func(e ExtHdr) string { return fmt.Sprint(e.LenOct) }))
	reg("ipv6.routing.type", ext(43, func(e ExtHdr) string { return fmt.Sprint(e.RtType) }))
	reg("ipv6.routing.segleft", ext(43, func(e ExtHdr) string { return fmt.Sprint(e.SegLeft) }))
	reg("ipv6.fraghdr.nxt", ext(44, func(e ExtHdr) string { return fmt.Sprint(e.Nxt) }))
	reg("ipv6.fraghdr.offset", ext(44, func(e ExtHdr) string { return fmt.Sprint(e.FragOff) }))
	reg("ipv6.fraghdr.more", ext(44, func(e ExtHdr) string { return boolStr(b2i(e.More)) }))
	reg("ipv6.fraghdr.ident", ext(44, func(e ExtHdr) string { return fmt.Sprintf("0x%08x", e.Ident) }))

	reg("tcp.srcport", tc(func(f *Frame) string { return fmt.Sprint(f.SPort) }))
	reg("tcp.dstport", tc(func(f *Frame) string { return fmt.Sprint(f.DPort) }))
	reg("tcp.seq_raw", tc(func(f *Frame) string { return fmt.Sprint(f.Seq) }))
	reg("tcp.ack_raw", tc(func(f *Frame) string { return fmt.Sprint(f.AckNum) }))
	reg("tcp.hdr_len", tc(func(f *Frame) string { return fmt.Sprint(f.DataOff) }))
	reg("tcp.flags", tc(func(f *Frame) string { return fmt.Sprintf("0x%04x", f.TFlags) }))
	reg("tcp.window_size_value", tc(func(f *Frame) string { return fmt.Sprint(f.Window) }))
	reg("tcp.checksum", tc(func(f *Frame) string { return fmt.Sprintf("0x%04x", f.TCksum) }))
	reg("tcp.urgent_pointer", tc(func(f *Frame) string { return fmt.Sprint(f.UrgPtr) }))
	reg("tcp.len", tc(func(f *Frame) string { return fmt.Sprint(f.TCPLen) }))

	reg("tcp.options.mss_val", tc(func(f *Frame) string { return joinU16(f, f.MSS) }))
	reg("tcp.options.wscale.shift", tc(func(f *Frame) string { return joinU8(f, f.WScale) }))
	reg("tcp.options.timestamp.tsval", tc(func(f *Frame) string { return joinU32(f, f.TSval) }))
	reg("tcp.options.timestamp.tsecr", tc(func(f *Frame) string { return joinU32(f, f.TSecr) }))
	reg("tcp.options.sack_le", tc(func(f *Frame) string { return joinEdges(f, 0) }))
	reg("tcp.options.sack_re", tc(func(f *Frame) string { return joinEdges(f, 1) }))

	reg("udp.srcport", ud(func(f *Frame) string { return fmt.Sprint(f.SPort) }))
	reg("udp.dstport", ud(func(f *Frame) string { return fmt.Sprint(f.DPort) }))
	reg("udp.length", ud(func(f *Frame) string { return fmt.Sprint(f.ULen) }))
	reg("udp.checksum", ud(func(f *Frame) string { return fmt.Sprintf("0x%04x", f.UCksum) }))
}

// absent reports a field as missing, unless the reason it is missing is that
// we gave up before reaching it.
func absent(f *Frame) string {
	if f.Refuse != "" {
		return refusedMark
	}
	return ""
}

func mac(f *Frame, b []byte) string {
	if !f.HasEth {
		return absent(f)
	}
	return hexcolon(b)
}

func hexcolon(b []byte) string {
	p := make([]string, len(b))
	for i, c := range b {
		p[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(p, ":")
}

// tag answers for every stacked tag introduced by one TPID, joined with
// commas the way tshark joins repeated occurrences of a field.
func tag(tpid uint16, fn func(VLANTag) string) fieldFn {
	return func(f *Frame) string {
		var out []string
		for _, t := range f.Tags {
			if t.TPID == tpid {
				out = append(out, fn(t))
			}
		}
		if len(out) == 0 {
			return absent(f)
		}
		return strings.Join(out, ",")
	}
}

// ext answers for every extension header of one protocol number, joined
// with commas as tshark joins repeated occurrences.
func ext(proto uint8, fn func(ExtHdr) string) fieldFn {
	return func(f *Frame) string {
		var out []string
		for _, e := range f.ExtHdrs {
			if e.Proto == proto {
				out = append(out, fn(e))
			}
		}
		if len(out) == 0 {
			return absent(f)
		}
		return strings.Join(out, ",")
	}
}

func joinU16(f *Frame, v []uint16) string {
	if len(v) == 0 {
		return absent(f)
	}
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = fmt.Sprint(x)
	}
	return strings.Join(out, ",")
}

func joinU8(f *Frame, v []uint8) string {
	if len(v) == 0 {
		return absent(f)
	}
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = fmt.Sprint(x)
	}
	return strings.Join(out, ",")
}

func joinU32(f *Frame, v []uint32) string {
	if len(v) == 0 {
		return absent(f)
	}
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = fmt.Sprint(x)
	}
	return strings.Join(out, ",")
}

// SACK edges alternate left, right. parity 0 picks the left edges.
func joinEdges(f *Frame, parity int) string {
	var out []string
	for i, e := range f.SACKEdges {
		if i%2 == parity {
			out = append(out, fmt.Sprint(e))
		}
	}
	if len(out) == 0 {
		return absent(f)
	}
	return strings.Join(out, ",")
}

func b2i(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func boolStr(v uint8) string {
	if v != 0 {
		return "True"
	}
	return "False"
}

func sl(fn fieldFn) fieldFn {
	return func(f *Frame) string {
		if !f.HasSLL {
			return absent(f)
		}
		return fn(f)
	}
}

func v4(fn fieldFn) fieldFn {
	return func(f *Frame) string {
		if f.IPVer != 4 {
			return absent(f)
		}
		return fn(f)
	}
}

func v6(fn fieldFn) fieldFn {
	return func(f *Frame) string {
		if f.IPVer != 6 {
			return absent(f)
		}
		return fn(f)
	}
}

func tc(fn fieldFn) fieldFn {
	return func(f *Frame) string {
		if !f.HasTCP {
			return absent(f)
		}
		return fn(f)
	}
}

func ud(fn fieldFn) fieldFn {
	return func(f *Frame) string {
		if !f.HasUDP {
			return absent(f)
		}
		return fn(f)
	}
}

func fieldNames() []string {
	var out []string
	for k := range fields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cmdFields(args []string) {
	var names []string
	var path string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-e":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "pcapd fields: -e needs a field name")
				os.Exit(exitUsage)
			}
			i++
			names = append(names, args[i])
		case "--list":
			for _, n := range fieldNames() {
				fmt.Println(n)
			}
			return
		default:
			if path != "" {
				fmt.Fprintln(os.Stderr, "pcapd fields: more than one file named")
				os.Exit(exitUsage)
			}
			path = args[i]
		}
	}
	if path == "" || len(names) == 0 {
		fmt.Fprintln(os.Stderr, "usage: pcapd fields -e FIELD [-e FIELD ...] FILE")
		os.Exit(exitUsage)
	}
	fns := make([]fieldFn, len(names))
	for i, n := range names {
		fn, ok := fields[n]
		if !ok {
			// An unknown field must be an error, not an empty column. An
			// empty column compares equal to tshark's empty column for a
			// field it also does not know, and the pair would agree
			// perfectly while measuring nothing.
			fmt.Fprintf(os.Stderr, "pcapd fields: unknown field %q (pcapd fields --list)\n", n)
			os.Exit(exitUsage)
		}
		fns[i] = fn
	}
	c := load(path)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	cols := make([]string, len(fns))
	for i := range c.Packets {
		f := decode(&c.Packets[i])
		for j, fn := range fns {
			cols[j] = fn(f)
		}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}
}
