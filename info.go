package main

import "fmt"

// Link type numbers, with the short names capinfos prints for them. The
// short name is what the suite compares against, because capinfos' long name
// ("Ethernet") is prose and its short one ("ether") is an identifier.
var linkNames = map[uint32]string{
	0:   "null",
	1:   "ether",
	9:   "ppp",
	101: "raw",
	105: "ieee-802-11",
	108: "loop",
	113: "linux-sll",
	127: "ieee-802-11-radiotap",
	147: "user0",
	228: "rawip4",
	229: "rawip6",
	276: "linux-sll2",
}

func linkName(lt uint32) string {
	if n, ok := linkNames[lt]; ok {
		return n
	}
	return fmt.Sprintf("unknown-%d", lt)
}

// tsPrecision names the precision the way capinfos does, from the number of
// timestamp units in a second.
func tsPrecision(div uint64) string {
	switch div {
	case 1000:
		return "milliseconds"
	case 1000000:
		return "microseconds"
	case 1000000000:
		return "nanoseconds"
	}
	return fmt.Sprintf("1/%d s", div)
}

func cmdInfo(c *Capture) {
	var dataSize uint64
	for i := range c.Packets {
		dataSize += uint64(c.Packets[i].OrigLen)
	}
	order := "little"
	if c.BigEnd {
		order = "big"
	}
	// filetype is the name capinfos prints, which distinguishes the
	// nanosecond pcap variant from the microsecond one by a different name
	// rather than by a separate field.
	ft := c.Format
	if c.Nanos {
		ft = "nsecpcap"
	}
	fmt.Printf("filetype: %s\n", ft)
	fmt.Printf("format: %s\n", c.Format)
	fmt.Printf("byteorder: %s\n", order)
	if c.Format == "pcap" {
		fmt.Printf("version: %d.%d\n", c.Major, c.Minor)
		fmt.Printf("tzoffset: %d\n", c.TZOffset)
	} else {
		fmt.Printf("sections: %d\n", c.Sections)
	}
	fmt.Printf("interfaces: %d\n", len(c.Ifaces))
	for i, in := range c.Ifaces {
		fmt.Printf("interface %d: linktype=%d encap=%s snaplen=%d tsdiv=%d precision=%s name=%s\n",
			i, in.LinkType, linkName(in.LinkType), in.SnapLen, in.TsDiv, tsPrecision(in.TsDiv), in.Name)
	}
	fmt.Printf("packets: %d\n", len(c.Packets))
	fmt.Printf("datasize: %d\n", dataSize)
}
