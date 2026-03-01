// pcapd reads packet capture files and reassembles TCP streams.
//
// Every subcommand takes a file and writes to stdout; a malformed file
// produces a message on stderr and exit status 1, never a partial decode
// presented as a whole one.
package main

import (
	"fmt"
	"os"
)

// Exit statuses. 2 is usage, 1 is a refused input. Keeping them apart matters
// to the test suite, which counts refusals separately from disagreements.
const (
	exitRefused = 1
	exitUsage   = 2
)

const usage = `usage: pcapd COMMAND [options] FILE

commands:
  info     file-level facts: format, byte order, link type, packet count
  fields   per-packet field values, one line per packet, tab separated
  counts   how many of each construct the named captures contain
  streams  one line per TCP conversation: index, endpoints, byte counts
  follow   the reassembled bytes of one TCP stream
`

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "pcapd: "+format+"\n", a...)
	os.Exit(exitRefused)
}

func load(path string) *Capture {
	b, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	c, err := readCapture(b)
	if err != nil {
		die("%v", err)
	}
	return c
}

// readCapture sniffs the first four bytes. pcapng always begins with a
// section header block, whose type 0x0a0d0d0a reads the same in either byte
// order; classic pcap begins with one of its magics. Anything else is
// refused here rather than being handed to the pcap reader, which would
// report a bad magic and so blame the wrong format.
func readCapture(b []byte) (*Capture, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("file is %d bytes, too short to hold any capture header", len(b))
	}
	if be32(b[0:4]) == 0x0a0d0d0a {
		return readPcapng(b)
	}
	return readPcap(b)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	case "info":
		if len(args) != 1 {
			fmt.Fprint(os.Stderr, "usage: pcapd info FILE\n")
			os.Exit(exitUsage)
		}
		cmdInfo(load(args[0]))
	case "fields":
		cmdFields(args)
	case "counts":
		cmdCounts(args)
	case "streams":
		cmdStreams(args)
	case "follow":
		cmdFollow(args)
	default:
		fmt.Fprintf(os.Stderr, "pcapd: unknown command %q\n", cmd)
		os.Exit(exitUsage)
	}
}
