// pcapd reads packet capture files and reassembles TCP streams.
//
// Usage is printed by -h. Every subcommand takes a file and writes to stdout;
// a malformed file produces a message on stderr and exit status 1.
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
  info     file-level facts: format, byte order, link types, packet count
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	}
	fmt.Fprintf(os.Stderr, "pcapd: unknown command %q\n", os.Args[1])
	os.Exit(exitUsage)
}
