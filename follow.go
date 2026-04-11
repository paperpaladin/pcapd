package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readStreams decodes the whole file with a session, so that reassembly
// state exists, and returns it.
func readStreams(path string, overlapLast bool) *Session {
	c := load(path)
	s := NewSession()
	s.OverlapLast = overlapLast
	for i := range c.Packets {
		decodeIn(s, &c.Packets[i])
	}
	for _, st := range s.Streams {
		st.finish()
	}
	return s
}

func cmdStreams(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: pcapd streams FILE")
		os.Exit(exitUsage)
	}
	s := readStreams(args[0], false)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for _, st := range s.Streams {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			st.Index, st.Nodes[0], st.Nodes[1],
			len(st.Bytes(0)), len(st.Bytes(1)), st.Packets,
			len(st.Conflicts), st.Dropped, st.OutOfOrd)
	}
}

const followRule = "==================================================================="

func cmdFollow(args []string) {
	overlapLast := false
	tsharkFormat := false
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--overlap=last":
			overlapLast = true
		case args[i] == "--overlap=first":
			overlapLast = false
		case args[i] == "--tshark":
			tsharkFormat = true
		case strings.HasPrefix(args[i], "-"):
			fmt.Fprintf(os.Stderr, "pcapd follow: unknown option %q\n", args[i])
			os.Exit(exitUsage)
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pcapd follow [--overlap=first|last] [--tshark] N FILE")
		os.Exit(exitUsage)
	}
	n, err := strconv.Atoi(rest[0])
	if err != nil || n < 0 {
		fmt.Fprintf(os.Stderr, "pcapd follow: %q is not a stream number\n", rest[0])
		os.Exit(exitUsage)
	}
	if tsharkFormat && overlapLast {
		// The per-segment line format says which bytes each segment
		// contributed, and under last-wins a segment can change bytes
		// another segment already contributed. There is no honest way to
		// write that in this format, so it is refused instead of being
		// approximated.
		fmt.Fprintln(os.Stderr, "pcapd follow: --tshark is only defined for --overlap=first")
		os.Exit(exitUsage)
	}
	s := readStreams(rest[1], overlapLast)
	if n >= len(s.Streams) {
		die("stream %d: the file holds %d TCP streams", n, len(s.Streams))
	}
	st := s.Streams[n]
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	if tsharkFormat {
		writeTsharkFollow(w, st)
		return
	}
	policy := "first"
	if overlapLast {
		policy = "last"
	}
	fmt.Fprintf(w, "stream %d: %s <-> %s\n", st.Index, st.Nodes[0], st.Nodes[1])
	fmt.Fprintf(w, "overlap policy: %s\n", policy)
	fmt.Fprintf(w, "bytes: %d from node 0, %d from node 1\n", len(st.Bytes(0)), len(st.Bytes(1)))
	fmt.Fprintf(w, "conflicts: %d\n", len(st.Conflicts))
	for _, cf := range st.Conflicts {
		fmt.Fprintf(w, "conflict: direction %d offset %d length %d packet %d earlier %s later %s kept %s\n",
			cf.Dir, cf.Offset, cf.Len, cf.Packet,
			hex.EncodeToString(cf.Earlier), hex.EncodeToString(cf.Later),
			map[bool]string{false: "earlier", true: "later"}[overlapLast])
	}
	fmt.Fprintf(w, "held-undelivered: %d bytes\n", st.Dropped)
	fmt.Fprintf(w, "0: %s\n", hex.EncodeToString(st.Bytes(0)))
	fmt.Fprintf(w, "1: %s\n", hex.EncodeToString(st.Bytes(1)))
}

// writeTsharkFollow reproduces the block tshark -z follow,tcp,raw,N prints,
// byte for byte, so the two can be diffed rather than interpreted.
func writeTsharkFollow(w *bufio.Writer, st *Stream) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, followRule)
	fmt.Fprintln(w, "Follow: tcp,raw")
	fmt.Fprintf(w, "Filter: tcp.stream eq %d\n", st.Index)
	fmt.Fprintf(w, "Node 0: %s\n", st.Nodes[0])
	fmt.Fprintf(w, "Node 1: %s\n", st.Nodes[1])
	for _, ch := range st.Chunks {
		if ch.Dir == 1 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprintln(w, hex.EncodeToString(ch.Data))
	}
	fmt.Fprintln(w, followRule)
}
