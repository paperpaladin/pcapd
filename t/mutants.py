"""Mutate the decoders and the reassembler; require the suite to go red.

A suite is worth the mutants it kills. Each entry below is a single edit
to one Go source, chosen to be a plausible mistake rather than a random
character: a bound loosened, a field read from the wrong place, a
comparison with the wrong sense, a rule dropped.

For each mutant the tree is edited, rebuilt and the whole suite is run.
A mutant that leaves the suite green is a SURVIVOR and is printed. Two
kinds of survivor exist and they are not the same thing: one says the
suite has a hole, the other says the mutation changes nothing
observable. The second is an equivalent mutant and is marked as such in
the table here, with the reason, rather than being quietly left out.

Usage: python3 t/mutants.py [GROUP ...]
Groups: container, protocol, reassembly. Default is all three.

The working tree is restored on the way out, including after a crash,
because leaving a deliberately broken decoder behind is worse than
whatever the run was going to tell you.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# group, file, description, old text, new text, expected
# expected is "kill" or an explanation of why it cannot be killed.
MUTANTS = [
    # ---------------------------------------------------------- container
    ("container", "pcapng.go", "block trailing length not checked",
     "if trail != total {", "if false {", "kill"),
    ("container", "pcapng.go", "block length minimum dropped",
     "if total < 12 {", "if total < 0 {", "kill"),
    ("container", "pcapng.go", "block length need not be a multiple of 4",
     "if total%4 != 0 {", "if false {", "kill"),
    ("container", "pcapng.go", "option length not bounded by the block",
     "if int(l) > c.left() {\n\t\t\treturn nil, fmt.Errorf(\"pcapng: %s: option %d claims %d bytes with %d left in the block\",",
     "if false {\n\t\t\treturn nil, fmt.Errorf(\"pcapng: %s: option %d claims %d bytes with %d left in the block\",", "kill"),
    ("container", "pcapng.go", "simple packet block length taken from the block again",
     "capLen := origLen\n\t\tif snap := f.Ifaces[0].SnapLen; snap != 0 && snap < capLen {\n\t\t\tcapLen = snap\n\t\t}",
     "capLen := uint32(c.left())\n\t\tif origLen < capLen {\n\t\t\tcapLen = origLen\n\t\t}", "kill"),
    ("container", "pcapng.go", "enhanced packet caplen not bounded by the block",
     "if int64(capLen) > int64(c.left()) {\n\t\t\treturn fmt.Errorf(\"pcapng: enhanced packet block at offset %d: captured length %d exceeds %d bytes of block body\",",
     "if false {\n\t\t\treturn fmt.Errorf(\"pcapng: enhanced packet block at offset %d: captured length %d exceeds %d bytes of block body\",", "kill"),
    ("container", "pcap.go", "captured length may exceed the original length",
     "if inclLen > origLen {", "if false {", "kill"),
    ("container", "pcap.go", "captured length may run past the end of the file",
     "if int64(inclLen) > int64(c.left()) {", "if false {", "kill"),
    ("container", "pcap.go", "nanosecond magic read as microsecond",
     "case magicNsec:\n\t\tbe, nanos = true, true", "case magicNsec:\n\t\tbe, nanos = true, false", "kill"),
    ("container", "pcap.go", "link type reserved bits ignored",
     "if network&0x03FF0000 != 0 {", "if false {", "kill"),
    ("container", "pcapng.go", "if_tsresol power-of-two branch dropped",
     "if v&0x80 != 0 {", "if false {", "kill"),

    # ----------------------------------------------------------- protocol
    ("protocol", "decode.go", "IPv4 header length ignored, fixed 20 bytes",
     "f.IHL = int(b0&0x0f) * 4", "f.IHL = 20", "kill"),
    ("protocol", "decode.go", "TCP data offset ignored, fixed 20 bytes",
     "f.DataOff = int(off>>4) * 4", "f.DataOff = 20", "kill"),
    ("protocol", "decode.go", "IPv4 fragment offset not scaled by 8",
     "f.FragOff = ff & 0x1fff", "f.FragOff = (ff & 0x1fff) / 8", "kill"),
    ("protocol", "decode.go", "more-fragments bit read as don't-fragment",
     "f.Flags = uint8(ff >> 13)", "f.Flags = uint8(ff>>13) ^ 1", "kill"),

    # --------------------------------------------------------- reassembly
    ("reassembly", "reasm_tcp.go", "sequence delta as plain subtraction",
     "abs := d.nextAbs + int64(int32(f.Seq-d.nextSeq))",
     "abs := d.nextAbs + (int64(f.Seq) - int64(d.nextSeq))", "kill"),
    ("reassembly", "reasm_tcp.go", "stream length from the capture, not the header",
     "wire := int64(f.TCPLen)\n\tif wire < int64(len(f.Payload)) {\n\t\twire = int64(len(f.Payload))\n\t}",
     "wire := int64(len(f.Payload))", "kill"),
    ("reassembly", "reasm_tcp.go", "out-of-order segments dropped instead of held",
     "st.OutOfOrd++\n\t\ts.stat(\"tcp.outoforder\")\n\t\td.held = append(d.held, heldSeg{abs: abs, wire: wire, data: data, packet: pkt})",
     "st.OutOfOrd++\n\t\ts.stat(\"tcp.outoforder\")\n\t\tif false {\n\t\t\td.held = append(d.held, heldSeg{abs: abs, wire: wire, data: data, packet: pkt})\n\t\t}", "kill"),
    ("reassembly", "reasm_tcp.go", "overlapping front of a segment re-emitted",
     "if cmp < int64(len(data)) {\n\t\t\tdata = data[cmp:]\n\t\t} else {\n\t\t\tdata = nil\n\t\t}", "", "kill"),
    ("reassembly", "reasm_tcp.go", "last-wins becomes the only policy",
     "if s.OverlapLast {\n\t\t\t\t\tcopy(old, data[:cmp])\n\t\t\t\t}", "copy(old, data[:cmp])", "kill"),
    ("reassembly", "reasm_tcp.go", "base taken from the SYN without the +1",
     "d.base = f.Seq + 1\n\t\t\td.nextSeq = f.Seq + 1", "d.base = f.Seq\n\t\t\td.nextSeq = f.Seq", "kill"),
    ("reassembly", "reasm_tcp.go", "data below the stream origin delivered anyway",
     "if abs+wire <= 0 {\n\t\t\treturn\n\t\t}", "if false {\n\t\t\treturn\n\t\t}", "kill"),
    ("reassembly", "reasm_tcp.go", "drain takes the highest held segment, not the lowest",
     "if best < 0 || d.held[i].abs < d.held[best].abs {",
     "if best < 0 || d.held[i].abs > d.held[best].abs {", "kill"),
    ("reassembly", "reasm_tcp.go", "zero-window probe advances the analysis position",
     "if !probe && (!d.haveNseq || int32(next-d.nseq) > 0) {",
     "if _ = probe; !d.haveNseq || int32(next-d.nseq) > 0 {", "kill"),
    ("reassembly", "reasm_tcp.go", "keep-alive checked before the zero-window probe",
     "case seglen == 1 && f.Seq == d.nseq && rev.haveWin && rev.win == 0:\n\t\t\tprobe = true\n\t\t\ts.stat(\"tcp.zerowindowprobe\")\n\t\tcase (seglen == 0 || seglen == 1) && f.Seq == d.nseq-1 &&\n\t\t\tf.TFlags&0x07 == 0: // not SYN, FIN or RST\n\t\t\ts.stat(\"tcp.keepalive\")",
     "case (seglen == 0 || seglen == 1) && f.Seq == d.nseq-1 &&\n\t\t\tf.TFlags&0x07 == 0: // not SYN, FIN or RST\n\t\t\ts.stat(\"tcp.keepalive\")\n\t\tcase seglen == 1 && f.Seq == d.nseq && rev.haveWin && rev.win == 0:\n\t\t\tprobe = true\n\t\t\ts.stat(\"tcp.zerowindowprobe\")",
     "equivalent: the two cases cannot both match, since seq cannot be "
     "both nseq and nseq-1, so the order of the switch is not observable"),
    ("reassembly", "reasm_ip.go", "fragment gap check removed",
     "for i := range filled {\n\t\tif !filled[i] {\n\t\t\ts.stat(\"ipfrag.gap\")\n\t\t\treturn nil, 0, false\n\t\t}\n\t}", "", "kill"),
    ("reassembly", "reasm_ip.go", "later fragment overwrites an earlier one",
     "if !filled[p.off+i] {\n\t\t\t\tbuf[p.off+i] = p.data[i]\n\t\t\t\tfilled[p.off+i] = true\n\t\t\t}",
     "buf[p.off+i] = p.data[i]\n\t\t\tfilled[p.off+i] = true", "kill"),
    ("reassembly", "reasm_ip.go", "65535-byte reassembly limit removed",
     "if off+len(data) > 65535 {", "if false {", "kill"),
    ("reassembly", "reasm_ip.go", "fragment key ignores the identification",
     "ident: ident, v6: f.IPVer == 6}", "ident: 0, v6: f.IPVer == 6}", "kill"),
]


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, **kw)


def main(argv):
    groups = argv[1:] or ["container", "protocol", "reassembly"]
    chosen = [m for m in MUTANTS if m[0] in groups]
    if not chosen:
        print("no mutants in %s" % groups)
        return 2
    backup = tempfile.mkdtemp(prefix="pcapd-mutants.")
    srcs = sorted({m[1] for m in chosen})
    for f in srcs:
        shutil.copy(os.path.join(ROOT, f), os.path.join(backup, f))
    killed = []
    survived = []
    equivalent = []
    broken = []
    try:
        for group, fname, desc, old, new, expect in chosen:
            path = os.path.join(ROOT, fname)
            with open(path) as f:
                src = f.read()
            if src.count(old) != 1:
                broken.append((desc, "pattern appears %d times" % src.count(old)))
                print("PATTERN %s/%s: appears %d times, not 1"
                      % (group, desc, src.count(old)))
                continue
            with open(path, "w") as f:
                f.write(src.replace(old, new, 1))
            try:
                b = run(["make", "-s"])
                if b.returncode != 0:
                    broken.append((desc, "does not compile"))
                    print("NOCOMPILE %s/%s" % (group, desc))
                    continue
                r = run(["./t/run.sh"])
                out = r.stdout.decode("utf-8", "replace")
                tail = out.strip().split("\n")[-1]
                fails = [l for l in out.split("\n") if l.startswith("FAIL")]
                if r.returncode != 0:
                    killed.append((group, desc, tail, fails[:3]))
                    print("killed   %-11s %s   [%s]" % (group, desc, tail))
                elif expect != "kill":
                    equivalent.append((group, desc, expect))
                    print("EQUIVALENT %-9s %s" % (group, desc))
                else:
                    survived.append((group, desc))
                    print("SURVIVED %-11s %s   [%s]" % (group, desc, tail))
            finally:
                shutil.copy(os.path.join(backup, fname), path)
    finally:
        for f in srcs:
            shutil.copy(os.path.join(backup, f), os.path.join(ROOT, f))
        run(["make", "-s"])
        shutil.rmtree(backup)

    print()
    for group, desc, tail, fails in killed:
        print("KILLED %s: %s" % (desc, fails[0][5:].strip() if fails else tail))
    for group, desc, why in equivalent:
        print("EQUIVALENT %s: %s" % (desc, why))
    for group, desc in survived:
        print("SURVIVOR %s" % desc)
    print("TOTAL mutants=%d killed=%d survived=%d equivalent=%d unusable=%d"
          % (len(chosen), len(killed), len(survived), len(equivalent),
             len(broken)))
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
