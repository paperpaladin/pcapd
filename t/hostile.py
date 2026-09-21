"""Malformed captures: build them, run them, and count what happened.

A length field that points past the end of the file is the obvious attack
on a parser whose every length comes out of the file. This builds a lot of
them, three ways.

  named     hand-written files, one per defect, each with a name saying
            what is wrong with it. These are the cases worth looking at
            by hand when one of them regresses.
  truncated every prefix of every valid capture, at a stride, which
            catches a length read before the bytes behind it exist.
  corrupted single bytes of valid captures overwritten with values chosen
            to be large, which is where a length field becomes an
            allocation or an index.

Every run is classified:

  refused   exit 1 with a message. The wanted outcome.
  accepted  exit 0. Only acceptable when the oracle accepts it too, and
            counted against the oracle below.
  crashed   a panic, a signal, or any other exit status.
  hung      did not finish inside the timeout.

crashed and hung must both be zero. accepted is compared with what tshark
and capinfos do with the same bytes: a file we read and they refuse is a
hole, and a file they read and we refuse is an over-refusal. Both are
counted and the second is allowed, because refusing something readable is
a smaller fault than reading something malformed, but it is not free and
the number is printed.
"""
import os
import struct
import subprocess
import sys

PCAPD = os.environ.get("PCAPD", "./pcapd")
TIMEOUT = 10


def run(cmd, timeout=TIMEOUT):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", ""
    return (p.returncode, p.stdout.decode("utf-8", "replace"),
            p.stderr.decode("utf-8", "replace"))


def check_batch(paths):
    """Run pcapd check over a batch and return a verdict per path.

    One process for the whole batch, because a sweep of thousands of
    mutants otherwise spends most of its time in execve. A panic inside
    check is caught and reported with the file that caused it; if the
    process dies anyway the whole batch is rerun one file at a time, so
    the failure is still attributed.
    """
    rc, out, err = run([PCAPD, "check"] + paths, timeout=TIMEOUT * 6)
    if rc is None:
        return {p: ("hung", "") for p in paths}
    verdicts = {}
    for line in out.split("\n"):
        if "\t" not in line:
            continue
        path, _, v = line.partition("\t")
        if v == "ok":
            verdicts[path] = ("accepted", "")
        elif v.startswith("PANIC"):
            verdicts[path] = ("crashed", v)
        else:
            verdicts[path] = ("refused", v)
    if rc != 0 or len(verdicts) != len(paths):
        # The process stopped partway: a signal, or a panic the recover
        # did not catch. Attribute it by rerunning one at a time.
        if len(paths) == 1:
            return {paths[0]: ("crashed", err.strip().split("\n")[0])}
        for p in paths:
            if p not in verdicts:
                verdicts.update(check_batch([p]))
    return verdicts


CAPTURE_TYPES = ("pcap", "pcapng", "nsecpcap", "modpcap")


def oracle(path):
    """What the oracles make of the file.

    True      Wireshark reads it as a capture.
    False     Wireshark refuses it and so does libpcap.
    "split"   Wireshark refuses it and libpcap reads it. The two
              oracles disagree and pcapd siding with either is
              defensible, so this is counted apart from both.
    "linktype" Wireshark refuses it only because it has no dissector
              for the link type.

    Exit status alone is not enough. Wireshark falls back to its MIME
    dissector for a file it cannot identify and reports one "packet"
    holding the whole thing, with a file type of "mime", and capinfos
    exits 0. Two sweep results were recorded as holes in pcapd on the
    strength of that before the type was checked.
    """
    rc, out, err = run(["capinfos", "-M", "-T", "-r", path])
    if rc != 0:
        if "unknown or unsupported" in err or "unknown encapsulation" in err:
            return "linktype"
        return "split" if libpcap_reads(path) else False
    cols = out.split("\n")[0].split("\t")
    if len(cols) < 2 or cols[1] not in CAPTURE_TYPES:
        return False
    rc, _, _ = run(["tshark", "-r", path, "-T", "fields", "-e", "frame.number"])
    if rc == 0:
        return True
    return "split" if libpcap_reads(path) else False


def libpcap_reads(path):
    """True when tcpdump walks the whole of a CLASSIC PCAP file.

    tcpdump is the second decoder, and for classic pcap it is libpcap
    reading the container rather than Wireshark's own reader, so the two
    are independent and a disagreement between them is worth recording.

    For pcapng it is not independent enough to be a tie-break. libpcap
    skips every block type it does not use and never looks inside an
    option list or a name resolution record, so "tcpdump read it" says
    only that the packet blocks were fine. The first version of this
    did not make that distinction and promptly reported
    ng-trailing-length-mismatch and ng-nrb-record-past-block as
    disagreements between the oracles, when in fact libpcap had never
    examined the thing that was wrong with either file. pcapng files
    return False here, which leaves Wireshark as the only authority on
    them, which it is.
    """
    with open(path, "rb") as f:
        if f.read(4) == b"\x0a\x0d\x0d\x0a":
            return False
    rc, _, err = run(["tcpdump", "-r", path, "-nn", "-c", "100000"])
    return rc == 0 and "truncated" not in err


# ------------------------------------------------------------ named cases


def named_cases():
    """Returns a list of (name, bytes)."""
    import mkcorpus as M
    out = []
    frames = M.conversation([(0, b"hello"), (1, b"there")])
    good = _bytes(lambda p: M.write_pcap(p, frames))
    goodng = _bytes(lambda p: M.write_pcapng(p, frames))

    def add(name, b):
        out.append((name, b))

    # Classic pcap.
    add("pcap-magic-wrong", b"\xde\xad\xbe\xef" + good[4:])
    add("pcap-version-3-4", good[:4] + struct.pack("<HH", 3, 4) + good[8:])
    add("pcap-header-23-bytes", good[:23])
    add("pcap-record-header-cut", good[:24 + 9])
    add("pcap-caplen-past-eof",
        good[:24 + 8] + struct.pack("<I", 0x7FFFFFFF) + good[24 + 12:])
    # Two shapes of the same field pair. The first claims 400 captured
    # bytes that are not in the file and both oracles refuse it. The
    # second has every captured byte present and only the ORIGINAL
    # length is wrong, which both oracles read, reporting frame.len as
    # the original length and frame.cap_len as the captured one. A
    # reader that refuses on caplen > origlen alone passes the first and
    # fails the second, which is what pcapd did.
    add("pcap-caplen-above-origlen",
        good[:24 + 8] + struct.pack("<II", 400, 60) + good[24 + 16:])
    _incl = struct.unpack("<I", good[24 + 8:24 + 12])[0]
    add("pcap-origlen-below-caplen",
        good[:24 + 12] + struct.pack("<I", _incl - 10) + good[24 + 16:])
    add("pcap-usec-too-big",
        good[:24 + 4] + struct.pack("<I", 1500000) + good[24 + 8:])
    # The one file in this list that the two oracles read differently.
    # It is the corpus file with one byte of the second record's
    # microsecond field set to 0xFF, which takes it from 1000 to
    # 16712680. tcpdump reads the file unchanged apart from that
    # timestamp. tshark refuses it, and the frames it does print before
    # giving up have their fields 8 bytes later than they were written,
    # which is the difference between pcap's 16-byte record header and
    # the 24-byte one of the variants that share the standard magic, so
    # it has picked a different variant off the back of one bad field.
    #
    # Making the same edit to a file built here does NOT reproduce it,
    # over 20 record and value pairs, so the trigger is some further
    # property of this capture that has not been pinned down. The file
    # is used rather than a construction for that reason.
    for src in ("t/corpus/hand/link-null6-linux.pcap",):
        if os.path.exists(src):
            with open(src, "rb") as f:
                b = f.read()
            if len(b) > 110:
                add("pcap-usec-second-record-oracles-differ",
                    b[:110] + b"\xff" + b[111:])
    add("pcap-snaplen-zero", good[:16] + struct.pack("<I", 0) + good[20:])
    # The link type field is 32 bits and only the low 16 are the type.
    # Bits 16 to 25 are reserved: libpcap refuses a file that sets any
    # of them, and reads one that sets bits 26 upwards, which carry
    # frame-check-sequence information. Both directions are here,
    # because a reader that ignores the mask entirely passes the second
    # and fails the first, and a reader that refuses the whole high half
    # does the opposite.
    add("pcap-linktype-reserved-bit",
        good[:20] + struct.pack("<I", 1 | (1 << 20)) + good[24:])
    add("pcap-linktype-fcs-bits",
        good[:20] + struct.pack("<I", 1 | (1 << 28)) + good[24:])
    add("pcap-one-byte-short", good[:-1])

    # pcapng.
    add("ng-no-section-header", goodng[28:])
    add("ng-bom-wrong",
        goodng[:8] + b"\x11\x22\x33\x44" + goodng[12:])
    add("ng-block-length-4", goodng[:4] + struct.pack("<I", 4) + goodng[8:])
    add("ng-block-length-not-multiple-of-4",
        goodng[:4] + struct.pack("<I", 29) + goodng[8:])
    # The two above are both caught by the trailing length, which no
    # longer matches once the front one is edited. These two write the
    # trailing copy where the claimed length puts it, so the only thing
    # left to object to is the length itself. Without the minimum check
    # the 8-byte block slices a block body from offset 8 to offset 4 and
    # panics; without the alignment check the 30-byte one is read.
    add("ng-block-total-8",
        goodng[:28] + struct.pack("<II", 1, 8) + goodng[28:])
    add("ng-block-total-30",
        goodng[:28] + struct.pack("<II", 1, 30) + b"\x00" * 18
        + struct.pack("<I", 30) + goodng[28:])
    add("ng-block-length-past-eof",
        goodng[:4] + struct.pack("<I", 0x40000000) + goodng[8:])
    add("ng-block-length-max",
        goodng[:4] + struct.pack("<I", 0xFFFFFFFF) + goodng[8:])
    add("ng-trailing-length-mismatch",
        goodng[:24] + struct.pack("<I", 32) + goodng[28:])
    add("ng-truncated-mid-block", goodng[:30])
    # An interface description block whose option list runs past its end.
    body = struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 2, 0x7FFF)
    add("ng-option-length-past-block",
        goodng[:28] + _ngblock(1, body) + goodng[28:])
    # An opt_endofopt whose length runs past the end of the block. The
    # one above has a length that fits, which Wireshark reads; this one
    # does not, which Wireshark refuses. A reader that returns at the
    # code before checking the length cannot tell them apart.
    add("ng-endofopt-length-past-block",
        goodng[:28] + _ngblock(1, struct.pack("<HHI", 1, 0, 65535)
                               + struct.pack("<HH", 0, 0x7FFF))
        + goodng[28:])
    add("ng-endofopt-with-length",
        goodng[:28] + _ngblock(1, struct.pack("<HHI", 1, 0, 65535)
                               + struct.pack("<HH", 0, 4) + b"\x00" * 4)
        + goodng[28:])
    # An enhanced packet block naming an interface that was never described.
    epb = struct.pack("<IIIII", 7, 0, 0, 4, 4) + b"\x00\x01\x02\x03"
    add("ng-epb-unknown-interface", goodng[:28] + _ngblock(6, epb) + goodng[28:])
    epb = struct.pack("<IIIII", 0, 0, 0, 0x7FFFFFFF, 0x7FFFFFFF) + b"\x00" * 4
    add("ng-epb-caplen-past-block", goodng + _ngblock(6, epb))
    epb = struct.pack("<IIIII", 0, 0, 0, 100, 4) + b"\x00" * 100
    add("ng-epb-caplen-above-origlen", goodng + _ngblock(6, epb))
    add("ng-if-tsresol-too-fine",
        goodng[:28] + _ngblock(1, struct.pack("<HHI", 1, 0, 65535)
                               + struct.pack("<HH", 9, 1) + bytes([60]) + b"\x00" * 3
                               + struct.pack("<HH", 0, 0)) + goodng[28:])
    # A simple packet block has no captured length of its own, so the
    # original length and the interface snaplen between them say how many
    # bytes the block must hold. These two claim more than it does.
    spb = struct.pack("<I", 0x7FFFFFFF) + b"\x00" * 60
    add("ng-spb-origlen-past-block", goodng + _ngblock(3, spb))
    spb = struct.pack("<I", 100) + b"\x00" * 60
    add("ng-spb-origlen-above-block", goodng + _ngblock(3, spb))

    # A name resolution record claiming more bytes than the block holds.
    nrb = struct.pack("<HH", 1, 0x7FFF) + b"\x0a\x00\x00\x01host\x00"
    add("ng-nrb-record-past-block", goodng + _ngblock(4, nrb))

    # Packet-level: lengths inside the packet rather than inside the file.
    def one(frame):
        return _bytes(lambda p: M.write_pcap(p, [frame]))

    add("ip4-ihl-below-minimum",
        one(M.eth(bytes([0x43]) + M.ip4(M.tcp(b"x"))[1:])))
    add("ip4-total-length-below-header",
        one(M.eth(M.ip4(M.tcp(b"x"), total_len=4))))
    add("ip4-total-length-huge",
        one(M.eth(M.ip4(M.tcp(b"x"), total_len=65535))))
    add("tcp-data-offset-zero",
        one(M.eth(M.ip4(M.tcp(b"x", doff=0)))))
    add("tcp-data-offset-15-short",
        one(M.eth(M.ip4(M.tcp(b"", doff=15)))))
    add("ip6-plen-huge",
        one(M.eth(M.ip6(M.tcp(b"x", src=M.IP6_A, dst=M.IP6_B, v6=True),
                        plen=65535, src=M.IP6_A, dst=M.IP6_B), M.ETH_IP6)))
    add("ip6-exthdr-length-huge",
        one(M.eth(M.ip6(struct.pack(">BB", 6, 255) + b"\x00" * 6
                        + M.tcp(b"x", src=M.IP6_A, dst=M.IP6_B, v6=True),
                        nxt=0, src=M.IP6_A, dst=M.IP6_B), M.ETH_IP6)))
    # A chain of hop-by-hop headers that never reaches a transport.
    chain = b"".join(struct.pack(">BB", 0, 0) + b"\x00" * 6 for _ in range(64))
    add("ip6-exthdr-chain-64",
        one(M.eth(M.ip6(chain, nxt=0, src=M.IP6_A, dst=M.IP6_B), M.ETH_IP6)))
    add("vlan-tags-32",
        one(M.eth(b"".join(struct.pack(">HH", 0, 0x8100) for _ in range(32))
                  + struct.pack(">HH", 0, 0x0800) + M.ip4(M.tcp(b"x")),
                  M.ETH_VLAN)))
    return out


def _ngblock(btype, body):
    total = 12 + len(body) + (-len(body)) % 4
    return (struct.pack("<II", btype, total) + body
            + b"\x00" * ((-len(body)) % 4) + struct.pack("<I", total))


def _bytes(writer):
    import tempfile
    fd, p = tempfile.mkstemp(suffix=".cap")
    os.close(fd)
    try:
        writer(p)
        with open(p, "rb") as f:
            return f.read()
    finally:
        os.unlink(p)


# ------------------------------------------------------------------ sweeps


def truncations(data, stride):
    n = len(data)
    for i in range(1, min(n, 400), stride):
        yield i, data[:i]
    i = 400
    while i < n:
        yield i, data[:i]
        i += max(stride, n // 40)


def corruptions(data, positions):
    for i in positions:
        if i >= len(data):
            continue
        for v in (0xFF, 0x7F, 0x80):
            yield i, data[:i] + bytes([v]) + data[i + 1:]


BATCH = 250
# How often the sweep stops to ask the oracle. Every named case is
# oracled; the truncation and corruption sweeps are sampled, because a
# capinfos and a tshark run cost about a hundred times what a pcapd run
# costs and the sweep is tens of thousands of files.
ORACLE_EVERY = int(os.environ.get("HOSTILE_ORACLE_EVERY", "25"))


def dump(outdir):
    """Write the named cases out as real files, one per defect.

    They are built in memory for the sweep, which does not need them on
    disk. On disk they are worth having: they are the cases a person
    looks at when one of them regresses, and two comments in the Go
    source name one each.
    """
    os.makedirs(outdir, exist_ok=True)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    n = 0
    for name, data in named_cases():
        with open(os.path.join(outdir, name + ".cap"), "wb") as f:
            f.write(data)
        n += 1
    return n


def main(argv):
    if argv[1] == "--dump":
        print("%d malformed files written to %s" % (dump(argv[2]), argv[2]))
        return 0
    workdir = argv[1]
    valid = argv[2:]
    os.makedirs(workdir, exist_ok=True)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    tally = {"refused": 0, "accepted": 0, "crashed": 0, "hung": 0}
    we_read_they_refuse = []
    they_read_we_refuse = 0
    oracled = 0
    runs = 0
    pending = []   # (name, path, check_oracle)
    linktype_only = [0]
    # Named cases are the ones a human wrote down on purpose. Every one
    # of them must land on the same side as the oracle; the sweep cases
    # are allowed to disagree and are counted instead.
    named_bad = [0]
    split = []

    def flush():
        nonlocal runs, they_read_we_refuse, oracled
        if not pending:
            return
        verdicts = check_batch([p for _, p, _ in pending])
        for name, path, want_oracle in pending:
            verdict, msg = verdicts.get(path, ("crashed", "no verdict"))
            tally[verdict] += 1
            runs += 1
            if verdict in ("crashed", "hung"):
                print("%s %s: %s" % (verdict.upper(), name, msg))
                keep = os.path.join(workdir, "keep-" + verdict + "-"
                                    + name.replace("/", "_"))
                os.replace(path, keep)
                continue
            if want_oracle:
                oracled += 1
                good = oracle(path)
                if good == "split":
                    # Wireshark refuses the file, libpcap reads it. Every
                    # one of these is named in the output: an oracle
                    # disagreement that nothing prints is indistinguishable
                    # from an oracle disagreement that nobody noticed.
                    split.append((name, verdict))
                    if os.path.exists(path):
                        os.unlink(path)
                    continue
                if good == "linktype":
                    # The oracle refuses the file only because the link
                    # type is not one it has a dissector for. pcapd reads
                    # the container and refuses the packets, which is a
                    # deliberate difference and not a hole; the README
                    # says so and this counts them.
                    linktype_only[0] += 1
                    if os.path.exists(path):
                        os.unlink(path)
                    continue
                if verdict == "accepted" and not good:
                    we_read_they_refuse.append(name)
                    if name.startswith("named/"):
                        named_bad[0] += 1
                    os.replace(path, os.path.join(
                        workdir, "keep-weread-" + name.replace("/", "_")))
                    continue
                if verdict == "refused" and good:
                    they_read_we_refuse += 1
                    if name.startswith("named/"):
                        named_bad[0] += 1
                    os.replace(path, os.path.join(
                        workdir, "keep-theyread-" + name.replace("/", "_")))
                    continue
            if os.path.exists(path):
                os.unlink(path)
        del pending[:]

    seq = [0]

    def shoot(name, data, check_oracle):
        seq[0] += 1
        path = os.path.join(workdir, "m%06d.cap" % seq[0])
        with open(path, "wb") as f:
            f.write(data)
        pending.append((name, path, check_oracle))
        if len(pending) >= BATCH:
            flush()

    for name, data in named_cases():
        shoot("named/" + name, data, True)
    flush()

    k = 0
    for path in valid:
        with open(path, "rb") as f:
            data = f.read()
        base = os.path.basename(path)
        for i, d in truncations(data, 7):
            k += 1
            shoot("trunc/%s@%d" % (base, i), d, k % ORACLE_EVERY == 0)
        # Bytes most likely to be a length: the file header, and the start
        # of each of the first few records or blocks.
        pos = list(range(0, min(len(data), 80)))
        pos += list(range(80, min(len(data), 400), 3))
        for i, d in corruptions(data, pos):
            k += 1
            shoot("corrupt/%s@%d" % (base, i), d, k % ORACLE_EVERY == 0)
    flush()

    for n in we_read_they_refuse[:20]:
        print("ACCEPTED-BY-US-ONLY %s" % n)
    for n, v in split[:20]:
        print("ORACLES-DISAGREE %s: wireshark refuses, libpcap reads, we %s" % (n, v))
    print("TOTAL runs=%d refused=%d accepted=%d crashed=%d hung=%d "
          "oracled=%d ouraccept_theirrefuse=%d theiraccept_ourrefuse=%d "
          "linktypeonly=%d namedbad=%d split=%d"
          % (runs, tally["refused"], tally["accepted"], tally["crashed"],
             tally["hung"], oracled, len(we_read_they_refuse),
             they_read_we_refuse, linktype_only[0], named_bad[0],
             len(split)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
