"""A third opinion on TCP reassembly, built from tshark's field output.

tshark's own follow command only implements one overlap policy, so it
cannot be the oracle for --overlap=last. What it can do is hand over the
segments: stream number, direction, sequence number, segment length and
captured payload, per packet. This script takes those and reassembles the
stream itself, under both policies, in a few lines of Python that share no
code with pcapd.

That is a weaker oracle than tshark's own reassembler and is described as
such in the README. It is not nothing: the segment list, the sequence
numbers and the payload bytes all come from Wireshark's dissector, so the
only thing being checked against our own reasoning is the placement rule.
"""
import os
import subprocess
import sys

PCAPD = os.environ.get("PCAPD", "./pcapd")

FIELDS = ["frame.number", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport",
          "tcp.dstport", "tcp.seq_raw", "tcp.len", "tcp.flags", "tcp.payload",
          "tcp.ack_raw"]


def segments(path):
    cmd = ["tshark", "-o", "tcp.relative_sequence_numbers:FALSE",
           "-r", path, "-T", "fields", "-E", "separator=/t"]
    for f in FIELDS:
        cmd += ["-e", f]
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        return None
    out = []
    for line in p.stdout.decode().split("\n"):
        if not line:
            continue
        c = line.split("\t")
        c += [""] * (len(FIELDS) - len(c))
        if c[1] == "":
            continue
        src = c[2] or c[3]
        out.append(dict(num=int(c[0]), stream=int(c[1]),
                        who=(src, c[4]), seq=int(c[6]), ln=int(c[7]),
                        ack=int(c[10]) if c[10] else 0,
                        flags=int(c[8], 16),
                        data=bytes.fromhex(c[9]) if c[9] else b""))
    return out


def reassemble(segs, last_wins):
    """Returns {stream: [bytes_dir0, bytes_dir1]} under one policy."""
    streams = {}
    for s in segs:
        st = streams.setdefault(s["stream"], dict(nodes=[], dirs=[mkdir(), mkdir()]))
        if s["who"] not in st["nodes"]:
            if len(st["nodes"]) < 2:
                st["nodes"].append(s["who"])
        d = st["dirs"][st["nodes"].index(s["who"])]
        if not d["have"]:
            if s["flags"] & 0x02:
                d["have"] = True
                d["nextseq"] = (s["seq"] + 1) & 0xFFFFFFFF
            elif s["ln"] > 0:
                d["have"] = True
                d["nextseq"] = s["seq"]
        # An acknowledgement from the other direction releases held
        # segments it covers, filling the hole in front of them. See
        # ackRelease in reasm_tcp.go: tshark does this and a capture
        # that lost packets needs it.
        if s["flags"] & 0x10:
            other = st["dirs"][1 - st["nodes"].index(s["who"])]
            ack_release(other, s["ack"], last_wins)
        if not d["have"] or s["ln"] == 0:
            continue
        delta = s["seq"] - d["nextseq"]
        if delta > 0x7FFFFFFF:
            delta -= 1 << 32
        elif delta < -0x7FFFFFFF:
            delta += 1 << 32
        place(d, d["nextabs"] + delta, s["ln"], s["data"], last_wins)
        drain(d, last_wins)
    return {k: [bytes(v["dirs"][0]["out"]), bytes(v["dirs"][1]["out"])]
            for k, v in streams.items()}


def ack_release(d, ack, last_wins):
    if not d["have"]:
        return
    delta = ack - d["nextseq"]
    if delta > 0x7FFFFFFF:
        delta -= 1 << 32
    elif delta < -0x7FFFFFFF:
        delta += 1 << 32
    ackabs = d["nextabs"] + delta
    while d["held"]:
        i = min(range(len(d["held"])), key=lambda i: d["held"][i][0])
        abs_, wire, data = d["held"][i]
        if abs_ + wire > ackabs:
            return
        d["held"].pop(i)
        if abs_ > d["nextabs"]:
            # The marker tshark prints is not part of the stream bytes,
            # so the position moves and nothing is appended.
            d["nextseq"] = (d["nextseq"] + abs_ - d["nextabs"]) & 0xFFFFFFFF
            d["nextabs"] = abs_
            d["exact"] = False
        _write(d, abs_, wire, data, last_wins)
        drain(d, last_wins)


def mkdir():
    return dict(have=False, nextseq=0, nextabs=0, out=bytearray(), held=[],
                exact=True)


def place(d, abs_, wire, data, last_wins):
    if abs_ < 0:
        if abs_ + wire <= 0:
            return
        data = data[-abs_:] if -abs_ < len(data) else b""
        wire += abs_
        abs_ = 0
    if abs_ > d["nextabs"]:
        d["held"].append((abs_, wire, data))
        return
    _write(d, abs_, wire, data, last_wins)


def _write(d, abs_, wire, data, last_wins):
    if abs_ < d["nextabs"]:
        n = min(d["nextabs"] - abs_, wire)
        cmp_ = min(n, len(data))
        if last_wins and d["exact"] and cmp_ > 0:
            d["out"][abs_:abs_ + cmp_] = data[:cmp_]
        data = data[cmp_:] if cmp_ < len(data) else b""
        wire -= n
        abs_ = d["nextabs"]
    if wire <= 0:
        return
    if len(data) < wire:
        d["exact"] = False
    d["out"] += data
    d["nextabs"] = abs_ + wire
    d["nextseq"] = (d["nextseq"] + wire) & 0xFFFFFFFF


def drain(d, last_wins):
    while True:
        cand = [i for i, h in enumerate(d["held"]) if h[0] <= d["nextabs"]]
        if not cand:
            return
        i = min(cand, key=lambda i: d["held"][i][0])
        abs_, wire, data = d["held"].pop(i)
        _write(d, abs_, wire, data, last_wins)


def pcapd_stream(path, n, policy):
    cmd = [PCAPD, "follow", "--overlap=" + policy, str(n), path]
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        return None
    out = [b"", b""]
    for line in p.stdout.decode().split("\n"):
        if line.startswith("0: "):
            out[0] = bytes.fromhex(line[3:])
        elif line.startswith("1: "):
            out[1] = bytes.fromhex(line[3:])
    return out


def main(argv):
    checked = differ = broken = 0
    nbytes = 0
    for path in argv[1:]:
        segs = segments(path)
        if segs is None:
            broken += 1
            print("BROKEN %s: tshark failed" % path)
            continue
        for policy, last in (("first", False), ("last", True)):
            want = reassemble(segs, last)
            for n in sorted(want):
                got = pcapd_stream(path, n, policy)
                if got is None:
                    broken += 1
                    print("BROKEN %s stream %d %s: pcapd failed" % (path, n, policy))
                    continue
                checked += 1
                nbytes += len(want[n][0]) + len(want[n][1])
                if got != want[n]:
                    differ += 1
                    print("DIFFER %s stream %d policy %s" % (path, n, policy))
                    for d in (0, 1):
                        if got[d] != want[n][d]:
                            print("    dir %d python %s" % (d, want[n][d].hex()[:80]))
                            print("    dir %d pcapd  %s" % (d, got[d].hex()[:80]))
    print("TOTAL checked=%d differ=%d bytes=%d broken=%d"
          % (checked, differ, nbytes, broken))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
