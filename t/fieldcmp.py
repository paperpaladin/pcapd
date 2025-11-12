"""Compare pcapd's field values against tshark's, cell by cell.

Per field and per packet, never per file. "Read 10,000 packets" says
nothing; the useful number is how many individual values were put next to
somebody else's value for the same thing.

Three outcomes per cell, counted separately:

    same      byte-identical strings
    differ    both sides produced a value and the values are not equal
    refused   pcapd printed "?", meaning it knows it did not decode this

A refusal is not a pass. It is counted apart from a disagreement because the
two need different work: a disagreement is a bug, a refusal is a feature
that is not written yet.
"""
import os
import subprocess
import sys

FIELDS = [
    "frame.number", "frame.len", "frame.cap_len", "frame.time_epoch",
    "eth.src", "eth.dst", "eth.type",
    "ip.version", "ip.hdr_len", "ip.dsfield", "ip.len", "ip.id", "ip.flags",
    "ip.frag_offset", "ip.ttl", "ip.proto", "ip.checksum", "ip.src", "ip.dst",
    "ipv6.version", "ipv6.tclass", "ipv6.flow", "ipv6.plen", "ipv6.nxt",
    "ipv6.hlim", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.hdr_len",
    "tcp.flags", "tcp.window_size_value", "tcp.checksum",
    "tcp.urgent_pointer", "tcp.len",
    "udp.srcport", "udp.dstport", "udp.length", "udp.checksum",
]

PCAPD = os.environ.get("PCAPD", "./pcapd")
MAXSHOW = int(os.environ.get("MAXSHOW", "12"))


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def rows(text, n):
    out = []
    for line in text.split("\n"):
        if line == "":
            continue
        cells = line.split("\t")
        cells += [""] * (n - len(cells))
        out.append(cells[:n])
    return out


def compare(path, fields):
    tcmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=/t"]
    for f in fields:
        tcmd += ["-e", f]
    rc, tout, terr = run(tcmd)
    if rc != 0:
        return None, "tshark failed: " + terr.strip().split("\n")[-1]
    pcmd = [PCAPD, "fields"]
    for f in fields:
        pcmd += ["-e", f]
    pcmd.append(path)
    rc, pout, perr = run(pcmd)
    if rc != 0:
        return None, "pcapd failed: " + perr.strip().split("\n")[-1]
    tr = rows(tout, len(fields))
    pr = rows(pout, len(fields))
    if len(tr) != len(pr):
        return None, "packet count: tshark %d, pcapd %d" % (len(tr), len(pr))
    same = differ = refused = 0
    shown = []
    for i, (a, b) in enumerate(zip(tr, pr)):
        for j, name in enumerate(fields):
            if b[j] == "?":
                refused += 1
            elif a[j] == b[j]:
                same += 1
            else:
                differ += 1
                if len(shown) < MAXSHOW:
                    shown.append("    packet %d %s: tshark %r pcapd %r"
                                 % (i + 1, name, a[j], b[j]))
    return (same, differ, refused, shown), None


def main(argv):
    paths = argv[1:]
    fields = FIELDS
    if paths and paths[0].startswith("--fields="):
        fields = paths[0][len("--fields="):].split(",")
        paths = paths[1:]
    tot_same = tot_diff = tot_ref = 0
    broken = 0
    for path in paths:
        res, err = compare(path, fields)
        if err:
            broken += 1
            print("BROKEN %s: %s" % (path, err))
            continue
        same, differ, refused, shown = res
        tot_same += same
        tot_diff += differ
        tot_ref += refused
        if differ:
            print("DIFFER %s: %d of %d" % (path, differ, same + differ + refused))
            for s in shown:
                print(s)
    print("TOTAL compared=%d same=%d differ=%d refused=%d broken=%d files=%d"
          % (tot_same + tot_diff, tot_same, tot_diff, tot_ref, broken, len(paths)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
