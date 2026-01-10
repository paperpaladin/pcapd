"""Compare pcapd's field values against tshark's, cell by cell.

Per field and per packet, never per file. "Read 10,000 packets" says
nothing; the useful number is how many individual values were put next to
somebody else's value for the same thing.

Four outcomes per cell, counted separately:

    same      byte-identical strings
    differ    both sides produced a value and the values are not equal
    refused   pcapd printed "?" and tshark printed a value. A layer we
              did not decode and tshark did: work that is not done.
    declined  pcapd printed "?" and tshark printed nothing either. We
              stopped at a layer tshark also does not dissect, so there
              is no value to be wrong about.

A refusal is not a pass. It is counted apart from a disagreement because
the two need different work: a disagreement is a bug, a refusal is a
feature that is not written yet. declined is split out from refused
because a file built to exercise an undecodable payload would otherwise
add hundreds to the refusal count and hide the ones that matter.
"""
import os
import subprocess
import sys

FIELDS = [
    "frame.number", "frame.len", "frame.cap_len", "frame.time_epoch",
    "eth.src", "eth.dst", "eth.type",
    "vlan.id", "vlan.priority", "vlan.dei", "vlan.etype",
    "ieee8021ad.id", "ieee8021ad.priority", "ieee8021ad.dei",
    "sll.pkttype", "sll.hatype", "sll.halen", "sll.etype", "sll.ifindex",
    "sll.src.eth",
    "ip.version", "ip.hdr_len", "ip.dsfield", "ip.len", "ip.id", "ip.flags",
    "ip.frag_offset", "ip.ttl", "ip.proto", "ip.checksum", "ip.src", "ip.dst",
    "ipv6.version", "ipv6.tclass", "ipv6.flow", "ipv6.plen", "ipv6.nxt",
    "ipv6.hlim", "ipv6.src", "ipv6.dst",
    "ipv6.hopopts.nxt", "ipv6.hopopts.len", "ipv6.hopopts.len_oct",
    "ipv6.dstopts.nxt", "ipv6.dstopts.len", "ipv6.dstopts.len_oct",
    "ipv6.routing.nxt", "ipv6.routing.len", "ipv6.routing.len_oct",
    "ipv6.routing.type", "ipv6.routing.segleft",
    "ipv6.fraghdr.nxt", "ipv6.fraghdr.offset", "ipv6.fraghdr.more",
    "ipv6.fraghdr.ident",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.hdr_len",
    "tcp.flags", "tcp.window_size_value", "tcp.checksum",
    "tcp.urgent_pointer", "tcp.len",
    "tcp.options.mss_val", "tcp.options.wscale.shift",
    "tcp.options.timestamp.tsval", "tcp.options.timestamp.tsecr",
    "tcp.options.sack_le", "tcp.options.sack_re",
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
    # Raw sequence numbers. tshark rewrites tcp.seq and the SACK edges as
    # offsets from the initial sequence number by default, so a SACK block
    # reads 229377 where the wire carries 4160109604. We compare what is in
    # the packet, so the preference is turned off rather than the
    # subtraction being reimplemented on our side.
    tcmd = ["tshark", "-o", "tcp.relative_sequence_numbers:FALSE",
            "-r", path, "-T", "fields", "-E", "separator=/t"]
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
    same = differ = refused = declined = 0
    shown = []
    for i, (a, b) in enumerate(zip(tr, pr)):
        for j, name in enumerate(fields):
            if b[j] == "?":
                if a[j] == "":
                    declined += 1
                else:
                    refused += 1
            elif a[j] == b[j]:
                same += 1
            else:
                differ += 1
                if len(shown) < MAXSHOW:
                    shown.append("    packet %d %s: tshark %r pcapd %r"
                                 % (i + 1, name, a[j], b[j]))
    return (same, differ, refused, declined, shown), None


def main(argv):
    paths = argv[1:]
    fields = FIELDS
    if paths and paths[0].startswith("--fields="):
        fields = paths[0][len("--fields="):].split(",")
        paths = paths[1:]
    tot_same = tot_diff = tot_ref = tot_dec = 0
    broken = 0
    for path in paths:
        res, err = compare(path, fields)
        if err:
            broken += 1
            print("BROKEN %s: %s" % (path, err))
            continue
        same, differ, refused, declined, shown = res
        tot_same += same
        tot_diff += differ
        tot_ref += refused
        tot_dec += declined
        if differ:
            print("DIFFER %s: %d of %d"
                  % (path, differ, same + differ + refused + declined))
            for s in shown:
                print(s)
    print("TOTAL compared=%d same=%d differ=%d refused=%d declined=%d "
          "broken=%d files=%d"
          % (tot_same + tot_diff, tot_same, tot_diff, tot_ref, tot_dec,
             broken, len(paths)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
