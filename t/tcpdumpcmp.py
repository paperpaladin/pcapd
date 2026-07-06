"""Compare pcapd's decode against tcpdump's, per packet and per field.

tshark is the main oracle and it is one program. tcpdump is a second one,
written by different people in a different decade, and for classic pcap it
reads the container through libpcap rather than through Wireshark's own
reader. Where the two agree, pcapd being wrong in the same way as both is
much less likely than pcapd being wrong in the same way as one.

What this compares is what tcpdump prints without -v: the ethernet
addresses where there are any, the addresses and ports, the transport
protocol, and for TCP the flags, the sequence and acknowledgement
numbers, the window and the payload length. That is a smaller set than
the tshark comparison and it is deliberately not the same set. tcpdump
prints a sequence number relative to the connection unless -S is given,
so -S is given; it verifies checksums unless -K is given, which costs
time and tells us nothing here, so -K is given.

Lines this cannot parse are counted and reported rather than skipped
quietly. A parser that silently drops what it does not understand ends
up comparing the three packets it could read and calling it a file.
"""
import os
import re
import subprocess
import sys

PCAPD = os.environ.get("PCAPD", "./pcapd")
MAXSHOW = int(os.environ.get("MAXSHOW", "12"))

# An address is an IPv4 dotted quad or an IPv6 address, and the port is
# glued on after a final dot in both cases, so the address is everything
# up to the last dot that is followed by digits and a space or a colon.
ADDR = r"([0-9A-Fa-f:.]+)\.(\d+)"
# Not anchored at the start of the line: -tt puts a timestamp there, and
# the first version of this was anchored, so eth.src and eth.dst were
# never once compared and the harness reported a clean run without them.
MACS = re.compile(r"(?:^|\s)((?:[0-9a-f]{2}:){5}[0-9a-f]{2}) > "
                  r"((?:[0-9a-f]{2}:){5}[0-9a-f]{2}), ethertype ")
TCPLINE = re.compile(
    ADDR + r" > " + ADDR + r": Flags \[([^\]]*)\]"
    r"(?:, seq (\d+)(?::\d+)?)?"
    r"(?:, ack (\d+))?"
    r", win (\d+)"
    r"(?:, urg \d+)?"
    r"(?:, options \[[^\]]*\])?"
    r", length (\d+)")
UDPLINE = re.compile(ADDR + r" > " + ADDR + r": UDP, length (\d+)")

# tcpdump's flag letters, in the order it prints them, against the bit in
# tcp.flags that each one stands for.
FLAGBIT = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, ".": 0x10,
           "U": 0x20, "E": 0x40, "W": 0x80, "N": 0x100}

PFIELDS = ["eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
           "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw",
           "tcp.flags", "tcp.window_size_value", "tcp.len",
           "udp.srcport", "udp.dstport", "udp.length"]


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr


def tcpdump_rows(path):
    """One dict per packet, in file order, or None for a line we cannot read.

    Returns the string tcpdump failed with instead of a list when it
    cannot read the file at all. libpcap is not Wireshark and there are
    pcapng files it will not take.
    """
    rc, out, err = run(["tcpdump", "-r", path, "-nn", "-tt", "-K", "-S", "-e"])
    msg = err.decode("utf-8", "replace")
    for line in msg.split("\n"):
        if line.startswith("tcpdump: "):
            return line[len("tcpdump: "):]
    if rc != 0:
        return msg.strip().split("\n")[-1] or "exit %d" % rc
    rows = []
    for line in out.split("\n"):
        if not line.strip():
            continue
        if line.startswith("\t") or line.startswith(" "):
            continue        # a continuation line, not a packet
        r = {}
        m = MACS.search(line)
        if m:
            r["eth.src"], r["eth.dst"] = m.group(1), m.group(2)
        m = TCPLINE.search(line)
        if m:
            src, sport, dst, dport, flags, seq, ack, win, ln = m.groups()
            r.update(addr(src, dst))
            r["tcp.srcport"], r["tcp.dstport"] = sport, dport
            bits = 0
            for ch in flags:
                bits |= FLAGBIT.get(ch, 0)
            r["tcp.flags"] = "0x%04x" % bits
            # tcpdump prints no "seq" for a bare ACK carrying no data, and
            # no "ack" when the ACK flag is clear. Absent is not zero, so
            # those cells are left out rather than guessed at.
            if seq is not None:
                r["tcp.seq_raw"] = seq
            if ack is not None:
                r["tcp.ack_raw"] = ack
            r["tcp.window_size_value"] = win
            r["tcp.len"] = ln
            rows.append(r)
            continue
        m = UDPLINE.search(line)
        if m:
            src, sport, dst, dport, ln = m.groups()
            r.update(addr(src, dst))
            r["udp.srcport"], r["udp.dstport"] = sport, dport
            # tcpdump prints the UDP payload length; udp.length is the
            # header and the payload together.
            r["udp.length"] = str(int(ln) + 8)
            rows.append(r)
            continue
        rows.append(r if r else line)
    return rows


def fragments(path):
    """Per-packet: is this an IP fragment? Asked of tshark, not of pcapd.

    tcpdump does not reassemble, so it reads the UDP or TCP header off
    the FIRST fragment and prints ports for it. tshark reassembles and
    attributes the transport header to the LAST fragment, where the
    datagram is complete, and prints nothing for the first. Neither is
    wrong and pcapd follows tshark, so the transport fields of any
    fragment are left out of this comparison. Which packets those are
    has to come from somewhere other than pcapd or the comparison is
    pcapd deciding what it is tested on.
    """
    rc, out, _ = run(["tshark", "-r", path, "-T", "fields",
                      "-e", "ip.flags.mf", "-e", "ip.frag_offset",
                      "-e", "ipv6.fraghdr.more", "-e", "ipv6.fraghdr.offset"])
    if rc != 0:
        return None
    flags = []
    for line in out.split("\n"):
        if not line:
            continue
        c = (line.split("\t") + ["", "", "", ""])[:4]
        flags.append(c[0] == "True" or c[1] not in ("", "0")
                     or c[2] == "True" or c[3] not in ("", "0"))
    return flags


TRANSPORT = ("tcp.", "udp.")


def addr(src, dst):
    k = "ipv6" if ":" in src else "ip"
    return {k + ".src": src, k + ".dst": dst}


def pcapd_rows(path):
    cmd = [PCAPD, "fields"]
    for f in PFIELDS:
        cmd += ["-e", f]
    cmd.append(path)
    rc, out, err = run(cmd)
    if rc != 0:
        return None
    rows = []
    for line in out.split("\n"):
        if not line:
            continue
        cells = line.split("\t")
        rows.append(dict(zip(PFIELDS, cells)))
    return rows


def norm(field, v):
    """Make the two spellings of the same value comparable.

    tcpdump writes an IPv6 address in its own shortened form and pcapd
    writes Go's, which agree for every address in this corpus but need
    not in general; both sides are put through the same shortener so the
    comparison is of the address and not of the spelling.
    """
    if field.endswith(".src") or field.endswith(".dst"):
        if ":" in v:
            try:
                import ipaddress
                return str(ipaddress.ip_address(v))
            except ValueError:
                return v
    if field == "tcp.flags":
        try:
            # tcpdump has no letter for the NS bit and never prints it, so
            # it is masked off both sides. pcapd agrees with tshark on
            # tcp.flags including that bit; this comparison simply cannot
            # see it. Measured on tcp-ecn.pcap, where tshark says 0x0110
            # and tcpdump prints "[.]".
            return "0x%04x" % (int(v, 0) & ~0x100)
        except ValueError:
            return v
    return v


def main(argv):
    files = argv[1:]
    compared = same = differ = refused = 0
    unparsed = 0
    fragskip = 0
    cannot = 0
    unparsed_eg = []
    misalign = 0
    shown = 0
    for path in files:
        td = tcpdump_rows(path)
        pd = pcapd_rows(path)
        fr = fragments(path)
        if isinstance(td, str):
            # libpcap refuses the file. Each one is printed by name with
            # what libpcap said, so a file joining this group is visible
            # rather than quietly dropping out of the comparison.
            cannot += 1
            print("TCPDUMP-CANNOT %s: %s" % (path, td))
            continue
        if td is None or pd is None or fr is None:
            misalign += 1
            print("BROKEN %s: tcpdump or pcapd would not read it" % path)
            continue
        if len(td) != len(pd):
            misalign += 1
            print("BROKEN %s: tcpdump printed %d packets, pcapd %d"
                  % (path, len(td), len(pd)))
            continue
        for i, (t, p) in enumerate(zip(td, pd)):
            if isinstance(t, str):
                # A line in a shape this does not read: a non-first
                # fragment, an IPv6 extension header chain, or a payload
                # tcpdump dissects further (DNS). Counted, and a sample
                # printed, because an unread line is a packet that
                # silently left the comparison.
                unparsed += 1
                if len(unparsed_eg) < 4:
                    unparsed_eg.append(t[:100])
                continue
            isfrag = fr[i] if i < len(fr) else False
            for field, tv in t.items():
                if isfrag and field.startswith(TRANSPORT):
                    fragskip += 1
                    continue
                pv = p.get(field, "?")
                compared += 1
                if pv == "?":
                    refused += 1
                    continue
                if norm(field, pv) == norm(field, tv):
                    same += 1
                else:
                    differ += 1
                    if shown < MAXSHOW:
                        shown += 1
                        print("DIFF %s packet %d %s: tcpdump %s, pcapd %s"
                              % (path, i + 1, field, tv, pv))
    for e in unparsed_eg:
        print("UNPARSED-SHAPE %s" % e)
    print("TOTAL files=%d compared=%d same=%d differ=%d refused=%d "
          "unparsed=%d broken=%d fragskip=%d cannot=%d"
          % (len(files), compared, same, differ, refused, unparsed, misalign,
             fragskip, cannot))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
