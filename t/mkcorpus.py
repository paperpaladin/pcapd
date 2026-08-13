"""Write capture files byte by byte.

The live corpus cannot produce an overlapping retransmission with a
different payload, a fragment with a hole in it, or a file in the byte order
this machine does not use. Those are written here, with no library between
the intent and the bytes, so that what the file contains is visible in the
source rather than being whatever a sending stack decided to do.

Standard library only. struct and nothing else.
"""
import os
import struct
import sys

# ---------------------------------------------------------------- checksums


def ones_complement(data):
    """The 16-bit one's complement sum every IP-family checksum uses."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# ------------------------------------------------------------- link layer

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")

ETH_IP4 = 0x0800
ETH_IP6 = 0x86DD
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8


def eth(payload, etype=ETH_IP4, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack(">H", etype) + payload


def vlan(payload, vid, etype=ETH_IP4, pcp=0, dei=0):
    tci = (pcp << 13) | (dei << 12) | (vid & 0x0FFF)
    return struct.pack(">HH", tci, etype) + payload


def sll(payload, etype=ETH_IP4, pkttype=0, hatype=1, addr=MAC_A):
    """Linux cooked capture v1: 16 bytes before the network header."""
    return (struct.pack(">HHH", pkttype, hatype, len(addr))
            + addr + b"\x00" * (8 - len(addr)) + struct.pack(">H", etype)
            + payload)


def sll2(payload, etype=ETH_IP4, ifindex=1, pkttype=0, hatype=1, addr=MAC_A):
    """Linux cooked capture v2: protocol first, 20 bytes total."""
    return (struct.pack(">HHI", etype, 0, ifindex)
            + struct.pack(">HBB", hatype, pkttype, len(addr))
            + addr + b"\x00" * (8 - len(addr)) + payload)


def null(payload, af=2):
    """DLT_NULL: a 4-byte host-order address family."""
    return struct.pack("<I", af) + payload


# --------------------------------------------------------------- network

IP_A = "10.0.0.1"
IP_B = "10.0.0.2"
IP6_A = "fd00::1"
IP6_B = "fd00::2"


def ip4addr(s):
    return bytes(int(x) for x in s.split("."))


def ip6addr(s):
    head, _, tail = s.partition("::")
    hp = [int(x, 16) for x in head.split(":") if x]
    tp = [int(x, 16) for x in tail.split(":") if x] if _ else []
    mid = [0] * (8 - len(hp) - len(tp))
    return b"".join(struct.pack(">H", g) for g in hp + mid + tp)


def ip4(payload, proto=6, src=IP_A, dst=IP_B, ident=0x1234, df=False, mf=False,
        frag=0, ttl=64, dscp=0, opts=b"", total_len=None, bad_cksum=False,
        version=4, ihl=None):
    assert len(opts) % 4 == 0
    hl = (20 + len(opts)) // 4 if ihl is None else ihl
    tl = 20 + len(opts) + len(payload) if total_len is None else total_len
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag // 8)
    hdr = (struct.pack(">BBHHHBBH", (version << 4) | hl, dscp, tl, ident,
                       flags, ttl, proto, 0)
           + ip4addr(src) + ip4addr(dst) + opts)
    ck = ones_complement(hdr) ^ (0xFFFF if bad_cksum else 0)
    hdr = hdr[:10] + struct.pack(">H", ck) + hdr[12:]
    return hdr + payload


def ip6(payload, nxt=6, src=IP6_A, dst=IP6_B, hlim=64, tclass=0, flow=0,
        plen=None):
    pl = len(payload) if plen is None else plen
    return (struct.pack(">IHBB", (6 << 28) | (tclass << 20) | flow, pl, nxt, hlim)
            + ip6addr(src) + ip6addr(dst) + payload)


def ip6_ext(nxt, data):
    """A generic IPv6 extension header: next header, length in 8-byte units
    minus one, then the body. data excludes the two leading bytes."""
    body = data
    if (len(body) + 2) % 8:
        body += b"\x00" * (8 - (len(body) + 2) % 8)
    return struct.pack(">BB", nxt, (len(body) + 2) // 8 - 1) + body


def ip6_frag(nxt, offset, more, ident):
    return struct.pack(">BBHI", nxt, 0, (offset & 0xFFF8) | (1 if more else 0), ident)


# -------------------------------------------------------------- transport

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 1, 2, 4, 8, 16, 32, 64, 128


def tcp(payload=b"", sport=1234, dport=80, seq=0, ack=0, flags=ACK,
        window=65535, urg=0, opts=b"", src=IP_A, dst=IP_B, v6=False,
        doff=None, bad_cksum=False):
    while len(opts) % 4:
        opts += b"\x00"
    off = (20 + len(opts)) // 4 if doff is None else doff
    # The ninth flag bit (NS, RFC 3540) lives in the low bit of the byte
    # that also holds the data offset, so flags above 0xff are split here
    # rather than being rejected.
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack,
                      (off << 4) | ((flags >> 8) & 1), flags & 0xFF,
                      window, 0, urg) + opts
    seg = hdr + payload
    ck = _l4_cksum(seg, 6, src, dst, v6) ^ (0xFFFF if bad_cksum else 0)
    return seg[:16] + struct.pack(">H", ck) + seg[18:]


def udp(payload=b"", sport=1234, dport=53, src=IP_A, dst=IP_B, v6=False,
        length=None, cksum=None):
    ln = 8 + len(payload) if length is None else length
    seg = struct.pack(">HHHH", sport, dport, ln, 0) + payload
    if cksum is None:
        # A zero checksum means "not computed" in IPv4 UDP, so a real zero
        # result is transmitted as 0xffff. Passing cksum=0 writes the
        # not-computed value on purpose.
        cksum = _l4_cksum(seg, 17, src, dst, v6) or 0xFFFF
    return seg[:6] + struct.pack(">H", cksum) + seg[8:]


def _l4_cksum(seg, proto, src, dst, v6):
    if v6:
        ph = ip6addr(src) + ip6addr(dst) + struct.pack(">IHBB", len(seg), 0, 0, proto)
    else:
        ph = ip4addr(src) + ip4addr(dst) + struct.pack(">BBH", 0, proto, len(seg))
    return ones_complement(ph + seg)


# ------------------------------------------------------------- containers

LINK_NULL, LINK_ETHER, LINK_RAW, LINK_SLL, LINK_SLL2 = 0, 1, 101, 113, 276


def write_pcap(path, frames, link=LINK_ETHER, big=False, nano=False,
               snaplen=262144, t0=1700000000, tzoff=0, major=2, minor=4):
    """frames is a list of bytes, or of (bytes, origlen) when the capture is
    meant to be shorter than the wire frame."""
    e = ">" if big else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(e + "IHHiIII", magic, major, minor, tzoff, 0, snaplen, link)
    for i, fr in enumerate(frames):
        data, origlen = (fr, len(fr)) if isinstance(fr, bytes) else fr
        frac = (i * 1000) % (1000000000 if nano else 1000000)
        out += struct.pack(e + "IIII", t0 + i // 1000, frac, len(data), origlen) + data
    _write(path, out)


def opt(code, value):
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def block(btype, body, big=False):
    e = ">" if big else "<"
    total = 12 + len(body) + (-len(body)) % 4
    return (struct.pack(e + "II", btype, total) + body
            + b"\x00" * ((-len(body)) % 4) + struct.pack(e + "I", total))


# --- pcapng at block level -------------------------------------------
#
# write_pcapng above is the convenience form. These build one block at a
# time, because the interesting pcapng files are the ones whose block
# sequence is unusual and no writer on this machine produces them.


def ng_shb(big=False, opts=b""):
    e = ">" if big else "<"
    return block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1) + opts,
                 big)


def ng_idb(link=LINK_ETHER, snaplen=262144, big=False, opts=None, name="if0",
           tsresol=6, tsoffset=None):
    e = ">" if big else "<"
    if opts is None:
        opts = _opt(e, 2, name.encode()) + _opt(e, 9, bytes([tsresol]))
        if tsoffset is not None:
            opts += _opt(e, 14, struct.pack(e + "Q", tsoffset))
        opts += _opt(e, 0, b"")
    return block(0x00000001, struct.pack(e + "HHI", link, 0, snaplen) + opts, big)


def ng_epb(data, ts=0, ifid=0, origlen=None, big=False, opts=b""):
    e = ">" if big else "<"
    ol = len(data) if origlen is None else origlen
    body = (struct.pack(e + "IIIII", ifid, ts >> 32, ts & 0xFFFFFFFF,
                        len(data), ol)
            + data + b"\x00" * ((-len(data)) % 4) + opts)
    return block(0x00000006, body, big)


def ng_spb(data, origlen=None, big=False):
    e = ">" if big else "<"
    ol = len(data) if origlen is None else origlen
    return block(0x00000003,
                 struct.pack(e + "I", ol) + data + b"\x00" * ((-len(data)) % 4),
                 big)


def ng_nrb(records, big=False):
    """records is a list of (type, address bytes, [names])."""
    e = ">" if big else "<"
    body = b""
    for typ, addr, names in records:
        v = addr + b"".join(n.encode() + b"\x00" for n in names)
        body += struct.pack(e + "HH", typ, len(v)) + v + b"\x00" * ((-len(v)) % 4)
    body += struct.pack(e + "HH", 0, 0)
    return block(0x00000004, body, big)


def ng_isb(ifid=0, ts=0, big=False):
    e = ">" if big else "<"
    body = struct.pack(e + "III", ifid, ts >> 32, ts & 0xFFFFFFFF)
    body += _opt(e, 0, b"")
    return block(0x00000005, body, big)


def ng_unknown(btype, body=b"\x00" * 8, big=False):
    return block(btype, body, big)


def write_pcapng(path, frames, link=LINK_ETHER, big=False, snaplen=262144,
                 tsresol=6, ifaces=None, t0=1700000000):
    e = ">" if big else "<"
    shb_body = struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = block(0x0A0D0D0A, shb_body, big)
    if ifaces is None:
        ifaces = [(link, snaplen, tsresol, "ifone")]
    for lt, sl, res, name in ifaces:
        body = struct.pack(e + "HHI", lt, 0, sl)
        body += _opt(e, 2, name.encode())          # if_name
        body += _opt(e, 9, bytes([res]))           # if_tsresol
        body += _opt(e, 0, b"")                    # opt_endofopt
        out += block(0x00000001, body, big)
    div = 10 ** tsresol
    for i, fr in enumerate(frames):
        if isinstance(fr, bytes):
            data, origlen, ifid = fr, len(fr), 0
        elif len(fr) == 2:
            data, origlen, ifid = fr[0], fr[1], 0
        else:
            data, origlen, ifid = fr
        ts = (t0 + i // 1000) * div + (i * div) // 1000
        body = (struct.pack(e + "IIIII", ifid, ts >> 32, ts & 0xFFFFFFFF,
                            len(data), origlen)
                + data + b"\x00" * ((-len(data)) % 4))
        out += block(0x00000006, body, big)
    _write(path, out)


def _opt(e, code, value):
    pad = (-len(value)) % 4
    return struct.pack(e + "HH", code, len(value)) + value + b"\x00" * pad


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


# --------------------------------------------------------------- scenarios


def conversation(payloads, sport=40000, dport=80, isn_c=1000, isn_s=5000,
                 src=IP_A, dst=IP_B, v6=False, handshake=True):
    """A plain TCP conversation. payloads is a list of (direction, bytes)
    with direction 0 for client to server. Returns a list of frames."""
    etype = ETH_IP6 if v6 else ETH_IP4
    net = ip6 if v6 else ip4

    def wrap(seg, fromclient):
        s, d = (src, dst) if fromclient else (dst, src)
        if v6:
            return eth(net(seg, nxt=6, src=s, dst=d), etype)
        return eth(net(seg, proto=6, src=s, dst=d), etype)

    frames = []
    cseq, sseq = isn_c, isn_s
    if handshake:
        frames.append(wrap(tcp(sport=sport, dport=dport, seq=cseq, ack=0,
                               flags=SYN, src=src, dst=dst, v6=v6), True))
        frames.append(wrap(tcp(sport=dport, dport=sport, seq=sseq, ack=cseq + 1,
                               flags=SYN | ACK, src=dst, dst=src, v6=v6), False))
        cseq += 1
        sseq += 1
        frames.append(wrap(tcp(sport=sport, dport=dport, seq=cseq, ack=sseq,
                               flags=ACK, src=src, dst=dst, v6=v6), True))
    for direction, data in payloads:
        if direction == 0:
            frames.append(wrap(tcp(data, sport=sport, dport=dport, seq=cseq,
                                   ack=sseq, flags=PSH | ACK, src=src, dst=dst,
                                   v6=v6), True))
            cseq += len(data)
        else:
            frames.append(wrap(tcp(data, sport=dport, dport=sport, seq=sseq,
                                   ack=cseq, flags=PSH | ACK, src=dst, dst=src,
                                   v6=v6), False))
            sseq += len(data)
    frames.append(wrap(tcp(sport=sport, dport=dport, seq=cseq, ack=sseq,
                           flags=FIN | ACK, src=src, dst=dst, v6=v6), True))
    frames.append(wrap(tcp(sport=dport, dport=sport, seq=sseq, ack=cseq + 1,
                           flags=FIN | ACK, src=dst, dst=src, v6=v6), False))
    return frames


def tcpseg(d, seq, data=b"", flags=None, ack=1, win=65535, sport=40000,
           dport=80):
    """One TCP segment on ethernet over IPv4. d is 0 for client to server."""
    if flags is None:
        flags = (PSH | ACK) if data else ACK
    if d == 0:
        return eth(ip4(tcp(data, sport=sport, dport=dport, seq=seq, ack=ack,
                           flags=flags, window=win)))
    return eth(ip4(tcp(data, sport=dport, dport=sport, seq=seq, ack=ack,
                       flags=flags, window=win, src=IP_B, dst=IP_A),
                   src=IP_B, dst=IP_A))


def handshake(isn_c=1000, isn_s=5000, sport=40000, dport=80):
    return [tcpseg(0, isn_c, b"", SYN, 0, sport=sport, dport=dport),
            tcpseg(1, isn_s, b"", SYN | ACK, isn_c + 1, sport=sport, dport=dport),
            tcpseg(0, isn_c + 1, b"", ACK, isn_s + 1, sport=sport, dport=dport)]


def reassembly_corpus(p):
    """The cases the live corpus cannot produce. Every one of these was
    first run through tshark to find out what it does, because the answer
    decides what correct means here."""
    hs = handshake()

    write_pcap(p("re-inorder.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1004, b"BBB"),
        tcpseg(1, 5001, b"ccc"), tcpseg(0, 1007, b"CCC")])

    # Out of order, and out of order where the FIRST data segment of the
    # direction is the late one, which is what decides where the stream
    # origin comes from.
    write_pcap(p("re-outoforder.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1007, b"CCC"), tcpseg(0, 1004, b"BBB")])
    write_pcap(p("re-outoforder-first.pcap"), hs + [
        tcpseg(0, 1004, b"BBB"), tcpseg(0, 1001, b"AAA"), tcpseg(0, 1007, b"CCC")])

    write_pcap(p("re-retransmission.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1001, b"AAA"), tcpseg(0, 1004, b"BBB")])

    # Overlapping segments. The first carries six bytes; the second starts
    # three in and disagrees about the three it repeats.
    write_pcap(p("re-overlap-conflict.pcap"), hs + [
        tcpseg(0, 1001, b"AAAAAA"), tcpseg(0, 1004, b"xxxyyy"),
        tcpseg(0, 1010, b"ZZZ")])
    write_pcap(p("re-overlap-same.pcap"), hs + [
        tcpseg(0, 1001, b"AAAAAA"), tcpseg(0, 1004, b"AAAyyy"),
        tcpseg(0, 1010, b"ZZZ")])
    # A later segment that starts BEFORE a held one and covers all of it.
    write_pcap(p("re-overlap-swallow.pcap"), hs + [
        tcpseg(0, 1004, b"BBB"), tcpseg(0, 1001, b"AAAAAAAAA")])
    # Overlap in both directions at once, and a conflict in each.
    write_pcap(p("re-overlap-bothways.pcap"), hs + [
        tcpseg(0, 1001, b"request-one"), tcpseg(0, 1005, b"XXXX-two"),
        tcpseg(1, 5001, b"reply-one"), tcpseg(1, 5004, b"YYY-two")])

    # A hole that never fills, with nothing acknowledging past it.
    # tshark delivers nothing after it and neither do we.
    write_pcap(p("re-permanent-gap.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1010, b"DDD"), tcpseg(1, 5001, b"reply")])

    # The same hole, acknowledged by the other direction. The bytes did
    # reach the far end; this capture missed them. tshark writes
    # "[6 bytes missing in capture file]" into the stream at that point
    # and releases everything the acknowledgement covers. Every one of
    # these was run through tshark before it was written down, because
    # the obvious rules are wrong: an acknowledgement at the start of the
    # hole or inside it releases nothing, and it is the END of a held
    # segment that has to be covered, not its start.
    write_pcap(p("re-gap-acked.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1010, b"DDD"),
        tcpseg(1, 5001, b"", ACK, 1013)])
    write_pcap(p("re-gap-ack-at-start.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1010, b"DDD"),
        tcpseg(1, 5001, b"", ACK, 1004)])
    write_pcap(p("re-gap-ack-inside.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1010, b"DDD"),
        tcpseg(1, 5001, b"", ACK, 1007)])
    write_pcap(p("re-gap-two-acked.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1010, b"DDD"),
        tcpseg(0, 1020, b"EEE"), tcpseg(1, 5001, b"", ACK, 1023)])
    write_pcap(p("re-gap-two-ack-first.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1010, b"DDD"),
        tcpseg(0, 1020, b"EEE"), tcpseg(1, 5001, b"", ACK, 1013)])
    # The missing bytes turn up after the position has already moved
    # past them. They are dropped, by tshark and by us.
    write_pcap(p("re-gap-acked-then-filled.pcap"), hs + [
        tcpseg(0, 1001, b"AAA"), tcpseg(0, 1010, b"DDD"),
        tcpseg(1, 5001, b"", ACK, 1013), tcpseg(0, 1004, b"BBBCCC")])

    # No handshake in the capture at all, and the same again where the
    # first data segment is not the lowest sequence number, so the bytes
    # below the origin are unreachable.
    write_pcap(p("re-nohandshake.pcap"), [
        tcpseg(0, 9000, b"midstream"), tcpseg(1, 7000, b"answer", ack=9009)])
    write_pcap(p("re-nohandshake-ooo.pcap"), [
        tcpseg(0, 1004, b"BBB"), tcpseg(0, 1001, b"AAA"), tcpseg(0, 1007, b"CCC")])

    # Sequence numbers crossing 2^32. A comparison written with < instead
    # of serial arithmetic is wrong only here.
    write_pcap(p("re-wraparound.pcap"), [
        tcpseg(0, 0xFFFFFFF0, b"", SYN, 0),
        tcpseg(1, 5000, b"", SYN | ACK, 0xFFFFFFF1),
        tcpseg(0, 0xFFFFFFF1, b"", ACK, 5001),
        tcpseg(0, 0xFFFFFFF1, b"ABCDEFGHIJKLMNO"),
        tcpseg(0, 0x00000000, b"WRAPPED")])

    # The same crossing with the segments out of order, which is the only
    # arrangement that can tell serial arithmetic from a subtraction. The
    # late segment sits at 0x00000001 while the stream is still at
    # 0xFFFFFFF1: sixteen bytes ahead serially, four billion behind as
    # plain integers. Replacing the serial comparison leaves the in-order
    # wraparound capture identical, so without this file the mutation
    # survives, which is what it did.
    write_pcap(p("re-wraparound-ooo.pcap"), [
        tcpseg(0, 0xFFFFFFF0, b"", SYN, 0),
        tcpseg(1, 5000, b"", SYN | ACK, 0xFFFFFFF1),
        tcpseg(0, 0xFFFFFFF1, b"", ACK, 5001),
        tcpseg(0, 0x00000001, b"SECOND-HALF"),
        tcpseg(0, 0xFFFFFFF1, b"FIRSTHALFxxxxxxx")])

    # A one-byte segment repeating the last delivered octet, one BELOW
    # the next expected sequence number. This comment used to call it a
    # zero-window probe; tshark calls it a keep-alive, and tshark is
    # right. It carries no new data and the stream must not grow by it.
    write_pcap(p("re-keepalive.pcap"), hs + [
        tcpseg(0, 1001, b"HELLO"),
        tcpseg(1, 5001, b"", ACK, 1006, win=0),
        tcpseg(0, 1005, b"H"),
        tcpseg(1, 5001, b"", ACK, 1006, win=0),
        tcpseg(0, 1006, b"WORLD")])

    # The real thing: one byte AT the next expected sequence number while
    # the other side has advertised a window of zero. tshark marks these
    # tcp.analysis.zero_window_probe and DELIVERS the byte, because it is
    # new data. The second probe repeats the first and is dropped by the
    # ordinary overlap path.
    write_pcap(p("re-zerowindow-probe.pcap"), hs + [
        tcpseg(0, 1001, b"HELLO"),
        tcpseg(1, 5001, b"", ACK, 1006, win=0),
        tcpseg(0, 1006, b"P"),
        tcpseg(1, 5001, b"", ACK, 1006, win=0),
        tcpseg(0, 1006, b"P"),
        tcpseg(1, 5001, b"", ACK, 1007),
        tcpseg(0, 1007, b"WORLD")])

    # A FIN does not consume a sequence number for reassembly, so data at
    # the FIN's own number is delivered, and data one past it is not.
    write_pcap(p("re-data-at-fin.pcap"), hs + [
        tcpseg(0, 1001, b"BEFORE"), tcpseg(0, 1007, b"", FIN | ACK),
        tcpseg(0, 1007, b"AFTER")])
    write_pcap(p("re-data-after-fin.pcap"), hs + [
        tcpseg(0, 1001, b"BEFORE"), tcpseg(0, 1007, b"", FIN | ACK),
        tcpseg(0, 1008, b"AFTER")])
    write_pcap(p("re-data-after-rst.pcap"), hs + [
        tcpseg(0, 1001, b"BEFORE"), tcpseg(1, 5001, b"", RST),
        tcpseg(0, 1007, b"AFTER")])

    # Three conversations interleaved, so the stream numbering is tested
    # against something other than a file with one stream in it.
    f = []
    for i in range(3):
        f += handshake(isn_c=1000 + i * 100, isn_s=5000 + i * 100,
                       sport=40000 + i, dport=80 + i)
    for i in range(3):
        f.append(tcpseg(0, 1001 + i * 100, bytes([0x61 + i]) * 4,
                        sport=40000 + i, dport=80 + i))
    write_pcap(p("re-three-streams.pcap"), f)


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    p = lambda n: os.path.join(outdir, n)

    basic = conversation([(0, b"GET / HTTP/1.0\r\n\r\n"),
                          (1, b"HTTP/1.0 200 OK\r\n\r\nhello")])
    write_pcap(p("tcp-basic.pcap"), basic)
    write_pcap(p("tcp-basic-be.pcap"), basic, big=True)
    write_pcap(p("tcp-basic-ns.pcap"), basic, nano=True)
    write_pcapng(p("tcp-basic.pcapng"), basic)
    write_pcapng(p("tcp-basic-be.pcapng"), basic, big=True)

    # The same conversation under every link type we decode. Stripping the
    # ethernet header off frames we built is safe because we built them.
    bare = [fr[14:] for fr in basic]
    write_pcap(p("link-raw.pcap"), bare, link=LINK_RAW)
    write_pcap(p("link-sll.pcap"), [sll(x) for x in bare], link=LINK_SLL)
    write_pcap(p("link-sll2.pcap"), [sll2(x) for x in bare], link=LINK_SLL2)
    write_pcap(p("link-null.pcap"), [null(x) for x in bare], link=LINK_NULL)
    write_pcap(p("link-loop.pcap"), [struct.pack(">I", 2) + x for x in bare],
               link=108)
    # A cooked header whose hardware address is not six bytes, so the
    # sll.src.eth field is absent rather than wrong.
    write_pcap(p("link-sll-halen0.pcap"),
               [sll(x, addr=b"") for x in bare], link=LINK_SLL)

    # 802.1Q, and two stacked tags. The outer tag of a stacked pair uses
    # the 802.1ad ethertype, which is what a provider bridge writes.
    tagged = [eth(vlan(fr[14:], 42), ETH_VLAN) for fr in basic]
    write_pcap(p("vlan-single.pcap"), tagged)
    stacked = [eth(vlan(vlan(fr[14:], 7, etype=ETH_IP4), 300, etype=ETH_VLAN),
                   ETH_QINQ) for fr in basic]
    write_pcap(p("vlan-stacked.pcap"), stacked)
    prio = [eth(vlan(fr[14:], 4095, pcp=5, dei=1), ETH_VLAN) for fr in basic]
    write_pcap(p("vlan-prio.pcap"), prio)

    # IPv6 extension header chains. The transport sits behind one, two and
    # three headers, and one file carries a next-header value no dissector
    # knows, which must stop the chain rather than be walked past.
    def v6pkt(chain, nxt_first, payload_proto=6, seq=1000):
        seg = tcp(b"ext-header payload", sport=40000, dport=80, seq=seq,
                  ack=1, flags=PSH | ACK, src=IP6_A, dst=IP6_B, v6=True)
        body = b"".join(chain) + seg
        return eth(ip6(body, nxt=nxt_first, src=IP6_A, dst=IP6_B), ETH_IP6)

    hop = ip6_ext(6, b"\x01\x02\x00\x00\x00\x00")          # PadN option
    dst = ip6_ext(6, b"\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    rt = struct.pack(">BBBB", 6, 0, 0, 0) + b"\x00" * 4
    write_pcap(p("ip6-hopopt.pcap"), [v6pkt([hop], 0)], link=LINK_ETHER)
    write_pcap(p("ip6-dstopt.pcap"), [v6pkt([dst], 60)], link=LINK_ETHER)
    write_pcap(p("ip6-routing.pcap"), [v6pkt([rt], 43)], link=LINK_ETHER)
    chain3 = [ip6_ext(60, b"\x01\x02\x00\x00\x00\x00"),
              ip6_ext(43, b"\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
              struct.pack(">BBBB", 6, 0, 0, 0) + b"\x00" * 4]
    write_pcap(p("ip6-chain3.pcap"), [v6pkt(chain3, 0)], link=LINK_ETHER)
    write_pcap(p("ip6-unknown-nh.pcap"),
               [eth(ip6(b"\xde\xad\xbe\xef" * 4, nxt=253, src=IP6_A,
                        dst=IP6_B), ETH_IP6)], link=LINK_ETHER)

    # Gaps the construct counter reported as zero. Each of these exists
    # because nothing in the live corpus reaches it, not because it seemed
    # like a nice idea.
    rr = bytes([7, 7, 4]) + b"\x00" * 4 + b"\x00"      # record route, padded
    write_pcap(p("ip4-options.pcap"),
               [eth(ip4(tcp(b"opt", seq=1, ack=1), opts=rr))])
    write_pcap(p("ip4-dscp.pcap"),
               [eth(ip4(tcp(b"ef", seq=1, ack=1), dscp=0xB8))])
    # A fragment offset above 4095, which needs 13 bits of the field. A
    # corpus whose offsets all fit in 12 bits cannot see a narrowed mask.
    write_pcap(p("ip4-fragoff13.pcap"),
               [eth(ip4(b"\xaa" * 64, ident=0x7777, mf=False, frag=40000))])
    write_pcap(p("ip6-tclass.pcap"),
               [eth(ip6(tcp(b"tc", seq=1, ack=1, src=IP6_A, dst=IP6_B, v6=True),
                        tclass=0xB8, flow=0xABCDE, src=IP6_A, dst=IP6_B),
                    ETH_IP6)])
    write_pcap(p("udp-nocksum.pcap"),
               [eth(ip4(udp(b"no checksum here", cksum=0), proto=17))])
    write_pcap(p("tcp-urg.pcap"),
               [eth(ip4(tcp(b"urgent!", seq=1, ack=1, flags=URG | PSH | ACK,
                            urg=4)))])
    write_pcap(p("tcp-ecn.pcap"),
               [eth(ip4(tcp(b"", seq=1, ack=1, flags=SYN | ECE | CWR))),
                eth(ip4(tcp(b"", seq=2, ack=1, flags=ACK | 0x100)))])
    # An option list with end-of-list padding and two SACK blocks, which
    # loopback traffic only produces when it happens to lose a segment.
    sackopt = (bytes([1, 1, 5, 18])
               + struct.pack(">IIII", 2000, 3000, 5000, 6000)
               + bytes([0, 0]))
    write_pcap(p("tcp-sack.pcap"),
               [eth(ip4(tcp(b"", seq=1, ack=1, opts=sackopt)))])
    write_pcap(p("tcp-zerowin.pcap"),
               [eth(ip4(tcp(b"", seq=1, ack=1, window=0)))])

    # pcapng block sequences no writer here produces. editcap always emits
    # section header, one interface description, then enhanced packet
    # blocks, so everything else in the format is dead code without these.
    bare_eth = basic
    blocks = [ng_shb(), ng_idb(snaplen=128)]
    blocks += [ng_spb(fr[:128], origlen=len(fr)) for fr in bare_eth]
    _write(p("ng-spb.pcapng"), b"".join(blocks))

    blocks = [ng_shb(), ng_idb()]
    blocks += [ng_epb(fr, ts=1700000000000000 + i) for i, fr in enumerate(bare_eth)]
    blocks.append(ng_nrb([(1, ip4addr("10.0.0.1"), ["alpha", "alpha.example"]),
                          (1, ip4addr("10.0.0.2"), ["beta"]),
                          (2, ip6addr("fd00::1"), ["gamma"])]))
    blocks.append(ng_isb(0, 1700000000000100))
    _write(p("ng-nrb-isb.pcapng"), b"".join(blocks))

    # Two sections, the second in the other byte order, each with its own
    # interface. A reader that fixes the byte order once cannot read this.
    blocks = [ng_shb(), ng_idb(), ng_epb(bare_eth[0], ts=1700000000000000)]
    blocks += [ng_shb(big=True), ng_idb(big=True),
               ng_epb(bare_eth[1], ts=1700000000000000, big=True)]
    _write(p("ng-twosections.pcapng"), b"".join(blocks))

    # Two interfaces with different link types in one section.
    blocks = [ng_shb(), ng_idb(link=LINK_ETHER, name="eth0"),
              ng_idb(link=LINK_RAW, name="tun0")]
    for i, fr in enumerate(bare_eth):
        blocks.append(ng_epb(fr, ts=1700000000000000 + i, ifid=0))
        blocks.append(ng_epb(fr[14:], ts=1700000000000000 + i, ifid=1))
    _write(p("ng-twoifaces.pcapng"), b"".join(blocks))

    # Timestamp resolutions other than microseconds: decimal nanoseconds,
    # and the power-of-two form, which almost nothing writes.
    blocks = [ng_shb(), ng_idb(tsresol=9)]
    blocks += [ng_epb(fr, ts=1700000000123456789 + i * 1000)
               for i, fr in enumerate(bare_eth)]
    _write(p("ng-tsresol9.pcapng"), b"".join(blocks))
    blocks = [ng_shb(), ng_idb(tsresol=0x8A)]  # 2^-10 seconds
    blocks += [ng_epb(fr, ts=1700000000 * 1024 + i)
               for i, fr in enumerate(bare_eth)]
    _write(p("ng-tsresol-pow2.pcapng"), b"".join(blocks))
    blocks = [ng_shb(), ng_idb(tsresol=6, tsoffset=1000000)]
    blocks += [ng_epb(fr, ts=700000000000000 + i)
               for i, fr in enumerate(bare_eth)]
    _write(p("ng-tsoffset.pcapng"), b"".join(blocks))

    # A block type nobody knows, which must be skipped by its length.
    blocks = [ng_shb(), ng_idb(), ng_unknown(0x12345678, b"opaque!\x00"),
              ng_epb(bare_eth[0], ts=1700000000000000),
              ng_unknown(0x0000000A, b"\x00" * 16),
              ng_epb(bare_eth[1], ts=1700000000000001)]
    _write(p("ng-unknown-block.pcapng"), b"".join(blocks))

    # IPv4 fragmentation by hand. A generator will not produce a gap, a
    # reversed arrival order or two fragments that disagree about the same
    # bytes, and those are the cases where reassembly is a policy rather
    # than an assembly.
    def frag4(payload, ident, pieces):
        """pieces is a list of (offset, length, more, fill). fill of None
        takes the real bytes from payload."""
        out = []
        for off, ln, more, fill in pieces:
            chunk = payload[off:off + ln] if fill is None else bytes([fill]) * ln
            out.append(eth(ip4(chunk, proto=17, ident=ident, mf=more,
                               frag=off)))
        return out

    dgram = udp(bytes(range(256)) * 8, sport=5000, dport=6000)
    n = len(dgram)
    assert n == 2056, n
    whole = [(0, 1024, True, None), (1024, 1024, True, None),
             (2048, n - 2048, False, None)]
    write_pcap(p("frag-inorder.pcap"), frag4(dgram, 0x1001, whole))
    write_pcap(p("frag-reversed.pcap"), frag4(dgram, 0x1002, whole[::-1]))
    write_pcap(p("frag-gap.pcap"),
               frag4(dgram, 0x1003, [whole[0], whole[2]]))
    write_pcap(p("frag-duplicate.pcap"),
               frag4(dgram, 0x1004, [whole[0], whole[0], whole[1], whole[2]]))
    # Two fragments covering 1024..2047, the second carrying different
    # bytes. Whichever reassembly wins, the two possible datagrams differ.
    conflict = [(0, 1024, True, None), (1024, 1024, True, None),
                (1024, 1024, True, 0x41), (2048, n - 2048, False, None)]
    write_pcap(p("frag-conflict.pcap"), frag4(dgram, 0x1005, conflict))
    same = [(0, 1024, True, None), (1024, 1024, True, None),
            (512, 1024, True, None), (2048, n - 2048, False, None)]
    write_pcap(p("frag-overlap-same.pcap"), frag4(dgram, 0x1006, same))
    # A fragment that claims to end past the 65535-byte ceiling.
    write_pcap(p("frag-oversize.pcap"),
               [eth(ip4(b"\x5a" * 600, proto=17, ident=0x1007, mf=True,
                        frag=65000))])

    reassembly_corpus(p)

    v6conv = conversation([(0, b"ping"), (1, b"pong")], v6=True,
                          src=IP6_A, dst=IP6_B)
    bare6 = [fr[14:] for fr in v6conv]
    write_pcap(p("link-raw6.pcap"), bare6, link=LINK_RAW)
    for af, name in ((10, "linux"), (28, "freebsd"), (30, "macos")):
        write_pcap(p("link-null6-%s.pcap" % name),
                   [struct.pack("<I", af) + x for x in bare6], link=LINK_NULL)
    write_pcap(p("link-loop6.pcap"),
               [struct.pack(">I", 24) + x for x in bare6], link=108)


if __name__ == "__main__":
    main(sys.argv[1])
