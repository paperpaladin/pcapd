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
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, off << 4, flags,
                      window, 0, urg) + opts
    seg = hdr + payload
    ck = _l4_cksum(seg, 6, src, dst, v6) ^ (0xFFFF if bad_cksum else 0)
    return seg[:16] + struct.pack(">H", ck) + seg[18:]


def udp(payload=b"", sport=1234, dport=53, src=IP_A, dst=IP_B, v6=False,
        length=None):
    ln = 8 + len(payload) if length is None else length
    seg = struct.pack(">HHHH", sport, dport, ln, 0) + payload
    ck = _l4_cksum(seg, 17, src, dst, v6)
    return seg[:6] + struct.pack(">H", ck or 0xFFFF) + seg[8:]


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
