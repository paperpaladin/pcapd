"""A third parser for the container format, in Python, with struct only.

tshark and tcpdump both read classic pcap through libpcap, so on the
container they are one opinion and not two. This is the second: the
block and record boundaries of a file worked out from the format alone,
with no protocol knowledge at all and no code shared with pcapd. It
produces exactly what "pcapd blocks" produces, and the suite requires
the two to be identical line for line.

It knows nothing about ethernet, IP, TCP or UDP, and deliberately so. A
boundary error in pcapd shows up here as a different offset or a
different length, and a second implementation that had the same
protocol code in it could go wrong in the same place.

It is also a refusal oracle of a weak kind: where it stops, it says why,
and the suite checks that pcapd refuses every file this refuses. The
reverse does not hold, because pcapd checks things this does not look
at.
"""
import os
import struct
import subprocess
import sys

PCAPD = os.environ.get("PCAPD", "./pcapd")

PCAP_MAGICS = {
    0xA1B2C3D4: ("big", False), 0xA1B23C4D: ("big", True),
    0xD4C3B2A1: ("little", False), 0x4D3CB2A1: ("little", True),
}
SHB = 0x0A0D0D0A
BLOCK_NAMES = {SHB: "shb", 1: "idb", 3: "spb", 4: "nrb", 5: "isb",
               6: "epb", 10: "dsb", 0x00000BAD: "custom",
               0x40000BAD: "custom"}


class Bad(Exception):
    pass


def spans(data):
    """[(offset, length, kind)] or raise Bad."""
    if len(data) < 4:
        raise Bad("file is %d bytes" % len(data))
    if struct.unpack(">I", data[:4])[0] == SHB:
        return spans_ng(data)
    return spans_pcap(data)


def spans_pcap(data):
    if len(data) < 24:
        raise Bad("header is %d bytes, need 24" % len(data))
    m = struct.unpack(">I", data[:4])[0]
    if m not in PCAP_MAGICS:
        raise Bad("bad magic %#010x" % m)
    order, _ = PCAP_MAGICS[m]
    e = ">" if order == "big" else "<"
    out = [(0, 24, "fileheader")]
    pos = 24
    while pos < len(data):
        if len(data) - pos < 16:
            raise Bad("record header at %d has %d bytes" % (pos, len(data) - pos))
        _, _, incl, orig = struct.unpack(e + "IIII", data[pos:pos + 16])
        if incl > orig:
            raise Bad("record at %d: caplen %d above origlen %d" % (pos, incl, orig))
        if pos + 16 + incl > len(data):
            raise Bad("record at %d: caplen %d runs past end" % (pos, incl))
        out.append((pos, 16 + incl, "record"))
        pos += 16 + incl
    return out


def spans_ng(data):
    out = []
    pos = 0
    e = "<"
    seen_section = False
    while pos < len(data):
        if len(data) - pos < 12:
            raise Bad("%d trailing bytes at %d" % (len(data) - pos, pos))
        btype_be = struct.unpack(">I", data[pos:pos + 4])[0]
        if btype_be == SHB:
            if len(data) - pos < 16:
                raise Bad("section header at %d is short" % pos)
            bom = struct.unpack(">I", data[pos + 8:pos + 12])[0]
            if bom == 0x1A2B3C4D:
                e = ">"
            elif bom == 0x4D3C2B1A:
                e = "<"
            else:
                raise Bad("section header at %d: byte-order magic %#010x" % (pos, bom))
            btype = SHB
            seen_section = True
        else:
            if not seen_section:
                raise Bad("block at %d before any section header" % pos)
            btype = struct.unpack(e + "I", data[pos:pos + 4])[0]
        total = struct.unpack(e + "I", data[pos + 4:pos + 8])[0]
        if total < 12:
            raise Bad("block at %d claims %d bytes" % (pos, total))
        if total % 4:
            raise Bad("block at %d claims %d, not a multiple of 4" % (pos, total))
        if pos + total > len(data):
            raise Bad("block at %d claims %d, %d left" % (pos, total, len(data) - pos))
        trail = struct.unpack(e + "I", data[pos + total - 4:pos + total])[0]
        if trail != total:
            raise Bad("block at %d: %d at the front, %d at the back" % (pos, total, trail))
        out.append((pos, total, BLOCK_NAMES.get(btype, "unknown-%#010x" % btype)))
        pos += total
    if not seen_section:
        raise Bad("no section header block")
    return out


def main(argv):
    files = argv[1:]
    agree = differ = both_refuse = we_refuse = they_refuse = 0
    units = 0
    shown = 0
    for path in files:
        with open(path, "rb") as f:
            data = f.read()
        try:
            mine = ["%d\t%d\t%s" % s for s in spans(data)]
            mine_bad = None
        except Bad as ex:
            mine, mine_bad = None, str(ex)
        p = subprocess.run([PCAPD, "blocks", path], capture_output=True)
        theirs = p.stdout.decode().split("\n") if p.returncode == 0 else None
        if theirs is not None:
            theirs = [x for x in theirs if x]
        if mine_bad and theirs is None:
            both_refuse += 1
            continue
        if mine_bad and theirs is not None:
            # Python stopped and pcapd read the file. Reported, because
            # it means one of the two is wrong about the container.
            they_refuse += 1
            if shown < 10:
                shown += 1
                print("PYTHON-ONLY-REFUSES %s: %s" % (path, mine_bad))
            continue
        if theirs is None:
            we_refuse += 1
            continue
        if mine == theirs:
            agree += 1
            units += len(mine)
            continue
        differ += 1
        if shown < 10:
            shown += 1
            print("LAYOUT %s: python %d units, pcapd %d" % (path, len(mine), len(theirs)))
            for i in range(max(len(mine), len(theirs))):
                a = mine[i] if i < len(mine) else "-"
                b = theirs[i] if i < len(theirs) else "-"
                if a != b:
                    print("   unit %d: python %s, pcapd %s" % (i, a, b))
                    break
    print("TOTAL files=%d agree=%d differ=%d units=%d bothrefuse=%d "
          "pcapdonlyrefuses=%d pythononlyrefuses=%d"
          % (len(files), agree, differ, units, both_refuse, we_refuse,
             they_refuse))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
