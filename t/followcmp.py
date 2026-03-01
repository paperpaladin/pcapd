"""Compare pcapd's TCP reassembly against tshark's, byte for byte.

For every stream in every file, the whole block that
tshark -z follow,tcp,raw,N prints is compared with what pcapd prints for
the same stream. Not a normalised version of each: the same bytes, because
a comparison that rewrites both sides measures the rewriter.

The counts reported are streams, output lines and reassembled bytes, so
that a file with one empty stream cannot look like coverage.
"""
import os
import subprocess
import sys

PCAPD = os.environ.get("PCAPD", "./pcapd")


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


def stream_count(path):
    rc, out, err = run([PCAPD, "streams", path])
    if rc != 0:
        return None, err.strip()
    return len([l for l in out.decode().split("\n") if l]), None


def main(argv):
    files = argv[1:]
    streams = same = differ = 0
    databytes = 0
    broken = 0
    for path in files:
        n, err = stream_count(path)
        if err:
            broken += 1
            print("BROKEN %s: %s" % (path, err))
            continue
        for i in range(n):
            rc, theirs, terr = run(["tshark", "-q", "-z",
                                    "follow,tcp,raw,%d" % i, "-r", path])
            if rc != 0:
                broken += 1
                print("BROKEN %s stream %d: tshark: %s"
                      % (path, i, terr.strip().split("\n")[-1]))
                continue
            rc, mine, perr = run([PCAPD, "follow", "--tshark", str(i), path])
            if rc != 0:
                broken += 1
                print("BROKEN %s stream %d: pcapd: %s"
                      % (path, i, perr.strip().split("\n")[-1]))
                continue
            streams += 1
            for line in theirs.split(b"\n"):
                s = line.strip()
                if s and all(c in b"0123456789abcdef" for c in s):
                    databytes += len(s) // 2
            if mine == theirs:
                same += 1
            else:
                differ += 1
                print("DIFFER %s stream %d" % (path, i))
                tl = theirs.decode("utf-8", "replace").split("\n")
                ml = mine.decode("utf-8", "replace").split("\n")
                for j in range(max(len(tl), len(ml))):
                    a = tl[j] if j < len(tl) else "<absent>"
                    b = ml[j] if j < len(ml) else "<absent>"
                    if a != b:
                        print("    line %d" % (j + 1))
                        print("      tshark %s" % a[:90])
                        print("      pcapd  %s" % b[:90])
    print("TOTAL streams=%d same=%d differ=%d bytes=%d broken=%d files=%d"
          % (streams, same, differ, databytes, broken, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
