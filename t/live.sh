#!/bin/sh
# Capture real loopback traffic into $1, one file per scenario.
#
# This runs inside "unshare -rn", a user and network namespace in which the
# invoking user is root and lo is a private interface. Without that there is
# no capture permission on this machine at all, and the whole corpus would be
# packets we wrote ourselves, which is a decoder tested against its author's
# idea of a packet.
#
# tcpdump needs -Z root here: it drops privileges to the "tcpdump" user by
# default and then cannot chown the save file, which it reports as
# "Couldn't change ownership of savefile" and exits.
set -u
OUT=$1
ip link set lo up || exit 2
ip addr show lo | grep -q 'inet ' || exit 2

# cap FILE FILTER DEVICE SCRIPT... -- start tcpdump, run a python traffic
# script, stop tcpdump, and insist that something was captured.
#
# -U and --immediate-mode are both load-bearing. Without them libpcap holds
# packets in its ring until the buffer timeout and tcpdump writes them in
# stdio-sized chunks, and SIGINT then takes the process down with packets
# still unwritten. The symptom is a 24-byte file: a valid capture of nothing,
# which every tool in the suite reads happily and agrees about. Three
# different scenarios produced one of those on three different runs before
# the flush was forced.
cap() {
	f=$1; filt=$2; dev=$3; shift 3
	try=0
	while [ $try -lt 3 ]; do
		try=$((try+1))
		rm -f "$OUT/$f"
		tcpdump -i "$dev" -Z root -s 0 -U --immediate-mode \
			-w "$OUT/$f" "$filt" >/dev/null 2>&1 &
		td=$!
		# tcpdump opens the capture socket before the save file, so the
		# file appearing means the socket is already listening.
		i=0
		while [ ! -s "$OUT/$f" ] && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.05; done
		sleep 0.3
		python3 "$@"
		sleep 0.5
		kill -INT $td 2>/dev/null
		wait $td 2>/dev/null
		# 24 bytes is the file header and no packets.
		sz=$(wc -c < "$OUT/$f")
		[ "$sz" -gt 24 ] && return 0
		echo "retry $f: captured nothing on attempt $try" >&2
	done
	echo "giving up on $f after $try attempts" >&2
	return 1
}

D=$(dirname "$0")
cap tcp-echo.pcap  'tcp'  lo "$D/traffic.py" echo4
cap tcp-bulk.pcap  'tcp'  lo "$D/traffic.py" bulk4
cap udp-echo.pcap  'udp'  lo "$D/traffic.py" udp4
cap tcp-rst.pcap   'tcp'  lo "$D/traffic.py" rst4
cap tcp6-echo.pcap 'tcp'  lo "$D/traffic.py" echo6
cap udp6-echo.pcap 'udp'  lo "$D/traffic.py" udp6
cap any-tcp.pcap   'tcp'  any "$D/traffic.py" echo4

# Fragmented IPv4 and IPv6, which need a small MTU on the loopback device.
ip link set lo mtu 1000
cap frag4.pcap 'ip'   lo "$D/traffic.py" bigudp4
ip link set lo mtu 1280
ip -6 addr add ::1/128 dev lo 2>/dev/null
sleep 0.3
cap frag6.pcap 'ip6'  lo "$D/traffic.py" bigudp6
ip link set lo mtu 65536
exit 0
