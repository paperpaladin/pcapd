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

# cap FILE FILTER COUNT SCRIPT -- start tcpdump, run a python traffic script,
# stop tcpdump. The count is a ceiling, not an expectation: tcpdump is killed
# when the traffic is done.
cap() {
	f=$1; filt=$2; dev=$3; shift 3
	tcpdump -i "$dev" -Z root -s 0 -w "$OUT/$f" "$filt" >/dev/null 2>&1 &
	td=$!
	# tcpdump needs to have the socket open before the traffic starts.
	i=0
	while [ ! -s "$OUT/$f" ] && [ $i -lt 50 ]; do i=$((i+1)); sleep 0.05; done
	sleep 0.3
	python3 "$@"
	sleep 0.4
	kill -INT $td 2>/dev/null
	wait $td 2>/dev/null
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
