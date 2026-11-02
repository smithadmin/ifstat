package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"
)

// EtherTypes we care about.
const (
	etherIPv4 = 0x0800
	etherIPv6 = 0x86DD
	etherVLAN = 0x8100
	etherQinQ = 0x88A8
	etherAll  = 0x0003 // ETH_P_ALL
)

// IP protocol numbers we name or parse ports for.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
	protoSCTP   = 132
)

// flowKey identifies a bidirectional connection: the two endpoints are
// stored in a canonical order so both directions land on the same key.
type flowKey struct {
	proto uint8
	a, b  netip.AddrPort
}

type portKey struct {
	proto uint8
	port  uint16
}

type tally struct {
	Packets uint64
	Bytes   uint64
}

type talker struct {
	Packets   uint64 // packets in which the address was source or destination
	SentBytes uint64
	RecvBytes uint64
}

// Capture sniffs packets on one interface using an AF_PACKET socket (Linux
// only, needs root or CAP_NET_RAW) and aggregates per-flow, per-port and
// per-address statistics. All fields are owned by the capture goroutine until
// Wait returns; read them only after that.
type Capture struct {
	fd       int
	loopback bool
	local    map[netip.Addr]bool

	Packets uint64 // packets seen
	Bytes   uint64 // IP-layer bytes (link-layer header is not included)
	Other   uint64 // non-IP packets (ARP, etc.) or unparseable ones

	Flows   map[flowKey]*tally
	Ports   map[portKey]*tally
	Talkers map[netip.Addr]*talker

	done chan struct{}
	err  error
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// StartCapture opens the socket and starts capturing in the background until
// ctx is cancelled.
func StartCapture(ctx context.Context, name string) (*Capture, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	// SOCK_DGRAM makes the kernel strip the link-layer header, so this works
	// for Ethernet, Wi-Fi, tun/wireguard and loopback alike; the EtherType is
	// reported in the returned sockaddr.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(etherAll)))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("packet capture needs root or CAP_NET_RAW (try sudo): %w", err)
		}
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(etherAll),
		Ifindex:  ifc.Index,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("binding to %s: %w", name, err)
	}
	// Wake up regularly so we notice cancellation even on a quiet link.
	tv := syscall.NsecToTimeval(int64(200 * time.Millisecond))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	// A bigger receive buffer reduces drops on busy links (best effort).
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8<<20)

	c := &Capture{
		fd:       fd,
		loopback: ifc.Flags&net.FlagLoopback != 0,
		local:    localAddrs(ifc),
		Flows:    make(map[flowKey]*tally),
		Ports:    make(map[portKey]*tally),
		Talkers:  make(map[netip.Addr]*talker),
		done:     make(chan struct{}),
	}
	go c.run(ctx)
	return c, nil
}

// Wait blocks until the capture goroutine has finished.
func (c *Capture) Wait() { <-c.done }

func (c *Capture) run(ctx context.Context) {
	defer close(c.done)
	defer syscall.Close(c.fd)

	buf := make([]byte, 65536)
	for ctx.Err() == nil {
		n, from, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			c.err = err
			return
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok {
			continue
		}
		// On loopback every packet is seen twice (outgoing + incoming);
		// keep only one copy.
		if c.loopback && ll.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}
		c.handle(buf[:n], htons(ll.Protocol))
	}
}

func (c *Capture) handle(p []byte, et uint16) {
	c.Packets++
	size := uint64(len(p))
	c.Bytes += size

	// Skip any VLAN tags that remain in the payload.
	for (et == etherVLAN || et == etherQinQ) && len(p) >= 4 {
		et = binary.BigEndian.Uint16(p[2:4])
		p = p[4:]
	}

	var (
		src, dst netip.Addr
		proto    uint8
		l4       []byte
		ok       bool
	)
	switch et {
	case etherIPv4:
		src, dst, proto, l4, ok = parseIPv4(p)
	case etherIPv6:
		src, dst, proto, l4, ok = parseIPv6(p)
	}
	if !ok {
		c.Other++
		return
	}

	var sp, dp uint16
	hasPorts := (proto == protoTCP || proto == protoUDP || proto == protoSCTP) && len(l4) >= 4
	if hasPorts {
		sp = binary.BigEndian.Uint16(l4[0:2])
		dp = binary.BigEndian.Uint16(l4[2:4])
	}

	// Connection (bidirectional 5-tuple, canonical order).
	a := netip.AddrPortFrom(src, sp)
	b := netip.AddrPortFrom(dst, dp)
	if cmpAddrPort(b, a) < 0 {
		a, b = b, a
	}
	fk := flowKey{proto: proto, a: a, b: b}
	ft := c.Flows[fk]
	if ft == nil {
		ft = &tally{}
		c.Flows[fk] = ft
	}
	ft.Packets++
	ft.Bytes += size

	// Port: count the lower of the two ports, which is almost always the
	// service port (the other side is usually an ephemeral port).
	if hasPorts {
		port := sp
		if dp < sp {
			port = dp
		}
		pk := portKey{proto: proto, port: port}
		pt := c.Ports[pk]
		if pt == nil {
			pt = &tally{}
			c.Ports[pk] = pt
		}
		pt.Packets++
		pt.Bytes += size
	}

	// Talkers: an address is "seen" whenever it is source or destination.
	if src == dst {
		t := c.talker(src)
		t.Packets++
		t.SentBytes += size
		t.RecvBytes += size
	} else {
		ts := c.talker(src)
		ts.Packets++
		ts.SentBytes += size
		td := c.talker(dst)
		td.Packets++
		td.RecvBytes += size
	}
}

func (c *Capture) talker(a netip.Addr) *talker {
	t := c.Talkers[a]
	if t == nil {
		t = &talker{}
		c.Talkers[a] = t
	}
	return t
}

func cmpAddrPort(x, y netip.AddrPort) int {
	if c := x.Addr().Compare(y.Addr()); c != 0 {
		return c
	}
	switch {
	case x.Port() < y.Port():
		return -1
	case x.Port() > y.Port():
		return 1
	}
	return 0
}

// parseIPv4 returns addresses, protocol and the layer-4 payload (nil for
// non-first fragments, which carry no port numbers).
func parseIPv4(p []byte) (src, dst netip.Addr, proto uint8, l4 []byte, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return
	}
	src = netip.AddrFrom4([4]byte(p[12:16]))
	dst = netip.AddrFrom4([4]byte(p[16:20]))
	proto = p[9]
	if binary.BigEndian.Uint16(p[6:8])&0x1fff == 0 {
		l4 = p[ihl:]
	}
	ok = true
	return
}

// parseIPv6 walks a bounded number of extension headers to find the
// upper-layer protocol.
func parseIPv6(p []byte) (src, dst netip.Addr, proto uint8, l4 []byte, ok bool) {
	if len(p) < 40 || p[0]>>4 != 6 {
		return
	}
	src = netip.AddrFrom16([16]byte(p[8:24]))
	dst = netip.AddrFrom16([16]byte(p[24:40]))
	ok = true
	nh := p[6]
	rest := p[40:]
	for i := 0; i < 8; i++ {
		switch nh {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				proto = nh
				return
			}
			n := (int(rest[1]) + 1) * 8
			if len(rest) < n {
				proto = nh
				return
			}
			nh, rest = rest[0], rest[n:]
			continue
		case 44: // fragment header
			if len(rest) < 8 {
				proto = nh
				return
			}
			fragOff := binary.BigEndian.Uint16(rest[2:4]) >> 3
			nh, rest = rest[0], rest[8:]
			if fragOff != 0 {
				proto = nh
				return
			}
			continue
		}
		break
	}
	proto = nh
	l4 = rest
	return
}

// localAddrs returns the addresses configured on the interface.
func localAddrs(ifc *net.Interface) map[netip.Addr]bool {
	m := make(map[netip.Addr]bool)
	addrs, err := ifc.Addrs()
	if err != nil {
		return m
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ad, ok := netip.AddrFromSlice(ipn.IP); ok {
				m[ad.Unmap()] = true
			}
		}
	}
	return m
}

// ---- reporting -----------------------------------------------------------

var services = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
	137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
	161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	514: "syslog", 587: "submission", 636: "ldaps", 853: "dns-tls",
	993: "imaps", 995: "pop3s", 1900: "ssdp", 3306: "mysql", 3389: "rdp",
	5060: "sip", 5353: "mdns", 5432: "postgres", 6379: "redis",
	8080: "http-alt", 8443: "https-alt", 51820: "wireguard",
}

func protoName(p uint8) string {
	switch p {
	case protoICMP:
		return "ICMP"
	case protoTCP:
		return "TCP"
	case protoUDP:
		return "UDP"
	case protoICMPv6:
		return "ICMPv6"
	case protoSCTP:
		return "SCTP"
	}
	return fmt.Sprintf("proto-%d", p)
}

func endpoint(ap netip.AddrPort) string {
	if ap.Port() == 0 {
		return ap.Addr().String()
	}
	return ap.String()
}

func flowLabel(k flowKey) string {
	return fmt.Sprintf("%-6s %s <-> %s", protoName(k.proto), endpoint(k.a), endpoint(k.b))
}

func portLabel(k portKey) string {
	name := services[k.port]
	if k.proto == protoUDP && k.port == 443 {
		name = "quic"
	}
	s := fmt.Sprintf("%d/%s", k.port, strings.ToLower(protoName(k.proto)))
	if name != "" {
		s += " (" + name + ")"
	}
	return s
}

type row struct {
	label   string
	packets uint64
	bytes   uint64
	detail  string
}

func printTop(title string, rows []row, n int, byBytes bool) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if byBytes {
			if a.bytes != b.bytes {
				return a.bytes > b.bytes
			}
			if a.packets != b.packets {
				return a.packets > b.packets
			}
		} else {
			if a.packets != b.packets {
				return a.packets > b.packets
			}
			if a.bytes != b.bytes {
				return a.bytes > b.bytes
			}
		}
		return a.label < b.label
	})

	fmt.Printf("\n%s\n", title)
	fmt.Println(strings.Repeat("-", 64))
	if len(rows) == 0 {
		fmt.Println("  (none seen)")
		return
	}
	if len(rows) > n {
		rows = rows[:n]
	}
	fmt.Printf("%3s %10s %12s  %s\n", "#", "Packets", "Bytes", "Item")
	for i, r := range rows {
		line := fmt.Sprintf("%3d %10d %12s  %s", i+1, r.packets, humanBytes(r.bytes), r.label)
		if r.detail != "" {
			line += "  [" + r.detail + "]"
		}
		fmt.Println(line)
	}
}

// Report prints the top-N connections, ports and talkers. Call only after Wait.
func (c *Capture) Report(top int, byBytes, noLocal bool) {
	rank := "packets"
	if byBytes {
		rank = "bytes"
	}
	fmt.Printf("\nPacket capture: %d packets (%s at IP layer), %d non-IP/unparsed\n",
		c.Packets, humanBytes(c.Bytes), c.Other)
	if c.err != nil {
		fmt.Printf("Warning: capture stopped early: %v\n", c.err)
	}

	flows := make([]row, 0, len(c.Flows))
	for k, t := range c.Flows {
		flows = append(flows, row{label: flowLabel(k), packets: t.Packets, bytes: t.Bytes})
	}
	printTop(fmt.Sprintf("Top %d connections (ranked by %s)", top, rank), flows, top, byBytes)

	ports := make([]row, 0, len(c.Ports))
	for k, t := range c.Ports {
		ports = append(ports, row{label: portLabel(k), packets: t.Packets, bytes: t.Bytes})
	}
	printTop(fmt.Sprintf("Top %d ports (ranked by %s)", top, rank), ports, top, byBytes)

	talkers := make([]row, 0, len(c.Talkers))
	for a, t := range c.Talkers {
		isLocal := c.local[a]
		if noLocal && isLocal {
			continue
		}
		label := a.String()
		if isLocal {
			label += " (this host)"
		}
		talkers = append(talkers, row{
			label:   label,
			packets: t.Packets,
			bytes:   t.SentBytes + t.RecvBytes,
			detail:  fmt.Sprintf("sent %s / recv %s", humanBytes(t.SentBytes), humanBytes(t.RecvBytes)),
		})
	}
	printTop(fmt.Sprintf("Top %d talkers (ranked by %s)", top, rank), talkers, top, byBytes)
}
