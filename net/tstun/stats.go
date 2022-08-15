package tstun

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// statistics is semantically a map[Connection]Counts.
type statistics struct {
	mu    sync.Mutex
	tcpV4 map[connectionV4]Counts
	tcpV6 map[connectionV6]Counts
	udpV4 map[connectionV4]Counts
	udpV6 map[connectionV6]Counts
	other map[Connection]Counts
}

// connectionV4 is subset of Connection optimized for Go map hashability.
type connectionV4 struct {
	srcAddr, dstAddr [4]byte
	srcPort, dstPort uint16
}

func connectionV4FromAddrs(src, dst netip.AddrPort) connectionV4 {
	return connectionV4{
		src.Addr().As4(), dst.Addr().As4(),
		src.Port(), dst.Port(),
	}
}

func (c connectionV4) asConnection(proto ipproto.Proto) Connection {
	return Connection{proto,
		netip.AddrPortFrom(netip.AddrFrom4(c.srcAddr), c.srcPort),
		netip.AddrPortFrom(netip.AddrFrom4(c.dstAddr), c.dstPort),
	}
}

// connectionV6 is subset of Connection optimized for Go map hashability.
type connectionV6 struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
}

func connectionV6FromAddrs(src, dst netip.AddrPort) connectionV6 {
	return connectionV6{
		src.Addr().As16(), dst.Addr().As16(),
		src.Port(), dst.Port(),
	}
}

func (c connectionV6) asConnection(proto ipproto.Proto) Connection {
	return Connection{proto,
		netip.AddrPortFrom(netip.AddrFrom16(c.srcAddr), c.srcPort),
		netip.AddrPortFrom(netip.AddrFrom16(c.dstAddr), c.dstPort),
	}
}

type Connection struct {
	Protocol    ipproto.Proto
	Source      netip.AddrPort
	Destination netip.AddrPort
}

func (c Connection) String() string {
	return fmt.Sprintf("%s: %s -> %s", c.Protocol, c.Source, c.Destination)
}

func (c Connection) MarshalText() ([]byte, error) {
	var b []byte
	b = c.Protocol.AppendTo(b)
	b = append(b, ": "...)
	b = c.Source.AppendTo(b)
	b = append(b, " -> "...)
	b = c.Destination.AppendTo(b)
	return b, nil
}

func (c *Connection) UnmarshalText(b []byte) error {
	i := bytes.Index(b, []byte(": "))
	j := bytes.Index(b, []byte(" -> "))
	if i < 0 || j < 0 || j < i+len(": ") {
		return errors.New("invalid connection")
	}
	proto := b[:i]
	src := b[i+len(": ") : j]
	dst := b[j+len(" -> "):]
	if err := c.Protocol.UnmarshalText(proto); err != nil {
		return fmt.Errorf("invalid connection: %w", err)
	}
	if err := c.Source.UnmarshalText(src); err != nil {
		return fmt.Errorf("invalid connection: %w", err)
	}
	if err := c.Destination.UnmarshalText(dst); err != nil {
		return fmt.Errorf("invalid connection: %w", err)
	}
	return nil
}

type Counts struct {
	TxPackets uint64 `json:"txPkts,omitempty"`  // number of packets sent
	TxBytes   uint64 `json:"txBytes,omitempty"` // number of bytes sent
	RxPackets uint64 `json:"rxPkts,omitempty"`  // number of packets received
	RxBytes   uint64 `json:"rxBytes,omitempty"` // number of bytes received

	// TODO: Record number of dropped packets?
	// TODO: Record just data payload of UDP or TCP?
	// TODO: Record number of TCP packets with SYN or FIN?
}

func (c Counts) update(size uint64, invert bool) Counts {
	if invert {
		c.RxPackets++
		c.RxBytes += size
	} else {
		c.TxPackets++
		c.TxBytes += size
	}
	return c
}

func (c Counts) Merge(s2 Counts) Counts {
	c.TxPackets += s2.TxPackets
	c.TxBytes += s2.TxBytes
	c.RxPackets += s2.RxPackets
	c.RxBytes += s2.RxBytes
	return c
}

func (m *statistics) UpdateRx(pkt []byte) { m.update(pkt, true) }
func (m *statistics) UpdateTx(pkt []byte) { m.update(pkt, false) }
func (m *statistics) update(pkt []byte, invert bool) {
	var p packet.Parsed
	p.Decode(pkt)

	src, dst := p.Src, p.Dst
	if invert {
		src, dst = dst, src
	}

	m.mu.Lock()
	switch {
	case p.IPProto == ipproto.TCP && p.IPVersion == 4:
		initMap(&m.tcpV4)
		conn := connectionV4FromAddrs(src, dst)
		m.tcpV4[conn] = m.tcpV4[conn].update(uint64(len(pkt)), invert)
	case p.IPProto == ipproto.TCP && p.IPVersion == 6:
		initMap(&m.tcpV6)
		conn := connectionV6FromAddrs(src, dst)
		m.tcpV6[conn] = m.tcpV6[conn].update(uint64(len(pkt)), invert)
	case p.IPProto == ipproto.UDP && p.IPVersion == 4:
		initMap(&m.udpV4)
		conn := connectionV4FromAddrs(src, dst)
		m.udpV4[conn] = m.udpV4[conn].update(uint64(len(pkt)), invert)
	case p.IPProto == ipproto.UDP && p.IPVersion == 6:
		initMap(&m.udpV6)
		conn := connectionV6FromAddrs(src, dst)
		m.udpV6[conn] = m.udpV6[conn].update(uint64(len(pkt)), invert)
	default:
		initMap(&m.other)
		conn := Connection{p.IPProto, src, dst}
		m.other[conn] = m.other[conn].update(uint64(len(pkt)), invert)
	}
	m.mu.Unlock()
}

// Extract extracts counts for every connection.
// It resets all connection counts back to zero.
func (m *statistics) Extract() map[Connection]Counts {
	m.mu.Lock()
	tcpV4 := m.tcpV4
	tcpV6 := m.tcpV6
	udpV4 := m.udpV4
	udpV6 := m.udpV6
	other := m.other

	m.tcpV4 = make(map[connectionV4]Counts, len(m.tcpV4))
	m.tcpV6 = make(map[connectionV6]Counts, len(m.tcpV6))
	m.udpV4 = make(map[connectionV4]Counts, len(m.udpV4))
	m.udpV6 = make(map[connectionV6]Counts, len(m.udpV6))
	m.other = make(map[Connection]Counts, len(m.other))
	m.mu.Unlock()

	all := other
	initMap(&all)
	for conn, cnts := range tcpV4 {
		all[conn.asConnection(ipproto.TCP)] = cnts
	}
	for conn, cnts := range tcpV6 {
		all[conn.asConnection(ipproto.TCP)] = cnts
	}
	for conn, cnts := range udpV4 {
		all[conn.asConnection(ipproto.UDP)] = cnts
	}
	for conn, cnts := range udpV6 {
		all[conn.asConnection(ipproto.UDP)] = cnts
	}
	return all
}

func (m *statistics) Reset() {
	m.mu.Lock()
	m.tcpV4 = nil
	m.tcpV6 = nil
	m.udpV4 = nil
	m.udpV6 = nil
	m.other = nil
	m.mu.Unlock()
}

func initMap[K comparable, V any](m *map[K]V) {
	if *m == nil {
		*m = make(map[K]V)
	}
}
