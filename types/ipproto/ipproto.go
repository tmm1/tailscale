// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ipproto contains IP Protocol constants.
package ipproto

import (
	"bytes"
	"fmt"
	"strconv"
)

// Proto is an IP subprotocol as defined by the IANA protocol
// numbers list
// (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml),
// or the special values Unknown or Fragment.
type Proto uint8

const (
	// Unknown represents an unknown or unsupported protocol; it's
	// deliberately the zero value. Strictly speaking the zero
	// value is IPv6 hop-by-hop extensions, but we don't support
	// those, so this is still technically correct.
	Unknown Proto = 0x00

	// Values from the IANA registry.
	ICMPv4 Proto = 0x01
	IGMP   Proto = 0x02
	ICMPv6 Proto = 0x3a
	TCP    Proto = 0x06
	UDP    Proto = 0x11
	SCTP   Proto = 0x84

	// TSMP is the Tailscale Message Protocol (our ICMP-ish
	// thing), an IP protocol used only between Tailscale nodes
	// (still encrypted by WireGuard) that communicates why things
	// failed, etc.
	//
	// Proto number 99 is reserved for "any private encryption
	// scheme". We never accept these from the host OS stack nor
	// send them to the host network stack. It's only used between
	// nodes.
	TSMP Proto = 99

	// Fragment represents any non-first IP fragment, for which we
	// don't have the sub-protocol header (and therefore can't
	// figure out what the sub-protocol is).
	//
	// 0xFF is reserved in the IANA registry, so we steal it for
	// internal use.
	Fragment Proto = 0xFF
)

func (p Proto) String() string {
	switch p {
	case Unknown:
		return "Unknown"
	case Fragment:
		return "Frag"
	case TSMP:
		return "TSMP"
	default:
		return string(p.AppendTo(nil))
	}
}

func (p Proto) AppendTo(b []byte) []byte {
	// NOTE: Any human-readable names must be kept unchanged,
	// otherwise we will be unable to parse older string representations.
	// This formats a subset of protocols printed by String to be conservative.
	switch p {
	case ICMPv4:
		return append(b, "ICMPv4"...)
	case IGMP:
		return append(b, "IGMP"...)
	case ICMPv6:
		return append(b, "ICMPv6"...)
	case UDP:
		return append(b, "UDP"...)
	case TCP:
		return append(b, "TCP"...)
	case SCTP:
		return append(b, "SCTP"...)
	default:
		return strconv.AppendUint(append(b, "IPProto-"...), uint64(p), 10)
	}
}

func (p Proto) MarshalText() ([]byte, error) {
	return p.AppendTo(nil), nil
}

func (p *Proto) UnmarshalText(b []byte) error {
	if bytes.HasPrefix(b, []byte("IPProto-")) {
		n, err := strconv.ParseUint(string(b[len("IPProto-"):]), 10, 8)
		if err != nil {
			return fmt.Errorf("invalid protocol: %s", b)
		}
		*p = Proto(n)
		return nil
	}
	switch string(b) {
	case "ICMPv4":
		*p = ICMPv4
	case "IGMP":
		*p = IGMP
	case "ICMPv6":
		*p = ICMPv6
	case "UDP":
		*p = UDP
	case "TCP":
		*p = TCP
	case "SCTP":
		*p = SCTP
	default:
		return fmt.Errorf("invalid protocol: %s", b)
	}
	return nil
}
