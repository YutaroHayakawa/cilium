package tables

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/statedb/index"
)

// NextHop represents a next-hop in the RIB
type NextHop interface {
	Kind() NextHopKind
}

// NextHopKind is a numeric ID of the nexthop kind
type NextHopKind uint8

const (
	NextHopKindUnspec NextHopKind = iota
	NextHopKindInterface
	NextHopKindIPv4
	NextHopKindIPv6
)

// Key returns a unique key for the next-hop kind
func (n NextHopKind) Key() index.Key {
	return []byte{byte(n)}
}

// NextHopIface represents a next-hop interface
type NextHopInterface struct {
	// Interface's name
	Name string
}

func (n NextHopInterface) Kind() NextHopKind {
	return NextHopKindInterface
}

// NextHopIPv4 represents a next-hop IPv4 address
type NextHopIPv4 struct {
	// Addr is an IPv4 address of the next-hop. Must be a valid IPv4 address.
	Addr netip.Addr
}

func (n NextHopIPv4) Kind() NextHopKind {
	return NextHopKindIPv4
}

// NextHopIPv6 represents a next-hop IPv6 address
type NextHopIPv6 struct {
	// Addr is an IPv6 address of the next-hop. Must be a valid IPv6 address.
	Addr netip.Addr
}

func (n NextHopIPv6) Kind() NextHopKind {
	return NextHopKindIPv6
}
