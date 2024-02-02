package tables

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/statedb/index"
)

type Prefix interface {
	Key() index.Key
}

// Unique IDs used for indexing the prefixes
const (
	prefixKindUnspec uint8 = iota
	prefixKindIPv4
	prefixKindIPv6
)

type IPv4Prefix struct {
	netip.Prefix
}

func (p IPv4Prefix) Key() index.Key {
	key := []byte{prefixKindIPv4}
	addr := p.Addr().As4()
	return append(key, addr[:]...)
}

type IPv6Prefix struct {
	netip.Prefix
}

func (p IPv6Prefix) Key() index.Key {
	key := []byte{prefixKindIPv6}
	addr := p.Addr().As16()
	return append(key, addr[:]...)
}
