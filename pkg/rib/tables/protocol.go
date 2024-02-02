package tables

import "github.com/cilium/cilium/pkg/statedb/index"

// Protocol represents a "protocol" that imports the route. Each protocol has
// an "administrative distance" that is used to resolve conflicts between
// routes imported by different protocols. The route with the lowest distance
// takes precedence.
type Protocol interface {
	Key() index.Key
	AdminDistance() uint8
}

// Administrative distances for different protocols. The value is taken from
// FRR (Zebra) and we added Kubernetes protocol with the distance same as
// static routes.
const (
	adminDistanceReserved0   uint8 = 0
	adminDistanceKubernetes  uint8 = 1
	adminDistanceEBGP        uint8 = 20
	adminDistanceIBGP        uint8 = 200
	adminDistanceReserved255 uint8 = 255
)

// Unique IDs used for indexing the protocols
const (
	protocolKindKubernetes uint8 = iota + 1
	protocolKindEBGP
	protocolKindIBGP
)

type ProtocolKubernetes struct{}

func (p ProtocolKubernetes) Key() index.Key {
	return []byte{protocolKindKubernetes}
}

func (p ProtocolKubernetes) AdminDistance() uint8 {
	return adminDistanceKubernetes
}

type ProtocolEBGP struct{}

func (p ProtocolEBGP) Key() index.Key {
	return []byte{protocolKindEBGP}
}

func (p ProtocolEBGP) AdminDistance() uint8 {
	return adminDistanceEBGP
}

type ProtocolIBGP struct{}

func (p ProtocolIBGP) Key() index.Key {
	return []byte{protocolKindIBGP}
}

func (p ProtocolIBGP) AdminDistance() uint8 {
	return adminDistanceIBGP
}
