package tables

import (
	"github.com/cilium/cilium/pkg/statedb/index"
)

// Route represents a route in the RIB
type Route struct {
	Prefix   Prefix
	NextHop  NextHop
	Protocol Protocol
	Owner    string
}

func (r Route) RouteID() RouteID {
	return RouteID{
		Prefix: r.Prefix,
		Owner:  r.Owner,
	}
}

type RouteID struct {
	Prefix Prefix
	Owner  string
}

func (r RouteID) Key() index.Key {
	key := r.Prefix.Key()
	return append(key, []byte(r.Owner)...)
}
