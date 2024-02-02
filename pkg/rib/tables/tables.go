package tables

import (
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var (
	// Primary index for the RIB table
	RIBIDIndex = statedb.Index[Route, RouteID]{
		Name: "id",
		FromObject: func(rt Route) index.KeySet {
			return index.NewKeySet(rt.RouteID().Key())
		},
		FromKey: RouteID.Key,
		Unique:  true,
	}

	// Index used by route owners
	RIBOwnerIndex = statedb.Index[Route, string]{
		Name: "owner",
		FromObject: func(rt Route) index.KeySet {
			return index.NewKeySet(index.String(rt.Owner))
		},
		FromKey: index.String,
		Unique:  false,
	}

	// Index used by RIB Processor for best path selection
	RIBPrefixIndex = statedb.Index[Route, Prefix]{
		Name: "prefix",
		FromObject: func(rt Route) index.KeySet {
			return index.NewKeySet(rt.Prefix.Key())
		},
		FromKey: Prefix.Key,
		Unique:  false,
	}

	// Primary index for the FIB table
	FIBIDIndex = statedb.Index[Route, Prefix]{
		Name: "id",
		FromObject: func(rt Route) index.KeySet {
			return index.NewKeySet(rt.Prefix.Key())
		},
		FromKey: Prefix.Key,
		Unique:  true,
	}

	// Index used by Datapath to instantiate the routes
	FIBNextHopKindIndex = statedb.Index[Route, NextHopKind]{
		Name: "nexthop-kind",
		FromObject: func(rt Route) index.KeySet {
			return index.NewKeySet(rt.NextHop.Kind().Key())
		},
		FromKey: NextHopKind.Key,
		Unique:  false,
	}
)

type RIB statedb.RWTable[Route]

func NewRIBTable() (RIB, error) {
	return statedb.NewTable[Route](
		"rib",
		RIBIDIndex,
		RIBOwnerIndex,
		RIBPrefixIndex,
	)
}

type FIB statedb.RWTable[Route]

func NewFIBTable() (FIB, error) {
	return statedb.NewTable[Route](
		"fib",
		FIBIDIndex,
		FIBNextHopKindIndex,
	)
}
