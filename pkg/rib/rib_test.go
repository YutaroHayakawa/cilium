// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/rib/tables"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	hive *hive.Hive
	db   *statedb.DB
	rib  tables.RIB
	fib  tables.FIB
}

var (
	rt0 = tables.Route{
		Prefix: tables.IPv4Prefix{
			Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		},
		NextHop: tables.NextHopIPv4{
			Addr: netip.MustParseAddr("10.0.0.1"),
		},
		Protocol: tables.ProtocolKubernetes{},
		Owner:    "ownerA",
	}
	rt1 = tables.Route{
		Prefix: tables.IPv4Prefix{
			Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		},
		NextHop: tables.NextHopIPv4{
			Addr: netip.MustParseAddr("10.0.0.1"),
		},
		Protocol: tables.ProtocolKubernetes{},
		Owner:    "ownerB",
	}
)

func newFixture() *fixture {
	f := &fixture{}
	h := hive.New(
		job.Cell,
		statedb.Cell,
		Cell,
		cell.Invoke(func(db *statedb.DB, rib tables.RIB, fib tables.FIB) {
			f.db = db
			f.rib = rib
			f.fib = fib
		}),
	)
	f.hive = h
	return f
}

func TestRIBInsert(t *testing.T) {
	tests := []struct {
		name     string
		insert   []tables.Route
		expected []tables.Route
	}{
		{
			name:     "prefix can be duplicated while owner is different",
			insert:   []tables.Route{rt0, rt1},
			expected: []tables.Route{rt0, rt1},
		},
		{
			name:     "prefix + owner can't be duplicated",
			insert:   []tables.Route{rt0, rt0},
			expected: []tables.Route{rt0},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			f.hive.Start(context.TODO())
			t.Cleanup(func() {
				f.hive.Stop(context.TODO())
			})

			// Insert routes
			wtxn := f.db.WriteTxn(f.rib)
			for _, rt := range test.insert {
				_, _, err := f.rib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			// Compare the result
			rtxn := f.db.ReadTxn()
			it, _ := f.rib.All(rtxn)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

func TestRIBLookup(t *testing.T) {
	tests := []struct {
		name     string
		insert   []tables.Route
		query    statedb.Query[tables.Route]
		expected []tables.Route
	}{
		{
			name:     "lookup by owner",
			insert:   []tables.Route{rt0, rt1},
			query:    tables.RIBOwnerIndex.Query(rt0.Owner),
			expected: []tables.Route{rt0},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			f.hive.Start(context.TODO())
			t.Cleanup(func() {
				f.hive.Stop(context.TODO())
			})

			wtxn := f.db.WriteTxn(f.rib)
			for _, rt := range test.insert {
				_, _, err := f.rib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			rtxn := f.db.ReadTxn()
			it, _ := f.rib.Get(rtxn, test.query)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

// Ensures each writers (route owners) can read/write routes individually
func TestRIBMultiWriterEvent(t *testing.T) {
	rt0DifferentPrefix := rt0
	rt0DifferentPrefix.Prefix = tables.IPv4Prefix{Prefix: netip.MustParsePrefix("10.0.1.0/24")}
	rt1DifferentPrefix := rt1
	rt1DifferentPrefix.Prefix = tables.IPv4Prefix{Prefix: netip.MustParsePrefix("10.0.1.0/24")}
	tests := []struct {
		name         string
		insert       tables.Route
		expectEventA bool
		expectEventB bool
	}{
		{
			name:         "insertion of A doesn't notify B",
			insert:       rt0DifferentPrefix,
			expectEventA: true,
			expectEventB: false,
		},
		{
			name:         "insertion of B doesn't notify A",
			insert:       rt1DifferentPrefix,
			expectEventA: false,
			expectEventB: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			f.hive.Start(context.TODO())
			t.Cleanup(func() {
				f.hive.Stop(context.TODO())
			})

			wtxn := f.db.WriteTxn(f.rib)
			_, _, err := f.rib.Insert(wtxn, rt0)
			r.NoError(err)
			_, _, err = f.rib.Insert(wtxn, rt1)
			r.NoError(err)
			wtxn.Commit()

			// Owner A
			rtxnA := f.db.ReadTxn()
			itA, watchA := f.rib.Get(rtxnA, tables.RIBOwnerIndex.Query("ownerA"))
			r.ElementsMatch(statedb.Collect(itA), []tables.Route{rt0})

			// Owner B
			rtxnB := f.db.ReadTxn()
			itB, watchB := f.rib.Get(rtxnB, tables.RIBOwnerIndex.Query("ownerB"))
			r.ElementsMatch(statedb.Collect(itB), []tables.Route{rt1})

			// Insert new Route
			wtxn = f.db.WriteTxn(f.rib)
			_, hadOld, err := f.rib.Insert(wtxn, test.insert)
			r.False(hadOld)
			r.NoError(err)
			wtxn.Commit()

			// Check event occurence
			select {
			case <-watchA:
				if !test.expectEventA {
					r.FailNow("unexpected event occured for A")
				}
			default:
				if test.expectEventA {
					r.FailNow("expected event for A, but didn't get it")
				}
			}

			// Check event occurence
			select {
			case <-watchB:
				if !test.expectEventB {
					r.FailNow("unexpected event occured for B")
				}
			default:
				if test.expectEventB {
					r.FailNow("expected event for B, but didn't get it")
				}
			}
		})
	}
}

func TestFIBInsert(t *testing.T) {
	tests := []struct {
		name     string
		insert   []tables.Route
		expected []tables.Route
	}{
		{
			name:     "prefix can't be duplicated",
			insert:   []tables.Route{rt0, rt1},
			expected: []tables.Route{rt1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			f.hive.Start(context.TODO())
			t.Cleanup(func() {
				f.hive.Stop(context.TODO())
			})

			wtxn := f.db.WriteTxn(f.fib)
			for _, rt := range test.insert {
				_, _, err := f.fib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			rtxn := f.db.ReadTxn()
			it, _ := f.fib.All(rtxn)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

func TestFIBLookup(t *testing.T) {
	// Variant of rt1 with different prefix and nexthop
	rt1DifferentNextHop := rt1
	rt1DifferentNextHop.Prefix = tables.IPv4Prefix{Prefix: netip.MustParsePrefix("10.0.1.0/24")}
	rt1DifferentNextHop.NextHop = tables.NextHopIPv6{
		Addr: netip.MustParseAddr("fd00::1"),
	}

	tests := []struct {
		name     string
		insert   []tables.Route
		query    statedb.Query[tables.Route]
		expected []tables.Route
	}{
		{
			name:     "lookup by nexthop",
			insert:   []tables.Route{rt0, rt1DifferentNextHop},
			query:    tables.FIBNextHopKindIndex.Query(rt0.NextHop.Kind()),
			expected: []tables.Route{rt0},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			f.hive.Start(context.TODO())
			t.Cleanup(func() {
				f.hive.Stop(context.TODO())
			})

			wtxn := f.db.WriteTxn(f.fib)
			for _, rt := range test.insert {
				_, _, err := f.fib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			rtxn := f.db.ReadTxn()
			it, _ := f.fib.Get(rtxn, test.query)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

func TestBestPathSelection(t *testing.T) {
	// Variant of rt0 with different protocol (eBGP) and owner
	rt0EBGP := rt0
	rt0EBGP.Protocol = tables.ProtocolEBGP{}
	rt0EBGP.Owner = "ownerB"

	// Variant of rt0 with different protocol (iBGP) and owner
	rt0IBGP := rt0
	rt0IBGP.Protocol = tables.ProtocolIBGP{}
	rt0IBGP.Owner = "ownerC"

	steps := []struct {
		name     string
		insert   *tables.Route
		del      *tables.Route
		bestPath tables.Route
	}{
		{
			name:     "init (eBGP route)",
			insert:   &rt0EBGP,
			bestPath: rt0EBGP,
		},
		{
			name:     "shoter distance protocol (Kubernetes) inserted",
			insert:   &rt0,
			bestPath: rt0,
		},
		{
			name:     "delete shorter distance protocol, another route promotes to the best path",
			del:      &rt0,
			bestPath: rt0EBGP,
		},
		{
			name:     "new route (iBGP) inserted, but no best path update",
			insert:   &rt0IBGP,
			bestPath: rt0EBGP,
		},
	}

	r := require.New(t)

	f := newFixture()
	r.NoError(f.hive.Start(context.TODO()))
	defer f.hive.Stop(context.TODO())

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			r := require.New(t)

			rtxn := f.db.ReadTxn()
			_, ribWatch := f.rib.All(rtxn)
			_, fibWatch := f.fib.All(rtxn)

			wtxn := f.db.WriteTxn(f.rib)

			if step.insert != nil {
				_, _, err := f.rib.Insert(wtxn, *step.insert)
				r.NoError(err)
			}

			if step.del != nil {
				_, _, err := f.rib.Delete(wtxn, *step.del)
				r.NoError(err)
			}

			wtxn.Commit()

			<-ribWatch
			<-fibWatch

			r.Eventually(func() bool {
				bestPath, _, found := f.fib.First(f.db.ReadTxn(), tables.FIBIDIndex.Query(rt0.Prefix))
				return assert.True(t, found) && assert.Equal(t, step.bestPath, bestPath)
			}, time.Second*2, time.Millisecond*400)
		})
	}
}
