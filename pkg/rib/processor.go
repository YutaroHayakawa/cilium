// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"context"
	"slices"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/rib/tables"
	"github.com/cilium/cilium/pkg/statedb"
)

type processorIn struct {
	cell.In

	DB  *statedb.DB
	RIB tables.RIB
	FIB tables.FIB

	LC    cell.Lifecycle
	JR    job.Registry
	Scope cell.Scope
}

// processor is responsible for calculating best paths from RIB and sync them
// to FIB.
type processor struct {
	db  *statedb.DB
	rib tables.RIB
	fib tables.FIB
}

func (p *processor) selectBest(rt tables.Route) (tables.Route, bool) {
	// Get a fresh transaction, so that we don't observe a deleted route
	it, _ := p.rib.Get(p.db.ReadTxn(), tables.RIBPrefixIndex.Query(rt.Prefix))

	rts := statedb.Collect(it)
	if len(rts) == 0 {
		// There's no route anymore
		return tables.Route{}, false
	} else {
		// Recalculate best path by comparing admin distances
		return slices.MinFunc(rts, func(rt1, rt2 tables.Route) int {
			d1 := rt1.Protocol.AdminDistance()
			d2 := rt2.Protocol.AdminDistance()
			switch {
			case d1 < d2:
				return -1
			case d1 > d2:
				return 1
			default:
				return 0
			}
		}), true
	}
}

func (p *processor) runBestPathSelection(ctx context.Context, health cell.HealthReporter) error {
	wtxn := p.db.WriteTxn(p.rib)
	dt, err := p.rib.DeleteTracker(wtxn, "best-path-selection")
	if err != nil {
		wtxn.Abort()
		health.Stopped("failed to register RIB delete tracker")
		return err
	}
	wtxn.Commit()

	rtxn := p.db.ReadTxn()

	for {
		watch := dt.Iterate(rtxn, func(rt tables.Route, _ bool, _ statedb.Revision) {
			var err error

			best, found := p.selectBest(rt)

			wtxn := p.db.WriteTxn(p.fib)

			if found {
				// Promote next best path
				_, _, err = p.fib.Insert(wtxn, best)
			} else {
				// No route to promote. Just delete the existing one.
				_, _, err = p.fib.Delete(wtxn, rt)
			}

			wtxn.Commit()

			if err != nil {
				health.Degraded("Best path update failed", err)
			} else {
				health.OK("Bast path is up-to-date")
			}
		})

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		rtxn = p.db.ReadTxn()
	}
}

func registerProcessor(in processorIn) error {
	p := &processor{
		db:  in.DB,
		rib: in.RIB,
		fib: in.FIB,
	}

	jg := in.JR.NewGroup(in.Scope)
	jg.Add(job.OneShot("best-path-selection", p.runBestPathSelection))
	in.LC.Append(jg)

	return nil
}
