// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/rib/tables"
	"github.com/cilium/cilium/pkg/statedb"
)

var Cell = cell.Module(
	"rib",
	"Routing Information Base",
	cell.Provide(
		tables.NewRIBTable,
		tables.NewFIBTable,
	),
	cell.Invoke(
		func(db *statedb.DB, rib tables.RIB, fib tables.FIB) {
			db.RegisterTable(rib, fib)
		},
		registerProcessor,
	),
)
