package routeexporter

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

type RouteExporterConfig struct {
	VrfName           string
	TableID           int
	ExportPodCIDR     bool
	PodCIDRProtocolID int
	ExportLBVIP       bool
	LBVIPProtocolID   int
	AddressFamilies   []int
}

type RouteExporter struct {
	RouteExporterConfig
	podCIDRSyncerLastError error
}

func NewRouteExporter(rec *RouteExporterConfig) (*RouteExporter, error) {
	if rec == nil {
		return nil, fmt.Errorf("no configuration provided")
	}

	if rec.VrfName == "" {
		return nil, fmt.Errorf("no VRF name specified")
	}

	if rec.TableID == 0 {
		return nil, fmt.Errorf("no table ID specified")
	}

	if rec.ExportPodCIDR {
		if rec.PodCIDRProtocolID == 0 {
			return nil, fmt.Errorf("no protocol ID specified for PodCIDR")
		}
		if rec.PodCIDRProtocolID < unix.RTPROT_STATIC {
			return nil, fmt.Errorf("protocol IDs < %d are reserved for kernel internal use", unix.RTPROT_STATIC)
		}
	}

	return &RouteExporter{RouteExporterConfig: *rec}, nil
}

func (re *RouteExporter) Run(ctx context.Context) error {
	if re.ExportPodCIDR {
		re.runPodCIDRSyncer(ctx)
	}
	return nil
}
