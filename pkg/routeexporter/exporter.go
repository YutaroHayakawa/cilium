package routeexporter

import (
	"fmt"
	"syscall"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type RouteExporterOptions struct {
	ExportPodCIDR     bool
	PodCIDRVrfName    string
	PodCIDRTableID    int
	PodCIDRProtocolID int
	ExportLBIP        bool
	LBIPVrfName       string
	LBIPTableID       int
	LBIPProtocolID    int
}

type RouteExporter struct {
	lock.Mutex
	RouteExporterOptions
	podCIDRSyncerLastError error
	lbIPSyncerLastError    error
}

func NewRouteExporter(opts *RouteExporterOptions) (*RouteExporter, error) {
	if opts == nil {
		return nil, fmt.Errorf("no configuration provided")
	}

	if opts.ExportPodCIDR {
		if opts.PodCIDRVrfName == "" {
			return nil, fmt.Errorf("no VRF name specified for PodCIDR")
		}

		if opts.PodCIDRTableID == 0 {
			return nil, fmt.Errorf("no table ID specified for PodCIDR")
		}

		err := validateProtocolID(opts.PodCIDRProtocolID)
		if err != nil {
			return nil, fmt.Errorf("invalid protocol ID specified for PodCIDR: %s", err.Error())
		}
	}

	if opts.ExportLBIP {
		if opts.LBIPVrfName == "" {
			return nil, fmt.Errorf("no VRF name specified for LBIP")
		}

		if opts.LBIPTableID == 0 {
			return nil, fmt.Errorf("no table ID specified for LBIP")
		}

		err := validateProtocolID(opts.LBIPProtocolID)
		if err != nil {
			return nil, fmt.Errorf("invalid protocol ID specified for LBIP: %s", err.Error())
		}
	}

	return &RouteExporter{RouteExporterOptions: *opts}, nil
}

func (re *RouteExporter) UpdateOrDeletePodCIDRRoutes(updatedPrefixes, deletedPrefixes []*cidr.CIDR) {
	re.Lock()
	defer re.Unlock()
	if err := updateKernelRoutes(re.PodCIDRVrfName, re.PodCIDRTableID, re.PodCIDRProtocolID, updatedPrefixes); err != nil {
		re.podCIDRSyncerLastError = err
	}
	if err := deleteKernelRoutes(re.PodCIDRVrfName, re.PodCIDRTableID, re.PodCIDRProtocolID, deletedPrefixes); err != nil {
		re.podCIDRSyncerLastError = err
	}
}

func (re *RouteExporter) UpdateOrDeleteLBIPRoutes(updatedPrefixes, deletedPrefixes []*cidr.CIDR) {
	re.Lock()
	defer re.Unlock()
	if err := updateKernelRoutes(re.LBIPVrfName, re.LBIPTableID, re.LBIPProtocolID, updatedPrefixes); err != nil {
		re.lbIPSyncerLastError = err
	}
	if err := deleteKernelRoutes(re.LBIPVrfName, re.LBIPTableID, re.LBIPProtocolID, deletedPrefixes); err != nil {
		re.lbIPSyncerLastError = err
	}
}

func validateProtocolID(protocolID int) error {
	if protocolID == 0 {
		return fmt.Errorf("no protocol ID specified")
	}
	if protocolID < unix.RTPROT_STATIC {
		return fmt.Errorf("protocol IDs < %d are reserved for kernel internal use", unix.RTPROT_STATIC)
	}
	return nil
}

func getOrCreateVrf(vrfName string, tableID int) (netlink.Link, error) {
	var vrf netlink.Link

	vrf, err := netlink.LinkByName(vrfName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Device not found. Recover by creating a new device.
			attrs := netlink.Vrf{
				LinkAttrs: netlink.LinkAttrs{
					Name: vrfName,
				},
				Table: uint32(tableID),
			}
			err := netlink.LinkAdd(&attrs)
			if err != nil {
				return nil, fmt.Errorf("couldn't create VRF %s: %s", vrfName, err.Error())
			}
			vrf, err = netlink.LinkByName(vrfName)
			if err != nil {
				return nil, fmt.Errorf("couldn't get VRF %s after creation: %s", vrfName, err.Error())
			}
		} else {
			// Unrecoverable error
			return nil, fmt.Errorf("failed to get VRF %s: %s", vrfName, err.Error())
		}
	}

	// Ensure the device is up
	if vrf.Attrs().OperState != netlink.OperUp {
		err := netlink.LinkSetUp(vrf)
		if err != nil {
			return nil, fmt.Errorf("couldn't bring up VRF %s: %s", vrfName, err.Error())
		}
	}

	return vrf, err
}

func updateKernelRoutes(vrfName string, tableID, protocolID int, prefixes []*cidr.CIDR) error {
	vrf, err := getOrCreateVrf(vrfName, tableID)
	if err != nil {
		return err
	}

	for _, prefix := range prefixes {
		route := netlink.Route{
			LinkIndex: vrf.Attrs().Index,
			Dst:       prefix.IPNet,
			Table:     tableID,
			Protocol:  netlink.RouteProtocol(protocolID),
		}
		err := netlink.RouteReplace(&route)
		if err != nil {
			return fmt.Errorf("couldn't replace route with prefix %s: %s", prefix, err.Error())
		}
	}

	return nil
}

func deleteKernelRoutes(vrfName string, tableID, protocolID int, prefixes []*cidr.CIDR) error {
	vrf, err := getOrCreateVrf(vrfName, tableID)
	if err != nil {
		return err
	}

	for _, prefix := range prefixes {
		route := netlink.Route{
			LinkIndex: vrf.Attrs().Index,
			Dst:       prefix.IPNet,
			Table:     tableID,
			Protocol:  netlink.RouteProtocol(protocolID),
		}
		err := netlink.RouteDel(&route)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == unix.EEXIST {
					// route doesn't exist, it's ok
					continue
				}
			}
			return fmt.Errorf("coudn't delete route with prefix %s: %s", prefix, err.Error())
		}
	}
	return nil
}
