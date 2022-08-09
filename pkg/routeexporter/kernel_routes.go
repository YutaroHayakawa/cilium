package routeexporter

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func reconcileVrf(vrfName string, tableID int) (netlink.Link, error) {
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

func reconcileRoutes(vrfIfindex, tableID, protocolID int, addSet, deleteSet *prefixSet) error {
	for prefix := range addSet.prefixes {
		_, dst, err := net.ParseCIDR(prefix)
		if err != nil {
			return fmt.Errorf("cound't parse prefix %s: %s", prefix, err.Error())
		}
		route := netlink.Route{
			LinkIndex: vrfIfindex,
			Dst:       dst,
			Table:     tableID,
			Protocol:  netlink.RouteProtocol(protocolID),
		}
		err = netlink.RouteReplace(&route)
		if err != nil {
			return fmt.Errorf("couldn't replace route with prefix %s: %s", prefix, err.Error())
		}
	}
	for prefix := range deleteSet.prefixes {
		_, dst, err := net.ParseCIDR(prefix)
		if err != nil {
			return fmt.Errorf("cound't parse prefix %s: %s", prefix, err.Error())
		}
		route := netlink.Route{
			LinkIndex: vrfIfindex,
			Dst:       dst,
			Table:     tableID,
			Protocol:  netlink.RouteProtocol(protocolID),
		}
		err = netlink.RouteDel(&route)
		if err != nil {
			return fmt.Errorf("coudn't delete route with prefix %s: %s", prefix, err.Error())
		}
	}
	return nil
}

func reconcileKernelRoutes(vrfName string, tableID, protocolID int, addSet, deleteSet *prefixSet) error {
	vrf, err := reconcileVrf(vrfName, tableID)
	if err != nil {
		return err
	}

	err = reconcileRoutes(vrf.Attrs().Index, tableID, protocolID, addSet, deleteSet)
	if err != nil {
		return err
	}

	return nil
}

func getKernelRoutes(tableID, protocolID int, afs []int) (*prefixSet, error) {
	filter := &netlink.Route{
		Table:    tableID,
		Protocol: netlink.RouteProtocol(protocolID),
	}

	mask := netlink.RT_FILTER_TABLE | netlink.RT_FILTER_PROTOCOL

	ret := newPrefixSet()
	for _, af := range afs {
		routes, err := netlink.RouteListFiltered(af, filter, mask)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			if route.Dst != nil {
				ret.add(route.Dst.String())
			}
		}
	}

	return ret, nil
}
