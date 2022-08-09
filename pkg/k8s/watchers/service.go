// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"net"

	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
)

func (k *K8sWatcher) servicesInit(slimClient slimclientset.Interface, swgSvcs *lock.StoppableWaitGroup, optsModifier func(*v1meta.ListOptions)) {
	apiGroup := resources.K8sAPIGroupServiceV1Core
	_, svcController := informer.NewInformer(
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped[*slim_corev1.ServiceList](slimClient.CoreV1().Services("")),
			optsModifier),
		&slim_corev1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(apiGroup, resources.MetricService, resources.MetricCreate, valid, equal)
				}()
				if k8sSvc := k8s.ObjToV1Services(obj); k8sSvc != nil {
					valid = true
					err := k.addK8sServiceV1(k8sSvc, swgSvcs)
					k.K8sEventProcessed(resources.MetricService, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, resources.MetricService, resources.MetricUpdate, valid, equal) }()
				if oldk8sSvc := k8s.ObjToV1Services(oldObj); oldk8sSvc != nil {
					if newk8sSvc := k8s.ObjToV1Services(newObj); newk8sSvc != nil {
						valid = true
						if k8s.EqualV1Services(oldk8sSvc, newk8sSvc, k.datapath.LocalNodeAddressing()) {
							equal = true
							return
						}

						err := k.updateK8sServiceV1(oldk8sSvc, newk8sSvc, swgSvcs)
						k.K8sEventProcessed(resources.MetricService, resources.MetricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, resources.MetricService, resources.MetricDelete, valid, equal) }()
				k8sSvc := k8s.ObjToV1Services(obj)
				if k8sSvc == nil {
					return
				}

				valid = true
				err := k.deleteK8sServiceV1(k8sSvc, swgSvcs)
				k.K8sEventProcessed(resources.MetricService, resources.MetricDelete, err == nil)
			},
		},
		nil,
	)
	k.blockWaitGroupToSyncResources(k.stop, swgSvcs, svcController.HasSynced, resources.K8sAPIGroupServiceV1Core)
	go svcController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(apiGroup)
}

func createExportRouteSpec(prefix *cidr.CIDR, ifindex, tableID, protocolID int) netlink.Route {
	return netlink.Route{
		LinkIndex: ifindex,
		Dst:       prefix.IPNet,
		Table:     tableID,
		Protocol:  netlink.RouteProtocol(protocolID),
	}
}

func updateExportRoutes(prefixes []*cidr.CIDR, ifindex, tableID, protocolID int) error {
	for _, prefix := range prefixes {
		route := createExportRouteSpec(prefix, ifindex, tableID, protocolID)
		err := netlink.RouteReplace(&route)
		if err != nil {
			return fmt.Errorf("couldn't replace route with prefix %s: %s", prefix, err.Error())
		}
	}
	return nil
}

func deleteExportRoutes(prefixes []*cidr.CIDR, ifindex, tableID, protocolID int) error {
	for _, prefix := range prefixes {
		route := createExportRouteSpec(prefix, ifindex, tableID, protocolID)
		err := netlink.RouteDel(&route)
		if err != nil {
			return fmt.Errorf("coudn't delete route with prefix %s: %s", prefix, err.Error())
		}
	}
	return nil
}

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

func updateOrRemoveExportRoutes(old, new []*cidr.CIDR, vrfName string, tableID, protocolID int) error {
	addedAuxRoutes, removedAuxRoutes := cidr.DiffCIDRLists(old, new)

	vrf, err := reconcileVrf(vrfName, tableID)
	if err != nil {
		return err
	}

	err = updateExportRoutes(addedAuxRoutes, vrf.Attrs().Index, tableID, protocolID)
	if err != nil {
		return err
	}

	err = deleteExportRoutes(removedAuxRoutes, vrf.Attrs().Index, tableID, protocolID)
	if err != nil {
		return err
	}

	return nil
}

func (k *K8sWatcher) addK8sServiceV1(svc *slim_corev1.Service, swg *lock.StoppableWaitGroup) error {
	svcID := k.K8sSvcCache.UpdateService(svc, swg)
	if option.Config.EnableLocalRedirectPolicy {
		if svc.Spec.Type == slim_corev1.ServiceTypeClusterIP {
			// The local redirect policies currently support services of type
			// clusterIP only.
			k.redirectPolicyManager.OnAddService(svcID)
		}
	}
	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnUpdateService(svc)
	}
	if option.Config.EnableRouteExporter && option.Config.RouteExporterExportLBIP {
		if len(svc.Status.LoadBalancer.Ingress) == 1 {
			fmt.Println("hogehoge")
			var prefixLenStr string

			ip := net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP)
			if ip.To4() != nil {
				prefixLenStr = "/32"
			} else {
				prefixLenStr = "/128"
			}

			prefix, err := cidr.ParseCIDR(ip.String() + prefixLenStr)
			if err != nil {
				return err
			}

			err = updateOrRemoveExportRoutes(
				[]*cidr.CIDR{},
				[]*cidr.CIDR{prefix},
				option.Config.RouteExporterVrfName,
				option.Config.RouteExporterTableID,
				option.Config.RouteExporterLBIPProtocolID,
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *K8sWatcher) updateK8sServiceV1(oldSvc, newSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) error {
	return k.addK8sServiceV1(newSvc, swg)
}

func (k *K8sWatcher) deleteK8sServiceV1(svc *slim_corev1.Service, swg *lock.StoppableWaitGroup) error {
	k.K8sSvcCache.DeleteService(svc, swg)
	svcID := k8s.ParseServiceID(svc)
	if option.Config.EnableLocalRedirectPolicy {
		if svc.Spec.Type == slim_corev1.ServiceTypeClusterIP {
			k.redirectPolicyManager.OnDeleteService(svcID)
		}
	}
	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnDeleteService(svc)
	}
	return nil
}
