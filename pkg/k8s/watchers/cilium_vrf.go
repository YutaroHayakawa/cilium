// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/cilium/pkg/k8s/client/listers/cilium.io/v2alpha1"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumVRFInit(ciliumNPClient *k8s.K8sCiliumClient) {
	apiGroup := k8sAPIGroupCiliumVRFV2Alpha1

	factory := externalversions.NewSharedInformerFactory(ciliumNPClient, time.Minute * 5)
	vrfLister := factory.Cilium().V2alpha1().CiliumVRFs().Lister()
	vrfInformer := factory.Cilium().V2alpha1().CiliumVRFs().Informer()
	vrfInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(_ interface{}) { reconcileVrfs(vrfLister) },
		UpdateFunc: func(_ interface{}, _ interface{}) { reconcileVrfs(vrfLister) },
		DeleteFunc: func(_ interface{}) {reconcileVrfs(vrfLister) },
	})

	k.blockWaitGroupToSyncResources(
		k.stop,
		nil,
		vrfInformer.HasSynced,
		apiGroup,
	)

	go vrfInformer.Run(k.stop)

	k.k8sAPIGroups.AddAPI(apiGroup)
}

func reconcileVrfs(vrfLister v2alpha1.CiliumVRFLister) {
	cvrfs, err := vrfLister.List(labels.NewSelector())
	if err != nil {
		return
	}

	desiredVrfs := make(map[string]uint32)
	for _, cvrf := range cvrfs {
		desiredVrfs[cvrf.GetName()] = cvrf.Spec.TableID
	}

	vrfs, err := getVrfs()
	if err != nil {
		return
	}

	currentVrfs := make(map[string]uint32)
	for _, vrf := range vrfs {
		currentVrfs[vrf.Attrs().Name] = uint32(vrf.Index)
	}

	for name, index := range desiredVrfs {
		ensureVrf(name, index)
	}

	for name := range currentVrfs {
		// VRF doesn't exist in desired, but exists in current. Should delete it.
		if _, ok := desiredVrfs[name]; !ok {
			deleteVrf(name)
		}
	}
}

func getVrfs() ([]*netlink.Vrf, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	vrfs := []*netlink.Vrf{}
	for _, link := range links {
		if vrf, ok := link.(*netlink.Vrf); ok {
			vrfs = append(vrfs, vrf)
		}
	}
	
	return vrfs, nil
}

func ensureVrf(vrfName string, tableID uint32) error {
	vrf, err := netlink.LinkByName(vrfName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Device not found. Recover by creating a new device.
			attrs := netlink.Vrf{
				LinkAttrs: netlink.LinkAttrs{
					Name: vrfName,
				},
				Table: tableID,
			}
			err := netlink.LinkAdd(&attrs)
			if err != nil {
				return fmt.Errorf("couldn't create VRF %s: %s", vrfName, err.Error())
			}
			vrf, err = netlink.LinkByName(vrfName)
			if err != nil {
				return fmt.Errorf("couldn't get VRF %s after creation: %s", vrfName, err.Error())
			}
		} else {
			// Unrecoverable error
			return fmt.Errorf("failed to get VRF %s: %s", vrfName, err.Error())
		}
	}

	// Ensure the device is up
	if vrf.Attrs().OperState != netlink.OperUp {
		err := netlink.LinkSetUp(vrf)
		if err != nil {
			return fmt.Errorf("couldn't bring up VRF %s: %s", vrfName, err.Error())
		}
	}

	return err
}

func deleteVrf(vrfName string) error {
	if vrf, err := netlink.LinkByName(vrfName); err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Not found. It's ok.
			return nil
		}
		return fmt.Errorf("failed to find vrf %s: %s", vrfName, err.Error())
	} else {
		if err = netlink.LinkDel(vrf); err != nil {
			return fmt.Errorf("failed to delete vrf %s: %s", vrf, err.Error())
		}
		return nil
	}
}
