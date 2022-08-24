// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/cilium/pkg/k8s/client/listers/cilium.io/v2alpha1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

var mutex lock.Mutex
var vrfLister v2alpha1.CiliumVRFLister

type Rule struct {
	srcIP           string
	table           int
	destinationCIDR string
}

func (k *K8sWatcher) ciliumVRFInit(ciliumNPClient *k8s.K8sCiliumClient) {
	apiGroup := k8sAPIGroupCiliumVRFV2Alpha1

	factory := externalversions.NewSharedInformerFactory(ciliumNPClient, time.Minute*5)
	vrfLister = factory.Cilium().V2alpha1().CiliumVRFs().Lister()
	vrfInformer := factory.Cilium().V2alpha1().CiliumVRFs().Informer()
	vrfInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { k.reconcileVrfs() },
		UpdateFunc: func(_ interface{}, _ interface{}) { k.reconcileVrfs() },
		DeleteFunc: func(_ interface{}) { k.reconcileVrfs() },
	})

	k.blockWaitGroupToSyncResources(
		k.stop,
		nil,
		vrfInformer.HasSynced,
		apiGroup,
	)

	go vrfInformer.Run(k.stop)

	k.k8sAPIGroups.AddAPI(apiGroup)

	k.endpointManager.GetEndpoints()
}

func (k *K8sWatcher) reconcileVrfs() {
	if vrfLister == nil {
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

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
		// desiredVRFs doesn't contain prefix
		ensureVrf(name, index)
	}

	for name := range currentVrfs {
		// VRF doesn't exist in desired, but exists in current. Should delete it.
		if _, ok := desiredVrfs[name]; !ok {
			deleteVrf(name)
		}
	}

	currentRules, err := getRules()
	if err != nil {
		fmt.Printf("=== Failed to get current rules: %s\n", err.Error())
		return
	}

	desiredRules := make(map[Rule]struct{})
	for _, cvrf := range cvrfs {
		selector, err := slimmetav1.LabelSelectorAsSelector(cvrf.Spec.PodSelector)
		if err != nil {
			return
		}

		for _, ep := range k.endpointManager.GetEndpoints() {
			if ep == nil {
				continue
			}

			p := ep.GetPod()
			if p == nil {
				continue
			}

			set := labels.Set(p.GetLabels())
			if selector.Matches(set) {
				for _, destinationCIDR := range cvrf.Spec.DestinationCIDRs {
					desiredRules[Rule{
						srcIP:           ep.GetIPv4Address() + "/32",
						table:           int(cvrf.Spec.TableID),
						destinationCIDR: destinationCIDR,
					}] = struct{}{}
				}
			}
		}
	}

	fmt.Printf("=== Current: %v\n", currentRules)
	fmt.Printf("=== Desired: %v\n", desiredRules)

	for rule := range desiredRules {
		ensureRule(&rule)
	}

	for rule := range currentRules {
		if _, ok := desiredRules[rule]; !ok {
			deleteRule(&rule)
		}
	}
}

func getRules() (map[Rule]struct{}, error) {
	rule := netlink.NewRule()
	rule.Priority = 999
	mask := netlink.RT_FILTER_PRIORITY

	nlRules, err := netlink.RuleListFiltered(unix.AF_INET, rule, mask)
	if err != nil {
		return nil, err
	}

	ret := make(map[Rule]struct{})
	for _, nlRule := range nlRules {
		ret[Rule{
			srcIP:           nlRule.Src.String(),
			table:           nlRule.Table,
			destinationCIDR: nlRule.Dst.String(),
		}] = struct{}{}
	}

	return ret, nil
}

func ensureRule(rule *Rule) error {
	fmt.Printf("====== Adding %v\n", *rule)
	_, sipNet, err := net.ParseCIDR(rule.srcIP)
	if err != nil {
		return err
	}
	_, dipNet, err := net.ParseCIDR(rule.destinationCIDR)
	if err != nil {
		return err
	}
	newRule := netlink.NewRule()
	newRule.Src = sipNet
	newRule.Dst = dipNet
	newRule.Table = rule.table
	newRule.Priority = 999
	err = netlink.RuleAdd(newRule)
	if err != nil {
		return err
	}
	return nil
}

func deleteRule(rule *Rule) error {
	fmt.Printf("====== Deleting %v\n", *rule)
	_, sipNet, err := net.ParseCIDR(rule.srcIP)
	if err != nil {
		return err
	}
	_, dipNet, err := net.ParseCIDR(rule.destinationCIDR)
	if err != nil {
		return err
	}
	newRule := netlink.NewRule()
	newRule.Src = sipNet
	newRule.Dst = dipNet
	newRule.Table = rule.table
	newRule.Priority = 999
	err = netlink.RuleDel(newRule)
	if err != nil {
		return err
	}
	return nil
}

func getVrfs() ([]*netlink.Vrf, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	vrfs := []*netlink.Vrf{}
	for _, link := range links {
		if vrf, ok := link.(*netlink.Vrf); ok {
			name := vrf.Name
			if option.Config.EnableRouteExporter &&
				(name == option.Config.RouteExporterLBIPVrfName ||
					name == option.Config.RouteExporterPodCIDRVrfName) {
				// Don't touch to the route exporter's VRF
				continue
			}
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
