package routeexporter

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

func getPodCIDRsFromK8sNode(node *v1.Node) *prefixSet {
	ret := newPrefixSet()

	if len(node.Spec.PodCIDRs) != 0 {
		for _, podCIDR := range node.Spec.PodCIDRs {
			ret.add(podCIDR)
		}
	} else {
		ret.add(node.Spec.PodCIDR)
	}

	return ret
}

func (re *RouteExporter) runPodCIDRSyncer(ctx context.Context) error {
	// only subscribe to the local node's change
	tweakList := informers.WithTweakListOptions(func(lo *metav1.ListOptions) {
		lo.FieldSelector = "metadata.name=" + nodetypes.GetName()
	})

	nodeInformer := informers.NewSharedInformerFactoryWithOptions(k8s.Client(),
		0, tweakList).Core().V1().Nodes().Informer()

	handler := func(nodeObj interface{}) {
		if node := k8s.ObjToV1Node(nodeObj); node != nil {
			podCIDRs := getPodCIDRsFromK8sNode(node)

			kernelRoutes, err := getKernelRoutes(re.TableID, re.PodCIDRProtocolID, re.AddressFamilies)
			if err != nil {
				re.podCIDRSyncerLastError = err
				return
			}

			addSet, deleteSet := podCIDRs.distance(kernelRoutes)

			err = reconcileKernelRoutes(re.VrfName, re.TableID, re.PodCIDRProtocolID, addSet, deleteSet)
			if err != nil {
				re.podCIDRSyncerLastError = err
				return
			}
		}
	}

	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    handler,
		UpdateFunc: func(_ interface{}, newObj interface{}) { handler(newObj) },
		DeleteFunc: func(_ interface{}) {},
	})

	go func() {
		nodeInformer.Run(ctx.Done())
	}()

	return nil
}
