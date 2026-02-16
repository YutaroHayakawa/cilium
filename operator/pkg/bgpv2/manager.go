// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bgpv2 implements the BGP Control Plane v2 operator for Cilium.
//
// This operator reconciles high-level BGP policies into lower-level node-specific
// configurations that are consumed by BGP agents running on each node.
//
// # Dual API Support
//
// The operator supports two API versions for backward compatibility:
//   - Legacy: CiliumBGPPeeringPolicy (v2alpha1) - Original BGP configuration API
//   - New: CiliumBGPClusterConfig (v2alpha1) - Improved cluster-wide BGP configuration
//
// Both APIs generate the same lower-level resources (CiliumBGPNodeConfig,
// CiliumBGPAdvertisement, CiliumBGPPeerConfig). When both APIs are present in the cluster,
// the NEW CiliumBGPClusterConfig takes precedence. This enables zero-downtime migration:
//   1. Deploy new CiliumBGPClusterConfig alongside existing CiliumBGPPeeringPolicy
//   2. Validate that new configs work correctly (new API takes precedence)
//   3. Delete legacy CiliumBGPPeeringPolicy resources
//
// # Architecture
//
// The reconciliation flow:
//  1. High-level policies (CiliumBGPPeeringPolicy or CiliumBGPClusterConfig) are watched
//  2. Changes trigger the main reconciliation loop in BGPResourceManager
//  3. Reconciliation logic (bgpp.go or cluster.go) generates lower-level resources
//  4. Generated resources are created/updated via Kubernetes API
//  5. BGP agents on nodes watch and apply the generated configurations
//
// # Resource Generation
//
// From CiliumBGPPeeringPolicy:
//   - Each policy + node + virtual router + peer → unique CiliumBGPPeerConfig
//   - Each policy + node + virtual router → unique CiliumBGPAdvertisement
//   - Each policy + node → unique CiliumBGPNodeConfig
//
// From CiliumBGPClusterConfig:
//   - Cluster config + node-specific overrides → CiliumBGPNodeConfig per node
//
// # Owner References and Garbage Collection
//
// All generated resources include OwnerReferences pointing to their source policy.
// This enables automatic cleanup via Kubernetes garbage collection when policies
// are deleted. The operator also performs additional orphan cleanup to handle
// edge cases where Kubernetes GC might not immediately remove resources.
//
// # Abbreviations Used in Code
//
//   - bgpp: CiliumBGPPeeringPolicy
//   - bgpnc: CiliumBGPNodeConfig
//   - bgpa: CiliumBGPAdvertisement
//   - bgppc: CiliumBGPPeerConfig
//   - cc: CiliumBGPClusterConfig
//
// For detailed issues and improvement opportunities, see pkg/bgp/ISSUES.md.
package bgpv2

import (
	"context"
	"errors"
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// retry options used in reconcileWithRetry method.
	//
	// With exponential backoff (factor=2) and 10 steps:
	// 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 512s
	// Total retry window: ~17 minutes (sum of all delays)
	// Maximum single delay: ~8.5 minutes (512s)
	//
	// These values provide a reasonable balance between:
	// - Quick recovery from transient errors
	// - Not overwhelming the API server with retries
	// - Eventual reconciliation of persistent issues
	bo = wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      0,
	}

	// maxErrorLen is the maximum length of error message to be logged.
	// Truncating to 140 characters keeps logs readable while preserving
	// enough context to identify the error type. Full errors are still
	// returned to callers for proper error handling.
	maxErrorLen = 140
)

type BGPParams struct {
	cell.In

	Logger       logrus.FieldLogger
	LC           cell.Lifecycle
	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig
	JobRegistry  job.Registry
	Scope        cell.Scope
	Config       Config

	// resource tracking
	LegacyBGPResource          resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy]
	ClusterConfigResource      resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	NodeConfigOverrideResource resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	NodeConfigResource         resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	NodeResource               resource.Resource[*cilium_api_v2.CiliumNode]
	AdvertisementResource      resource.Resource[*cilium_api_v2alpha1.CiliumBGPAdvertisement]
	PeerConfigResource         resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
}

type BGPResourceManager struct {
	logger    logrus.FieldLogger
	clientset k8s_client.Clientset
	lc        cell.Lifecycle
	jobs      job.Registry
	scope     cell.Scope

	// For BGP Cluster Config
	clusterConfig           resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	nodeConfigOverride      resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	nodeConfig              resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	ciliumNode              resource.Resource[*cilium_api_v2.CiliumNode]
	clusterConfigStore      resource.Store[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	nodeConfigOverrideStore resource.Store[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	nodeConfigStore         resource.Store[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	ciliumNodeStore         resource.Store[*cilium_api_v2.CiliumNode]
	nodeConfigClient        cilium_client_v2alpha1.CiliumBGPNodeConfigInterface

	// For legacy BGP Peering Policy
	peeringPolicy      resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy]
	advert             resource.Resource[*cilium_api_v2alpha1.CiliumBGPAdvertisement]
	peerConfig         resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
	peeringPolicyStore resource.Store[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy]
	advertStore        resource.Store[*cilium_api_v2alpha1.CiliumBGPAdvertisement]
	peerConfigStore    resource.Store[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
	advertClient       cilium_client_v2alpha1.CiliumBGPAdvertisementInterface
	peerConfigClient   cilium_client_v2alpha1.CiliumBGPPeerConfigInterface

	// internal state
	reconcileCh      chan struct{}
	bgpPolicySyncCh  chan struct{}
	bgpClusterSyncCh chan struct{}
}

// registerBGPResourceManager creates a new BGPResourceManager operator instance.
func registerBGPResourceManager(p BGPParams) *BGPResourceManager {
	// if BGPResourceManager Control Plane is not enabled or BGPv2 API is not enabled, return nil
	if !p.DaemonConfig.BGPControlPlaneEnabled() || !p.Config.BGPv2Enabled {
		return nil
	}

	b := &BGPResourceManager{
		logger:    p.Logger,
		clientset: p.Clientset,
		jobs:      p.JobRegistry,
		lc:        p.LC,
		scope:     p.Scope,

		reconcileCh:        make(chan struct{}, 1),
		bgpPolicySyncCh:    make(chan struct{}, 1),
		bgpClusterSyncCh:   make(chan struct{}, 1),
		clusterConfig:      p.ClusterConfigResource,
		nodeConfigOverride: p.NodeConfigOverrideResource,
		nodeConfig:         p.NodeConfigResource,
		ciliumNode:         p.NodeResource,
		peeringPolicy:      p.LegacyBGPResource,
		advert:             p.AdvertisementResource,
		peerConfig:         p.PeerConfigResource,
	}

	b.nodeConfigClient = b.clientset.CiliumV2alpha1().CiliumBGPNodeConfigs()
	b.peerConfigClient = b.clientset.CiliumV2alpha1().CiliumBGPPeerConfigs()
	b.advertClient = b.clientset.CiliumV2alpha1().CiliumBGPAdvertisements()

	// initialize jobs and register them with lifecycle
	jobs := b.initializeJobs()
	p.LC.Append(jobs)

	return b
}

func (b *BGPResourceManager) initializeJobs() job.Group {
	jobGroup := b.jobs.NewGroup(
		b.scope,
		job.WithLogger(b.logger),
		job.WithPprofLabels(pprof.Labels("cell", "bgpv2-cp-operator")),
	)

	jobGroup.Add(
		job.OneShot("bgpv2-operator-main", func(ctx context.Context, health cell.HealthReporter) error {
			// initialize resource stores
			err := b.initializeStores(ctx)
			if err != nil {
				return err
			}

			b.logger.Info("BGPv2 control plane operator started")

			return b.Run(ctx)
		}),

		// Tracking jobs to do
		job.OneShot("bgpv2-operator-peering-policy-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.peeringPolicy.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case b.bgpPolicySyncCh <- struct{}{}:
					default:
					}
				}

				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-cluster-config-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.clusterConfig.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case b.bgpClusterSyncCh <- struct{}{}:
					default:
					}
				}

				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-node-config-override-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.nodeConfigOverride.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-node-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.ciliumNode.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
	)

	return jobGroup
}

func (b *BGPResourceManager) initializeStores(ctx context.Context) (err error) {
	defer func() {
		hr := cell.GetHealthReporter(b.scope, "bgpv2-store-initialization")
		if err != nil {
			hr.Stopped("store initialization failed")
		} else {
			hr.OK("store initialization successful")
		}
	}()

	b.clusterConfigStore, err = b.clusterConfig.Store(ctx)
	if err != nil {
		return
	}

	b.nodeConfigOverrideStore, err = b.nodeConfigOverride.Store(ctx)
	if err != nil {
		return
	}

	b.nodeConfigStore, err = b.nodeConfig.Store(ctx)
	if err != nil {
		return
	}

	b.advertStore, err = b.advert.Store(ctx)
	if err != nil {
		return
	}

	b.peerConfigStore, err = b.peerConfig.Store(ctx)
	if err != nil {
		return
	}

	b.ciliumNodeStore, err = b.ciliumNode.Store(ctx)
	if err != nil {
		return
	}

	b.peeringPolicyStore, err = b.peeringPolicy.Store(ctx)
	if err != nil {
		return
	}

	return nil
}

// triggerReconcile initiates level triggered reconciliation.
func (b *BGPResourceManager) triggerReconcile() {
	select {
	case b.reconcileCh <- struct{}{}:
		b.logger.Debug("BGP reconciliation triggered")
	default:
	}
}

// Run starts the BGPResourceManager operator.
func (b *BGPResourceManager) Run(ctx context.Context) (err error) {
	// make sure both policy and cluster config are synced before starting the reconciliation
	<-b.bgpClusterSyncCh
	<-b.bgpPolicySyncCh

	// trigger reconciliation for first time.
	b.triggerReconcile()

	for {
		select {
		case <-ctx.Done():
			return

		case _, open := <-b.reconcileCh:
			if !open {
				return
			}

			err := b.reconcileWithRetry(ctx)
			if err != nil {
				b.logger.WithError(err).Error("BGP reconciliation failed")
			} else {
				b.logger.Debug("BGP reconciliation successful")
			}
		}
	}
}

// reconcileWithRetry retries reconcile with exponential backoff.
func (b *BGPResourceManager) reconcileWithRetry(ctx context.Context) error {
	retryFn := func(ctx context.Context) (bool, error) {
		err := b.reconcile(ctx)

		switch {
		case err != nil:
			// log error, continue retry
			b.logger.WithError(TrimError(err, maxErrorLen)).Warn("BGP reconciliation error")
			return false, nil
		default:
			// no error, stop retry
			return true, nil
		}
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

// reconcile is called when any interesting resource change event is triggered.
func (b *BGPResourceManager) reconcile(ctx context.Context) error {
	var err error
	ppEnabled, ccEnabled := len(b.peeringPolicyStore.List()) > 0, len(b.clusterConfigStore.List()) > 0

	switch {
	case ppEnabled && ccEnabled:
		// Migration scenario: Both APIs are present in the cluster.
		//
		// When both legacy CiliumBGPPeeringPolicy and new CiliumBGPClusterConfig exist,
		// we only reconcile CiliumBGPClusterConfig to avoid conflicts and provide a clean
		// migration path. This means:
		//
		// 1. Operators can deploy new CiliumBGPClusterConfig alongside existing policies
		// 2. The new API takes precedence once both are present
		// 3. Legacy policies can be safely deleted after validation
		//
		// This design allows zero-downtime migration from legacy to new API.
		err = b.reconcileBGPClusterConfigs(ctx)
	case ppEnabled:
		err = b.reconcileBGPPeeringPolicies(ctx)
	case ccEnabled:
		err = b.reconcileBGPClusterConfigs(ctx)
	}

	// clean up any orphan objects
	dErr := b.deleteOrphanObjects(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	return err
}

// deleteOrphanObjects deletes stale BGP object.
//
// If BGP objects were created by operator on behalf of CiliumBGPPeeringPolicy or CiliumBGPClusterConfig,
// then owner field is set explicitly.
// If the owner is deleted, then we need to clean up objects which were created by the operator on behalf of the owner.
func (b *BGPResourceManager) deleteOrphanObjects(ctx context.Context) error {
	var err error

	// cleanup orphan CiliumBGPNodeConfig objects
	dErr := b.deleteOrphanBGPNC(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	dErr = b.deleteOrphanBGPA(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	dErr = b.deleteOrphanBGPPC(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	return err
}

// deleteOrphanBGPNC deletes orphan CiliumBGPNodeConfig objects. If owner is not of kind BGP peering policy or BGP cluster config,
// or if the owner does not exist, then the CiliumNodeConfig object is deleted.
func (b *BGPResourceManager) deleteOrphanBGPNC(ctx context.Context) error {
	var allErr error
	for _, nc := range b.nodeConfigStore.List() {
		var err error
		ownerExists := false

		kind, name := getOwnerKindAndName(nc)
		switch kind {
		case cilium_api_v2alpha1.BGPPKindDefinition:
			_, ownerExists, err = b.peeringPolicyStore.GetByKey(resource.Key{Name: name})

		case cilium_api_v2alpha1.BGPCCKindDefinition:
			_, ownerExists, err = b.clusterConfigStore.GetByKey(resource.Key{Name: name})
		}

		if err != nil {
			allErr = errors.Join(allErr, err)
			continue
		}

		if !ownerExists {
			// Parent policy which resulted in creation of this CiliumBGPNodeConfig object is missing.
			// We can go ahead and delete this node config object.

			dErr := b.nodeConfigClient.Delete(ctx, nc.GetName(), meta_v1.DeleteOptions{})
			if dErr != nil && k8s_errors.IsNotFound(dErr) {
				// object is already removed from API server.
				continue
			} else if dErr != nil {
				allErr = errors.Join(allErr, dErr)
			} else {
				b.logger.WithFields(logrus.Fields{
					"node config":   nc.GetName(),
					"parent policy": name,
					"parent kind":   kind,
				}).Info("Deleting BGP node config object, parent policy not found")
			}
		}
	}
	return allErr
}

// deleteOrphanBGPA deletes orphan CiliumBGPAdvertisement objects. If owner is of kind BGP peering policy, but policy is not found,
// we delete the CiliumBGPAdvertisement object.
//
// Note: This function only handles BGPPeeringPolicy owners, unlike deleteOrphanBGPNC which handles
// both BGPPeeringPolicy and BGPClusterConfig. This is intentional because:
// - CiliumBGPAdvertisement is only generated by legacy BGPPeeringPolicy reconciliation (bgpp.go)
// - CiliumBGPClusterConfig does not generate CiliumBGPAdvertisement resources
//
// If this changes in the future, this function should be updated to check both owner kinds.
func (b *BGPResourceManager) deleteOrphanBGPA(ctx context.Context) error {
	var allErr error
	for _, advert := range b.advertStore.List() {
		kind, name := getOwnerKindAndName(advert)

		if kind != cilium_api_v2alpha1.BGPPKindDefinition {
			// skip advertisements which are not created by CiliumBGPPeeringPolicy
			continue
		}

		_, ownerExists, err := b.peeringPolicyStore.GetByKey(resource.Key{Name: name})
		if err != nil {
			allErr = errors.Join(allErr, err)
			continue
		}

		if !ownerExists {
			dErr := b.advertClient.Delete(ctx, advert.GetName(), meta_v1.DeleteOptions{})
			if dErr != nil && k8s_errors.IsNotFound(dErr) {
				// object is already removed from API server.
				continue
			} else if dErr != nil {
				allErr = errors.Join(allErr, dErr)
			} else {
				b.logger.WithFields(logrus.Fields{
					"advertisement": advert.GetName(),
					"parent policy": name,
					"parent kind":   kind,
				}).Info("Deleting BGP advertisement object, parent policy not found")
			}
		}
	}
	return allErr
}

// deleteOrphanBGPPC deletes orphan CiliumBGPPeerConfig objects. If owner is of kind BGP peering policy, but policy is not found,
// we delete the CiliumBGPPeerConfig object.
//
// Note: This function only handles BGPPeeringPolicy owners, unlike deleteOrphanBGPNC which handles
// both BGPPeeringPolicy and BGPClusterConfig. This is intentional because:
// - CiliumBGPPeerConfig is only generated by legacy BGPPeeringPolicy reconciliation (bgpp.go)
// - CiliumBGPClusterConfig does not generate CiliumBGPPeerConfig resources
//
// If this changes in the future, this function should be updated to check both owner kinds.
func (b *BGPResourceManager) deleteOrphanBGPPC(ctx context.Context) error {
	var allErr error
	for _, pc := range b.peerConfigStore.List() {
		kind, name := getOwnerKindAndName(pc)

		if kind != cilium_api_v2alpha1.BGPPKindDefinition {
			// skip peer configs which are not created by CiliumBGPPeeringPolicy
			continue
		}

		_, ownerExists, err := b.peeringPolicyStore.GetByKey(resource.Key{Name: name})
		if err != nil {
			allErr = errors.Join(allErr, err)
			continue
		}

		if !ownerExists {
			dErr := b.peerConfigClient.Delete(ctx, pc.GetName(), meta_v1.DeleteOptions{})
			if dErr != nil && k8s_errors.IsNotFound(dErr) {
				// object is already removed from API server.
				continue
			} else if dErr != nil {
				allErr = errors.Join(allErr, dErr)
			} else {
				b.logger.WithFields(logrus.Fields{
					"peer config":   pc.GetName(),
					"parent policy": name,
					"parent kind":   kind,
				}).Info("Deleting BGP peer config object, parent policy not found")
			}
		}
	}
	return allErr
}

// getOwnerKindAndName returns owner kind and name for a given object.
//
// BGP resources created by this operator will have exactly 1 owner reference.
// If the object has 0 or multiple owners, this function returns empty strings
// ("", "") to indicate the owner could not be determined.
//
// Note: Returning empty strings rather than an error allows callers to handle
// unexpected owner counts as "no owner found" and skip cleanup for those resources.
// This is safe because Kubernetes garbage collection will eventually clean up
// resources if their owners are truly deleted.
func getOwnerKindAndName[T meta_v1.Object](obj T) (string, string) {
	owners := obj.GetOwnerReferences()

	// we expect only 1 owner for BGP resources
	if len(owners) != 1 {
		return "", ""
	}

	return owners[0].Kind, owners[0].Name
}

// TrimError trims error message to maxLen.
func TrimError(err error, maxLen int) error {
	if err == nil {
		return nil
	}

	if len(err.Error()) > maxLen {
		return fmt.Errorf("%s... ", err.Error()[:maxLen])
	}
	return err
}
