# operator/pkg/bgpv2 - BGP Control Plane v2 Operator

This package implements the BGP Control Plane operator for Cilium, responsible for reconciling high-level BGP policies into lower-level node-specific configurations.

## Overview

The BGP Control Plane v2 operator manages two API versions:
1. **Legacy**: `CiliumBGPPeeringPolicy` (v2alpha1) - Original BGP configuration API
2. **New**: `CiliumBGPClusterConfig` (v2alpha1) - Improved cluster-wide BGP configuration

Both APIs are reconciled into the same set of lower-level resources:
- `CiliumBGPNodeConfig` - Per-node BGP router configuration
- `CiliumBGPAdvertisement` - Route advertisement policies
- `CiliumBGPPeerConfig` - Individual peer settings

## Architecture

```
┌─────────────────────────────────────────────────────┐
│          High-Level APIs (User Input)               │
│                                                      │
│  ┌──────────────────────┐  ┌────────────────────┐  │
│  │CiliumBGPPeeringPolicy│  │CiliumBGPClusterConfig│ │
│  │     (Legacy)         │  │      (New)          │  │
│  └──────────┬───────────┘  └──────────┬─────────┘  │
└─────────────┼──────────────────────────┼────────────┘
              │                          │
              │  Reconciliation Loop     │
              │  (BGPResourceManager)    │
              ▼                          ▼
        ┌─────────────────────────────────────┐
        │     bgpp.go          cluster.go     │
        │  (Legacy Logic)    (New Logic)      │
        └─────────┬───────────────────────────┘
                  │
                  │ Generates
                  ▼
┌─────────────────────────────────────────────────────┐
│         Low-Level Resources (Generated)             │
│                                                      │
│  ┌────────────────┐  ┌──────────────────────────┐  │
│  │CiliumBGPNode   │  │CiliumBGPAdvertisement   │  │
│  │Config          │  │                          │  │
│  └────────────────┘  └──────────────────────────┘  │
│                                                      │
│  ┌────────────────────────────────────────────────┐ │
│  │CiliumBGPPeerConfig                            │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
                      │
                      │ Consumed by
                      ▼
              ┌───────────────┐
              │  BGP Agents   │
              │  (on nodes)   │
              └───────────────┘
```

## File Structure

| File | Purpose |
|------|---------|
| **cell.go** | Hive dependency injection setup; registers BGP operator as a pluggable module |
| **manager.go** | Core orchestration; lifecycle management, reconciliation loop, orphan cleanup |
| **bgpp.go** | Reconciles legacy `CiliumBGPPeeringPolicy` into generated resources |
| **cluster.go** | Reconciles new `CiliumBGPClusterConfig` into generated resources |
| **\*_test.go** | Unit tests with shared test fixtures |

## Key Concepts

### Dual API Support

The operator supports both legacy and new APIs simultaneously to enable migration:

- **New API precedence**: If both a `CiliumBGPPeeringPolicy` and `CiliumBGPClusterConfig` are present in the cluster, the NEW `CiliumBGPClusterConfig` takes precedence (see `manager.go:378-393`)
- **Migration path**: Operators can deploy new configs alongside legacy policies, validate they work correctly, then safely delete the legacy resources
- **Deprecation timeline**: TBD (not yet announced)

### Reconciliation Loop

The operator uses Cilium's `hive/job` framework:

1. **Watchers**: Separate jobs track changes to policies and cluster configs
2. **Event channels**: Changes trigger notifications via Go channels
3. **Main loop**: Processes events and reconciles desired state
4. **Backoff retry**: Failed reconciliations retry with exponential backoff (~8.5 minute max window)

### Resource Generation

Each high-level policy generates multiple low-level resources:

**From CiliumBGPPeeringPolicy**:
```
Policy (1) → NodeConfigs (N) + Advertisements (N*M) + PeerConfigs (N*M*P)
  where:
    N = matching nodes
    M = virtual routers per policy
    P = peers per virtual router
```

**From CiliumBGPClusterConfig**:
```
ClusterConfig (1) + Overrides (K) → NodeConfigs (N)
  where:
    N = matching nodes
    K = node-specific overrides
```

### Owner References

Generated resources have `OwnerReferences` pointing to their source policy:
- Enables Kubernetes garbage collection
- Operator performs additional orphan cleanup for stale resources
- **Note**: Orphan cleanup behavior differs between resource types (see ISSUES.md #3)

### Naming Conventions

Generated resource names use deterministic patterns:

```go
// Peer key format
peerKey := fmt.Sprintf("%s-%s-%s", policyName, localASN, normalizedPeerAddr)

// Normalization rules
// - CIDR "/" → "-"
// - IPv6 ":" → "."  
// - Lowercase
```

Examples:
- `10.0.0.1/32` → `10-0-0-1-32`
- `2001:db8::1` → `2001.db8..1`

## Common Abbreviations

| Abbreviation | Full Name |
|--------------|-----------|
| **bgpp** | CiliumBGPPeeringPolicy |
| **bgpnc** | CiliumBGPNodeConfig |
| **bgpa** | CiliumBGPAdvertisement |
| **bgppc** | CiliumBGPPeerConfig |
| **cc** | CiliumBGPClusterConfig |

## Development

### Building the Operator

From repository root:
```bash
make operator-generic
```

### Running Tests

```bash
go test ./operator/pkg/bgpv2/...
```

Run with verbose output:
```bash
go test -v ./operator/pkg/bgpv2/...
```

### Local Development

Use the BGP development lab (see `Documentation/contributing/development/bgp_cplane.rst`):

```bash
# Deploy lab environment
make kind-bgp-v4

# Build and deploy operator
KIND_CLUSTER_NAME=bgp-cplane-dev-v4 make kind-image
cilium install --chart-directory install/kubernetes/cilium \
  -f contrib/containerlab/bgp-cplane-dev-v4/values.yaml \
  --set operator.image.override="localhost:5000/cilium/operator-generic:local"
```

### Debugging

Enable operator debug logging:
```bash
kubectl -n kube-system set env deployment/cilium-operator CILIUM_DEBUG=true
kubectl -n kube-system logs deployment/cilium-operator -f
```

Check generated resources:
```bash
# List generated configs
kubectl get ciliumbgpnodeconfigs
kubectl get ciliumbgpadvertisements
kubectl get ciliumbgppeerconfigs

# Inspect a specific config
kubectl describe ciliumbgpnodeconfig <name>
```

## Configuration Examples

### Legacy API (CiliumBGPPeeringPolicy)

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPPeeringPolicy
metadata:
  name: rack0
spec:
  nodeSelector:
    matchLabels:
      rack: rack0
  virtualRouters:
  - localASN: 64512
    neighbors:
    - peerAddress: '10.0.0.1/32'
      peerASN: 64512
```

### New API (CiliumBGPClusterConfig)

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPClusterConfig
metadata:
  name: cluster-config
spec:
  bgpInstances:
  - name: instance-65001
    localASN: 65001
    peers:
    - name: peer-65000
      peerASN: 65000
      peerAddress: 10.0.1.1
```

## Known Issues

### Race Condition in Node Deletion

There's a known race condition in stale node deletion logic (see `cluster.go:199` and issue #30320). The operator may not immediately clean up BGP configurations for deleted nodes.

**Workaround**: Manual cleanup may be required in some scenarios.

### Magic Constants

The reconciliation retry logic uses specific values:
- **Backoff steps**: 10 (results in ~8.5 minute max retry window)
- **Max error length**: 140 characters (for log truncation)

These values were chosen empirically and may need tuning for different cluster sizes.

### Code Duplication

Several functions have similar patterns that could be consolidated:
- Upsert logic (see `bgpp.go` and `cluster.go`)
- Orphan cleanup functions (see `manager.go`)

See [pkg/bgp/ISSUES.md](../../pkg/bgp/ISSUES.md) for comprehensive list of known issues.

## Migration Guide

### Moving from Legacy to New API

1. **Assessment**: Audit existing `CiliumBGPPeeringPolicy` resources
2. **Parallel deployment**: Create equivalent `CiliumBGPClusterConfig` resources
3. **Validation**: Verify both generate identical low-level configs
4. **Cutover**: Delete legacy policies (new configs take effect immediately)
5. **Cleanup**: Remove legacy CRD definitions after full migration

**Important**: During migration, the NEW `CiliumBGPClusterConfig` takes precedence if both APIs are present in the cluster. This allows safe validation of new configs before removing legacy policies.

## References

- [BGP Control Plane Documentation](../../Documentation/network/bgp-control-plane.rst)
- [BGP Development Guide](../../Documentation/contributing/development/bgp_cplane.rst)
- [Hive Framework](https://pkg.go.dev/github.com/cilium/cilium/pkg/hive)
- [CRD Definitions](../../pkg/k8s/apis/cilium.io/v2alpha1/)

## Contributing

When contributing to this package:

1. **Maintain dual API support**: Changes should work for both legacy and new APIs
2. **Add tests**: Include unit tests for new functionality
3. **Update documentation**: Keep this README and ISSUES.md current
4. **Consider migration impact**: Breaking changes affect both API versions

See [ISSUES.md](../../pkg/bgp/ISSUES.md) for areas needing improvement.
