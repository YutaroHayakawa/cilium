# Understanding of Cilium BGP Packages

**Author**: New sig-bgp Team Member  
**Date**: 2026-02-17  
**Purpose**: Document understanding of `pkg/bgp` and `operator/pkg/bgp` packages

---

## Executive Summary

Cilium's BGP Control Plane enables Kubernetes clusters to advertise routes to external BGP routers, making Pod networks and LoadBalancer Services reachable from outside the cluster. The implementation is split into two complementary control planes:

1. **Operator-Side Control Plane** (`operator/pkg/bgp`): Cluster-wide configuration orchestration
2. **Agent-Side Control Plane** (`pkg/bgp`): Per-node BGP router implementation

---

## Part 1: `pkg/bgp` - Agent-Side BGP Control Plane

### Overview

The agent-side package (`pkg/bgp`) implements the **per-node BGP router functionality** that runs on every Cilium-enabled node. It is responsible for:

- Running actual BGP protocol speakers (currently GoBGP)
- Establishing BGP peering sessions with external routers
- Advertising routes for Pod CIDRs, LoadBalancer IPs, and other network resources
- Handling route policies and neighbor management
- Providing REST API for querying BGP state

**Key Point**: This package does **NOT** program the datapath - it only handles BGP route advertisement for making cluster resources reachable externally.

### Architecture Components

#### 1. **Agent Controller** (`agent/`)
- **Purpose**: Kubernetes controller that drives the BGP reconciliation loop
- **Watches**: `CiliumBGPNodeConfig` CRD (node-specific configuration)
- **Behavior**: 
  - Listens for configuration changes on the local node
  - Evaluates if the node matches BGP configuration criteria
  - Triggers reconciliation via BGPRouterManager
  - Uses `BGPCPSignaler` for event notification

**File**: `agent/controller.go`

#### 2. **BGPRouterManager** (`manager/`)
- **Purpose**: Declarative API layer for managing BGP router instances
- **Responsibilities**:
  - Creates/removes BGP router instances based on `CiliumBGPNodeInstance` specs
  - Orchestrates ConfigReconcilers in priority order
  - Manages multiple BGP routers per node (multi-ASN support)
  - Handles failures gracefully (continues with other instances on error)

**Key Interface**:
```go
type BGPRouterManager interface {
    ReconcileInstances(ctx, CiliumBGPNodeConfig, CiliumNode) error
    GetPeers(ctx, GetPeersRequest) (*GetPeersResponse, error)
    GetRoutes(ctx, GetRoutesParams) ([]*BgpRoute, error)
    GetRoutePolicies(ctx, GetRoutePoliciesParams) ([]*BgpRoutePolicy, error)
    Stop(ctx) error
}
```

#### 3. **ConfigReconcilers** (`manager/reconciler/`)
- **Purpose**: Order-dependent reconciliation of BGP configuration aspects
- **Pattern**: Each reconciler focuses on a specific configuration domain
- **Priority-based execution**: Lower priority number = earlier execution

**Available Reconcilers**:
- **NeighborReconciler**: Manages BGP neighbor/peer configuration
- **PodCIDRReconciler**: Advertises Pod CIDR routes
- **ServiceReconciler**: Advertises LoadBalancer Service IPs
- **PodIPPoolReconciler**: Advertises PodIPPool ranges
- **DefaultGatewayReconciler**: Advertises default gateway routes
- **InterfaceReconciler**: Configures network interfaces for BGP

**Interface**:
```go
type ConfigReconciler interface {
    Name() string
    Priority() int
    Init(*BGPInstance) error
    Cleanup(*BGPInstance)
    Reconcile(ctx context.Context, params ReconcileParams) error
}
```

#### 4. **Router Interface** (`types/bgp.go`)
- **Purpose**: Vendor-agnostic abstraction for BGP protocol operations
- **Design**: Allows swapping BGP backends (currently only GoBGP, but extensible to FRR, BIRD, etc.)

**Key Methods**:
```go
type Router interface {
    // Neighbor management
    AddNeighbor(context.Context, NeighborRequest) error
    UpdateNeighbor(context.Context, NeighborRequest) error
    RemoveNeighbor(context.Context, NeighborRequest) error
    ResetNeighbor(context.Context, NeighborRequest) error
    
    // Route management
    AdvertisePath(context.Context, PathRequest) (PathResponse, error)
    WithdrawPath(context.Context, PathRequest) error
    
    // Policy management
    AddRoutePolicy(context.Context, RoutePolicyRequest) error
    RemoveRoutePolicy(context.Context, RoutePolicyRequest) error
    
    // State queries
    GetPeerState(context.Context) (GetPeerStateResponse, error)
    GetRoutes(context.Context, *GetRoutesRequest) (*GetRoutesResponse, error)
    GetBGP(context.Context) (GetBGPResponse, error)
    
    Stop()
}
```

#### 5. **GoBGP Provider** (`gobgp/`)
- **Purpose**: Concrete implementation of Router interface using GoBGP library
- **Role**: Translation layer between Cilium types and GoBGP types
- **Implementation**: `gobgp.RouterProvider` creates `gobgp.Router` instances

**Files**: `gobgp/router.go`, `gobgp/conversions.go`

#### 6. **REST API Handlers** (`api/`)
- **Purpose**: Expose BGP state via Cilium REST API
- **Endpoints**:
  - `/bgp/peers` - Get BGP peer status
  - `/bgp/routes` - Get advertised/received routes
  - `/bgp/route-policies` - Get configured route policies

**Files**: `api/get_peer.go`, `api/get_routes.go`, `api/get_route_policies.go`

#### 7. **Metrics** (`metrics/`)
- **Purpose**: Prometheus metrics for BGP control plane monitoring
- **Metrics**: Peer session state, route counts, reconciliation errors, etc.

#### 8. **Types** (`types/`)
- **Purpose**: Core BGP type definitions and utilities
- **Contents**: Path, Neighbor, RoutePolicy, BGPInstance, interfaces

---

### Data Flow: Configuration to BGP Advertisement

```
1. Kubernetes API Server
   ↓ (CiliumBGPNodeConfig created/updated)
   
2. Agent Controller (agent/controller.go)
   ↓ (watches CiliumBGPNodeConfig for local node)
   ↓ (evaluates if reconciliation needed)
   
3. BGPRouterManager (manager/)
   ↓ (ReconcileInstances called)
   ↓ (creates/removes BGP router instances)
   ↓ (triggers ConfigReconcilers by priority)
   
4. ConfigReconcilers (manager/reconciler/)
   ├─ NeighborReconciler → Establish peer sessions
   ├─ PodCIDRReconciler → Advertise Pod CIDRs
   ├─ ServiceReconciler → Advertise LoadBalancer IPs
   ├─ PodIPPoolReconciler → Advertise IP pool ranges
   └─ DefaultGatewayReconciler → Advertise default routes
   ↓ (each calls Router interface methods)
   
5. GoBGP Router (gobgp/)
   ↓ (translates to GoBGP API calls)
   
6. GoBGP Server
   ↓ (BGP protocol speaker)
   
7. External BGP Router
   (receives route advertisements)
```

---

## Part 2: `operator/pkg/bgp` - Operator-Side BGP Control Plane

### Overview

The operator-side package (`operator/pkg/bgp`) implements the **cluster-wide BGP configuration orchestration** that runs in the Cilium Operator. It is responsible for:

- Processing `CiliumBGPClusterConfig` CRDs (cluster-wide configuration)
- Creating/updating/deleting `CiliumBGPNodeConfig` resources for each node
- Managing BGP router ID allocation from IP pools
- Monitoring peer configuration health (e.g., missing auth secrets)
- Reporting status conditions on BGP resources

**Key Point**: The operator does **NOT** run BGP routers or establish peering sessions. It only manages the **configuration** that the agents will consume.

### Architecture Components

#### 1. **BGPResourceManager** (`manager.go`)
- **Purpose**: Core reconciliation engine for operator-side BGP logic
- **Responsibilities**:
  - Watches cluster-wide BGP resources (`CiliumBGPClusterConfig`, `CiliumBGPPeerConfig`)
  - Creates node-specific configurations (`CiliumBGPNodeConfig`)
  - Allocates/deallocates BGP router IDs from IP pools
  - Manages reconciliation state and job registration

**Key Methods**:
```go
func (bgp *BGPResourceManager) registerClusterConfigReconciler()
func (bgp *BGPResourceManager) registerPeerConfigReconciler()
```

#### 2. **Cluster Config Reconciliation** (`cluster.go`)
- **Purpose**: Process `CiliumBGPClusterConfig` resources
- **Logic**:
  1. List all `CiliumBGPClusterConfig` resources
  2. For each config:
     - Evaluate `spec.NodeSelector` to find matching nodes
     - For each matching node:
       - Allocate router ID from IP pool (if needed)
       - Create/update `CiliumBGPNodeConfig` with merged configuration
     - For unmatched nodes:
       - Deallocate router ID
       - Delete `CiliumBGPNodeConfig`
  3. Handle orphaned `CiliumBGPNodeConfig` resources (no matching cluster config)

**Function**: `reconcileBGPClusterConfigs()`

#### 3. **Peer Config Status Reconciliation** (`peer.go`)
- **Purpose**: Monitor `CiliumBGPPeerConfig` resources for health issues
- **Responsibilities**:
  - Check if referenced authentication secrets exist
  - Report missing secrets as status conditions on `CiliumBGPPeerConfig`
  - Alert operators to configuration problems

**Type**: `peerConfigStatusReconciler`

#### 4. **Metrics** (`metrics.go`)
- **Purpose**: Operator-side BGP metrics
- **Metrics**:
  - `bgp_operator_reconciliation_errors_total` - Reconciliation error count
  - `bgp_operator_reconciliation_duration_seconds` - Reconciliation duration

#### 5. **Hive Integration** (`cell.go`)
- **Purpose**: Dependency injection and module registration
- **Role**: Registers BGP operator module in Cilium's Hive framework

---

### Data Flow: Cluster Config to Node Config

```
1. User creates CiliumBGPClusterConfig
   ↓
   
2. Operator BGPResourceManager (operator/pkg/bgp/manager.go)
   ↓ (watches CiliumBGPClusterConfig)
   
3. Cluster Reconciliation (operator/pkg/bgp/cluster.go)
   ├─ Evaluate spec.NodeSelector
   ├─ Find matching CiliumNode resources
   │  
   ├─ For each matching node:
   │  ├─ Allocate router ID from IP pool
   │  └─ Create/Update CiliumBGPNodeConfig
   │     (name = node name)
   │  
   └─ For unmatched nodes:
      ├─ Deallocate router ID
      └─ Delete CiliumBGPNodeConfig
   ↓
   
4. CiliumBGPNodeConfig created/updated
   ↓ (watched by Agent-Side Controller)
   
5. Agent-Side BGP Control Plane (pkg/bgp)
   (continues with agent-side flow described above)
```

---

## Part 3: Relationship Between Operator and Agent Packages

### Division of Responsibilities

| Aspect | Operator (`operator/pkg/bgp`) | Agent (`pkg/bgp`) |
|--------|------------------------------|-------------------|
| **Scope** | Cluster-wide | Per-node |
| **Input CRDs** | `CiliumBGPClusterConfig` | `CiliumBGPNodeConfig` |
| **Output** | `CiliumBGPNodeConfig` per node | BGP route advertisements |
| **Operations** | Config CRUD, node selection, router ID allocation | Run BGP servers, establish peering, advertise routes |
| **Runs On** | Cilium Operator pod(s) | Every Cilium Agent node |
| **State** | K8s resources (CRDs) | BGP protocol state (GoBGP) |

### Two-Level Control Plane Pattern

This architecture follows a **two-level control plane** pattern:

1. **Level 1 (Operator)**: High-level, cluster-wide policy → Node-specific configuration
2. **Level 2 (Agent)**: Node-specific configuration → Actual BGP protocol operations

**Benefits**:
- **Separation of concerns**: Configuration management vs. protocol implementation
- **Scalability**: Operator handles cluster-wide logic once; agents run independently
- **Flexibility**: Per-node overrides possible via `CiliumBGPNodeConfigOverride`
- **Resilience**: Agent continues operating even if operator is down

---

## Part 4: Key Custom Resource Definitions (CRDs)

### 1. `CiliumBGPClusterConfig`
- **Scope**: Cluster-wide
- **Purpose**: Define BGP configuration policy for groups of nodes
- **Key Fields**:
  - `spec.NodeSelector`: Label selector for matching nodes
  - `spec.BGPInstances[]`: List of BGP router configurations
    - `localASN`: Autonomous System Number for this instance
    - `routerID`: BGP router ID (optional, can be auto-allocated)
    - `peers[]`: References to `CiliumBGPPeerConfig` resources
  
### 2. `CiliumBGPNodeConfig`
- **Scope**: Node-specific (created by operator)
- **Purpose**: Desired BGP configuration for a specific node
- **Key Fields**:
  - `metadata.name`: Matches node name
  - `spec.BGPInstances[]`: Effective BGP configuration for this node
  - `status`: Current BGP state (managed by agent)

### 3. `CiliumBGPPeerConfig`
- **Scope**: Cluster-wide
- **Purpose**: Define BGP peer/neighbor configuration
- **Key Fields**:
  - `spec.peerAddress`: IP address of BGP peer
  - `spec.peerASN`: Peer's Autonomous System Number
  - `spec.authSecretRef`: Reference to Kubernetes Secret for BGP auth
  - `spec.gracefulRestart`: Graceful restart configuration
  - `spec.families[]`: Enabled address families (IPv4, IPv6, etc.)

### 4. `CiliumBGPAdvertisement`
- **Scope**: Cluster-wide
- **Purpose**: Define what routes to advertise
- **Key Fields**:
  - `spec.advertisements[]`: List of advertisement rules
    - `advertisementType`: PodCIDR, LoadBalancerIP, CiliumPodIPPool
    - `selector`: Match specific resources
    - `attributes`: BGP attributes (communities, local-pref, etc.)

### 5. `CiliumBGPNodeConfigOverride`
- **Scope**: Node-specific
- **Purpose**: Override cluster config for specific nodes
- **Use Case**: Per-node customization (different router ID, additional peers, etc.)

---

## Part 5: Questions and Non-Obvious Parts

### Questions for the Team

1. **Router ID Allocation**: 
   - How is the IP pool for router ID allocation selected? 
   - Is there a default pool, or must it always be explicitly configured?
   - What happens if the pool is exhausted?

2. **Multi-ASN Support**:
   - What are the practical use cases for running multiple BGP instances (different ASNs) on the same node?
   - Are there any gotchas or limitations when using multi-ASN configurations?

3. **GoBGP Dependency**:
   - Are there plans to support other BGP implementations (FRR, BIRD)?
   - What would be involved in adding a new Router provider?
   - Why was GoBGP chosen over other options?

4. **State Reconciliation**:
   - How does the system handle BGP session state during agent restarts?
   - Is there any graceful restart support to avoid route flapping?
   - How are transient GoBGP errors handled vs. persistent configuration errors?

5. **Reconciler Priority**:
   - What determines the priority values for ConfigReconcilers?
   - Can operators add custom reconcilers, or is this internal only?
   - What happens if a reconciler fails partway through - is there rollback?

6. **Route Policies**:
   - The route policy reconciler is mentioned but seems less documented than others
   - How are BGP route policies specified and applied?
   - What policy actions are supported (permit, deny, modify attributes)?

7. **Failover Scenarios**:
   - If the operator is down, agents continue with last known config - but what about new nodes?
   - How long can the operator be down before BGP functionality degrades?
   - Are there any mechanisms to alert on operator-agent config drift?

### Non-Obvious Parts Requiring Clarification

1. **StateReconciler vs ConfigReconciler**:
   - The README mentions both ConfigReconcilers and StateReconcilers
   - StateReconcilers seem less documented - what exactly do they do?
   - When would you use one vs. the other?

2. **BGPInstance Wrapping**:
   - What exactly is wrapped in a `BGPInstance` struct?
   - It seems to contain more than just a Router - what metadata is tracked?

3. **Signal-based Event Notification**:
   - The agent uses a "BGPCPSignaler" for events
   - Why use a custom signaling mechanism vs. standard K8s watches?
   - What events trigger signals vs. direct reconciliation?

4. **Order-Dependent Reconciliation**:
   - Why is order important for reconcilers?
   - Can you provide a specific example where wrong order would break things?

5. **Graceful Handling of Partial Failures**:
   - Manager "logs and continues" on instance failures
   - Does this mean some BGP instances could be running while others fail?
   - How is this status communicated back to users?

---

## Part 6: Potential Issues Found

### 1. Documentation Gaps

**Issue**: Limited documentation on StateReconcilers
- **Impact**: Unclear when/how StateReconcilers are used vs. ConfigReconcilers
- **Suggestion**: Add StateReconciler documentation to pkg/bgp/README.md

### 2. Error Handling Visibility

**Issue**: When BGPRouterManager continues after instance failure, error may not be visible to users
- **Impact**: Partial BGP deployment might go unnoticed
- **Suggestion**: Consider adding status conditions to CiliumBGPNodeConfig to surface per-instance errors

### 3. Router ID Allocation Documentation

**Issue**: Router ID allocation mechanism not well documented
- **Impact**: Unclear how to configure or troubleshoot router ID issues
- **Suggestion**: Add section to operator documentation on router ID pool configuration

### 4. GoBGP as Single Implementation

**Issue**: Router interface exists but only GoBGP is implemented
- **Impact**: Tight coupling despite abstraction; may mislead contributors
- **Suggestion**: Either document future plans for other providers or simplify if GoBGP is the only planned implementation

### 5. Testing Complexity

**Issue**: BGP testing requires external routers (ContainerLab setup)
- **Impact**: High barrier to entry for contributors
- **Suggestion**: Consider adding more unit tests with mock Router implementations

---

## Part 7: Strengths of the Architecture

1. **Clear Separation of Concerns**: Operator vs. Agent responsibility split is well-defined
2. **Vendor-Agnostic Design**: Router interface enables future flexibility
3. **Declarative API**: BGPRouterManager provides clean abstraction
4. **Reconciler Pattern**: Modular reconcilers are easy to understand and extend
5. **Multi-ASN Support**: Advanced feature for complex topologies
6. **Well-Structured Code**: Clear package organization and naming

---

## Part 8: Summary for sig-bgp Team

As a new team member, I've explored both BGP packages and believe I have a solid understanding:

**`pkg/bgp`** (Agent-Side):
- Runs BGP protocol speakers (GoBGP) on each node
- Advertises routes to external routers
- Modular reconciler-based architecture
- Provides REST API for querying BGP state

**`operator/pkg/bgp`** (Operator-Side):
- Orchestrates cluster-wide BGP configuration
- Translates CiliumBGPClusterConfig → CiliumBGPNodeConfig
- Manages router ID allocation
- Monitors peer config health

The two-level control plane design is elegant and scalable. I have questions about router ID allocation, state reconcilers, and error handling visibility (see Part 5), and I've noted some documentation gaps (see Part 6).

I'm ready to contribute to sig-bgp and would appreciate guidance on the questions above!

---

## References

- [pkg/bgp/README.md](pkg/bgp/README.md)
- [Documentation/network/bgp-control-plane/](Documentation/network/bgp-control-plane/)
- [Documentation/contributing/development/bgp_cplane.rst](Documentation/contributing/development/bgp_cplane.rst)
- Source code exploration in `pkg/bgp/` and `operator/pkg/bgp/`
