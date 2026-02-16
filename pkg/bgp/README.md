# pkg/bgp - MetalLB Integration for BGP

This package provides BGP functionality for Cilium by integrating with the [MetalLB](https://metallb.universe.tf/) library. It enables Cilium to announce service IPs and pod CIDRs via BGP to external routers.

> **Note**: This is the MetalLB-based BGP integration. For the newer BGP Control Plane, see the main [BGP Control Plane documentation](../../Documentation/network/bgp-control-plane.rst).

## Architecture Overview

The package wraps MetalLB's BGP implementation to integrate with Cilium's Kubernetes event handling. The main components are:

```
┌─────────────────────────────────────────────────────────┐
│                     Kubernetes                          │
│              (Services, Nodes, Endpoints)               │
└────────────────────┬────────────────────────────────────┘
                     │ Watch Events
                     ▼
              ┌──────────────┐
              │   Speaker    │  ← Main orchestrator
              │  (speaker/)  │    Processes K8s events
              └──────┬───────┘    Manages announcement state
                     │
       ┌─────────────┼─────────────┐
       │             │             │
       ▼             ▼             ▼
  ┌────────┐   ┌─────────┐   ┌────────┐
  │ Fence  │   │ Manager │   │MetalLB │
  │        │   │         │   │Library │
  └────────┘   └─────────┘   └────────┘
  Deduplication  IP Allocation  BGP Protocol
  & Ordering     (LoadBalancer) Implementation
```

## Directory Structure

| Directory | Purpose |
|-----------|---------|
| **config/** | MetalLB configuration parsing (YAML/JSON format) |
| **fence/** | Event deduplication and ordering using UUID + revision tracking |
| **k8s/** | Kubernetes client wrapper for MetalLB integration |
| **log/** | Logging wrapper providing consistent log output |
| **manager/** | Service LoadBalancer IP allocation and management |
| **mock/** | Test mocks (both generated and hand-written) |
| **speaker/** | BGP speaker/announcement controller (main entry point) |

## Key Components

### Speaker (`speaker/`)

The speaker is the main orchestrator that:
- Watches Kubernetes resources (Services, Nodes, Endpoints)
- Queues events via workqueue for ordered processing
- Coordinates with Manager for IP allocation
- Drives MetalLB to announce routes via BGP
- Maintains announcement state for each service

**Event Flow**:
```
K8s Event → Queue → Process Handler → Speaker → MetalLB → BGP Announcement
```

### Manager (`manager/`)

Manages LoadBalancer service IP allocation:
- Assigns IPs from configured pools
- Tracks IP usage across services
- Handles IP release on service deletion
- Integrates with MetalLB's IP allocation logic

### Fence (`fence/`)

Prevents stale/out-of-order event processing:
- Each resource has a UUID + revision
- Fence tracks the highest revision seen
- Events with lower revisions are dropped
- Prevents replay attacks and ordering issues

## Important Patterns

### Three-Layer Speaker Architecture

The speaker has three conceptual layers:
1. **MetalLBSpeaker** (exported interface) - Public API for Cilium
2. **metalLBSpeaker** (internal struct) - Wrapper managing state
3. **MetalLB Controller** (upstream) - Actual BGP protocol implementation

This layering allows Cilium to:
- Add Kubernetes-specific event handling
- Maintain additional state beyond MetalLB's model
- Isolate Cilium from MetalLB API changes

### Event Processing

Events are processed asynchronously:
1. Event arrives from K8s watch
2. Queued via `workqueue.TypedRateLimitingInterface`
3. Fence checks if event is stale
4. Handler processes event (allocate IP, update announcement)
5. State synchronized to MetalLB

### Locking Strategy

The speaker uses an embedded `sync.Mutex` to protect:
- Service announcement map
- Concurrent access from event handlers
- State consistency during reconciliation

## Development

### Building

From the repository root:
```bash
make build
```

### Testing

Run unit tests:
```bash
go test ./pkg/bgp/...
```

Run specific package tests:
```bash
go test ./pkg/bgp/speaker -v
go test ./pkg/bgp/fence -v
```

### Key Dependencies

- **MetalLB**: `go.universe.tf/metallb` - Upstream BGP implementation
- **workqueue**: `k8s.io/client-go/util/workqueue` - Event processing queue
- **Kubernetes client-go**: Standard K8s client libraries

## Configuration

Configuration is loaded from MetalLB-compatible ConfigMaps. See `config/` package for parsing details.

Example configuration:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bgp-config
data:
  config: |
    address-pools:
    - name: default
      protocol: bgp
      addresses:
      - 192.168.1.240-192.168.1.250
```

## Integration with Cilium

The BGP package is instantiated by Cilium's daemon and receives events through Cilium's Kubernetes resource watchers. The speaker implements the necessary interfaces to receive service and node updates.

## Troubleshooting

### Check BGP Session Status

Use Cilium CLI:
```bash
cilium bgp peers
```

### Check Announced Routes

```bash
cilium bgp routes
```

### Enable Debug Logging

Set the BGP log level:
```bash
cilium config set debug-verbose bgp
```

## Known Limitations

1. Only supports MetalLB-compatible configuration format
2. Speaker maintains a single shared state for all services
3. Event processing is sequential (not parallelized)
4. Context propagation uses `context.TODO()` in some paths (see ISSUES.md)

## Future Improvements

See [ISSUES.md](./ISSUES.md) for a comprehensive list of identified issues and improvement opportunities.

## References

- [MetalLB Documentation](https://metallb.universe.tf/)
- [Cilium BGP Documentation](../../Documentation/network/bgp.rst)
- [BGP Control Plane](../../Documentation/network/bgp-control-plane.rst) (newer implementation)
