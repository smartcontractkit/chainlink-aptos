# LOOP Architecture: Relayer vs RelayerSet

Understanding the two different gRPC boundaries in the Chainlink LOOP architecture.

## Overview

There are **two separate gRPC boundaries** where chain-specific services (like Aptos) need to be implemented:

1. **Relayer LOOP**: When an individual relayer runs as a separate process
2. **RelayerSet for Capabilities**: When capabilities run as separate processes and need to call back to relayers

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Core Node Process                     │
│                                                              │
│  ┌──────────────┐                                           │
│  │ Relayer Set  │ ◄─────────────────┐                      │
│  │  - EVM       │                    │                      │
│  │  - Solana    │                    │                      │
│  │  - Aptos     │                    │                      │
│  └──────────────┘                    │                      │
│         │                            │                      │
│         │ Embedded Mode              │ LOOP Mode            │
│         ▼                            │                      │
│  ┌──────────────┐             ┌─────┴──────┐              │
│  │ Relayer      │             │ RelayerSet │              │
│  │ Logic        │             │   Server   │              │
│  └──────────────┘             └─────┬──────┘              │
│                                      │                      │
└──────────────────────────────────────┼──────────────────────┘
                                       │ gRPC
                    ┌──────────────────┼──────────────────────┐
                    │                  │                      │
              ┌─────▼──────┐    ┌─────▼──────┐              │
              │ Capability │    │ Capability │              │
              │ Process 1  │    │ Process 2  │              │
              │            │    │            │              │
              │ ┌────────┐ │    │ ┌────────┐ │              │
              │ │Relayer │ │    │ │Relayer │ │              │
              │ │  Set   │ │    │ │  Set   │ │              │
              │ │ Client │ │    │ │ Client │ │              │
              │ └────────┘ │    │ └────────┘ │              │
              └────────────┘    └────────────┘              │
                                                             │
                   Capability Processes (LOOP Mode)         │
                                                             │
└─────────────────────────────────────────────────────────────┘
```

## The Two Packages

### 1. `pkg/loop/internal/relayer/` - Standalone Relayer LOOP

**Location**: `chainlink-common/pkg/loop/internal/relayer/aptos.go`

**Purpose**: Allows a relayer to run as a separate LOOP process (optional feature).

**Process Boundary**: 
```
Core Node ◄──[gRPC]──► Relayer Process (standalone)
```

**When Used**: 
- When environment variable `CL_APTOS_PLUGIN_CMD` is set
- Relayer runs as external binary, not embedded in core node

**Key Components**:

```go
// AptosClient - Used by core node to call standalone relayer
type AptosClient struct {
    grpcClient aptospb.AptosClient
}

func (ac *AptosClient) AccountAPTBalance(ctx context.Context, req aptos.AccountAPTBalanceRequest) (*aptos.AccountAPTBalanceReply, error) {
    // Convert Go types → Proto types
    reply, err := ac.grpcClient.AccountAPTBalance(ctx, &aptospb.AccountAPTBalanceRequest{
        Address: req.Address[:],
    })
    // Convert Proto types → Go types
    return &aptos.AccountAPTBalanceReply{Value: reply.Value}, nil
}

// aptosServer - Used by standalone relayer to receive calls
type aptosServer struct {
    impl types.AptosService // Actual business logic
}

func (s *aptosServer) AccountAPTBalance(ctx context.Context, req *aptospb.AccountAPTBalanceRequest) (*aptospb.AccountAPTBalanceReply, error) {
    // Convert Proto types → Go types
    reply, err := s.impl.AccountAPTBalance(ctx, aptos.AccountAPTBalanceRequest{
        Address: aptos.AccountAddress(req.Address),
    })
    // Convert Go types → Proto types
    return &aptospb.AccountAPTBalanceReply{Value: reply.Value}, nil
}
```

**Call Flow**:
```
Core Node Logic
    → AptosClient (proto conversion)
        → [gRPC over network/pipe]
            → aptosServer (proto conversion)
                → Aptos Business Logic (in separate process)
```

---

### 2. `pkg/loop/internal/relayerset/` - RelayerSet for Capabilities

**Location**: `chainlink-common/pkg/loop/internal/relayerset/aptos.go`

**Purpose**: Allows capability processes to call back to relayers in the core node.

**Process Boundary**:
```
Capability Process ◄──[gRPC]──► Core Node (RelayerSet)
```

**When Used**:
- **Always** when capabilities run in LOOP mode
- Capability needs to call chain-specific functions
- Most common use case

**Key Components**:

```go
// aptosClient - Used by capability to call back to core node
// Adds RelayID to context so server knows which relayer to use
type aptosClient struct {
    relayID types.RelayID  // Which relayer? (e.g., "aptos.mainnet")
    client  aptospb.AptosClient
}

func (ac *aptosClient) AccountAPTBalance(ctx context.Context, in *aptospb.AccountAPTBalanceRequest, opts ...grpc.CallOption) (*aptospb.AccountAPTBalanceReply, error) {
    // Add RelayID to context metadata
    ctx = appendRelayID(ctx, ac.relayID)
    return ac.client.AccountAPTBalance(ctx, in, opts...)
}

// aptosServer - Used by core node to receive calls from capabilities
type aptosServer struct {
    parent *Server  // Has access to RelayerSet
}

func (as *aptosServer) AccountAPTBalance(ctx context.Context, req *aptospb.AccountAPTBalanceRequest) (*aptospb.AccountAPTBalanceReply, error) {
    // Get the AptosService for the specific relayer
    aptosService, err := as.parent.getAptosService(ctx)
    
    // Convert proto → Go types and call business logic
    reply, err := aptosService.AccountAPTBalance(ctx, aptos.AccountAPTBalanceRequest{
        Address: aptos.AccountAddress(req.Address),
    })
    
    // Convert Go types → proto
    return &aptospb.AccountAPTBalanceReply{Value: reply.Value}, nil
}

// Helper to extract RelayID and get the right service
func (s *Server) getAptosService(ctx context.Context) (types.AptosService, error) {
    relayID, err := readContextValue(ctx, metadataRelayID)
    relayer, err := s.impl.Get(ctx, relayID)  // Get specific relayer
    return relayer.Aptos()  // Get its Aptos service
}
```

**Call Flow**:
```
Capability Logic
    → aptosClient.AccountAPTBalance() [adds RelayID to context]
        → [gRPC back to Core Node]
            → RelayerSet Server
                → Extract RelayID from context
                    → Get correct Aptos relayer from RelayerSet
                        → Call Aptos Business Logic
```

---

## Key Differences

| Aspect | `relayer/` (Standalone Relayer) | `relayerset/` (Capability Callbacks) |
|--------|--------------------------------|-------------------------------------|
| **Process Boundary** | Core Node ↔ Relayer Process | Capability Process ↔ Core Node |
| **Direction** | Core calls relayer | Capability calls back to core |
| **RelayID Handling** | Not needed (single relayer) | Critical (multiple relayers) |
| **Client Purpose** | Proto conversion only | Add RelayID + forward call |
| **Server Purpose** | Call business logic directly | Find relayer + call its logic |
| **When Needed** | Optional (relayer LOOP mode) | Required (capability LOOP mode) |
| **Frequency of Use** | Rare (most relayers embedded) | Common (most capabilities LOOPified) |

---

## Context Metadata Pattern

The `relayerset` uses gRPC metadata to pass the `RelayID`:

```go
// Client side: Add RelayID to context
func appendRelayID(ctx context.Context, relayID types.RelayID) context.Context {
    return metadata.AppendToOutgoingContext(ctx, 
        metadataRelayID, relayID.String())
}

// Server side: Extract RelayID from context
func readContextValue(ctx context.Context, key string) (string, error) {
    md, ok := metadata.FromIncomingContext(ctx)
    values := md.Get(key)
    return values[0], nil
}
```

This allows multiple relayers (EVM mainnet, Solana devnet, Aptos testnet, etc.) to share the same gRPC connection, with the server routing calls to the correct relayer based on metadata.

---

## Which Package Do I Need?

### For Most Implementations: Start with `relayerset/`

If you're building a new chain integration (like Aptos), you'll almost certainly need `relayerset/` first because:

1. ✅ Capabilities typically run in LOOP mode
2. ✅ Capabilities need to call chain-specific functions
3. ✅ This is the standard architecture for most chains

### Optional: Add `relayer/` Later

You only need `relayer/` if:

1. You want the relayer itself to run as a separate process
2. You're isolating relayer logic for security/stability
3. You're implementing optional LOOP mode for relayers

**Most chains only implement `relayerset/` initially.**

---

## Implementation Order

### Step 1: Proto + Types (Both packages share these)
1. Create `.proto` file: `pkg/chains/aptos/aptos.proto`
2. Create Go types: `pkg/types/chains/aptos/aptos.go`
3. Add interface: `pkg/types/relayer.go`
4. Run `make generate` to create gRPC stubs

### Step 2: RelayerSet (Required for capabilities)
1. Create `pkg/loop/internal/relayerset/aptos.go`
2. Update `pkg/loop/internal/relayerset/server.go`
3. Update `pkg/loop/internal/relayerset/client.go`
4. Update `pkg/loop/internal/relayerset/relayer.go`
5. Register in `pkg/loop/internal/pb/relayerset/helper.go`

### Step 3: Business Logic
1. Implement actual Aptos service in `chainlink-aptos/`
2. Connect to Aptos SDK/RPC

### Step 4: Relayer LOOP (Optional)
1. Create `pkg/loop/internal/relayer/aptos.go`
2. Create standalone binary in `chainlink-aptos/cmd/`
3. Add environment variable support

---

## Real-World Example

### Capability Calling Aptos

```go
// In capability process (e.g., WriteTarget capability)
func (w *WriteTarget) Execute(ctx context.Context, req capabilities.CapabilityRequest) {
    // Get Aptos service from relayer set
    aptosService, err := w.relayer.Aptos()
    
    // Call method - this goes over gRPC back to core node
    balance, err := aptosService.AccountAPTBalance(ctx, 
        aptos.AccountAPTBalanceRequest{
            Address: accountAddr,
        })
    
    // Use result...
}
```

**What happens under the hood:**

1. `w.relayer.Aptos()` returns an `aptosClient` wrapper
2. `AccountAPTBalance()` call:
   - Adds RelayID ("aptos.mainnet") to context metadata
   - Makes gRPC call back to core node
3. Core node's `aptosServer`:
   - Extracts RelayID from metadata
   - Finds Aptos mainnet relayer in RelayerSet
   - Calls that relayer's `AccountAPTBalance()`
4. Result flows back through gRPC to capability

---

## Summary

- **`relayer/`**: For standalone relayer processes (optional, advanced)
- **`relayerset/`**: For capability-to-relayer calls (required, standard)

**Most implementations only need `relayerset/` initially.**

The key insight: gRPC boundaries can be in different places depending on what's LOOPified:
- If relayers are LOOPified → use `relayer/`
- If capabilities are LOOPified → use `relayerset/` ✅ (most common)

