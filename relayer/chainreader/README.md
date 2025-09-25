# ChainReader Module

## Overview

The ChainReader module is responsible for reading on-chain data from the Aptos blockchain. It provides a standardized interface to query smart contract states, read function outputs, and track events. The module acts as a bridge between Chainlink's off-chain infrastructure and Aptos smart contracts.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ChainReader   │───▶│   LogPoller     │───▶│   Database      │
│                 │    │                 │    │   (Events &     │
│  - Module Mgmt  │    │  - Event Sync   │    │   Transactions) │
│  - Data Query   │    │  - TX Sync      │    │                 │
│  - Address Bind │    │  - Caching      │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Aptos Client   │    │   Config Mgmt   │    │   Event Cache   │
│                 │    │                 │    │                 │
│  - RPC Calls    │    │  - Module Cfg   │    │  - Resource     │
│  - State Query  │    │  - Event Cfg    │    │  - Block        │
│  - TX Query     │    │  - Function Cfg │    │  - Address      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Key Components

### 1. AptosChainReader

The main entry point that implements the `ContractReader` interface. It manages:
- **Module Address Binding**: Maps contract names to their Aptos addresses
- **Configuration Management**: Handles module and event configurations
- **Data Querying**: Provides methods to read on-chain state and events
- **Lifecycle Management**: Start/stop operations and health reporting

Key methods:
- `GetLatestValue()`: Reads current state from smart contracts
- `QueryKey()`: Queries historical events with filtering
- `Bind()/Unbind()`: Manages contract address bindings

### 2. LogPoller (Event & Transaction Synchronization)

The LogPoller is the engine that keeps the local database synchronized with on-chain events and transactions:

#### Event Polling (`event_poller.go`)
- **Periodic Sync**: Runs on configurable intervals to sync events
- **Module Registration**: Tracks which modules and events to monitor
- **Incremental Updates**: Only syncs new events since last sync
- **Error Handling**: Robust error handling with retry mechanisms

#### Transaction Polling (`tx_poller.go`)
- **Transaction Tracking**: Monitors specific transactions (e.g., CCIP executions)
- **State Verification**: Tracks transaction execution states

##### CCIP Transaction Polling & Synthetic Event Generation

Due to Aptos lacking a try/catch mechanism, the transaction poller implements a failure detection and synthetic event generation system for CCIP transactions.

**Problem**: When CCIP execution transactions fail on Aptos, there's no automatic event emission indicating the failure. This makes it difficult for the off-chain system to track failed message executions.

**Solution**: The transaction poller monitors transmitter accounts for failed transactions and generates synthetic `ExecutionStateChanged` events to maintain consistency with successful executions that emit real events.

**Process**:
- **Monitor Transmitters**: Track all transactions from known transmitter accounts
- **Detect Failures**: Filter for failed offramp execute function calls
- **Extract Message Data**: Parse execution reports and message details from transaction arguments
- **Generate Events**: Create synthetic ExecutionStateChanged events with failure state
- **Database Storage**: Store synthetic events alongside real events with distinguishing offset values

This approach ensures failed executions are properly tracked and can be queried through the same interface as successful executions.

### 3. Database Layer (`db/db.go`)

Provides persistent storage for events and transactions:

#### Event Storage
```sql
CREATE TABLE aptos.events (
    event_account_address TEXT,
    event_handle TEXT,
    event_field_name TEXT,
    event_offset BIGINT,
    tx_version BIGINT,
    block_height TEXT,
    block_hash BYTEA,
    block_timestamp BIGINT,
    data JSONB
);
```

#### Key Operations
- `InsertEvents()`: Batch insert events with conflict resolution
- `QueryEvents()`: Query events with filtering and pagination

### 4. Configuration System (`config/config.go`)

Defines the structure for:
- **Module Configuration**: Contract addresses, function definitions
- **Event Configuration**: Event handles, field mappings, address resolution
- **Function Parameters**: Type definitions and validation
- **Field Renaming**: Support for field name transformations

### 5. LOOP Reader (`loop/loop_reader.go`)

The LOOP Reader is a specialized wrapper that addresses the limitations of interacting with ChainReader over LOOP gRPC.

#### Purpose & Problem Solved

**Challenge**: The standard ChainReader interface assumes direct in-process communication, but LOOP plugins run in separate processes and communicate via gRPC. This creates issues with serialization and type safety across process boundaries.

**Solution**: The LOOP Reader acts as a translation layer that handles the complexities of cross-process communication while maintaining the familiar ChainReader interface.

#### Key Features

**Automatic Re-binding**: Maintains a cache of module addresses and automatically re-binds contracts before each operation to handle plugin restarts gracefully.

**Serialization Bridge**: Handles the serialization process:
- **Request Path**: Go structs → JSON → byte arrays for gRPC transmission
- **Response Path**: Byte arrays → JSON parsing → Aptos-specific deserialization → Go types
- **Type Preservation**: Uses Aptos codec for proper type conversion

**Query Expression Serialization**: Recursively converts complex query filters with nested expressions to formats suitable for cross-process transmission while maintaining type safety.

**Type-Safe Response Decoding**: Converts JSON responses back to expected Go types, handling different data structures while maintaining compatibility with the existing ChainReader interface.

## Data Flow

### Event Synchronization Flow

1. **Registration Phase**
   ```
   ChainReader → LogPoller.RegisterModule()
   ├─ Store module info (address, events, ref count)
   └─ Start event polling if first registration
   ```

2. **Polling Phase**
   ```
   Timer Trigger → SyncAllEvents()
   ├─ For each registered module
   │  ├─ Query Aptos RPC for new events
   │  ├─ Parse and validate event data
   │  └─ Store in database
   └─ Update sync checkpoints
   ```

3. **Query Phase**
   ```
   ChainReader.QueryKey() → Database Query
   ├─ Apply filters and sorting
   ├─ Transform field names
   └─ Return structured results
   ```

### State Reading Flow

1. **Function Call Resolution**
   ```
   GetLatestValue() → Parse Read Identifier
   ├─ Extract: address, contract, method
   ├─ Validate bound address
   └─ Get function configuration
   ```

2. **Parameter Processing**
   ```
   Process Parameters → Aptos RPC Call
   ├─ Convert parameter types
   ├─ Serialize for BCS encoding
   └─ Call view function
   ```

3. **Result Processing**
   ```
   RPC Response → Transform Results
   ├─ Apply field renames
   ├─ Handle struct unwrapping
   └─ Return typed result
   ```

## Caching Strategy

The ChainReader implements multi-layer caching:

### Resource Cache
- **Purpose**: Cache smart contract resource data
- **TTL**: 15 minutes
- **Use Case**: Reduces RPC calls for frequently accessed state

### Block Cache
- **Purpose**: Cache block information
- **TTL**: 15 minutes  
- **Use Case**: Avoid re-fetching block metadata

### Event Address Cache
- **Purpose**: Cache resolved event account addresses
- **TTL**: 15 minutes
- **Use Case**: Avoid re-computing dynamic event addresses

## Metrics

The ChainReader system exposes several Prometheus metrics to monitor performance, reliability, and data flow across its components. These metrics track RPC latency, event ingestion, query performance, dataset sizes, and account balances.

### Exposed Metrics

- **aptos_account_balance**  
  *Type*: GaugeVec  
  *Labels*: `chainFamily`, `chainID`, `networkName`, `account`  
  *Description*: Tracks the balance of Aptos accounts.

- **aptos_rpc_call_latency**  
  *Type*: HistogramVec  
  *Labels*: `chainFamily`, `chainID`, `networkName`, `rpcUrl`, `success`, `rpcCallName`  
  *Description*: Measures the duration of Aptos RPC calls in milliseconds, labeled by chain info, RPC endpoint, call name, and success status.

- **aptos_log_poller_events_inserted**  
  *Type*: CounterVec  
  *Labels*: `chainFamily`, `chainID`, `networkName`, `event`, `isSynthetic`  
  *Description*: Counts the number of events inserted by LogPoller, distinguishing between real and synthetic events.

- **aptos_cr_query_duration**  
  *Type*: HistogramVec  
  *Labels*: `chainFamily`, `chainID`, `networkName`, `query`, `event`  
  *Description*: Tracks the duration of ChainReader queries fetching events from the database.

- **aptos_cr_query_dataset_size**  
  *Type*: GaugeVec  
  *Labels*: `chainFamily`, `chainID`, `networkName`, `query`, `event`  
  *Description*: Records the size of datasets returned by ChainReader queries.


