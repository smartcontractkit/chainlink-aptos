# ChainWriter Module

## Overview

The ChainWriter module handles transaction execution on the Aptos blockchain. It provides a standardized interface for submitting transactions, managing transaction lifecycle, and handling fee estimation. The module acts as the write interface between Chainlink's off-chain infrastructure and Aptos smart contracts.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ChainWriter   │───▶│  Transaction    │───▶│  Aptos Client   │
│                 │    │   Manager       │    │                 │
│  - TX Submit    │    │   (TXM)         │    │  - RPC Calls    │
│  - Gas Calc     │    │                 │    │  - State Query  │
│  - Status Track │    │  - TX Queue     │    │  - Broadcast    │
└─────────────────┘    │  - TX Store     │    └─────────────────┘
         │             │  - Broadcast    │             │
         │             │  - Confirm      │             │
         ▼             └─────────────────┘             ▼
┌─────────────────┐              │            ┌─────────────────┐
│   Config Mgmt   │              │            │   Blockchain    │
│                 │              ▼            └─────────────────┘
│  - Module Cfg   │    ┌─────────────────┐       
│  - Function Cfg │    │  Account Store  │
│  - Gas Strategy │    │                 │
└─────────────────┘    │  - Key Mgmt     │
                       │  - Nonce Track  │
                       │  - Signing      │
                       └─────────────────┘
```

## Key Components

### 1. AptosChainWriter

The main entry point that implements the `ContractWriter` interface:

#### Core Responsibilities
- **Transaction Submission**: Converts high-level calls to Aptos transactions
- **Parameter Conversion**: Handles type conversion and BCS encoding
- **Gas Management**: Calculates and manages transaction gas limits
- **Status Tracking**: Monitors transaction execution status

#### Key Methods
- `SubmitTransaction()`: Main entry point for transaction submission
- `GetTransactionStatus()`: Query transaction execution status
- `GetTransactionFee()`: Retrieve actual transaction fees
- `GetFeeComponents()`: Estimate gas fees for transactions

### 2. Transaction Manager (TXM)

The Transaction Manager is the core engine responsible for transaction lifecycle management. It maintains transaction queues, handles signing, broadcasting, and confirmation tracking.

#### Core TXM Processes

**Enqueue Process**: Validates parameters, converts function arguments to BCS format, creates transaction instances, and adds them to the broadcast queue.

**Broadcast Loop**: Continuously processes the transaction queue by loading account information, building transaction payloads, signing transactions, and submitting them to the Aptos network.

**Confirmation Loop**: Periodically checks transaction status on-chain, updates local transaction states, handles confirmations and failures, and performs cleanup of completed transactions.

## Transaction Flow

### 1. Transaction Submission Flow

**Contract & Method Resolution**: Extract contract address, module name, and function name from the request, then validate against the configuration.

**Parameter Processing**: Convert arguments using mapstructure, apply type conversions, and handle default values for optional parameters.

**Transaction Enqueuing**: Create transaction ID, validate public key and address, convert parameters to BCS format, and add to broadcast queue.

### 2. Transaction Broadcasting Flow

**Enqueue Transaction**: Retrieve transaction from broadcast channel and load account information including nonce and authentication keys.

**Build Transaction**: Create EntryFunctionPayload with gas parameters, apply sequence number, and prepare transaction for signing.

**Sign Transaction**: Create raw transaction, sign with private key, and create signed transaction ready for network submission.

**Network Submission**: Send to Aptos RPC, handle immediate errors, update transaction status, and schedule for confirmation tracking.

### 3. Transaction Confirmation Flow

**Query Pending Transactions**: Filter transactions by status and sort by submission time for processing order.

**Check Network Status**: Query transaction by hash, check for confirmation, and handle network errors gracefully.

**Update Transaction State**: Mark confirmed transactions as successful, handle failures with appropriate error states, manage timeouts with retry logic, and log all state changes.

**Cleanup**: Remove old successful transactions, archive failed transactions, and update performance metrics.

## Gas Limit Management

### General Gas Handling

Gas limits in Aptos transactions are handled through a multi-tiered approach:

**Transaction Simulation**: The TXM can optionally simulate transactions before submission to estimate actual gas usage, applying a safety multiplier to ensure successful execution.

**Metadata Override**: Gas limits can be explicitly set through transaction metadata, giving callers direct control when needed.

**Default Fallback**: When no specific gas limit is provided and simulation is disabled, the system uses configurable default values.

**Dynamic Pricing**: Gas prices are determined through RPC estimation, with priority pricing available for retry attempts.

### CCIP-Specific Gas Limit Handling

For CCIP execute transactions, special gas limit calculation is performed:

**Overhead Addition**: A baseline execution overhead is added to ensure the transaction can be attempted on-chain even with receiver gas estimation uncertainties.

**Token Transfer Gas**: Additional gas is allocated for each token transfer in the message, accounting for the destination gas requirements.

**Report Parsing**: The system extracts gas requirements from execution reports embedded in transaction parameters to calculate total needed gas.

This specialized handling ensures CCIP cross-chain messages have adequate gas allocation for successful execution.

## Account Management

### Account Store
The TXM maintains an `AccountStore` that manages:
- **Account Information**: Sequence numbers, authentication keys
- **Key Management**: Public/private key pairs for signing
- **Nonce Tracking**: Prevents duplicate sequence numbers
- **Multisig Support**: Handles multi-signature account operations

### Key Management Flow

**Account Resolution**: Resolve public key to account address, check for authentication key rotation, load current sequence number, and prepare for signing operations.

## In-Memory Storage & Transaction Management

### Storage Architecture

The ChainWriter operates entirely in-memory without persistent storage. All transaction state is maintained in concurrent-safe maps during the transaction lifecycle.

### Transaction Lifecycle Management

**In-Memory Transaction Store**: Pending transactions are stored in memory and tracked from submission through final confirmation.

**Automatic Pruning**: The system implements automatic cleanup of completed transactions:
- **Trigger Conditions**: Pruning occurs periodically based on configurable intervals
- **Retention Policy**: Transactions are eligible for removal after reaching final states (Finalized, Failed, Fatal) and exceeding the configured expiration time

**Restart Behavior**: When the service restarts, all in-memory transaction state is lost. Active transactions must be resubmitted by callers if needed.


## Error Handling & Resilience

### Transaction Error States

The system tracks transactions through various states: Unknown, Queued, Broadcast, ConfirmationPending, Confirmed, and Failed. Each state represents a specific point in the transaction lifecycle and determines appropriate handling actions.

### Error Recovery Mechanisms

1. **Network Failures**
   - Automatic retry with exponential backoff
   - Circuit breaker for persistent failures
   - Graceful degradation of service

2. **Transaction Failures**
   - Detailed error classification
   - Automatic replay for temporary failures
   - Manual intervention for permanent failures

3. **Account Issues**
   - Sequence number synchronization
   - Authentication key validation
   - Balance and permission checks

## Configuration

The ChainWriter is configured through module definitions that specify contract addresses, function mappings, signing keys, and parameter schemas. Each module can define multiple functions with their respective parameter types, requirements, and default values. The configuration supports both simple module mappings and complex parameter validation with type safety.
