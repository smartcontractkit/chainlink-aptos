[//]: # (Documentation generated from docs.toml - DO NOT EDIT.)

This document describes the TOML format for configuration.
## Example

```toml
ChainID = "4"

[[Aptos.Nodes]]
Name = 'primary'
URL = "http://chainlink-aptos.devnet:8080/v1"
```

## Global
```toml
Enabled = true # Default
ChainID = 'TODO' # Example
NetworkName = 'TODO' # Example
NetworkNameFull = 'TODO' # Example
```


### Enabled
```toml
Enabled = true # Default
```
Enabled TODO

### ChainID
```toml
ChainID = 'TODO' # Example
```
ChainID TODO

### NetworkName
```toml
NetworkName = 'TODO' # Example
```
NetworkName TODO

### NetworkNameFull
```toml
NetworkNameFull = 'TODO' # Example
```
NetworkNameFull TODO

## TransactionManager
```toml
[TransactionManager]
BroadcastChanSize = 100 # Default
ConfirmPoll = '2s' # Default
ConfirmPollSecs = 1 # Example
DefaultMaxGasAmount = 200000 # Default
MaxSimulateAttempts = 5 # Default
MaxSubmitRetryAttempts = 10 # Default
SubmitDelayDuration = '3s'  # Default
TxExpiration = '10s'  # Default
TxExpirationSecs = 360 # Example
MaxTxRetryAttempts = 5  # Default
PruneInterval = '4h'  # Default
PruneIntervalSecs = 1 # Example
PruneTxExpiration = '2h'  # Default
PruneTxExpirationSecs = 42 # Example
```


### BroadcastChanSize
```toml
BroadcastChanSize = 100 # Default
```
BroadcastChanSize TODO

### ConfirmPoll
```toml
ConfirmPoll = '2s' # Default
```
ConfirmPoll TODO

### ConfirmPollSecs
```toml
ConfirmPollSecs = 1 # Example
```
ConfirmPollSecs is deprecated. Use ConfirmPoll instead.

### DefaultMaxGasAmount
```toml
DefaultMaxGasAmount = 200000 # Default
```
DefaultMaxGasAmount TODO
https://github.com/aptos-labs/aptos-ts-sdk/blob/32d4360740392782c1368647f89ba62e1b6a2cb3/src/utils/const.ts#L21

### MaxSimulateAttempts
```toml
MaxSimulateAttempts = 5 # Default
```
MaxSimulateAttempts TODO

### MaxSubmitRetryAttempts
```toml
MaxSubmitRetryAttempts = 10 # Default
```
MaxSubmitRetryAttempts TODO

### SubmitDelayDuration
```toml
SubmitDelayDuration = '3s'  # Default
```
SubmitDelayDuration TODO

### TxExpiration
```toml
TxExpiration = '10s'  # Default
```
TxExpiration TODO

### TxExpirationSecs
```toml
TxExpirationSecs = 360 # Example
```
TxExpirationSecs is deprecated. Use TxExpiration instead.

### MaxTxRetryAttempts
```toml
MaxTxRetryAttempts = 5  # Default
```
MaxTxRetryAttempts TODO

### PruneInterval
```toml
PruneInterval = '4h'  # Default
```
PruneInterval TODO

### PruneIntervalSecs
```toml
PruneIntervalSecs = 1 # Example
```
PruneIntervalSecs is deprecated. Use PruneInterval instead.

### PruneTxExpiration
```toml
PruneTxExpiration = '2h'  # Default
```
PruneTxExpiration TODO

### PruneTxExpirationSecs
```toml
PruneTxExpirationSecs = 42 # Example
```
PruneTxExpirationSecs is deprecated. Use PruneTxExpiration instead.

## LogPoller
```toml
[LogPoller]
EventPollingInterval = '12s' # Default
TxPollingInterval = '12s' # Default
PollTimeout = '10s' # Default
EventBatchSize = 100 # Default
TxBatchSize = 100 # Default
TXPollerDisabled = false # Default
```


### EventPollingInterval
```toml
EventPollingInterval = '12s' # Default
```
EventPollingInterval TODO

### TxPollingInterval
```toml
TxPollingInterval = '12s' # Default
```
TxPollingInterval TODO

### PollTimeout
```toml
PollTimeout = '10s' # Default
```
PollTimeout TODO

### EventBatchSize
```toml
EventBatchSize = 100 # Default
```
EventBatchSize TODO

### TxBatchSize
```toml
TxBatchSize = 100 # Default
```
TxBatchSize TODO

### TXPollerDisabled
```toml
TXPollerDisabled = false # Default
```
TXPollerDisabled TODO

## BalanceMonitor
```toml
[BalanceMonitor]
BalancePollPeriod = '10s' # Default
```


### BalancePollPeriod
```toml
BalancePollPeriod = '10s' # Default
```
BalancePollPeriod TODO

## WriteTargetCap
```toml
[WriteTargetCap]
ConfirmerPollPeriod = '1s' # Default
ConfirmerTimeout = '10s' # Default
```


### ConfirmerPollPeriod
```toml
ConfirmerPollPeriod = '1s' # Default
```
ConfirmerPollPeriod TODO

### ConfirmerTimeout
```toml
ConfirmerTimeout = '10s' # Default
```
ConfirmerTimeout TODO

## Workflow
```toml
[Workflow]
ForwarderAddress = 'TODO' # Example
PublicKey = 'TODO' # Example
```


### ForwarderAddress
```toml
ForwarderAddress = 'TODO' # Example
```
ForwarderAddress TODO

### PublicKey
```toml
PublicKey = 'TODO' # Example
```
PublicKey TODO

## Nodes
```toml
[[Nodes]]
Name = 'TODO' # Example
URL = '' # Example
```


### Name
```toml
Name = 'TODO' # Example
```
Name TODO

### URL
```toml
URL = '' # Example
```
URL TODO

