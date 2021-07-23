---
title: ArbOwner.sol Spec
id: ArbOwner
---

### `giveOwnership(address newOwnerAddr)` (external)

### `addToReserveFunds()` (external)

### `setFeesEnabled(bool enabled)` (external)

### `getFeeRecipients() → address, address` (external)

### `setFeeRecipients(address netFeeRecipient, address congestionFeeRecipient)` (external)

### `setFairGasPriceSender(address addr, bool isFairGasPriceSender)` (external)

### `isFairGasPriceSender(address addr) → bool` (external)

### `getAllFairGasPriceSenders() → bytes` (external)

### `setGasAccountingParams(uint256 speedLimitPerBlock, uint256 gasPoolMax, uint256 maxTxGasLimit)` (external)

### `setSecondsPerSend(uint256 blocksPerSend)` (external)

### `setL1GasPriceEstimate(uint256 priceInGwei)` (external)

### `deployContract(bytes constructorData, address deemedSender, uint256 deemedNonce) → address` (external)

### `startCodeUpload()` (external)

### `continueCodeUpload(bytes marshalledCode)` (external)

### `getUploadedCodeHash() → bytes32` (external)

### `finishCodeUploadAsPluggable(uint256 id, bool keepState)` (external)

### `finishCodeUploadAsArbosUpgrade(bytes32 newCodeHash, bytes32 oldCodeHash)` (external)

### `bindAddressToPluggable(address addr, uint256 pluggableId)` (external)

### `allowAllSenders()` (external)

### `allowOnlyOwnerToSend()` (external)

### `isAllowedSender(address addr) → bool` (external)

### `addAllowedSender(address addr)` (external)

### `removeAllowedSender(address addr)` (external)

### `getAllAllowedSenders() → bytes` (external)

### `getTotalOfEthBalances() → uint256` (external)
