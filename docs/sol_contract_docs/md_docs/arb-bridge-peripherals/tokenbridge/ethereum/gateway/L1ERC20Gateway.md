---
title: L1ERC20Gateway.sol Spec
id: L1ERC20Gateway
---

Layer 1 Gateway contract for bridging standard ERC20s

This contract handles token deposits, holds the escrowed tokens on layer 1, and (ultimately) finalizes withdrawals.

Any ERC20 that requires non-standard functionality should use a separate gateway.
Messages to layer 2 use the inbox's createRetryableTicket method.

### `onlyWhitelisted()`

### `updateWhitelistSource(address newSource)` (external)

### `initialize(address _l2Counterpart, address _router, address _inbox, bytes32 _cloneableProxyHash, address _l2BeaconProxyFactory)` (public)

### `postUpgradeInit()` (external)

### `outboundTransfer(address _l1Token, address _to, uint256 _amount, uint256 _maxGas, uint256 _gasPriceBid, bytes _data) → bytes` (public)

Deposit ERC20 token from Ethereum into Arbitrum. If L2 side hasn't been deployed yet, includes name/symbol/decimals data for initial L2 deploy. Initiate by GatewayRouter.

- `_l1Token`: L1 address of ERC20

- `_to`: account to be credited with the tokens in the L2 (can be the user's L2 account or a contract)

- `_amount`: Token Amount

- `_maxGas`: Max gas deducted from user's L2 balance to cover L2 execution

- `_gasPriceBid`: Gas price for L2 execution

- `_data`: encoded data from router and user

**Returns**: res: abi encoded inbox sequence number

### `getOutboundCalldata(address _token, address _from, address _to, uint256 _amount, bytes _data) → bytes outboundCalldata` (public)

### `WhitelistSourceUpdated(address newSource)`
