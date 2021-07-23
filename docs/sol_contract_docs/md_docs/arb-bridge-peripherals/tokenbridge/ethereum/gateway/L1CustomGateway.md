---
title: L1CustomGateway.sol Spec
id: L1CustomGateway
---

Gatway for "custom" bridging functionality

Handles some (but not all!) custom Gateway needs.

### `onlyWhitelisted()`

### `updateWhitelistSource(address newSource)` (external)

### `initialize(address _l1Counterpart, address _l1Router, address _inbox, address _owner)` (public)

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

### `registerTokenToL2(address _l2Address, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSubmissionCost) → uint256` (external)

Allows L1 Token contract to trustlessly register its custom L2 counterpart. (other registerTokenToL2 method allows excess eth recovery from \_maxSubmissionCost and is recommended)

- `_l2Address`: counterpart address of L1 token

- `_maxGas`: max gas for L2 retryable exrecution

- `_gasPriceBid`: gas price for L2 retryable ticket

- `_maxSubmissionCost`: base submission cost L2 retryable tick3et

**Returns**: Retryable: ticket ID

### `registerTokenToL2(address _l2Address, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSubmissionCost, address _creditBackAddress) → uint256` (public)

Allows L1 Token contract to trustlessly register its custom L2 counterpart.

- `_l2Address`: counterpart address of L1 token

- `_maxGas`: max gas for L2 retryable exrecution

- `_gasPriceBid`: gas price for L2 retryable ticket

- `_maxSubmissionCost`: base submission cost L2 retryable tick3et

- `_creditBackAddress`: address for crediting back overpayment of \_maxSubmissionCost

**Returns**: Retryable: ticket ID

### `forceRegisterTokenToL2(address[] _l1Addresses, address[] _l2Addresses, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSubmissionCost) → uint256` (external)

Allows owner to force register a custom L1/L2 token pair.

\_l1Addresses[i] counterpart is assumed to be \_l2Addresses[i]

- `_l1Addresses`: array of L1 addresses

- `_l2Addresses`: array of L2 addresses

- `_maxGas`: max gas for L2 retryable exrecution

- `_gasPriceBid`: gas price for L2 retryable ticket

- `_maxSubmissionCost`: base submission cost L2 retryable tick3et

**Returns**: Retryable: ticket ID

### `WhitelistSourceUpdated(address newSource)`
