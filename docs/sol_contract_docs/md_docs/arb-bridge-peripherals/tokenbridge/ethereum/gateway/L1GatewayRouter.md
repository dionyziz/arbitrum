---
title: L1GatewayRouter.sol Spec
id: L1GatewayRouter
---

Handles deposits from Erhereum into Arbitrum. Tokens are routered to their appropriate L1 gateway (Router itself also conforms to the Gateway itnerface).

Router also serves as an L1-L2 token address oracle.

### `onlyOwner()`

### `initialize(address _owner, address _defaultGateway, address _whitelist, address _counterpartGateway, address _inbox)` (public)

### `setDefaultGateway(address newL1DefaultGateway, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSubmissionCost) → uint256` (external)

### `setOwner(address newOwner)` (external)

### `setGateway(address _gateway, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSubmissionCost) → uint256` (external)

Allows L1 Token contract to trustlessly register its gateway. (other setGateway method allows excess eth recovery from \_maxSubmissionCost and is recommended)

- `_gateway`: l1 gateway address

- `_maxGas`: max gas for L2 retryable exrecution

- `_gasPriceBid`: gas price for L2 retryable ticket

- `_maxSubmissionCost`: base submission cost L2 retryable tick3et

**Returns**: Retryable: ticket ID

### `setGateway(address _gateway, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSubmissionCost, address _creditBackAddress) → uint256` (public)

Allows L1 Token contract to trustlessly register its gateway.

- `_gateway`: l1 gateway address

- `_maxGas`: max gas for L2 retryable exrecution

- `_gasPriceBid`: gas price for L2 retryable ticket

- `_maxSubmissionCost`: base submission cost L2 retryable tick3et

- `_creditBackAddress`: address for crediting back overpayment of \_maxSubmissionCost

**Returns**: Retryable: ticket ID

### `setGateways(address[] _token, address[] _gateway, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSubmissionCost) → uint256` (external)

### `outboundTransfer(address _token, address _to, uint256 _amount, uint256 _maxGas, uint256 _gasPriceBid, bytes _data) → bytes` (public)
