---
title: L1ArbitrumExtendedGateway.sol Spec
id: L1ArbitrumExtendedGateway
---

### `transferExitAndCall(uint256 _exitNum, address _initialDestination, address _newDestination, bytes _newData, bytes _data)` (external)

Allows a user to redirect their right to claim a withdrawal to another address.

This method also allows you to make an arbitrary call after the transfer.
This does not validate if the exit was already triggered. It is assumed the `_exitNum` is
validated off-chain to ensure this was not yet triggered.

- `_exitNum`: Sequentially increasing exit counter determined by the L2 bridge

- `_initialDestination`: address the L2 withdrawal call initially set as the destination.

- `_newDestination`: address the L1 will now call instead of the previously set destination

- `_newData`: data to be used in inboundEscrowAndCall

- `_data`: optional data for external call upon transfering the exit

### `getExternalCall(uint256 _exitNum, address _initialDestination, bytes _initialData) → address target, bytes data` (public)

this does not verify if the external call was already done

### `encodeWithdrawal(uint256 _exitNum, address _initialDestination) → bytes32` (public)

### `WithdrawRedirected(address from, address to, uint256 exitNum, bytes newData, bytes data, bool madeExternalCall)`
