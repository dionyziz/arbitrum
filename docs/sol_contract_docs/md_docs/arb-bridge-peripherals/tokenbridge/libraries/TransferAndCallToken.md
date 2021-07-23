---
title: TransferAndCallToken.sol Spec
id: TransferAndCallToken
---

based on Implementation from https://github.com/smartcontractkit/LinkToken/blob/master/contracts/v0.6/ERC677Token.sol
Implementation doesn't return a bool on onTokenTransfer, and so doesn't adhere to the proposed 677 standard, thus, tho it's similar to ERC677, we don't refer to it as such.

### `transferAndCall(address _to, uint256 _value, bytes _data) → bool success` (public)

transfer token to a contract address with additional data if the recipient is a contact.

- `_to`: The address to transfer to.

- `_value`: The amount to be transferred.

- `_data`: The extra data to be passed to the receiving contract.
