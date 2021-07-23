---
title: Rollup.sol Spec
id: Rollup
---

### `constructor(uint256 _confirmPeriodBlocks)` (public)

### `initialize(bytes32 _machineHash, uint256[4] _rollupParams, address _stakeToken, address _owner, bytes _extraConfig, address[6] connectedContracts, address[2] _facets, uint256[2] sequencerInboxParams)` (public)

### `postUpgradeInit(address newAdminFacet)` (external)

### `getFacets() → address, address` (external)

This contract uses a dispatch pattern from EIP-2535: Diamonds
together with Open Zeppelin's proxy

### `getAdminFacet() → address` (public)

### `getUserFacet() → address` (public)
