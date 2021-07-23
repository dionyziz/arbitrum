---
title: SequencerInbox.sol Spec
id: SequencerInbox
---

### `initialize(contract IBridge _delayedInbox, address _sequencer, address _rollup)` (external)

### `setSequencer(address newSequencer)` (external)

### `setMaxDelayBlocks(uint256 newMaxDelayBlocks)` (external)

### `setMaxDelaySeconds(uint256 newMaxDelaySeconds)` (external)

### `forceInclusion(uint256 _totalDelayedMessagesRead, uint8 kind, uint256[2] l1BlockAndTimestamp, uint256 inboxSeqNum, uint256 gasPriceL1, address sender, bytes32 messageDataHash, bytes32 delayedAcc)` (external)

Move messages from the delayed inbox into the Sequencer inbox. Callable by any address. Necessary iff Sequencer hasn't included them before delay period expired.

### `addSequencerL2BatchFromOrigin(bytes transactions, uint256[] lengths, uint256[] sectionsMetadata, bytes32 afterAcc)` (external)

### `addSequencerL2Batch(bytes transactions, uint256[] lengths, uint256[] sectionsMetadata, bytes32 afterAcc)` (external)

Sequencer adds a batch to inbox.

sectionsMetadata lets the sequencer delineate new l1Block numbers and l1Timestamps within a given batch; this lets the sequencer minimize the number of batches created (and thus amortizing cost) while still giving timely receipts

- `transactions`: concatenated bytes of L2 messages

- `lengths`: length of each txn in transctions (for parsing)

- `sectionsMetadata`: Each consists of [numItems, l1BlockNumber, l1Timestamp, newTotalDelayedMessagesRead, newDelayedAcc]

- `afterAcc`: Expected inbox hash after batch is added

### `proveInboxContainsMessage(bytes proof, uint256 _messageCount) → uint256, bytes32` (external)

Show that given messageCount falls inside of some batch and prove/return inboxAcc state. This is used to ensure that the creation of new nodes are replay protected to the state of the inbox, thereby ensuring their validity/invalidy can't be modified upon reorging the inbox contents.

(wrapper in leiu of proveBatchContainsSequenceNumber for sementics)

**Returns**: message: count at end of target batch, inbox hash as of target batch)

### `proveBatchContainsSequenceNumber(bytes proof, uint256 _messageCount) → uint256, bytes32` (external)

### `getInboxAccsLength() → uint256` (external)
