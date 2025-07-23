# NIP-EE MLS Visualizer

## Overview

The MLS visualizer demonstrates NIP-EE (Nostr MLS Encrypted Events) - a protocol for end-to-end encrypted group messaging on Nostr using the Message Layer Security (MLS) protocol. The visualizer focuses on making the MLS protocol's epoch management, forward secrecy, and group operations visible and understandable.

## Current Status

### ✅ WASM Integration Complete
- **Cleaned up obsolete functions**: Removed deprecated NIP-44 and old MLS functions
- **Fixed BigInt alignment**: Proper 8-byte alignment for epoch values
- **Updated TypeScript definitions**: Matches current WASM exports
- **NIP-EE functions integrated**: `createEncryptedGroupMessage` and `decryptGroupMessage`

### 🚀 Progress Update - Almost There!
- **Group Creation**: Alice can create MLS groups successfully
- **Basic Messaging**: Encrypted messages can be sent
- **Property Consistency**: Fixed `currentExporterSecret` naming issue
- **UI Updates**: Visualizer shows groups, epochs, and messages

### 🚨 Critical Issue - Improper Group Join Flow

**Current (WRONG) Flow:**
1. Alice creates group at epoch 0
2. Bob just copies Alice's group state
3. Both derive different exporter secrets from same state (!)
4. Epoch never advances
5. Decryption fails

**Correct MLS Flow (TO BE IMPLEMENTED):**
1. Alice creates group at epoch 0
2. Alice proposes to add Bob (creates Add proposal)
3. Alice commits the proposal → **epoch advances to 1**
4. Alice creates Welcome message with:
   - Current group state
   - Bob's position in the tree
   - Secrets needed to join
5. Bob processes Welcome message to properly join at epoch 1
6. Both derive the SAME exporter secret from epoch 1 state

## Why This Matters

### MLS Security Properties
- **No State Copying**: You can't just copy someone's group state - that breaks all security guarantees
- **Welcome Messages**: The ONLY way to join an MLS group is through a Welcome message
- **Epoch Advancement**: Adding members MUST advance the epoch for forward secrecy
- **Deterministic Secrets**: Given the same group state, everyone derives the same secrets

### What's Breaking
- Bob is at the wrong epoch (0 instead of 1)
- Bob has stale state (pre-commit instead of post-commit)
- Different states → different exporter secrets → decryption fails
- No actual member addition through MLS protocol

## Implementation Plan

### Phase 1: Fix Member Addition Flow (URGENT)
1. **Implement Proposal UI**
   - Add "Propose Add Member" button for Alice
   - Show pending proposals in UI
   - Add "Commit Proposals" button

2. **Welcome Message Generation**
   - After commit, generate Welcome for Bob
   - Welcome contains everything Bob needs to join
   - Store Welcome in a way Bob can retrieve it

3. **Welcome Processing**
   - Bob processes Welcome instead of copying state
   - Bob joins at the current epoch (1, not 0)
   - Bob derives correct exporter secret

### Phase 2: Verify Correct Operation
1. **Epoch Display**
   - Show current epoch prominently
   - Show when epoch advances
   - Highlight epoch mismatch issues

2. **Secret Verification**
   - Display exporter secrets (for debugging)
   - Verify both parties have same secret
   - Show when secrets differ

3. **Message Flow**
   - Show which epoch messages are from
   - Show decryption success/failure
   - Explain why decryption fails

## Technical Requirements

### WASM Functions Needed
```typescript
// Generate Welcome message after commit
createWelcome(state: Uint8Array, newMemberIndex: number): Uint8Array

// Process Welcome to join group
processWelcome(welcome: Uint8Array, joinerPrivateKey: Uint8Array): {
  state: Uint8Array;
  epoch: bigint;
  memberCount: number;
}
```

### State Management
- Track pending proposals
- Show commit status
- Store Welcome messages for retrieval
- Properly update epoch after commits

## Success Metrics

### Immediate Goals
- ✅ Groups can be created
- ✅ Messages can be encrypted
- ❌ Members join properly through Welcome messages
- ❌ Epoch advances on member addition
- ❌ All members derive same exporter secret
- ❌ Messages decrypt successfully

### Visualization Goals
- 🎯 Clear display of MLS protocol flow
- 🎯 Visual feedback when epoch advances
- 🎯 Show Welcome message creation/processing
- 🎯 Highlight security properties

## Current Blockers

1. **Missing Welcome Message Support**
   - Need WASM exports for Welcome creation/processing
   - May not be implemented in Zig yet

2. **UI Flow Issues**  
   - No UI for proposal/commit flow
   - No way to transfer Welcome to Bob
   - No visual indication of epoch changes

3. **State Synchronization**
   - Bob needs to get Welcome, not copy state
   - Need proper state update after commit
   - Must ensure consistent view of group state

## Next Steps

1. Check if Welcome message functions exist in Zig
2. Add WASM exports for Welcome creation/processing
3. Implement proper proposal/commit UI flow
4. Fix Bob's join to use Welcome messages
5. Verify epoch advancement and secret derivation

The visualizer is close to demonstrating real MLS group messaging - we just need to fix the fundamental issue of how members join groups!