import { readFileSync } from 'fs';
import { resolve } from 'path';

// Load WASM module - use the same file as the visualizer
const wasmPath = resolve(__dirname, '../visualizer/src/nostr_mls.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Define WASM imports
const imports = {
    env: {
        getRandomValues: (ptr: number, len: number) => {
            const bytes = new Uint8Array(exports.memory.buffer, ptr, len);
            crypto.getRandomValues(bytes);
            console.log('Generated random bytes:', len);
        },
        wasm_log_error: (strPtr: number, len: number) => {
            const bytes = new Uint8Array(exports.memory.buffer, strPtr, len);
            const message = new TextDecoder().decode(bytes);
            console.error('🔴 WASM error:', message);
        },
        getCurrentTimestamp: () => BigInt(Math.floor(Date.now() / 1000))
    }
};

// Instantiate WASM
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const exports = wasmInstance.exports as any;

// Initialize WASM
if (exports.wasm_init) {
    exports.wasm_init();
}

// Check if MLS functions are available
console.log('Available MLS exports:', Object.keys(exports).filter(name => name.includes('mls')));

// Helper functions
function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// Memory alignment helpers (from WASM.md)
function ensureAlignment(ptr: number, alignment: number): number {
    const mask = alignment - 1;
    return (ptr + mask) & ~mask;
}

function allocateAlignedU32(): { ptr: number; alignedPtr: number; view: Uint32Array } {
    const ptr = exports.wasm_alloc(8); // Allocate extra for alignment
    const alignedPtr = ensureAlignment(ptr, 4);
    const view = new Uint32Array(exports.memory.buffer, alignedPtr, 1);
    return { ptr, alignedPtr, view };
}

function allocateAlignedU64(): { ptr: number; alignedPtr: number; view: BigUint64Array } {
    const ptr = exports.wasm_alloc(16); // Allocate extra for alignment
    const alignedPtr = ensureAlignment(ptr, 8);
    const view = new BigUint64Array(exports.memory.buffer, alignedPtr, 1);
    return { ptr, alignedPtr, view };
}

function freeAligned(allocation: { ptr: number }): void {
    exports.wasm_free(allocation.ptr, 8);
}

// Test functions
async function testStateInitialization() {
    console.log('\n🎯 Testing State Machine Initialization');
    
    // Create a group ID
    const groupId = crypto.getRandomValues(new Uint8Array(32));
    console.log('Group ID:', bytesToHex(groupId));
    
    // Create creator identity
    const creatorPrivateKeyPtr = exports.wasm_alloc(32);
    const creatorPublicKeyPtr = exports.wasm_alloc(32);
    
    const identitySuccess = exports.wasm_create_identity(creatorPrivateKeyPtr, creatorPublicKeyPtr);
    if (!identitySuccess) {
        console.error('❌ Failed to create identity');
        return false;
    }
    
    const creatorPrivateKey = new Uint8Array(exports.memory.buffer, creatorPrivateKeyPtr, 32);
    const creatorPublicKey = new Uint8Array(exports.memory.buffer, creatorPublicKeyPtr, 32);
    console.log('Creator public key:', bytesToHex(creatorPublicKey));
    
    // Allocate space for group ID and keys
    const groupIdPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, groupIdPtr, 32).set(groupId);
    
    const identityPubkeyPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, identityPubkeyPtr, 32).set(creatorPublicKey);
    
    const signingKeyPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, signingKeyPtr, 32).set(creatorPrivateKey);
    
    // Allocate output buffer for state
    const maxStateSize = 10240; // 10KB should be enough
    const outStatePtr = exports.wasm_alloc(maxStateSize);
    const outStateLenAlloc = allocateAlignedU32();
    outStateLenAlloc.view[0] = maxStateSize;
    
    // Initialize group using REAL MLS
    const success = exports.wasm_mls_init_group(
        groupIdPtr,
        identityPubkeyPtr,
        signingKeyPtr,
        outStatePtr,
        outStateLenAlloc.alignedPtr
    );
    
    if (!success) {
        console.error('❌ Failed to initialize group');
        // Clean up
        exports.wasm_free(creatorPrivateKeyPtr, 32);
        exports.wasm_free(creatorPublicKeyPtr, 32);
        exports.wasm_free(groupIdPtr, 32);
        exports.wasm_free(identityPubkeyPtr, 32);
        exports.wasm_free(signingKeyPtr, 32);
        exports.wasm_free(outStatePtr, maxStateSize);
        freeAligned(outStateLenAlloc);
        return false;
    }
    
    const stateLen = outStateLenAlloc.view[0];
    const stateData = new Uint8Array(exports.memory.buffer, outStatePtr, stateLen);
    console.log('✅ Group initialized!');
    console.log('State size:', stateLen, 'bytes');
    
    // Clean up
    exports.wasm_free(creatorPrivateKeyPtr, 32);
    exports.wasm_free(creatorPublicKeyPtr, 32);
    exports.wasm_free(groupIdPtr, 32);
    exports.wasm_free(identityPubkeyPtr, 32);
    exports.wasm_free(signingKeyPtr, 32);
    freeAligned(outStateLenAlloc);
    
    return { stateData: new Uint8Array(stateData), statePtr: outStatePtr, maxStateSize };
}

async function testGetStateInfo(stateData: Uint8Array) {
    console.log('\n📊 Testing Get State Info');
    
    // Allocate memory for state data
    const statePtr = exports.wasm_alloc(stateData.length);
    new Uint8Array(exports.memory.buffer, statePtr, stateData.length).set(stateData);
    
    // Allocate outputs
    const epochAlloc = allocateAlignedU64();
    const memberCountAlloc = allocateAlignedU32();
    const pendingProposalsAlloc = allocateAlignedU32();
    const exporterSecretPtr = exports.wasm_alloc(32);
    const treeHashPtr = exports.wasm_alloc(32);
    
    const success = exports.wasm_mls_get_info(
        statePtr,
        stateData.length,
        epochAlloc.alignedPtr,
        memberCountAlloc.alignedPtr,
        pendingProposalsAlloc.alignedPtr,
        exporterSecretPtr,
        treeHashPtr
    );
    
    if (!success) {
        console.error('❌ Failed to get state info');
        exports.wasm_free(statePtr, stateData.length);
        freeAligned(epochAlloc);
        freeAligned(memberCountAlloc);
        freeAligned(pendingProposalsAlloc);
        exports.wasm_free(exporterSecretPtr, 32);
        exports.wasm_free(treeHashPtr, 32);
        return false;
    }
    
    const epoch = epochAlloc.view[0];
    const memberCount = memberCountAlloc.view[0];
    const pendingProposals = pendingProposalsAlloc.view[0];
    const exporterSecret = new Uint8Array(exports.memory.buffer, exporterSecretPtr, 32);
    const treeHash = new Uint8Array(exports.memory.buffer, treeHashPtr, 32);
    
    console.log('✅ Got state info:');
    console.log('  Epoch:', epoch.toString());
    console.log('  Members:', memberCount);
    console.log('  Pending proposals:', pendingProposals);
    console.log('  Exporter secret:', bytesToHex(exporterSecret));
    console.log('  Tree hash:', bytesToHex(treeHash));
    
    // Clean up
    exports.wasm_free(statePtr, stateData.length);
    freeAligned(epochAlloc);
    freeAligned(memberCountAlloc);
    freeAligned(pendingProposalsAlloc);
    exports.wasm_free(exporterSecretPtr, 32);
    exports.wasm_free(treeHashPtr, 32);
    
    return true;
}

async function testProposeAddMember(stateData: Uint8Array): Promise<Uint8Array | null> {
    console.log('\n➕ Testing Propose Add Member');
    
    // Create new member identity
    const newMemberPrivateKeyPtr = exports.wasm_alloc(32);
    const newMemberPublicKeyPtr = exports.wasm_alloc(32);
    
    const identitySuccess = exports.wasm_create_identity(newMemberPrivateKeyPtr, newMemberPublicKeyPtr);
    if (!identitySuccess) {
        console.error('❌ Failed to create new member identity');
        return null;
    }
    
    const newMemberPrivateKey = new Uint8Array(exports.memory.buffer, newMemberPrivateKeyPtr, 32);
    const newMemberPublicKey = new Uint8Array(exports.memory.buffer, newMemberPublicKeyPtr, 32);
    console.log('New member public key:', bytesToHex(newMemberPublicKey));
    
    // Allocate memory for state data
    const statePtr = exports.wasm_alloc(stateData.length);
    new Uint8Array(exports.memory.buffer, statePtr, stateData.length).set(stateData);
    
    // Allocate memory for new member identity
    const newMemberIdentityPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, newMemberIdentityPtr, 32).set(newMemberPublicKey);
    
    const newMemberSigningKeyPtr = exports.wasm_alloc(32);
    new Uint8Array(exports.memory.buffer, newMemberSigningKeyPtr, 32).set(newMemberPrivateKey);
    
    // Allocate output buffer
    const maxStateSize = 10240;
    const outStatePtr = exports.wasm_alloc(maxStateSize);
    const outStateLenAlloc = allocateAlignedU32();
    outStateLenAlloc.view[0] = maxStateSize;
    
    // Propose add (sender_index = 0 for creator)
    const success = exports.wasm_state_machine_propose_add(
        statePtr,
        stateData.length,
        0, // sender_index
        newMemberIdentityPtr,
        newMemberSigningKeyPtr,
        outStatePtr,
        outStateLenAlloc.alignedPtr
    );
    
    if (!success) {
        console.error('❌ Failed to propose add member');
        exports.wasm_free(newMemberPrivateKeyPtr, 32);
        exports.wasm_free(newMemberPublicKeyPtr, 32);
        exports.wasm_free(statePtr, stateData.length);
        exports.wasm_free(newMemberIdentityPtr, 32);
        exports.wasm_free(newMemberSigningKeyPtr, 32);
        exports.wasm_free(outStatePtr, maxStateSize);
        freeAligned(outStateLenAlloc);
        return null;
    }
    
    const newStateLen = outStateLenAlloc.view[0];
    const newStateData = new Uint8Array(exports.memory.buffer, outStatePtr, newStateLen);
    console.log('✅ Member add proposed!');
    console.log('New state size:', newStateLen, 'bytes');
    
    // Clean up
    exports.wasm_free(newMemberPrivateKeyPtr, 32);
    exports.wasm_free(newMemberPublicKeyPtr, 32);
    exports.wasm_free(statePtr, stateData.length);
    exports.wasm_free(newMemberIdentityPtr, 32);
    exports.wasm_free(newMemberSigningKeyPtr, 32);
    exports.wasm_free(outStatePtr, maxStateSize);
    freeAligned(outStateLenAlloc);
    
    return new Uint8Array(newStateData);
}

async function testCommitProposals(stateData: Uint8Array): Promise<{ newState: Uint8Array; epoch: bigint; exporterSecret: Uint8Array } | null> {
    console.log('\n✅ Testing Commit Proposals');
    
    // Allocate memory for state data
    const statePtr = exports.wasm_alloc(stateData.length);
    new Uint8Array(exports.memory.buffer, statePtr, stateData.length).set(stateData);
    
    // Allocate output buffer
    const maxStateSize = 10240;
    const outStatePtr = exports.wasm_alloc(maxStateSize);
    const outStateLenAlloc = allocateAlignedU32();
    outStateLenAlloc.view[0] = maxStateSize;
    
    // Allocate epoch and exporter secret outputs
    const outEpochAlloc = allocateAlignedU64();
    const outExporterSecretPtr = exports.wasm_alloc(32);
    
    // Commit proposals (committer_index = 0 for creator)
    const success = exports.wasm_state_machine_commit_proposals(
        statePtr,
        stateData.length,
        0, // committer_index
        outStatePtr,
        outStateLenAlloc.alignedPtr,
        outEpochAlloc.alignedPtr,
        outExporterSecretPtr
    );
    
    if (!success) {
        console.error('❌ Failed to commit proposals');
        exports.wasm_free(statePtr, stateData.length);
        exports.wasm_free(outStatePtr, maxStateSize);
        freeAligned(outStateLenAlloc);
        freeAligned(outEpochAlloc);
        exports.wasm_free(outExporterSecretPtr, 32);
        return null;
    }
    
    const newStateLen = outStateLenAlloc.view[0];
    const newStateData = new Uint8Array(exports.memory.buffer, outStatePtr, newStateLen);
    const newEpoch = outEpochAlloc.view[0];
    const exporterSecret = new Uint8Array(exports.memory.buffer, outExporterSecretPtr, 32);
    
    console.log('✅ Proposals committed!');
    console.log('New epoch:', newEpoch.toString());
    console.log('New state size:', newStateLen, 'bytes');
    console.log('New exporter secret:', bytesToHex(exporterSecret));
    
    // Clean up
    exports.wasm_free(statePtr, stateData.length);
    exports.wasm_free(outStatePtr, maxStateSize);
    freeAligned(outStateLenAlloc);
    freeAligned(outEpochAlloc);
    exports.wasm_free(outExporterSecretPtr, 32);
    
    return {
        newState: new Uint8Array(newStateData),
        epoch: newEpoch,
        exporterSecret: new Uint8Array(exporterSecret)
    };
}

// Main test function
async function runTests() {
    console.log('🧪 Testing MLS State Machine WASM Functions');
    console.log('============================================');
    
    try {
        // Test 1: Initialize group
        const initResult = await testStateInitialization();
        if (!initResult) {
            console.error('❌ State initialization test failed');
            return;
        }
        
        // Test 2: Get initial state info
        const infoSuccess = await testGetStateInfo(initResult.stateData);
        if (!infoSuccess) {
            console.error('❌ Get state info test failed');
            exports.wasm_free(initResult.statePtr, initResult.maxStateSize);
            return;
        }
        
        // Test 3: Propose adding a member
        const stateAfterPropose = await testProposeAddMember(initResult.stateData);
        if (!stateAfterPropose) {
            console.error('❌ Propose add member test failed');
            exports.wasm_free(initResult.statePtr, initResult.maxStateSize);
            return;
        }
        
        // Test 4: Get state info after proposal
        console.log('\n📊 State info after proposal:');
        await testGetStateInfo(stateAfterPropose);
        
        // Test 5: Commit proposals
        const commitResult = await testCommitProposals(stateAfterPropose);
        if (!commitResult) {
            console.error('❌ Commit proposals test failed');
            exports.wasm_free(initResult.statePtr, initResult.maxStateSize);
            return;
        }
        
        // Test 6: Get final state info
        console.log('\n📊 Final state info:');
        await testGetStateInfo(commitResult.newState);
        
        // Clean up original allocation
        exports.wasm_free(initResult.statePtr, initResult.maxStateSize);
        
        console.log('\n✅ All state machine tests passed!');
        
    } catch (error) {
        console.error('❌ Test error:', error);
    }
}

// Run tests
runTests().catch(console.error);