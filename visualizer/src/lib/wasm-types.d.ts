/**
 * Type definitions for Nostr MLS WASM exports
 * Generated from Zig WASM exports
 */

export interface NostrMLSWasmExports {
  // Memory management
  memory: WebAssembly.Memory;
  wasm_init(): void;
  wasm_get_version(): number;
  wasm_alloc(size: number): number;
  wasm_alloc_u32(count: number): number;
  wasm_free(ptr: number, size: number): void;
  wasm_free_u32(ptr: number, count: number): void;
  wasm_align_ptr(ptr: number, alignment: number): number;

  // Core cryptographic functions
  wasm_create_identity(out_private_key: number, out_public_key: number): boolean;
  wasm_get_public_key_from_private(private_key: number, out_public_key: number): boolean;
  wasm_get_public_key_hex(private_key: number, out_pubkey_hex: number): boolean;
  wasm_sign_schnorr(message_hash: number, private_key: number, out_signature: number): boolean;
  wasm_verify_schnorr(message_hash: number, signature: number, public_key: number): boolean;

  // MLS Functions
  wasm_mls_init_group(
    group_id: number,              // [*]const u8 - 32 bytes (unused)
    creator_identity_pubkey: number, // [*]const u8 - 32 bytes
    creator_signing_key: number,    // [*]const u8 - 32 bytes
    out_state: number,             // [*]u8 - serialized MlsGroup state
    out_state_len: number          // *u32 - pointer to state length
  ): boolean;

  wasm_mls_get_info(
    state_data: number,            // [*]const u8
    state_data_len: number,        // u32
    out_epoch: number,             // *u64
    out_member_count: number,      // *u32
    out_pending_proposals: number, // *u32
    out_exporter_secret: number,   // [*]u8 - 32 bytes
    out_tree_hash: number          // [*]u8 - 32 bytes
  ): boolean;

  wasm_mls_test(): boolean;

  wasm_state_machine_propose_add(
    state_data: number,            // [*]const u8
    state_data_len: number,        // u32
    member_key_package: number,    // [*]const u8
    member_key_package_len: number, // u32
    out_state: number,             // [*]u8
    out_state_len: number          // *u32
  ): boolean;

  wasm_state_machine_commit_proposals(
    state_data: number,            // [*]const u8
    state_data_len: number,        // u32
    out_state: number,             // [*]u8
    out_state_len: number          // *u32
  ): boolean;

  wasm_state_machine_get_info(
    state_data: number,            // [*]const u8
    state_data_len: number,        // u32
    out_epoch: number,             // *u64
    out_member_count: number,      // *u32
    out_pending_proposals: number, // *u32
    out_exporter_secret: number,   // [*]u8 - 32 bytes
    out_tree_hash: number          // [*]u8 - 32 bytes
  ): boolean;

  wasm_state_machine_create_welcome(
    state_data: number,            // [*]const u8
    state_data_len: number,        // u32
    new_member_index: number,      // u32
    out_welcome: number,           // [*]u8
    out_welcome_len: number        // *u32
  ): boolean;

  wasm_state_machine_process_welcome(
    welcome_data: number,          // [*]const u8
    welcome_data_len: number,      // u32
    joiner_private_key: number,    // [*]const u8 - 32 bytes
    out_state: number,             // [*]u8
    out_state_len: number,         // *u32
    out_epoch: number,             // *u64
    out_member_count: number       // *u32
  ): boolean;

  // NIP-EE Functions
  wasm_nip_ee_generate_exporter_secret(
    state_data: number,
    state_data_len: number,
    out_secret: number
  ): boolean;

  wasm_nip_ee_create_encrypted_group_message(
    group_id: number,              // [*]const u8 - 32 bytes
    epoch: bigint,                 // u64
    sender_index: number,          // u32
    message_content: number,       // [*]const u8
    message_content_len: number,   // u32
    mls_signature: number,         // [*]const u8
    mls_signature_len: number,     // u32
    exporter_secret: number,       // [*]const u8 - 32 bytes
    out_encrypted: number,         // [*]u8
    out_len: number                // *u32
  ): boolean;

  wasm_nip_ee_decrypt_group_message(
    encrypted_content: number,     // [*]const u8
    encrypted_content_len: number, // u32
    exporter_secret: number,       // [*]const u8 - 32 bytes
    out_decrypted: number,         // [*]u8
    out_len: number                // *u32
  ): boolean;

  // Event functions
  wasm_create_event(
    private_key: number,           // [*]const u8 - 32 bytes
    kind: number,                  // u32
    content: number,               // [*]const u8
    content_len: number,           // u32
    tags_json: number,             // [*]const u8
    tags_json_len: number,         // u32
    out_event_json: number,        // [*]u8
    out_len: number                // *u32
  ): boolean;
  
  wasm_create_nostr_event_id(
    pubkey: number,                // [*]const u8 - 64 hex chars
    created_at: bigint,            // u64
    kind: number,                  // u32
    tags_json: number,             // [*]const u8
    tags_len: number,              // u32
    content: number,               // [*]const u8
    content_len: number,           // u32
    out_id: number                 // [*]u8 - 32 bytes
  ): boolean;

  // NIP-59 Gift Wrapping Functions
  wasm_create_gift_wrap(
    sender_privkey: number,        // [*]const u8 - 32 bytes
    recipient_pubkey: number,      // [*]const u8 - 32 bytes
    rumor_json: number,            // [*]const u8
    rumor_json_len: number,        // u32
    out_wrapped_json: number,      // [*]u8
    out_len: number                // *u32
  ): boolean;

  wasm_unwrap_gift_wrap(
    wrapped_json: number,          // [*]const u8
    wrapped_json_len: number,      // u32
    recipient_privkey: number,     // [*]const u8 - 32 bytes
    out_rumor_json: number,        // [*]u8
    out_len: number                // *u32
  ): boolean;

  // Utility functions
  bytes_to_hex(
    bytes: number,
    bytes_len: number,
    out_hex: number,
    out_hex_len: number
  ): boolean;

  hex_to_bytes(
    hex: number,
    hex_len: number,
    out_bytes: number,
    out_bytes_len: number
  ): boolean;
  
  base64_encode(
    bytes: number,
    bytes_len: number,
    out_base64: number,
    out_base64_len: number
  ): boolean;
  
  base64_decode(
    base64: number,
    base64_len: number,
    out_bytes: number,
    out_bytes_len: number
  ): boolean;
  
  // Additional Nostr functions
  wasm_create_text_note_working(
    private_key: number,
    content: number,
    content_len: number,
    out_event_json: number,
    out_len: number
  ): boolean;
  
  wasm_create_reply_note(
    private_key: number,
    content: number,
    content_len: number,
    reply_to_event_id: number,
    out_event_json: number,
    out_len: number
  ): boolean;
  
  wasm_verify_event(
    event_json: number,
    event_json_len: number
  ): boolean;
  
  wasm_get_public_key(
    private_key: number,
    out_public_key: number
  ): boolean;
  
  wasm_pubkey_to_hex(
    public_key: number,
    out_hex: number
  ): void;
}

// Helper type for the complete WASM instance
export interface NostrMLSWasmInstance extends WebAssembly.Instance {
  exports: NostrMLSWasmExports;
}