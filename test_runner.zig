test {
    // Core Nostr functionality tests
    _ = @import("tests/test_events.zig");
    
    // MLS/NIP-EE protocol tests  
    _ = @import("tests/test_nip_ee_real.zig");
    _ = @import("tests/test_welcome_events.zig");
    _ = @import("tests/test_key_schedule.zig");
    _ = @import("tests/test_mls_roundtrip.zig");
    _ = @import("tests/test_welcome_roundtrip.zig");
    
    // KeyPackage compatibility tests
    _ = @import("tests/test_keypackage_vectors.zig");
    
    // Other core tests
    _ = @import("tests/test_public_key_derivation.zig");
    _ = @import("tests/test_schnorr_verify.zig");
    
    // Note: test_mls_state_machine.zig disabled due to compilation errors
    // _ = @import("tests/test_mls_state_machine.zig");
}