const std = @import("std");
const nostr = @import("src/root.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.debug.print("\n=== Simple MLS State Machine Test ===\n", .{});
    
    // Create MLS provider
    var mls_provider = nostr.mls.provider.MlsProvider.init(allocator);
    
    // Generate a valid private key
    const creator_privkey = try nostr.crypto.generatePrivateKey();
    
    // Create key package
    const creator_kp = try nostr.mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        creator_privkey,
        .{},
    );
    defer nostr.mls.key_packages.freeKeyPackage(allocator, creator_kp);
    
    // Initialize group
    const group_id = nostr.crypto.sha256Hash("test-group-simple");
    var state_machine = try nostr.mls.state_machine.MLSStateMachine.initializeGroup(
        allocator,
        group_id,
        creator_kp,
        &mls_provider,
    );
    defer state_machine.deinit();
    
    std.debug.print("✓ Group created successfully!\n", .{});
    std.debug.print("  - Epoch: {}\n", .{state_machine.epoch});
    std.debug.print("  - Members: {}\n", .{state_machine.getMemberCount()});
    std.debug.print("  - Group ID: {s}\n", .{std.fmt.fmtSliceHexLower(&group_id)});
    
    // Add a member
    const bob_privkey = try nostr.crypto.generatePrivateKey();
    const bob_kp = try nostr.mls.key_packages.generateKeyPackage(
        allocator,
        &mls_provider,
        bob_privkey,
        .{},
    );
    defer nostr.mls.key_packages.freeKeyPackage(allocator, bob_kp);
    
    try state_machine.proposeAdd(0, bob_kp);
    std.debug.print("\n✓ Proposed adding Bob\n", .{});
    
    const commit_result = try state_machine.commitProposals(0, &mls_provider);
    std.debug.print("\n✓ Committed proposals!\n", .{});
    std.debug.print("  - New epoch: {}\n", .{commit_result.epoch});
    std.debug.print("  - Members: {}\n", .{state_machine.getMemberCount()});
    std.debug.print("  - Exporter secret: {s}\n", .{std.fmt.fmtSliceHexLower(&state_machine.epoch_secrets.exporter_secret)});
    
    std.debug.print("\n✅ State machine working correctly!\n", .{});
}