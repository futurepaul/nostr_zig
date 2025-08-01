const std = @import("std");
const mls_zig = @import("mls_zig");

/// Simple in-memory storage for HPKE keypairs
/// In production, this would be encrypted and persisted to disk
pub const KeyStorage = struct {
    allocator: std.mem.Allocator,
    // Map from Nostr pubkey hex to KeyPackageBundle
    bundles: std.hash_map.StringHashMap(StoredBundle),
    
    pub const StoredBundle = struct {
        key_package_event_id: []const u8,
        init_private_key: [32]u8,
        encryption_private_key: [32]u8,
        signature_private_key: [64]u8,
        
        pub fn deinit(self: StoredBundle, allocator: std.mem.Allocator) void {
            allocator.free(self.key_package_event_id);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) KeyStorage {
        return .{
            .allocator = allocator,
            .bundles = std.hash_map.StringHashMap(StoredBundle).init(allocator),
        };
    }
    
    pub fn deinit(self: *KeyStorage) void {
        var iter = self.bundles.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.bundles.deinit();
    }
    
    /// Store a KeyPackageBundle for a user
    pub fn storeBundle(
        self: *KeyStorage,
        nostr_pubkey_hex: []const u8,
        bundle: mls_zig.key_package_flat.KeyPackageBundle,
        key_package_event_id: []const u8,
    ) !void {
        const pubkey_copy = try self.allocator.dupe(u8, nostr_pubkey_hex);
        errdefer self.allocator.free(pubkey_copy);
        
        const event_id_copy = try self.allocator.dupe(u8, key_package_event_id);
        errdefer self.allocator.free(event_id_copy);
        
        const stored = StoredBundle{
            .key_package_event_id = event_id_copy,
            .init_private_key = bundle.private_init_key,
            .encryption_private_key = bundle.private_encryption_key,
            .signature_private_key = bundle.private_signature_key,
        };
        
        try self.bundles.put(pubkey_copy, stored);
    }
    
    /// Retrieve stored HPKE private keys for a user
    pub fn getHpkePrivateKey(self: *KeyStorage, nostr_pubkey_hex: []const u8) ?[32]u8 {
        const entry = self.bundles.get(nostr_pubkey_hex) orelse return null;
        return entry.init_private_key;
    }
    
    /// Get all stored keys for a user
    pub fn getStoredBundle(self: *KeyStorage, nostr_pubkey_hex: []const u8) ?StoredBundle {
        return self.bundles.get(nostr_pubkey_hex);
    }
    
    /// Save to file (for persistence between test runs)
    pub fn saveToFile(self: *KeyStorage, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        
        var writer = file.writer();
        
        // Simple JSONL format: one line per entry
        var iter = self.bundles.iterator();
        while (iter.next()) |entry| {
            try writer.print("{{\"pubkey\":\"{s}\",\"event_id\":\"{s}\",\"init_key\":\"{}\",\"enc_key\":\"{}\",\"sig_key\":\"{}\"}}\n", .{
                entry.key_ptr.*,
                entry.value_ptr.key_package_event_id,
                std.fmt.fmtSliceHexLower(&entry.value_ptr.init_private_key),
                std.fmt.fmtSliceHexLower(&entry.value_ptr.encryption_private_key),
                std.fmt.fmtSliceHexLower(&entry.value_ptr.signature_private_key),
            });
        }
    }
    
    /// Load from file
    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !KeyStorage {
        var storage = KeyStorage.init(allocator);
        errdefer storage.deinit();
        
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) return storage;
            return err;
        };
        defer file.close();
        
        const content = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
        defer allocator.free(content);
        
        // Parse JSONL
        var lines = std.mem.tokenize(u8, content, "\n");
        while (lines.next()) |line| {
            // Simple manual parsing for now
            // In production, use proper JSON parser
            _ = line;
            // TODO: Parse JSON and populate storage
        }
        
        return storage;
    }
};

// Global storage instance for tests
var global_key_storage: ?*KeyStorage = null;

pub fn getGlobalStorage(allocator: std.mem.Allocator) !*KeyStorage {
    if (global_key_storage) |storage| {
        return storage;
    }
    
    const storage = try allocator.create(KeyStorage);
    storage.* = KeyStorage.init(allocator);
    global_key_storage = storage;
    return storage;
}

pub fn deinitGlobalStorage() void {
    if (global_key_storage) |storage| {
        storage.deinit();
        // Note: in real code we'd also free the storage pointer
        global_key_storage = null;
    }
}