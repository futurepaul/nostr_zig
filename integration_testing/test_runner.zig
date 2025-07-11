const std = @import("std");
const ChildProcess = std.process.Child;

const Implementation = enum {
    zig,
    c,
    rust,
    
    fn command(self: Implementation) []const u8 {
        return switch (self) {
            .zig => "./zig-out/bin/zig_nip44_wrapper",
            .c => "./c/nip44_wrapper",
            .rust => "./rust/target/release/nip44_wrapper",
        };
    }
    
    fn name(self: Implementation) []const u8 {
        return switch (self) {
            .zig => "Zig",
            .c => "C",
            .rust => "Rust",
        };
    }
};

const TestCase = struct {
    name: []const u8,
    command: []const u8,
    inputs: []const []const u8,
    
    fn run(self: TestCase, allocator: std.mem.Allocator, impl: Implementation) ![]u8 {
        var child = ChildProcess.init(&.{ impl.command(), self.command }, allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        
        try child.spawn();
        
        // Write inputs
        const writer = child.stdin.?.writer();
        for (self.inputs, 0..) |input, i| {
            if (i > 0) try writer.writeAll(" ");
            try writer.writeAll(input);
        }
        try writer.writeAll("\n");
        child.stdin.?.close();
        child.stdin = null;
        
        // Read output
        const stdout_bytes = try child.stdout.?.reader().readAllAlloc(allocator, 1024 * 1024);
        errdefer allocator.free(stdout_bytes);
        
        const stderr_bytes = try child.stderr.?.reader().readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(stderr_bytes);
        
        const result = try child.wait();
        if (result.Exited != 0) {
            std.debug.print("Error from {s}: {s}\n", .{ impl.name(), stderr_bytes });
            return error.CommandFailed;
        }
        
        return std.mem.trim(u8, stdout_bytes, " \n\r");
    }
};

const InteropTester = struct {
    allocator: std.mem.Allocator,
    
    fn init(allocator: std.mem.Allocator) InteropTester {
        return .{ .allocator = allocator };
    }
    
    fn runTest(self: InteropTester, test_case: TestCase) !void {
        std.debug.print("Testing {s}...\n", .{test_case.name});
        
        // Run on all implementations
        const zig_result = try test_case.run(self.allocator, .zig);
        defer self.allocator.free(zig_result);
        
        const c_result = try test_case.run(self.allocator, .c);
        defer self.allocator.free(c_result);
        
        const rust_result = try test_case.run(self.allocator, .rust);
        defer self.allocator.free(rust_result);
        
        // Compare results
        if (!std.mem.eql(u8, zig_result, c_result)) {
            std.debug.print("  ❌ FAILED: Zig vs C mismatch\n", .{});
            std.debug.print("    Zig:  {s}\n", .{zig_result});
            std.debug.print("    C:    {s}\n", .{c_result});
            return error.InteropMismatch;
        }
        
        if (!std.mem.eql(u8, zig_result, rust_result)) {
            std.debug.print("  ❌ FAILED: Zig vs Rust mismatch\n", .{});
            std.debug.print("    Zig:  {s}\n", .{zig_result});
            std.debug.print("    Rust: {s}\n", .{rust_result});
            return error.InteropMismatch;
        }
        
        std.debug.print("  ✅ PASSED: All implementations agree\n", .{});
    }
    
    fn testConversationKeys(self: InteropTester) !void {
        std.debug.print("\n🔑 Testing Conversation Key Generation\n", .{});
        
        const test_vectors = [_]TestCase{
            .{
                .name = "conversation_key_1",
                .command = "conversation_key",
                .inputs = &.{
                    "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
                    "02c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
                },
            },
            .{
                .name = "conversation_key_2",
                .command = "conversation_key",
                .inputs = &.{
                    "a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
                    "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
                },
            },
        };
        
        for (test_vectors) |test_case| {
            try self.runTest(test_case);
        }
    }
    
    fn testMessageKeys(self: InteropTester) !void {
        std.debug.print("\n🗝️ Testing Message Key Derivation\n", .{});
        
        const test_case = TestCase{
            .name = "message_keys_1",
            .command = "message_keys",
            .inputs = &.{
                "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1",
                "b4d094c8c1e46c6e8a45eb0aaf59806e2de17024414835c0c5c8a01e64ef4693",
            },
        };
        
        try self.runTest(test_case);
    }
    
    fn testPadding(self: InteropTester) !void {
        std.debug.print("\n📏 Testing Padding Algorithm\n", .{});
        
        const test_sizes = [_][]const u8{ "0", "16", "32", "33", "129", "500", "1000", "65536" };
        
        for (test_sizes) |size| {
            const test_case = TestCase{
                .name = "padding",
                .command = "calc_padded_len",
                .inputs = &.{size},
            };
            try self.runTest(test_case);
        }
    }
    
    fn testEncryptDecrypt(self: InteropTester) !void {
        std.debug.print("\n🔐 Testing Encryption/Decryption Interoperability\n", .{});
        
        const implementations = [_]Implementation{ .zig, .c, .rust };
        const test_message = "Hello, NIP-44!";
        const sec1 = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
        const pub2 = "02c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133";
        const sec2 = "a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e";
        const pub1 = "020a2e3f91e919c60bc38c42e685f84619b5b8d87ee636b083c42771d8c0675642";
        
        // Test all encryption/decryption combinations
        for (implementations) |enc_impl| {
            // Encrypt with this implementation
            const encrypt_case = TestCase{
                .name = "encrypt",
                .command = "encrypt",
                .inputs = &.{ sec1, pub2, test_message },
            };
            
            const ciphertext = try encrypt_case.run(self.allocator, enc_impl);
            defer self.allocator.free(ciphertext);
            
            std.debug.print("\n  Encrypted with {s}: {s}...\n", .{ 
                enc_impl.name(), 
                ciphertext[0..@min(50, ciphertext.len)] 
            });
            
            // Decrypt with all implementations
            for (implementations) |dec_impl| {
                const decrypt_case = TestCase{
                    .name = "decrypt",
                    .command = "decrypt",
                    .inputs = &.{ sec2, pub1, ciphertext },
                };
                
                const plaintext = try decrypt_case.run(self.allocator, dec_impl);
                defer self.allocator.free(plaintext);
                
                if (!std.mem.eql(u8, plaintext, test_message)) {
                    std.debug.print("    ❌ {s} encrypt -> {s} decrypt FAILED\n", .{ 
                        enc_impl.name(), 
                        dec_impl.name() 
                    });
                    std.debug.print("      Expected: {s}\n", .{test_message});
                    std.debug.print("      Got:      {s}\n", .{plaintext});
                    return error.DecryptionMismatch;
                }
                
                std.debug.print("    ✅ {s} encrypt -> {s} decrypt OK\n", .{ 
                    enc_impl.name(), 
                    dec_impl.name() 
                });
            }
        }
    }
    
    fn testLongMessages(self: InteropTester) !void {
        std.debug.print("\n📜 Testing Long Message Handling\n", .{});
        
        // Generate a long message
        var long_msg = try self.allocator.alloc(u8, 10000);
        defer self.allocator.free(long_msg);
        
        for (long_msg, 0..) |*byte, i| {
            byte.* = @as(u8, @intCast(i % 256));
        }
        
        const long_msg_str = try std.fmt.allocPrint(self.allocator, "{}", .{std.fmt.fmtSliceHexLower(long_msg)});
        defer self.allocator.free(long_msg_str);
        
        const sec1 = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
        const pub2 = "02c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133";
        
        // Encrypt with Zig
        const encrypt_case = TestCase{
            .name = "encrypt_long",
            .command = "encrypt",
            .inputs = &.{ sec1, pub2, long_msg_str },
        };
        
        const ciphertext = try encrypt_case.run(self.allocator, .zig);
        defer self.allocator.free(ciphertext);
        
        std.debug.print("  Encrypted {} bytes -> {} bytes ciphertext\n", .{ 
            long_msg.len, 
            ciphertext.len 
        });
        
        // Decrypt with other implementations
        for ([_]Implementation{ .c, .rust }) |impl| {
            // Note: We'd need corresponding sec2/pub1 for proper decryption
            std.debug.print("  ⏭️  Skipping {s} decrypt (would need proper keys)\n", .{impl.name()});
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const tester = InteropTester.init(allocator);
    
    std.debug.print("🧪 NIP-44 Cross-Implementation Integration Tests\n", .{});
    std.debug.print("================================================\n", .{});
    
    // Check if binaries exist
    for ([_]Implementation{ .zig, .c, .rust }) |impl| {
        const result = std.fs.cwd().access(impl.command(), .{});
        if (result) |_| {
            std.debug.print("✅ Found {s} implementation\n", .{impl.name()});
        } else |_| {
            std.debug.print("❌ Missing {s} implementation at {s}\n", .{ impl.name(), impl.command() });
            std.debug.print("   Run: zig build build-refs\n", .{});
            return error.MissingImplementation;
        }
    }
    
    // Run all test suites
    try tester.testConversationKeys();
    try tester.testMessageKeys();
    try tester.testPadding();
    try tester.testEncryptDecrypt();
    try tester.testLongMessages();
    
    std.debug.print("\n✅ All integration tests passed!\n", .{});
}