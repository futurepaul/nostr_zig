const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Add websocket dependency
    const websocket_dep = b.dependency("websocket", .{
        .target = target,
        .optimize = optimize,
    });
    const websocket_mod = websocket_dep.module("websocket");

    // Add mls_zig dependency
    const mls_dep = b.dependency("mls_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const mls_mod = mls_dep.module("mls_zig");

    // Build secp256k1 library
    const secp256k1_lib = b.addStaticLibrary(.{
        .name = "secp256k1",
        .target = target,
        .optimize = optimize,
    });
    
    // Add secp256k1 source files
    secp256k1_lib.addCSourceFile(.{
        .file = b.path("deps/secp256k1/src/secp256k1.c"),
        .flags = &[_][]const u8{
            "-DHAVE_CONFIG_H=1",
            "-DECMULT_WINDOW_SIZE=15",
            "-DECMULT_GEN_PREC_BITS=4",
            "-DUSE_EXTERNAL_DEFAULT_CALLBACKS=1",
            "-DENABLE_MODULE_ECDH=1",
            "-DENABLE_MODULE_RECOVERY=1",
            "-DENABLE_MODULE_EXTRAKEYS=1",
            "-DENABLE_MODULE_SCHNORRSIG=1",
            "-DUSE_SCALAR_4X64=1",
            "-DUSE_FIELD_5X52=1",
            "-DUSE_FIELD_INV_BUILTIN=1",
            "-DUSE_SCALAR_INV_BUILTIN=1",
            "-DUSE_ECMULT_STATIC_PRECOMPUTATION=1",
            "-fvisibility=hidden",
        },
    });
    
    // Add precomputed tables
    secp256k1_lib.addCSourceFile(.{
        .file = b.path("deps/secp256k1/src/precomputed_ecmult.c"),
        .flags = &[_][]const u8{"-DHAVE_CONFIG_H=1"},
    });
    secp256k1_lib.addCSourceFile(.{
        .file = b.path("deps/secp256k1/src/precomputed_ecmult_gen.c"),
        .flags = &[_][]const u8{"-DHAVE_CONFIG_H=1"},
    });
    
    // Add external callbacks
    secp256k1_lib.addCSourceFile(.{
        .file = b.path("src/secp256k1/callbacks.c"),
        .flags = &[_][]const u8{},
    });
    
    // Add include directories
    secp256k1_lib.addIncludePath(b.path("deps/secp256k1"));
    secp256k1_lib.addIncludePath(b.path("deps/secp256k1/src"));
    secp256k1_lib.addIncludePath(b.path("deps/secp256k1/include"));
    secp256k1_lib.addIncludePath(b.path("src/secp256k1"));
    
    // Link with C library
    secp256k1_lib.linkLibC();
    
    // Create secp256k1 module
    const secp256k1_mod = b.createModule(.{
        .root_source_file = b.path("src/secp256k1/secp256k1.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp256k1_mod.addIncludePath(b.path("deps/secp256k1/include"));
    secp256k1_mod.addIncludePath(b.path("src/secp256k1"));
    secp256k1_mod.linkLibrary(secp256k1_lib);

    // Build bech32 library
    const bech32_lib = b.addStaticLibrary(.{
        .name = "bech32",
        .target = target,
        .optimize = optimize,
    });
    
    // Add bech32 C source
    bech32_lib.addCSourceFile(.{
        .file = b.path("deps/bech32/ref/c/segwit_addr.c"),
        .flags = &[_][]const u8{"-std=c99"},
    });
    bech32_lib.addIncludePath(b.path("deps/bech32/ref/c"));
    bech32_lib.linkLibC();
    
    // Create bech32 module with proper include paths
    const bech32_mod = b.createModule(.{
        .root_source_file = b.path("src/bech32.zig"),
        .target = target,
        .optimize = optimize,
    });
    bech32_mod.addIncludePath(b.path("deps/bech32/ref/c"));
    bech32_mod.linkLibrary(bech32_lib);


    // This creates a "module", which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Every executable or library we compile will be based on one or more modules.
    const lib_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // We will also create a module for our other entry point, 'main.zig'.
    const exe_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add websocket, secp256k1, bech32, and mls_zig imports to modules
    lib_mod.addImport("websocket", websocket_mod);
    lib_mod.addImport("secp256k1", secp256k1_mod);
    lib_mod.addImport("bech32", bech32_mod);
    lib_mod.addImport("mls_zig", mls_mod);
    exe_mod.addImport("websocket", websocket_mod);
    exe_mod.addImport("secp256k1", secp256k1_mod);
    exe_mod.addImport("bech32", bech32_mod);
    exe_mod.addImport("mls_zig", mls_mod);

    // Modules can depend on one another using the `std.Build.Module.addImport` function.
    // This is what allows Zig source code to use `@import("foo")` where 'foo' is not a
    // file path. In this case, we set up `exe_mod` to import `lib_mod`.
    exe_mod.addImport("nostr_zig_lib", lib_mod);

    // Now, we will create a static library based on the module we created above.
    // This creates a `std.Build.Step.Compile`, which is the build step responsible
    // for actually invoking the compiler.
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "nostr_zig",
        .root_module = lib_mod,
    });
    
    // Add library dependencies
    lib.linkLibrary(secp256k1_lib);
    lib.linkLibrary(bech32_lib);
    lib.addIncludePath(b.path("deps/secp256k1/include"));
    lib.addIncludePath(b.path("src/secp256k1"));
    lib.addIncludePath(b.path("deps/bech32/ref/c"));
    lib.linkLibC();

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // This creates another `std.Build.Step.Compile`, but this one builds an executable
    // rather than a static library.
    const exe = b.addExecutable(.{
        .name = "nostr_zig",
        .root_module = exe_mod,
    });
    
    // Add library dependencies to the executable
    exe.linkLibrary(secp256k1_lib);
    exe.linkLibrary(bech32_lib);
    exe.addIncludePath(b.path("deps/secp256k1/include"));
    exe.addIncludePath(b.path("src/secp256k1"));
    exe.addIncludePath(b.path("deps/bech32/ref/c"));
    exe.linkLibC();

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);

    // Add test for roundtrip
    const roundtrip_test = b.addTest(.{
        .root_source_file = b.path("src/test_roundtrip.zig"),
        .target = target,
        .optimize = optimize,
    });
    roundtrip_test.root_module.addImport("websocket", websocket_mod);
    roundtrip_test.root_module.addImport("secp256k1", secp256k1_mod);
    roundtrip_test.root_module.addImport("nostr", lib_mod);
    const run_roundtrip_test = b.addRunArtifact(roundtrip_test);
    
    const roundtrip_step = b.step("test-roundtrip", "Run roundtrip test");
    roundtrip_step.dependOn(&run_roundtrip_test.step);

    // Add basic client example
    const basic_example = b.addExecutable(.{
        .name = "basic_client",
        .root_source_file = b.path("examples/basic_client.zig"),
        .target = target,
        .optimize = optimize,
    });
    basic_example.root_module.addImport("nostr_zig", lib_mod);
    
    const run_basic_example = b.addRunArtifact(basic_example);
    const example_step = b.step("example", "Run basic client example");
    example_step.dependOn(&run_basic_example.step);
    
    // Add realistic client example
    const realistic_example = b.addExecutable(.{
        .name = "realistic_client",
        .root_source_file = b.path("examples/realistic_client.zig"),
        .target = target,
        .optimize = optimize,
    });
    realistic_example.root_module.addImport("nostr_zig", lib_mod);
    
    const run_realistic_example = b.addRunArtifact(realistic_example);
    const realistic_step = b.step("example-realistic", "Run realistic client example");
    realistic_step.dependOn(&run_realistic_example.step);
    
    // Add signature demo
    const sig_demo = b.addExecutable(.{
        .name = "signature_demo",
        .root_source_file = b.path("test_real_signatures.zig"),
        .target = target,
        .optimize = optimize,
    });
    sig_demo.root_module.addImport("nostr_zig", lib_mod);
    
    const run_sig_demo = b.addRunArtifact(sig_demo);
    const sig_demo_step = b.step("sig-demo", "Run signature demonstration");
    sig_demo_step.dependOn(&run_sig_demo.step);
    
    // Add roundtrip demo
    const roundtrip_demo = b.addExecutable(.{
        .name = "roundtrip_demo",
        .root_source_file = b.path("test_roundtrip_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    roundtrip_demo.root_module.addImport("nostr_zig", lib_mod);
    
    const run_roundtrip_demo = b.addRunArtifact(roundtrip_demo);
    const roundtrip_demo_step = b.step("roundtrip", "Run roundtrip demonstration");
    roundtrip_demo_step.dependOn(&run_roundtrip_demo.step);
    
    // Add simple roundtrip test
    const simple_roundtrip = b.addExecutable(.{
        .name = "simple_roundtrip",
        .root_source_file = b.path("test_simple_roundtrip.zig"),
        .target = target,
        .optimize = optimize,
    });
    simple_roundtrip.root_module.addImport("nostr_zig", lib_mod);
    
    const run_simple_roundtrip = b.addRunArtifact(simple_roundtrip);
    const simple_roundtrip_step = b.step("simple-roundtrip", "Run simple roundtrip test");
    simple_roundtrip_step.dependOn(&run_simple_roundtrip.step);
    
    // Add MLS HKDF debug test
    const mls_hkdf_debug = b.addExecutable(.{
        .name = "mls_hkdf_debug",
        .root_source_file = b.path("debug_mls_hkdf.zig"),
        .target = target,
        .optimize = optimize,
    });
    mls_hkdf_debug.root_module.addImport("mls_zig", mls_mod);
    
    const run_mls_hkdf_debug = b.addRunArtifact(mls_hkdf_debug);
    const mls_hkdf_debug_step = b.step("debug-mls-hkdf", "Debug MLS HKDF implementation");
    mls_hkdf_debug_step.dependOn(&run_mls_hkdf_debug.step);
    
    // Add padding debug test
    const padding_debug = b.addExecutable(.{
        .name = "padding_debug",
        .root_source_file = b.path("debug_padding.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    const run_padding_debug = b.addRunArtifact(padding_debug);
    const padding_debug_step = b.step("debug-padding", "Debug padding algorithm");
    padding_debug_step.dependOn(&run_padding_debug.step);
    
    // Add HKDF chain debug test
    const hkdf_chain_debug = b.addExecutable(.{
        .name = "hkdf_chain_debug",
        .root_source_file = b.path("debug_hkdf_chain.zig"),
        .target = target,
        .optimize = optimize,
    });
    hkdf_chain_debug.root_module.addImport("mls_zig", mls_mod);
    hkdf_chain_debug.root_module.addImport("secp256k1", secp256k1_mod);
    hkdf_chain_debug.linkLibrary(secp256k1_lib);
    hkdf_chain_debug.addIncludePath(b.path("deps/secp256k1/include"));
    hkdf_chain_debug.addIncludePath(b.path("src/secp256k1"));
    hkdf_chain_debug.linkLibC();
    
    const run_hkdf_chain_debug = b.addRunArtifact(hkdf_chain_debug);
    const hkdf_chain_debug_step = b.step("debug-hkdf-chain", "Debug complete HKDF chain");
    hkdf_chain_debug_step.dependOn(&run_hkdf_chain_debug.step);
    
    // Add Rust padding debug test
    const rust_padding_debug = b.addExecutable(.{
        .name = "rust_padding_debug",
        .root_source_file = b.path("debug_rust_padding.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    const run_rust_padding_debug = b.addRunArtifact(rust_padding_debug);
    const rust_padding_debug_step = b.step("debug-rust-padding", "Debug Rust reference padding");
    rust_padding_debug_step.dependOn(&run_rust_padding_debug.step);
    
    // Add public key debug test
    const pubkey_debug = b.addExecutable(.{
        .name = "pubkey_debug",
        .root_source_file = b.path("debug_pubkey.zig"),
        .target = target,
        .optimize = optimize,
    });
    pubkey_debug.root_module.addImport("secp256k1", secp256k1_mod);
    pubkey_debug.linkLibrary(secp256k1_lib);
    pubkey_debug.addIncludePath(b.path("deps/secp256k1/include"));
    pubkey_debug.addIncludePath(b.path("src/secp256k1"));
    pubkey_debug.linkLibC();
    
    const run_pubkey_debug = b.addRunArtifact(pubkey_debug);
    const pubkey_debug_step = b.step("debug-pubkey", "Debug public key derivation");
    pubkey_debug_step.dependOn(&run_pubkey_debug.step);
    
    // Add conversation key sec2 debug test
    const conv_key_sec2_debug = b.addExecutable(.{
        .name = "conv_key_sec2_debug",
        .root_source_file = b.path("debug_conversation_key_sec2.zig"),
        .target = target,
        .optimize = optimize,
    });
    conv_key_sec2_debug.root_module.addImport("secp256k1", secp256k1_mod);
    conv_key_sec2_debug.linkLibrary(secp256k1_lib);
    conv_key_sec2_debug.addIncludePath(b.path("deps/secp256k1/include"));
    conv_key_sec2_debug.addIncludePath(b.path("src/secp256k1"));
    conv_key_sec2_debug.linkLibC();
    
    const run_conv_key_sec2_debug = b.addRunArtifact(conv_key_sec2_debug);
    const conv_key_sec2_debug_step = b.step("debug-conv-key-sec2", "Debug conversation key with sec2");
    conv_key_sec2_debug_step.dependOn(&run_conv_key_sec2_debug.step);
}
