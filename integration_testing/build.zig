const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build Zig NIP-44 wrapper
    const zig_wrapper = b.addExecutable(.{
        .name = "zig_nip44_wrapper",
        .root_source_file = b.path("zig/nip44_wrapper.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Create secp256k1 module first
    const secp256k1_wrapper = b.createModule(.{
        .root_source_file = b.path("../src/secp256k1/secp256k1.zig"),
        .link_libc = true,
    });
    
    // Create v2 module first since nip44 depends on it
    const v2_module = b.createModule(.{
        .root_source_file = b.path("../src/nip44/v2.zig"),
    });
    
    // Create nip44 module with dependencies
    const nip44_module = b.createModule(.{
        .root_source_file = b.path("../src/nip44/mod.zig"),
    });
    nip44_module.addImport("secp256k1", secp256k1_wrapper);
    nip44_module.addImport("v2.zig", v2_module);
    
    // Add imports to wrapper
    zig_wrapper.root_module.addImport("nip44", nip44_module);
    zig_wrapper.root_module.addImport("secp256k1", secp256k1_wrapper);
    
    // Link with C libraries
    zig_wrapper.linkLibC();
    
    // Add secp256k1 library
    const secp256k1_lib = b.addStaticLibrary(.{
        .name = "secp256k1",
        .target = target,
        .optimize = optimize,
    });
    secp256k1_lib.linkLibC();
    secp256k1_lib.addCSourceFiles(.{
        .root = b.path("../deps/secp256k1"),
        .files = &.{
            "src/secp256k1.c",
            "src/precomputed_ecmult.c",
            "src/precomputed_ecmult_gen.c",
        },
        .flags = &.{
            "-DENABLE_MODULE_EXTRAKEYS",
            "-DENABLE_MODULE_SCHNORRSIG", 
            "-DENABLE_MODULE_ECDH",
            "-DENABLE_MODULE_RECOVERY",
            "-DECMULT_WINDOW_SIZE=15",
            "-DECMULT_GEN_PREC_BITS=4",
            "-DUSE_ECMULT_STATIC_PRECOMPUTATION",
        },
    });
    secp256k1_lib.addIncludePath(b.path("../deps/secp256k1"));
    secp256k1_lib.addIncludePath(b.path("../deps/secp256k1/include"));
    secp256k1_lib.addIncludePath(b.path("../src/secp256k1"));
    
    // Add callbacks C file
    secp256k1_lib.addCSourceFile(.{
        .file = b.path("../src/secp256k1/callbacks.c"),
        .flags = &.{"-std=c99"},
    });
    
    zig_wrapper.linkLibrary(secp256k1_lib);
    
    b.installArtifact(zig_wrapper);

    // Integration test runner
    const integration_test = b.addExecutable(.{
        .name = "integration_test",
        .root_source_file = b.path("test_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    const run_integration = b.addRunArtifact(integration_test);
    const integration_step = b.step("test-integration", "Run cross-implementation tests");
    integration_step.dependOn(&run_integration.step);
    
    // Fuzz testing
    const fuzz_test = b.addExecutable(.{
        .name = "fuzz_nip44",
        .root_source_file = b.path("fuzz/fuzz_nip44.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_test.root_module.addImport("nip44", nip44_module);
    fuzz_test.root_module.addImport("secp256k1", secp256k1_wrapper);
    fuzz_test.linkLibC();
    fuzz_test.linkLibrary(secp256k1_lib);
    
    const run_fuzz = b.addRunArtifact(fuzz_test);
    const fuzz_step = b.step("fuzz", "Run fuzz tests on NIP-44 implementation");
    fuzz_step.dependOn(&run_fuzz.step);

    // Build reference implementations
    const build_refs_step = b.step("build-refs", "Build C and Rust reference implementations");
    
    // Build C reference
    const build_c = b.addSystemCommand(&.{
        "sh", "-c",
        \\cd c && sh build.sh
    });
    build_refs_step.dependOn(&build_c.step);
    
    // Build Rust reference  
    const build_rust = b.addSystemCommand(&.{
        "sh", "-c", 
        \\cd rust && sh build.sh
    });
    build_refs_step.dependOn(&build_rust.step);
    
    // Make integration tests depend on building references
    integration_step.dependOn(build_refs_step);
}