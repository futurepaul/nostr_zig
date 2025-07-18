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

    // Add hpke dependency
    const hpke_dep = b.dependency("hpke", .{
        .target = target,
        .optimize = optimize,
    });
    
    // Try to get the artifact instead of module
    const hpke_lib = hpke_dep.artifact("hpke");
    
    // Add hpke to the library module - use the root source file
    lib_mod.addImport("hpke", hpke_lib.root_module);

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

    // Modules can depend on one another using the `std.Build.Module.addImport` function.
    // This is what allows Zig source code to use `@import("foo")` where 'foo' is not a
    // file path. In this case, we set up `exe_mod` to import `lib_mod`.
    exe_mod.addImport("mls_zig_lib", lib_mod);
    exe_mod.addImport("hpke", hpke_lib.root_module);

    // Now, we will create a static library based on the module we created above.
    // This creates a `std.Build.Step.Compile`, which is the build step responsible
    // for actually invoking the compiler.
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "mls_zig",
        .root_module = lib_mod,
    });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);
    
    // Expose the library module for external projects to import
    const mls_zig_mod = b.addModule("mls_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mls_zig_mod.addImport("hpke", hpke_lib.root_module);

    // This creates another `std.Build.Step.Compile`, but this one builds an executable
    // rather than a static library.
    const exe = b.addExecutable(.{
        .name = "mls_zig_demo",
        .root_module = exe_mod,
    });

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

    // Test vectors test step
    const test_vectors_tests = b.addTest(.{
        .root_source_file = b.path("src/test_vectors.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Add the library module to test vectors so it can access our implementation
    test_vectors_tests.root_module.addImport("mls_zig_lib", lib_mod);
    test_vectors_tests.root_module.addImport("hpke", hpke_lib.root_module);
    
    const run_test_vectors = b.addRunArtifact(test_vectors_tests);
    
    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
    
    const test_vectors_step = b.step("test-vectors", "Run OpenMLS test vectors");
    test_vectors_step.dependOn(&run_test_vectors.step);
    
    // Example for NIP-EE core functionality (working today)
    const nip_ee_core_example = b.addExecutable(.{
        .name = "nip_ee_core",
        .root_source_file = b.path("examples/nip_ee_core.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Add the library module to examples
    nip_ee_core_example.root_module.addImport("mls_zig", lib_mod);
    nip_ee_core_example.root_module.addImport("hpke", hpke_lib.root_module);
    
    const run_nip_ee_core_example = b.addRunArtifact(nip_ee_core_example);
    
    // Example for NIP-44 HKDF functionality
    const nip44_hkdf_example = b.addExecutable(.{
        .name = "nip44_hkdf",
        .root_source_file = b.path("examples/nip44_hkdf.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    nip44_hkdf_example.root_module.addImport("mls_zig", lib_mod);
    nip44_hkdf_example.root_module.addImport("hpke", hpke_lib.root_module);
    
    const run_nip44_hkdf_example = b.addRunArtifact(nip44_hkdf_example);
    
    const example_step = b.step("example", "Run NIP-EE core example");
    example_step.dependOn(&run_nip_ee_core_example.step);
    
    const nip44_step = b.step("example-nip44", "Run NIP-44 HKDF example");
    nip44_step.dependOn(&run_nip44_hkdf_example.step);
}
