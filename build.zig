const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const channel_dep = b.dependency("channel_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const channel_module = channel_dep.module("channel");

    const hub_service_module = b.addModule("hub_service", .{
        .root_source_file = b.path("src/hub_service.zig"),
        .target = target,
        .optimize = optimize,
    });
    hub_service_module.addImport("channel", channel_module);

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "hub_service_zig",
        .root_module = hub_service_module,
    });
    b.installArtifact(lib);

    const unit_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hub_service", .module = hub_service_module },
        },
    });
    const unit_tests = b.addTest(.{
        .name = "test-unit",
        .root_module = unit_test_module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_unit_step = b.step("test-unit", "Run unit tests");
    test_unit_step.dependOn(&run_unit_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const example_module = b.createModule(.{
        .root_source_file = b.path("src/example.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hub_service", .module = hub_service_module },
        },
    });
    const example_exe = b.addExecutable(.{
        .name = "hub-service-zig-example",
        .root_module = example_module,
    });
    b.installArtifact(example_exe);

    const run_example = b.addRunArtifact(example_exe);
    const run_example_step = b.step("run-example", "Run the echo example service");
    run_example_step.dependOn(&run_example.step);
}
