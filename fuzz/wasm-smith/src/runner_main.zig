//! A simple CLI for running fuzz targets w/o instrumentation or linking to AFL's runtime libraries.

const std = @import("std");
const wasmstint = @import("wasmstint");
const harness = @import("harness");

pub fn main() !void {
    const max_file_size = 2 * (1024 * 1024);
    var main_pages = try wasmstint.PageBufferAllocator.init(max_file_size);
    defer main_pages.deinit();
    var main_arena = std.heap.ArenaAllocator.init(main_pages.allocator());

    const file: std.fs.File = input: {
        var args = try std.process.argsWithAllocator(main_arena.allocator());
        _ = args.next();

        const input = try std.fs.cwd().openFileZ(
            args.next() orelse @panic("no input file provided"),
            .{},
        );

        if (args.next() != null)
            @panic("cannot execute more than one file");

        break :input input;
    };

    _ = main_arena.reset(.retain_capacity);

    const bytes: []const u8 = try file.readToEndAlloc(
        main_arena.allocator(),
        max_file_size,
    );

    const result: harness.Result = try @call(
        .never_inline,
        @import("target").target,
        .{bytes},
    );

    std.debug.print("{s}\n", .{@tagName(result)});
}
