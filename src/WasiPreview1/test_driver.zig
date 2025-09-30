const Arguments = cli_args.CliArgs(.{
    .description = "Interpreter of WebAssembly programs using the `wasi_snapshot_preview1` ABI",
    .flags = &[_]cli_args.Flag{
        cli_args.Flag.string(
            .{
                .long = "module",
                .short = 'm',
                .description = "Path to .wasm program to execute",
            },
            "PATH",
        ).required(),
        cli_args.Flag.string(
            .{
                .long = "test",
                .description = "Path to .json test file",
            },
            "PATH",
        ).required(),
        cli_args.Flag.string(
            .{
                .long = "interpreter",
                .description = "Path to wasmstint-wasip1 executable",
            },
            "PATH",
        ).required(),
        cli_args.Flag.remainder, // additional arguments to pass to `wasmstint-wasip1`
    },
});

fn oom(context: []const u8) noreturn {
    std.debug.panic("out of memory: {s}", .{context});
}

const Specification = struct {
    args: []const []const u8,
    dirs: []const []const u8,
    env: std.json.ArrayHashMap([]const u8),
    exit_code: ?u32,
    stderr: ?[]const u8,
    stdout: ?[]const u8,
};

pub fn main() void {
    var arena = ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var scratch = ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    const arguments: struct { parsed: Arguments.Parsed, forwarded: []const [:0]const u8 } = args: {
        var parser: Arguments = undefined;
        parser.init();

        var args = cli_args.ArgIterator.initProcessArgs(&scratch) catch oom("argv");
        _ = args.next().?;
        const parsed = parser.remainingArguments(&args, &arena) catch oom("CLI args");

        const forwarded = arena.allocator().alloc([:0]const u8, args.remaining.len) catch
            oom("forwarded argv");
        for (forwarded, args.remaining) |*dst, src| {
            dst.* = arena.allocator().dupeZ(u8, src) catch oom("forwarded CLI arg");
        }

        break :args .{ .parsed = parsed, .forwarded = forwarded };
    };

    // The steps to perform are documented at `tests/wasi/doc/specification.md` or at
    // https://github.com/WebAssembly/wasi-testsuite/blob/60e08baeb4b098a0926fecd7aa7c5b1913413db2/doc/specification.md

    // TODO: Perform cleanup of test cases (maybe after open dirs are discovered?)

    _ = scratch.reset(.retain_capacity);

    const spec = std.json.parseFromSlice(
        Specification,
        arena.allocator(),
        undefined,
        .{},
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("JSON specification"),
        else => |bad| std.debug.panic("TODO JSON Diagnostics {t}", .{bad}),
    };

    // TODO: launch the interpreter process
    _ = arguments;
    _ = spec;

    std.process.cleanExit();
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const cli_args = @import("cli_args");

test {
    _ = main;
}
