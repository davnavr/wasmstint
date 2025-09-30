const Arguments = cli_args.CliArgs(.{
    .description = "Invokes with `wasmstint-wasip1` on WASI testsuite tests",
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

fn abnormalExitFmt(code: u8, comptime fmt: []const u8, args: anytype) u8 {
    std.debug.assert(code != 0);
    {
        var stderr_buf: [256]u8 align(16) = undefined;
        const stderr = std.debug.lockStderrWriter(&stderr_buf);
        defer stderr.flush() catch {};

        const config = std.Io.tty.detectConfig(std.fs.File.stderr());
        config.setColor(stderr, .bright_red) catch {};
        stderr.writeAll("error: ") catch {};
        config.setColor(stderr, .reset) catch {};
        stderr.print(fmt ++ "\n", args) catch {};
    }

    if (builtin.mode != .Debug) {
        std.process.exit(code);
    } else {
        return code;
    }
}

const Specification = struct {
    args: []const []const u8 = &.{},
    dirs: []const []const u8 = &.{},
    env: std.json.ArrayHashMap([]const u8) = .{ .map = .empty },
    exit_code: u8 = 0, // u32 or i32?
    stderr: []const u8 = "",
    stdout: []const u8 = "",
};

pub fn main() u8 {
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

    const fmt_json_path = std.unicode.fmtUtf8(arguments.parsed.@"test");
    const json_bytes = FileContent.readFileZ(
        std.fs.cwd(),
        arguments.parsed.@"test",
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("JSON file bytes"),
        else => |bad| return abnormalExitFmt(
            1,
            "could not open JSON file {f}: {t}",
            .{ fmt_json_path, bad },
        ),
    };
    // defer json_bytes.deinit();

    // The steps to perform are documented at `tests/wasi/doc/specification.md` or at
    // https://github.com/WebAssembly/wasi-testsuite/blob/60e08baeb4b098a0926fecd7aa7c5b1913413db2/doc/specification.md

    // TODO: Perform cleanup of test cases (maybe after open dirs are discovered?)

    _ = scratch.reset(.retain_capacity);
    const spec = spec: {
        var scanner = std.json.Scanner.initCompleteInput(scratch.allocator(), json_bytes.contents);
        var diagnostics = std.json.Diagnostics{};
        scanner.enableDiagnostics(&diagnostics);
        break :spec std.json.parseFromTokenSourceLeaky(
            Specification,
            arena.allocator(),
            &scanner,
            .{ .duplicate_field_behavior = .@"error", .ignore_unknown_fields = false },
        ) catch |e| switch (e) {
            error.OutOfMemory => oom("parsed JSON specification"),
            error.BufferUnderrun => unreachable,
            else => |bad| return abnormalExitFmt(
                1,
                "{f}:{}:{}: parse failed {t}",
                .{ fmt_json_path, diagnostics.getLine(), diagnostics.getColumn(), bad },
            ),
        };
    };

    // TODO: launch the interpreter process
    _ = spec;

    std.process.cleanExit();
    return 0;
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const cli_args = @import("cli_args");
const FileContent = @import("FileContent");

test {
    _ = main;
}
