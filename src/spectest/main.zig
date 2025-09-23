//! Executes WASM JSON spec tests.

const Arguments = cli_args.CliArgs(.{
    .description = "WebAssembly specification JSON test interpreter.",
    .flags = &[_]cli_args.Flag{
        .string(
            .{
                .long = "run",
                .short = 'r',
                .description = "Path to .json specification test file",
            },
            "PATH",
        ),

        cli_args.Flag.intUnsigned(
            .{ .long = "rng-seed", .description = "Specifies the RNG seed to use" },
            "SEED",
            u256,
        ).optional(),

        cli_args.Flag.intUnsigned(
            .{
                .long = "fuel",
                .description = "Limits the number of WASM instructions executed",
            },
            "AMOUNT",
            u64,
        ).withDefault(3_000_000),

        cli_args.Flag.intUnsigned(
            .{
                .long = "max-stack-size",
                .description = "Limits the size of the WASM value/call stack",
            },
            "AMOUNT",
            u32,
        ).withDefault(5000),

        cli_args.Flag.intUnsigned(
            .{
                .long = "max-memory-size",
                .description = "Upper bound on the size of a WASM linear memory, in bytes",
            },
            "SIZE",
            usize,
        ).withDefault(1000 * 65536),

        .boolean(.{ .long = "wait-for-debugger" }),
    },
});

fn parseProgramArguments(scratch: *ArenaAllocator, arena: *ArenaAllocator) Arguments.Parsed {
    var buf: [512]u8 align(16) = undefined;
    var buf_allocator = std.heap.FixedBufferAllocator.init(&buf);
    const parser = Arguments.init(buf_allocator.allocator()) catch @panic("oom");
    return parser.programArguments(scratch, arena) catch @panic("oom");
}

pub fn main() u8 {
    var scratch = ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    var arena = ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const arguments = parseProgramArguments(&scratch, &arena);
    _ = scratch.reset(.retain_capacity);

    if (arguments.@"wait-for-debugger") {
        wasmstint.waitForDebugger();
    }

    const stderr_buffer = std.heap.page_allocator.alignedAlloc(
        u8,
        .fromByteUnits(std.heap.page_size_min),
        8192,
    ) catch @panic("oom");
    const stderr = State.Output{
        .tty_config = std.Io.tty.detectConfig(std.fs.File.stderr()),
        .writer = std.debug.lockStderrWriter(stderr_buffer),
    };
    // Flush happens even if error occurs
    defer std.debug.unlockStderrWriter();

    const fmt_json_path = std.unicode.fmtUtf8(arguments.run);

    const cwd = std.fs.cwd();
    const json_file = wasmstint.FileContent.readFileZ(cwd, arguments.run) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        else => |io_err| {
            stderr.writeErrorPreamble();
            stderr.print("Failed to open file {f}: {t}\n", .{ fmt_json_path, io_err });
            return 1;
        },
    };

    var json_dir = std.fs.cwd().openDir(
        std.fs.path.dirname(arguments.run).?,
        .{ .access_sub_paths = true },
    ) catch |e| {
        stderr.writeErrorPreamble();
        stderr.print("Could not open directory {f}: {t}\n", .{ fmt_json_path, e });
        return 1;
    };
    errdefer json_dir.close();

    var rng = rng: {
        var init = std.Random.Xoshiro256{ .s = undefined };
        if (arguments.@"rng-seed") |seed| {
            init.s = @bitCast(seed);
        } else if (builtin.os.tag == .windows) {
            // Undefined symbol: SystemFunction032
            // Don't want to linkadvapi32 right now
            init.seed(42);
        } else {
            std.posix.getrandom(std.mem.asBytes(&init.s)) catch @panic("cannot obtain RNG");
        }

        break :rng init;
    };

    var json_script: Parser = undefined;
    json_script.init(&arena, json_file.contents, &scratch) catch |e|
        handleJsonError(arguments.run, &json_script, stderr, e);

    _ = scratch.reset(.retain_capacity);
    const fmt_wast_path = std.unicode.fmtUtf8(json_script.source_filename);

    var interpreter_allocated_amount = @as(usize, arguments.@"max-stack-size") *| 16;
    var interpreter_allocator = wasmstint.LimitedAllocator.init(
        &interpreter_allocated_amount,
        std.heap.page_allocator,
    );

    var imports: Imports = undefined;
    imports.init(rng.random(), &arena);

    var state: State = undefined;
    State.init(
        &state,
        interpreter_allocator.allocator(),
        arguments.@"max-memory-size",
        .{ .remaining = arguments.fuel },
        &imports,
        json_dir,
        &rng,
    );

    const exit_code: u8 = while (true) {
        const command = (json_script.next(&arena, &scratch) catch |e|
            handleJsonError(arguments.run, &json_script, stderr, e)) orelse break 0;

        stderr.print(
            "{f}:{} {t}\n",
            .{ fmt_wast_path, command.line, command.type },
        );

        _ = scratch.reset(.retain_capacity);
        state.processCommand(&command, stderr, &scratch) catch |e| switch (e) {
            error.ScriptError => {
                if (builtin.mode == .Debug) {
                    if (@errorReturnTrace()) |trace| {
                        trace.format(stderr.writer) catch {};
                    }
                }
                break 1;
            },
        };

        _ = scratch.reset(.retain_capacity);
    } else 0;

    stderr.print("{} tests passed\n", .{json_script.command_count});

    return exit_code;
}

fn handleJsonError(
    path: [:0]const u8,
    parser: *const Parser,
    stderr: State.Output,
    err: Parser.Error,
) noreturn {
    const fmt_path = std.unicode.fmtUtf8(path);

    switch (err) {
        error.OutOfMemory => @panic("oom"),
        error.MalformedJson => {
            const diagnostics = parser.diagnostics;
            stderr.print(
                "{f}:{}:{}: ",
                .{ fmt_path, diagnostics.getLine(), diagnostics.getColumn() },
            );
            stderr.setColor(.bright_red);
            stderr.writeAll("error: ");
            stderr.setColor(.reset);
            stderr.writeAll("JSON input was malformed\n");

            if (builtin.mode == .Debug) {
                if (@errorReturnTrace()) |trace| {
                    trace.format(stderr.writer) catch {};
                }
            }
        },
    }

    std.debug.unlockStderrWriter();
    std.process.exit(1);
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const cli_args = @import("cli_args");
const Parser = @import("Parser.zig");
const State = @import("State.zig");
const Imports = @import("Imports.zig");
