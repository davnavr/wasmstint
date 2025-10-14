//! Spawning of subprocesses and checking of outputs for tests.

fn formatBashString(s: []const u8, writer: *Writer) Writer.Error!void {
    try writer.writeByte('"');
    for (s) |b| {
        switch (b) {
            0 => try writer.writeAll("\\0"),
            '\x07' => try writer.writeAll("\\b"),
            '\x0C' => try writer.writeAll("\\f"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            '\x0B' => try writer.writeAll("\\v"),
            '\"' => try writer.writeAll("\\\""),
            else => if (std.ascii.isPrint(b)) {
                try writer.writeByte(b);
            } else {
                try writer.print("\\x{X:0>2}", .{b});
            },
        }
    }
    try writer.writeByte('"');
}

fn formatArgv(args: []const []const u8, writer: *Writer) Writer.Error!void {
    for (0.., args) |i, a| {
        if (i > 0) {
            try writer.writeByte(' ');
        }

        try formatBashString(a, writer);
    }
}

pub fn fmtArgv(argv: []const []const u8) std.fmt.Alt([]const []const u8, formatArgv) {
    return .{ .data = argv };
}

fn formatSignalNumber(num: u32, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    inline for (@typeInfo(std.posix.SIG).@"struct".decls) |decl| {
        const field = @field(std.posix.SIG, decl.name);
        if (@TypeOf(field) == comptime_int) {
            if (field == num) {
                try writer.writeAll(decl.name);
                return;
            }
        }
    }

    try writer.writeAll("unknown signal");
}

pub fn fmtSignalNumber(num: u32) std.fmt.Alt(u32, formatSignalNumber) {
    return .{ .data = num };
}

pub const WasiArguments = struct {
    preopen_dirs: []const PreopenDir = &.{},
    env: []const Env = &.{},
    args: []const []const u8 = &.{},

    pub const PreopenDir = struct {
        host: []const u8,
        guest: []const u8,
        mode: Mode,

        const Mode = enum {
            read_only,
            read_write,

            fn arg(mode: Mode) []const u8 {
                return switch (mode) {
                    .read_only => "ro",
                    .read_write => "rw",
                };
            }
        };
    };

    pub const Env = struct {
        key: []const u8,
        value: []const u8,
    };

    fn initInterpreterProcess(
        arguments: WasiArguments,
        interpreter: []const u8,
        wasm: []const u8,
        arena: *std.heap.ArenaAllocator,
    ) std.mem.Allocator.Error![]const []const u8 {
        const argv_count = 3 +
            (arguments.preopen_dirs.len * 4) +
            (arguments.env.len * 2) +
            arguments.args.len +
            @intFromBool(arguments.args.len > 0);

        var argv = try std.ArrayList([]const u8).initCapacity(arena.allocator(), argv_count);
        defer std.debug.assert(argv.items.len == argv.capacity);

        argv.appendSliceAssumeCapacity(&.{ interpreter, "--module", wasm });

        for (arguments.preopen_dirs) |dir| {
            argv.appendSliceAssumeCapacity(&.{ "--dir", dir.host, dir.guest, dir.mode.arg() });
        }

        for (arguments.env) |entry| {
            argv.appendSliceAssumeCapacity(&.{
                "--env",
                try std.fmt.allocPrint(
                    arena.allocator(),
                    "{s}={s}",
                    .{ entry.key, entry.value },
                ),
            });
        }

        if (arguments.args.len > 0) {
            argv.appendAssumeCapacity("--");
            argv.appendSliceAssumeCapacity(arguments.args);
        }

        return argv.items;
    }
};

const ExpectedOutput = struct {
    // TODO: Figure out how to get `i32` exit codes on windows
    exit_code: u32 = 0,
    stdin: []const u8 = "",
    stdout: []const u8 = "",
    stderr: []const u8 = "",

    stdio_max_bytes: usize = 64 * 1024 * 1024, // 64 MiB
    // /// How much time, in nanoseconds, the interpreter process can execute for.
    // timeout: u64 = 10 * std.time.ns_per_s,
};

pub fn invokeWasiInterpreter(
    interpreter: []const u8,
    wasm: []const u8,
    arguments: WasiArguments,
    expected: ExpectedOutput,
) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var stdout = std.ArrayList(u8).empty;
    defer stdout.deinit(std.testing.allocator);
    var stderr = std.ArrayList(u8).empty;
    defer stderr.deinit(std.testing.allocator);

    const exit_code = exit: {
        const argv = try arguments.initInterpreterProcess(interpreter, wasm, &arena);
        var interp = std.process.Child.init(argv, arena.allocator());
        interp.stdin_behavior = if (expected.stdin.len == 0) .Ignore else .Pipe;
        interp.stdout_behavior = .Pipe;
        interp.stderr_behavior = .Pipe;

        errdefer std.debug.print("error in interpreter subprocess {f}", .{fmtArgv(argv)});

        try interp.spawn();
        try interp.waitForSpawn();
        interp.collectOutput(
            std.testing.allocator,
            &stdout,
            &stderr,
            expected.stdio_max_bytes,
        ) catch |err| {
            _ = interp.kill() catch |kill_err| {
                std.debug.print("attempt to kill interpreter process due to {t} failed", .{err});
                return kill_err;
            };

            return err;
        };

        switch (try interp.wait()) {
            .Exited => |code| break :exit code,
            .Unknown => |n| {
                if (builtin.os.tag == .windows) {
                    std.debug.print("interpreter process exited for unknown reason", .{});
                } else {
                    std.debug.print("interpreter process exited with unknown status {d}", .{n});
                }

                return error.ExitedUnknownStatus;
            },
            .Signal => |num| {
                if (builtin.os.tag == .windows) {
                    unreachable;
                }

                std.debug.print(
                    "interpreter process exited with signal {d} ({f})",
                    .{ num, fmtSignalNumber(num) },
                );

                return error.ExitedWithSignal;
            },
            .Stopped => |num| {
                if (builtin.os.tag == .windows) {
                    unreachable;
                }

                std.debug.print(
                    "interpreter process stopped {d} ({f})",
                    .{ num, fmtSignalNumber(num) },
                );
                return error.StoppedWithSignal;
            },
        }
    };

    var fail = false;
    if (exit_code != expected.exit_code) {
        std.debug.print("expected exit code {d}, got {d}", .{ expected.exit_code, exit_code });
        fail = true;
    }

    if (fail) {
        return error.DifferenceInOutput;
    }
}

const std = @import("std");
const builtin = @import("builtin");
const Writer = std.Io.Writer;
