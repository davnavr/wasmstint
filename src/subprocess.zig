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
    if (std.enums.fromInt(std.posix.SIG, num)) |known| {
        try writer.print("SIG{t}", .{known});
    } else {
        try writer.writeAll("unknown signal");
    }

    try writer.print(" {d}", .{num});
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
    // TODO: Make these paths to files, to allow auto update via environment variable
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

        errdefer std.debug.print("error in interpreter subprocess {f}\n", .{fmtArgv(argv)});

        try interp.spawn();
        try interp.waitForSpawn();
        interp.collectOutput(
            std.testing.allocator,
            &stdout,
            &stderr,
            expected.stdio_max_bytes,
        ) catch |err| {
            _ = interp.kill() catch |kill_err| {
                std.debug.print("attempt to kill interpreter process due to {t} failed\n", .{err});
                return kill_err;
            };

            return err;
        };

        switch (try interp.wait()) {
            .Exited => |code| break :exit code,
            .Unknown => |n| {
                if (builtin.os.tag == .windows) {
                    std.debug.print("interpreter process exited for unknown reason\n", .{});
                } else {
                    std.debug.print("interpreter process exited with unknown status {d}\n", .{n});
                }

                return error.ExitedUnknownStatus;
            },
            .Signal => |num| {
                if (builtin.os.tag == .windows) {
                    unreachable;
                }

                std.debug.print(
                    "interpreter process exited with signal {d} ({f})\n",
                    .{ num, fmtSignalNumber(num) },
                );

                return error.ExitedWithSignal;
            },
            .Stopped => |num| {
                if (builtin.os.tag == .windows) {
                    unreachable;
                }

                std.debug.print(
                    "interpreter process stopped {d} ({f})\n",
                    .{ num, fmtSignalNumber(num) },
                );
                return error.StoppedWithSignal;
            },
        }
    };

    var fail = false;
    if (exit_code != expected.exit_code) {
        std.debug.print("expected exit code {d}, got {d}\n", .{ expected.exit_code, exit_code });
        fail = true;
    }

    if (std.mem.indexOfDiff(u8, stdout.items, expected.stdout)) |diff_index| {
        fail = true;
        std.debug.print("stdout stream differs at byte index {d}:\n", .{diff_index});
        try printDiff(expected.stdout, stdout.items, diff_index);
    }

    if (std.mem.indexOfDiff(u8, stderr.items, expected.stderr)) |diff_index| {
        fail = true;
        std.debug.print("stderr stream differs at byte index {d}:\n", .{diff_index});
        try printDiff(expected.stderr, stderr.items, diff_index);
    }

    if (fail) {
        return error.DifferenceInOutput;
    }
}

fn isAsciiString(s: []const u8) bool {
    for (s) |b| {
        if (!std.ascii.isAscii(b)) {
            return false;
        }
    }

    return true;
}

fn printDiff(expected: []const u8, actual: []const u8, diff_index: usize) !void {
    @branchHint(.unlikely);
    var stderr_buf: [256]u8 align(16) = undefined;
    const stderr, const color = std.debug.lockStderrWriter(&stderr_buf);
    defer stderr.flush() catch {};

    std.debug.assert(@max(expected.len, actual.len) > 0);

    if (false and isAsciiString(expected) and isAsciiString(actual)) {
        const first_line_start = if (std.mem.lastIndexOfScalar(
            u8,
            expected[0..diff_index],
            '\n',
        )) |i| i + 1 else 0;

        var remaining_expected = expected[first_line_start..];
        var remaining_actual = actual[first_line_start..];
        while (remaining_expected.len > 0 or remaining_actual.len > 0) {
            if (remaining_expected.len > 0) {
                printDiffLine(stderr, color, .bright_green, '+', &remaining_expected);
            }

            if (remaining_actual.len > 0) {
                printDiffLine(stderr, color, .bright_red, '-', &remaining_actual);
            }
        }

        try color.setColor(stderr, .reset);
    } else {
        @branchHint(.unlikely);
        try printDiffHexDump(stderr, color, expected, actual);
    }
}

fn printDiffLine( // TODO
    stderr: *std.Io.Writer,
    config: HasColor,
    color: Color,
    prefix_char: u8,
    remaining: *[]const u8,
) !void {
    const newline_index = std.mem.indexOfScalar(u8, remaining.*, '\n');
    const line = remaining.*[0..(newline_index orelse remaining.len)];
    defer remaining.* = remaining.*[(if (newline_index) |i| i + 1 else remaining.len)..];
    config.setColor(stderr, color) catch {};
    stderr.writeAll(&.{ prefix_char, ' ' }) catch {};

    for (line) |b| {
        switch (@as(u7, @intCast(b))) {
            '\n' => unreachable,
            inline 0...std.ascii.control_code.ht,
            std.ascii.control_code.vt...std.ascii.control_code.us,
            => |ctrl| {
                const codepoint = @as(u24, 0x2400) + ctrl;
                stderr.writeAll(&std.unicode.utf8EncodeComptime(codepoint)) catch {};
            },
            '\x7F' => stderr.writeAll("\u{2421}") catch {},
            else => stderr.writeByte(b) catch {},
        }
    }

    stderr.writeByte('\n') catch {};
}

const hex_dump_line_width = 16;

fn printDiffHexDump(
    stderr: *std.Io.Writer,
    config: HasColor,
    expected: []const u8,
    actual: []const u8,
) !void {
    const expected_diff_color = Color.bright_green;
    const actual_diff_color = Color.bright_red;

    const max_len = @max(expected.len, actual.len);
    std.debug.assert(max_len > 0);
    const addr_width = std.math.log2_int_ceil(usize, max_len + 1);
    var remaining_expected = expected;
    var remaining_actual = actual;

    var addr: usize = 0;
    while (remaining_expected.len > 0 or remaining_actual.len > 0) {
        defer addr += hex_dump_line_width;
        defer stderr.flush() catch {};
        const expected_line = remaining_expected[0..@min(hex_dump_line_width, remaining_expected.len)];
        remaining_expected = remaining_expected[expected_line.len..];

        const actual_line = remaining_actual[0..@min(hex_dump_line_width, remaining_actual.len)];
        remaining_actual = remaining_actual[actual_line.len..];

        try config.setColor(stderr, .bright_black);
        try stderr.print("{[addr]X:0>[width]}", .{ .addr = addr, .width = addr_width });
        try config.setColor(stderr, .reset);
        try stderr.writeAll(" |");
        try printDiffHexDumpLine(stderr, config, expected_line, actual_line, expected_diff_color);
        try printDiffHexDumpLine(stderr, config, actual_line, expected_line, actual_diff_color);
        try stderr.writeByte('\n');
    }
}

fn setColorInfallible(writer: *Writer, config: HasColor, color: Color) error{Unexpected}!void {
    return config.setColor(writer, color) catch |e| switch (e) {
        error.WriteFailed => unreachable,
        error.Unexpected => |err| err,
    };
}

const cp_437_non_ascii: [128]u14 = .{
    0xC7,   0xFC,   0xE9,   0xE2,   0xE4,   0xE0,   0xE5,   0xE7,   0xEA,   0xEB,   0xE8,   0xEF,   0xEE,   0xEC,   0xC4,   0xC5,
    0xC9,   0xE6,   0xC6,   0xF4,   0xF8,   0xF2,   0xFB,   0xF9,   0xFF,   0xD6,   0xDC,   0xA2,   0xA3,   0xA5,   0x20A7, 0x192,
    0xE1,   0xED,   0xF3,   0xFA,   0xF1,   0xD1,   0xAA,   0xBA,   0xBF,   0x2310, 0xAC,   0xBD,   0xBC,   0xA1,   0xAB,   0xBB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x3B1,  0xDF,   0x393,  0x3C0,  0x3A3,  0x3C3,  0xB5,   0x3C4,  0x3A6,  0x398,  0x3A9,  0x3B4,  0x221E, 0x3C6,  0x3B5,  0x2229,
    0x2261, 0xB1,   0x2265, 0x2264, 0x2320, 0x2321, 0xF7,   0x2248, 0xB0,   0x2119, 0xB7,   0x221A, 0x207F, 0xB2,   0x25A0, 0x237D,
};

fn printDiffHexDumpLine(
    stderr: *Writer,
    config: HasColor,
    line: []const u8,
    other: []const u8,
    diff_color: Color,
) !void {
    var hex_buf: [(3 + 10) * hex_dump_line_width]u8 = undefined;
    var hex = Writer.fixed(&hex_buf);
    var text_buf: [(4 + 10) * hex_dump_line_width]u8 = undefined;
    var text = Writer.fixed(&text_buf);
    for (line, 0..) |line_byte, i| {
        const other_byte = if (i < other.len) other[i] else null;
        if (line_byte != other_byte) {
            try setColorInfallible(&hex, config, diff_color);
            try setColorInfallible(&text, config, diff_color);
        }

        hex.print(" {X:0>2}", .{line_byte}) catch unreachable;

        var utf8_buf: [4]u8 align(4) = undefined;
        text.writeAll(switch (line_byte) {
            0...std.ascii.control_code.us => ctrl: {
                const codepoint = @as(u21, 0x2400) + line_byte; // Use unicode control pictures
                const len = std.unicode.utf8Encode(codepoint, &utf8_buf) catch unreachable;
                break :ctrl utf8_buf[0..len];
            },
            std.ascii.control_code.del => "\u{2421}",
            ' '...'~' => &[1]u8{line_byte},
            else => non_ascii: {
                // Use Code Page 437, this isn't used for ASCII control since it looks nicer
                const codepoint = cp_437_non_ascii[line_byte - 0x80];
                const len = std.unicode.utf8Encode(codepoint, &utf8_buf) catch unreachable;
                break :non_ascii utf8_buf[0..len];
            },
        }) catch unreachable;

        if (line_byte != other_byte) {
            try setColorInfallible(&hex, config, .reset);
            try setColorInfallible(&text, config, .reset);
        }
    }

    const remainder_count = hex_dump_line_width - line.len;
    try stderr.writeAll(hex.buffered());
    try stderr.splatByteAll(' ', 3 * remainder_count);
    try stderr.writeAll(" |");
    try stderr.writeAll(text.buffered());
    try stderr.splatBytesAll("\u{25E6}", remainder_count);
    try stderr.writeAll("|");
}

const std = @import("std");
const builtin = @import("builtin");
const Writer = std.Io.Writer;
const HasColor = std.Io.tty.Config;
const Color = std.Io.tty.Color;
