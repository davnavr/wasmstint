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

fn formatSignalNumber(num: std.posix.SIG, writer: *Io.Writer) Io.Writer.Error!void {
    switch (num) {
        else => |known| try writer.print("SIG{t}", .{known}),
        _ => try writer.writeAll("unknown signal"),
    }
}

pub fn fmtSignalNumber(num: std.posix.SIG) std.fmt.Alt(std.posix.SIG, formatSignalNumber) {
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

    stdio_max_bytes: u64 = 1 * 1024 * 1024, // 1 MiB

    /// How much time, in nanoseconds, the interpreter process can execute for.
    timeout: Io.Timeout = .{
        .duration = .{
            .raw = .fromNanoseconds(10 * std.time.ns_per_s),
            .clock = .awake,
        },
    },
};

pub fn invokeWasiInterpreter(
    io: Io,
    allocator: std.mem.Allocator,
    interpreter: []const u8,
    wasm: []const u8,
    arguments: WasiArguments,
    expected: ExpectedOutput,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var stdout: []const u8 = undefined;
    var stderr: []const u8 = undefined;
    const exit_code = exit: {
        const argv = try arguments.initInterpreterProcess(interpreter, wasm, &arena);
        errdefer std.debug.print("error in interpreter subprocess {f}\n", .{fmtArgv(argv)});
        // `std.process.run()` doesn't allow passing stdin
        var interp = try std.process.spawn(io, .{
            .argv = argv,
            .stdin = if (expected.stdin.len == 0) .ignore else .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        defer interp.kill(io);

        if (expected.stdin.len > 0) {
            try interp.stdin.?.writeStreamingAll(io, expected.stdin);
        }

        // Taken from `std.process.run()`, because I'm lazy and `collectOutput()` was removed.
        var readers_buf: Io.File.MultiReader.Buffer(2) = undefined;
        var readers: Io.File.MultiReader = undefined;
        readers.init(
            arena.allocator(),
            io,
            readers_buf.toStreams(),
            &.{ interp.stdout.?, interp.stderr.? },
        );

        const stdout_reader = readers.reader(0);
        const stderr_reader = readers.reader(1);

        const capacity = expected.stdout.len + expected.stderr.len;
        while (readers.fill(capacity, expected.timeout)) |_| {
            if (stdout_reader.buffered().len > expected.stdio_max_bytes) return error.StreamTooLong;
            if (stderr_reader.buffered().len > expected.stdio_max_bytes) return error.StreamTooLong;
        } else |e| switch (e) {
            error.EndOfStream => {},
            else => |err| return err,
        }

        try readers.checkAnyError();
        stdout = stdout_reader.buffered();
        stderr = stderr_reader.buffered();
        switch (try interp.wait(io)) {
            .exited => |code| break :exit code,
            .unknown => |n| {
                if (builtin.os.tag == .windows) {
                    std.debug.print("interpreter process exited for unknown reason\n", .{});
                } else {
                    std.debug.print("interpreter process exited with unknown status {d}\n", .{n});
                }

                return error.ExitedUnknownStatus;
            },
            .signal => |num| {
                if (builtin.os.tag == .windows) {
                    unreachable;
                }

                std.debug.print(
                    "interpreter process exited with signal {d} ({f})\n",
                    .{ @intFromEnum(num), fmtSignalNumber(num) },
                );

                return error.ExitedWithSignal;
            },
            .stopped => |num| {
                if (builtin.os.tag == .windows) {
                    unreachable;
                }

                std.debug.print("interpreter process stopped ({d})\n", .{num});

                return error.StoppedWithSignal;
            },
        }
    };

    var fail = false;
    if (exit_code != expected.exit_code) {
        std.debug.print("expected exit code {d}, got {d}\n", .{ expected.exit_code, exit_code });
        fail = true;
    }

    if (std.mem.indexOfDiff(u8, stdout, expected.stdout)) |diff_index| {
        fail = true;
        std.debug.print("stdout stream differs at byte index {d}:\n", .{diff_index});
        try printDiff(expected.stdout, stdout, diff_index);
    }

    if (std.mem.indexOfDiff(u8, stderr, expected.stderr)) |diff_index| {
        fail = true;
        std.debug.print("stderr stream differs at byte index {d}:\n", .{diff_index});
        try printDiff(expected.stderr, stderr, diff_index);
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
    const stderr = std.debug.lockStderr(&stderr_buf).terminal();
    defer stderr.writer.flush() catch {};

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
                printDiffLine(stderr, .bright_green, '+', &remaining_expected);
            }

            if (remaining_actual.len > 0) {
                printDiffLine(stderr, .bright_red, '-', &remaining_actual);
            }
        }

        try stderr.setColor(.reset);
    } else {
        // @branchHint(.unlikely);
        try printDiffHexDump(stderr, expected, actual);
    }
}

fn printDiffLine( // TODO: currently unused
    stderr: Terminal,
    color: Color,
    prefix_char: u8,
    remaining: *[]const u8,
) !void {
    const newline_index = std.mem.indexOfScalar(u8, remaining.*, '\n');
    const line = remaining.*[0..(newline_index orelse remaining.len)];
    defer remaining.* = remaining.*[(if (newline_index) |i| i + 1 else remaining.len)..];
    stderr.setColor(color) catch {};
    stderr.writer.writeAll(&.{ prefix_char, ' ' }) catch {};

    for (line) |b| {
        switch (@as(u7, @intCast(b))) {
            '\n' => unreachable,
            inline 0...std.ascii.control_code.ht,
            std.ascii.control_code.vt...std.ascii.control_code.us,
            => |ctrl| {
                const codepoint = @as(u24, 0x2400) + ctrl;
                stderr.writer.writeAll(&std.unicode.utf8EncodeComptime(codepoint)) catch {};
            },
            '\x7F' => stderr.writer.writeAll("\u{2421}") catch {},
            else => stderr.writer.writeByte(b) catch {},
        }
    }

    stderr.writer.writeByte('\n') catch {};
}

const hex_dump_line_width = 16;

fn printDiffHexDump(stderr: Terminal, expected: []const u8, actual: []const u8) !void {
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
        defer stderr.writer.flush() catch {};
        const expected_line = remaining_expected[0..@min(hex_dump_line_width, remaining_expected.len)];
        remaining_expected = remaining_expected[expected_line.len..];

        const actual_line = remaining_actual[0..@min(hex_dump_line_width, remaining_actual.len)];
        remaining_actual = remaining_actual[actual_line.len..];

        try stderr.setColor(.bright_black);
        try stderr.writer.print("{[addr]X:0>[width]}", .{ .addr = addr, .width = addr_width });
        try stderr.setColor(.reset);
        try stderr.writer.writeAll(" |");
        try printDiffHexDumpLine(stderr, expected_line, actual_line, expected_diff_color);
        try printDiffHexDumpLine(stderr, actual_line, expected_line, actual_diff_color);
        try stderr.writer.writeByte('\n');
    }
}

fn setColorInfallible(terminal: Terminal, color: Color) error{ Unexpected, Canceled }!void {
    return terminal.setColor(color) catch |e| switch (e) {
        error.WriteFailed => unreachable,
        error.Unexpected, error.Canceled => |err| err,
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
    stderr: Terminal,
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
            try setColorInfallible(.{ .writer = &hex, .mode = stderr.mode }, diff_color);
            try setColorInfallible(.{ .writer = &text, .mode = stderr.mode }, diff_color);
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
            try setColorInfallible(.{ .writer = &hex, .mode = stderr.mode }, .reset);
            try setColorInfallible(.{ .writer = &text, .mode = stderr.mode }, .reset);
        }
    }

    const remainder_count = hex_dump_line_width - line.len;
    try stderr.writer.writeAll(hex.buffered());
    try stderr.writer.splatByteAll(' ', 3 * remainder_count);
    try stderr.writer.writeAll(" |");
    try stderr.writer.writeAll(text.buffered());
    try stderr.writer.splatBytesAll("\u{25E6}", remainder_count);
    try stderr.writer.writeAll("|");
}

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Writer = Io.Writer;
const Terminal = Io.Terminal;
const Color = Terminal.Color;
