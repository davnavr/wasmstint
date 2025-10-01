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
        ),
        cli_args.Flag.string(
            .{
                .long = "interpreter",
                .description = "Path to wasmstint-wasip1 executable",
            },
            "PATH",
        ).required(),
        cli_args.Flag.integerSizeSuffix(.{ .long = "max-output-bytes" }, usize)
            .withDefault(8192),
        cli_args.Flag.remainder, // additional arguments to pass to `wasmstint-wasip1`
    },
});

fn oom(context: []const u8) noreturn {
    std.debug.panic("out of memory: {s}", .{context});
}

fn abnormalExitFmt(code: u8, comptime fmt: []const u8, args: anytype) u8 {
    @branchHint(.cold);
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
    var arena = ArenaAllocator.init(page_allocator);
    defer arena.deinit();
    var scratch = ArenaAllocator.init(page_allocator);
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
            if (std.mem.eql(u8, "--", src)) {
                return abnormalExitFmt(
                    2,
                    "unexpected '--' flag\nnote: use test file to pass arguments to module",
                    .{},
                );
            }

            dst.* = arena.allocator().dupeZ(u8, src) catch oom("forwarded CLI arg");
        }

        break :args .{ .parsed = parsed, .forwarded = forwarded };
    };

    // The steps to perform are documented at `tests/wasi/doc/specification.md` or at
    // https://github.com/WebAssembly/wasi-testsuite/blob/60e08baeb4b098a0926fecd7aa7c5b1913413db2/doc/specification.md

    // TODO: Perform cleanup of test cases (maybe after open dirs are discovered?)

    _ = scratch.reset(.retain_capacity);
    const spec: Specification = if (arguments.parsed.@"test") |test_path| spec: {
        const fmt_json_path = std.unicode.fmtUtf8(test_path);
        const json_bytes = FileContent.readFileZ(
            std.fs.cwd(),
            test_path,
        ) catch |e| switch (e) {
            error.OutOfMemory => oom("JSON file bytes"),
            else => |bad| return abnormalExitFmt(
                1,
                "could not open JSON file {f}: {t}",
                .{ fmt_json_path, bad },
            ),
        };
        // defer json_bytes.deinit();

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
    } else Specification{};

    _ = scratch.reset(.retain_capacity);
    const argv: []const []const u8 = argv: {
        const argv_count = 3 +
            (spec.dirs.len * 3) +
            (spec.env.map.count() * 2) +
            arguments.forwarded.len +
            (if (spec.args.len > 0) 1 + spec.args.len else 0);

        var argv = std.ArrayListAligned([]const u8, .fromByteUnits(@sizeOf([]const u8)))
            .initCapacity(scratch.allocator(), argv_count) catch
            oom("interpreter argv");
        defer std.debug.assert(argv.items.len == argv.capacity);

        argv.appendSliceAssumeCapacity(&.{
            arguments.parsed.interpreter,
            "--module",
            arguments.parsed.module,
        });

        if (spec.dirs.len > 0) {
            @panic("TODO: arguments for preopened dirs");
        }

        var env_map = spec.env.map.iterator();
        while (env_map.next()) |entry| {
            argv.appendSliceAssumeCapacity(&.{
                "--env",
                std.fmt.allocPrint(
                    scratch.allocator(),
                    "{s}={s}",
                    .{ entry.key_ptr.*, entry.value_ptr.* },
                ) catch oom("env var"),
            });
        }

        argv.appendSliceAssumeCapacity(arguments.forwarded);

        if (spec.args.len > 0) {
            argv.appendAssumeCapacity("--");
            argv.appendSliceAssumeCapacity(spec.args);
        }

        break :argv argv.items;
    };

    var interp = std.process.Child.init(argv, scratch.allocator());
    interp.stdin_behavior = .Ignore;
    interp.stdout_behavior = .Pipe;
    interp.stderr_behavior = .Pipe;

    const page_size = std.heap.pageSize();
    var stdout = std.ArrayList(u8).initCapacity(page_allocator, page_size) catch
        oom("stdout buffer");
    defer stdout.deinit(page_allocator);
    var stderr = std.ArrayList(u8).initCapacity(page_allocator, page_size) catch
        oom("stderr buffer");
    defer stderr.deinit(page_allocator);

    const exit_code: u8 = exit: {
        const ArgvFormatter = struct {
            // Bash-style escape sequences, because those are more familiar
            fn formatString(s: []const u8, writer: *std.Io.Writer) std.Io.Writer.Error!void {
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

            pub fn format(
                args: []const []const u8,
                writer: *std.Io.Writer,
            ) std.Io.Writer.Error!void {
                for (0.., args) |i, a| {
                    if (i > 0) {
                        try writer.writeByte(' ');
                    }

                    try formatString(a, writer);
                }
            }
        };
        const fmt_argv = std.fmt.Alt([]const []const u8, ArgvFormatter.format){ .data = argv };

        interp.spawn() catch |e|
            return abnormalExitFmt(1, "{t}: failed to spawn command {f}", .{ e, fmt_argv });
        interp.collectOutput(
            page_allocator,
            &stdout,
            &stderr,
            arguments.parsed.@"max-output-bytes",
        ) catch |collect_err| {
            _ = interp.kill() catch |kill_err| return abnormalExitFmt(
                1,
                "failed to kill interpreter process {d} due to {t} after {t}",
                .{
                    if (@typeInfo(std.process.Child.Id) == .pointer)
                        @intFromPtr(interp.id)
                    else
                        interp.id,
                    kill_err,
                    collect_err,
                },
            );
        };

        const term = interp.wait() catch |e|
            return abnormalExitFmt(1, "{t}: failed to wait for process {f}", .{ e, fmt_argv });

        const SignalFormatter = struct {
            fn format(num: u32, writer: *std.Io.Writer) std.Io.Writer.Error!void {
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
        };

        switch (term) {
            .Exited => |code| break :exit code,
            .Unknown => |n| return if (builtin.os.tag == .windows)
                abnormalExitFmt(
                    1,
                    "interpreter process exited for unknown reason: {f}",
                    .{fmt_argv},
                )
            else
                abnormalExitFmt(
                    1,
                    "interpreter process exited with unknown status {d}: {f}",
                    .{ n, fmt_argv },
                ),
            .Signal => |num| if (builtin.os.tag == .windows)
                unreachable
            else
                return abnormalExitFmt(
                    1,
                    "interpreter process exited with signal {d} ({f}): {f}",
                    .{ num, std.fmt.Alt(u32, SignalFormatter.format){ .data = num }, fmt_argv },
                ),
            .Stopped => |num| if (builtin.os.tag == .windows)
                unreachable
            else
                return abnormalExitFmt(
                    1,
                    "interpreter process stopped {d}: {f}",
                    .{ num, fmt_argv },
                ),
        }
    };

    if (exit_code != spec.exit_code) {
        return abnormalExitFmt(
            1,
            "expected exit code {}, but got {}",
            .{ spec.exit_code, exit_code },
        );
    }

    var output_difference = false;
    if (std.mem.indexOfDiff(u8, stdout.items, spec.stdout)) |diff_index| {
        output_difference = true;
        printDiff("stdout", spec.stdout, @alignCast(stdout.items), diff_index);
    }

    if (std.mem.indexOfDiff(u8, stderr.items, spec.stderr)) |diff_index| {
        output_difference = true;
        printDiff("stderr", spec.stderr, @alignCast(stderr.items), diff_index);
    }

    if (output_difference) {
        return abnormalExitFmt(1, "actual outputs differ from expected", .{});
    }

    std.process.cleanExit();
    return 0;
}

fn isAsciiString(s: []const u8) bool {
    for (s) |b| {
        if (!std.ascii.isAscii(b)) {
            return false;
        }
    }

    return true;
}

fn printDiff(
    name: []const u8,
    expected: []const u8,
    actual: []align(std.heap.page_size_min) const u8,
    diff_index: usize,
) void {
    @branchHint(.unlikely);
    var stderr_buf: [512]u8 align(16) = undefined;
    const stderr = std.debug.lockStderrWriter(&stderr_buf);
    defer stderr.flush() catch {};
    const color = std.Io.tty.detectConfig(std.fs.File.stderr());

    color.setColor(stderr, .bright_red) catch {};
    stderr.writeAll("error: ") catch {};
    color.setColor(stderr, .reset) catch {};
    stderr.writeAll(name) catch {};
    stderr.writeAll(" stream differs:\n") catch {};

    if (isAsciiString(expected) and isAsciiString(actual)) {
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

        color.setColor(stderr, .reset) catch {};
    } else {
        @branchHint(.unlikely);
        @panic("TODO: print hex diff");
    }
}

fn printDiffLine(
    stderr: *std.Io.Writer,
    config: std.Io.tty.Config,
    color: std.Io.tty.Color,
    prefix_char: u8,
    remaining: *[]const u8,
) void {
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

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const page_allocator = std.heap.page_allocator;
const cli_args = @import("cli_args");
const FileContent = @import("FileContent");

test {
    _ = main;
}
