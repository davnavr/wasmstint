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
    const cwd = std.fs.cwd();
    const spec: Specification = if (arguments.parsed.@"test") |test_path| spec: {
        const fmt_json_path = std.unicode.fmtUtf8(test_path);
        const json_bytes = FileContent.readFileZ(cwd, test_path) catch |e| switch (e) {
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

    const interpreter_real_path = cwd.realpathAlloc(
        arena.allocator(),
        arguments.parsed.interpreter,
    ) catch |e| return abnormalExitFmt(
        1,
        "{t}: could not get path to interpreter {f}",
        .{ e, std.unicode.fmtUtf8(arguments.parsed.interpreter) },
    );

    const module_real_path = cwd.realpathAlloc(
        arena.allocator(),
        arguments.parsed.module,
    ) catch |e| return abnormalExitFmt(
        1,
        "{t}: could not get path to module {f}",
        .{ e, std.unicode.fmtUtf8(arguments.parsed.module) },
    );

    _ = scratch.reset(.retain_capacity);
    const argv: []const []const u8 = argv: {
        const argv_count = 3 +
            (spec.dirs.len * 4) +
            (spec.env.map.count() * 2) +
            arguments.forwarded.len +
            (if (spec.args.len > 0) 1 + spec.args.len else 0);

        var argv = std.ArrayListAligned([]const u8, .fromByteUnits(@sizeOf([]const u8)))
            .initCapacity(scratch.allocator(), argv_count) catch
            oom("interpreter argv");
        defer std.debug.assert(argv.items.len == argv.capacity);

        argv.appendSliceAssumeCapacity(&.{
            interpreter_real_path,
            "--module",
            module_real_path,
        });

        if (spec.dirs.len > 0) {
            for (spec.dirs) |dir| {
                const dir_rel = std.mem.concat(arena.allocator(), u8, &.{ "./", dir }) catch
                    oom("relative dir path");
                argv.appendSliceAssumeCapacity(&.{ "--dir", dir_rel, dir, "rw" });
            }
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

    if (arguments.parsed.@"test") |test_path| {
        // TODO(zig): https://github.com/ziglang/zig/issues/5190
        interp.cwd = std.fs.path.dirname(test_path);
    }

    const page_size = std.heap.pageSize();
    var stdout = std.ArrayList(u8).initCapacity(page_allocator, page_size) catch
        oom("stdout buffer");
    defer stdout.deinit(page_allocator);
    var stderr = std.ArrayList(u8).initCapacity(page_allocator, page_size) catch
        oom("stderr buffer");
    defer stderr.deinit(page_allocator);

    const exit_code: u8 = exit: {
        const fmt_argv = subprocess.fmtArgv(argv);

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
                    .{ num, subprocess.fmtSignalNumber(num), fmt_argv },
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

    var output_difference = false;
    if (std.mem.indexOfDiff(u8, stdout.items, spec.stdout)) |diff_index| {
        output_difference = true;
        subprocess.printDiff("stdout", spec.stdout, @alignCast(stdout.items), diff_index);
    }

    if (std.mem.indexOfDiff(u8, stderr.items, spec.stderr)) |diff_index| {
        output_difference = true;
        subprocess.printDiff("stderr", spec.stderr, @alignCast(stderr.items), diff_index);
    }

    if (exit_code != spec.exit_code) {
        return abnormalExitFmt(
            1,
            "expected exit code {}, but got {}",
            .{ spec.exit_code, exit_code },
        );
    }

    if (output_difference) {
        return abnormalExitFmt(1, "actual outputs differ from expected", .{});
    }

    std.process.cleanExit();
    return 0;
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const page_allocator = std.heap.page_allocator;
const cli_args = @import("cli_args");
const subprocess = @import("subprocess");
const FileContent = @import("FileContent");

test {
    _ = main;
}
