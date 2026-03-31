pub const std_options = std.Options{
    .log_level = .debug,
    .networking = false,
};

const needs_wasm = @typeInfo(@TypeOf(target.testOne)).@"fn".params.len == 4;

const Arguments = cli_args.CliArgs(.{
    .description = "Standalone fuzz test case executor.",
    .flags = &(.{
        cli_args.Flag.string(
            .{
                .long = "input",
                .short = 'i',
                .description = "Path to test input, - to use stdin",
            },
            "PATH",
        ).required(),
        cli_args.Flag.boolean(.{
            .long = "skip-bad-input",
            .description = "Don't fail if error.BadInput is returned",
        }),
        cli_args.Flag.boolean(.{
            .long = "skip-out-of-memory",
            .description = "Don't fail if error.OutOfMemory is returned",
        }),
    } ++ if (needs_wasm) .{
        cli_args.Flag.string(
            .{
                .long = "save-module",
                .description = "Path where the generated WASM module is written, - to use stdout",
            },
            "PATH",
        ),
        cli_args.Flag.string(
            .{
                .long = "replace-module",
                .description = "Path to WASM module to use instead, - to use stdout",
            },
            "PATH",
        ),
    } else .{}),
});

const InputSource = union(enum) {
    stdin: StdinBuffer,
    file: file_content.FileContent,

    const StdinBuffer = std.ArrayListAligned(u8, .fromByteUnits(16));

    fn contents(input: *const InputSource) []const u8 {
        return switch (input.*) {
            .stdin => |*buf| buf.items,
            .file => |*file| file.contents(),
        };
    }

    fn deinit(input: *InputSource, allocator: std.mem.Allocator) void {
        switch (input.*) {
            .stdin => |*buf| buf.deinit(allocator),
            .file => |*file| file.deinit(),
        }
        input.* = undefined;
    }

    fn read(
        io: std.Io,
        dir: std.Io.Dir,
        path: [:0]const u8,
        scratch: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,
    ) !InputSource {
        return if (!std.mem.eql(u8, path, "-")) InputSource{
            .file = try file_content.readFilePortable(io, dir, path, scratch.allocator()),
        } else stdin: {
            var buf = StdinBuffer.empty;
            var streaming = std.Io.File.stdin().readerStreaming(io, &.{});
            streaming.interface.appendRemainingAligned(
                allocator,
                .fromByteUnits(16),
                &buf,
                .unlimited,
            ) catch |e| return switch (e) {
                error.OutOfMemory => |oom| oom,
                error.StreamTooLong => unreachable,
                error.ReadFailed => streaming.err.?,
            };

            break :stdin InputSource{ .stdin = buf };
        };
    }
};

pub fn main(init: std.process.Init.Minimal) !u8 {
    var allocator = std.heap.DebugAllocator(.{ .safety = true }).init;
    defer {
        const leak_count = allocator.detectLeaks();
        allocator.deinitWithoutLeakChecks();
        if (leak_count > 0) {
            std.log.err("{d} leaked allocations", .{leak_count});
            std.process.exit(1);
        }
    }

    var scratch = std.heap.ArenaAllocator.init(allocator.allocator());
    defer scratch.deinit();

    var arguments_arena = std.heap.ArenaAllocator.init(allocator.allocator());
    defer arguments_arena.deinit();

    const arguments = args: {
        var parser: Arguments = undefined;
        parser.init();
        break :args parser.programArguments(init.args, &scratch, &arguments_arena) catch
            @panic("args oom");
    };
    _ = scratch.reset(.retain_capacity);

    if (needs_wasm and
        std.mem.eql(u8, arguments.input, "-") and
        arguments.@"replace-module" != null and
        std.mem.eql(u8, arguments.@"replace-module".?, "-"))
    {
        std.log.err("cannot use stdout for both --input and --replace-module", .{});
        return 1;
    }

    var io_threaded = std.Io.Threaded.init_single_threaded;
    const io = io_threaded.io();

    const cwd = std.Io.Dir.cwd();
    var input_src = InputSource.read(
        io,
        cwd,
        arguments.input,
        &scratch,
        allocator.allocator(),
    ) catch |e| switch (e) {
        error.OutOfMemory => std.debug.panic(
            "oom reading {f}",
            .{std.unicode.fmtUtf8(arguments.input)},
        ),
        else => |err| {
            std.log.err(
                "failed to read file {f}: {t}",
                .{ std.unicode.fmtUtf8(arguments.input), err },
            );
            return 1;
        },
    };

    defer input_src.deinit(allocator.allocator());

    _ = scratch.reset(.retain_capacity);

    var input = if (needs_wasm) fuzz_data.Input.init(input_src.contents());

    // Generate the WASM module
    const configuration = if (needs_wasm) ffi.wasm_smith.Configuration.fromTarget(target);
    var wasm_buffer: if (needs_wasm) ffi.wasm_smith.ModuleBuffer else void = undefined;
    if (needs_wasm) {
        wasm_buffer.generate(&input, &configuration) catch |e| return switch (e) {
            error.BadInput => {
                std.log.err("failed to generate WASM module", .{});
                return @intFromBool(!arguments.@"skip-bad-input");
            },
        };
    }
    defer if (needs_wasm) wasm_buffer.deinit();

    if (!needs_wasm) {
        // no module to save
    } else if (arguments.@"save-module") |save_module_path| {
        const fmt_path = std.unicode.fmtUtf8(save_module_path);
        const save_stdout = std.mem.eql(u8, "-", save_module_path);
        const file = if (save_stdout)
            std.Io.File.stdout()
        else
            cwd.createFile(io, save_module_path, .{}) catch |e| {
                std.log.err("could not open path to save module {f}: {t}", .{ fmt_path, e });
                return 1;
            };
        defer if (!save_stdout) file.close(io);

        var writer = file.writerStreaming(io, &.{});
        writer.interface.writeAll(wasm_buffer.bytes()) catch {
            std.log.err("could not save module to {f}: {t}", .{ fmt_path, writer.err.? });
            return 1;
        };
    }

    var replaced_module: if (needs_wasm) InputSource else void = undefined;
    const wasm: if (needs_wasm) []const u8 else void = if (comptime !needs_wasm) {
        // nothing
    } else if (arguments.@"replace-module") |replace_module_path| replace: {
        replaced_module = InputSource.read(
            io,
            cwd,
            replace_module_path,
            &scratch,
            allocator.allocator(),
        ) catch |e| {
            std.log.err(
                "could not open module file {f}: {t}",
                .{ std.unicode.fmtUtf8(replace_module_path), e },
            );
            return 1;
        };
        break :replace replaced_module.contents();
    } else wasm_buffer.bytes();

    defer if (needs_wasm and arguments.@"replace-module" != null) {
        replaced_module.deinit(allocator.allocator());
    };

    @call(
        .auto,
        target.testOne,
        (if (needs_wasm) .{ wasm, &input } else .{input_src.contents()}) ++
            .{ &scratch, allocator.allocator() },
    ) catch |e| err: {
        switch (@as(anyerror, e)) {
            error.BadInput => if (arguments.@"skip-bad-input") {
                std.log.warn("test case rejected", .{});
                if (@errorReturnTrace()) |t| {
                    std.debug.dumpStackTrace(t);
                }
                break :err;
            },
            error.OutOfMemory => if (arguments.@"skip-out-of-memory") {
                std.log.warn("test case out-of-memory", .{});
                if (@errorReturnTrace()) |t| {
                    std.debug.dumpStackTrace(t);
                }
                break :err;
            },
            else => {},
        }

        return e;
    };

    return 0;
}

const std = @import("std");
const target = @import("target");
const file_content = @import("file_content");
const cli_args = @import("cli_args");
const ffi = @import("ffi");
const fuzz_data = @import("fuzz_data");
