const Arguments = cli_args.CliArgs(.{
    .description = "Standalone fuzz test case executor.",
    .flags = &[_]cli_args.Flag{
        cli_args.Flag.string(
            .{
                .long = "input",
                .short = 'i',
                .description = "Path to test input, or - to use stdin",
            },
            "PATH",
        ).required(),
        cli_args.Flag.string(
            .{
                .long = "save-module",
                .description = "Path where the generated WASM module is written",
            },
            "PATH",
        ),
    },
});

const Input = union(enum) {
    stdin,
    path: [:0]const u8,
};

const Harness = struct {
    const SaveError = std.Io.File.OpenError || std.fs.File.WriteError;

    save_module_path: ?[:0]const u8,
    file_err: ?SaveError = null,
    io: std.Io,

    fn saveGeneratedModule(
        harness: *Harness,
        path: [:0]const u8,
        module: []const u8,
    ) SaveError!void {
        const file = try std.Io.Dir.cwd().createFile(harness.io, path, .{});
        defer file.close(harness.io);

        var writer = std.fs.File.adaptFromNewApi(file).writerStreaming(&.{});
        writer.interface.writeAll(module) catch {
            harness.file_err = writer.err;
        };

        std.debug.print("saved module to {f}\n", .{std.unicode.fmtUtf8(path)});
    }

    pub fn generatedModule(harness: *Harness, module: []const u8) void {
        const save_path = if (harness.save_module_path) |path| path else return;
        harness.saveGeneratedModule(save_path, module) catch |e| {
            harness.file_err = e;
        };
    }

    fn testOne(
        harness: *Harness,
        input: []const u8,
        scratch: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,
    ) anyerror!void {
        try @import("target").testOne(input, scratch, allocator, harness);
    }
};

pub fn main() !u8 {
    var allocator = std.heap.DebugAllocator(.{ .safety = true }).init;
    defer {
        const leak_count = allocator.detectLeaks();
        allocator.deinitWithoutLeakChecks();
        if (leak_count > 0) {
            std.debug.print("{d} leaked allocations\n", .{leak_count});
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
        break :args parser.programArguments(&scratch, &arguments_arena) catch @panic("args oom");
    };
    _ = scratch.reset(.retain_capacity);

    const input_source = if (std.mem.eql(u8, arguments.input, "-"))
        Input.stdin
    else
        Input{ .path = arguments.input };

    var io_threaded = std.Io.Threaded.init_single_threaded;
    const io = io_threaded.ioBasic();

    var input_file: file_content.FileContent = undefined;
    var input_stdin = std.ArrayListAligned(u8, .fromByteUnits(16)).empty;
    const input: []const u8 = switch (input_source) {
        .path => |input_path| path: {
            input_file = file_content.readFilePortable(
                io,
                std.Io.Dir.cwd(),
                input_path,
                scratch.allocator(),
            ) catch |e| switch (e) {
                error.OutOfMemory => std.debug.panic(
                    "oom reading {f}",
                    .{std.unicode.fmtUtf8(input_path)},
                ),
                else => |io_err| std.debug.panic(
                    "failed to open file {f}: {t}\n",
                    .{ std.unicode.fmtUtf8(input_path), io_err },
                ),
            };

            break :path input_file.contents();
        },
        .stdin => stdin: {
            var streaming = std.Io.File.stdin().readerStreaming(io, &.{});
            streaming.interface.appendRemainingAligned(
                allocator.allocator(),
                .fromByteUnits(16),
                &input_stdin,
                .unlimited,
            ) catch |e| switch (e) {
                error.OutOfMemory => @panic("oom reading stdin"),
                error.StreamTooLong => unreachable,
                error.ReadFailed => {
                    std.debug.print("error reading stdin: {t}", .{streaming.err.?});
                    return 1;
                },
            };

            break :stdin input_stdin.items;
        },
    };

    defer switch (input_source) {
        .path => input_file.deinit(),
        .stdin => input_stdin.deinit(allocator.allocator()),
    };

    defer _ = scratch.reset(.retain_capacity);

    var harness = Harness{
        .save_module_path = arguments.@"save-module",
        .io = io,
    };

    harness.testOne(input, &scratch, allocator.allocator()) catch |e| switch (e) {
        error.SkipZigTest => {
            std.debug.print("test input rejected\n", .{});
            return 0;
        },
        else => return e,
    };

    if (harness.file_err) |e| {
        std.debug.print("error saving module: {t}", .{e});
        return 1;
    }

    return 0;
}

const std = @import("std");
const file_content = @import("file_content");
const cli_args = @import("cli_args");
