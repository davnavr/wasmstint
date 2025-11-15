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
        cli_args.Flag.string(
            .{
                .long = "replace-module",
                .description = "Path to WASM module to use instead",
            },
            "PATH",
        ),
    },
});

const Input = union(enum) {
    stdin,
    path: [:0]const u8,
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

    // Generate the WASM module
    const configuration = wasm_smith.Configuration{};
    var wasm_buffer: wasm_smith.ModuleBuffer = undefined;
    wasm_smith.generateModule(input, &wasm_buffer, &configuration) catch |e| return switch (e) {
        error.BadInput => error.SkipZigTest,
    };

    defer wasm_smith.freeModule(&wasm_buffer);

    if (arguments.@"save-module") |save_module_path| {
        const fmt_path = std.unicode.fmtUtf8(save_module_path);
        const file = std.Io.Dir.cwd().createFile(io, save_module_path, .{}) catch |e| {
            std.debug.print("error opening path to save module {f}: {t}\n", .{ fmt_path, e });
            return 1;
        };
        defer file.close(io);

        var writer = std.fs.File.adaptFromNewApi(file).writerStreaming(&.{});
        writer.interface.writeAll(wasm_buffer.bytes()) catch {
            std.debug.print("error saving module to {f}: {t}", .{ fmt_path, writer.err.? });
            return 1;
        };
    }

    var replaced_module: file_content.FileContent = undefined;
    const wasm: []const u8 = if (arguments.@"replace-module") |replace_module_path| replace: {
        replaced_module = file_content.readFilePortable(
            io,
            std.Io.Dir.cwd(),
            replace_module_path,
            allocator.allocator(),
        ) catch |e| {
            std.debug.print(
                "could not open module file {f}: {t}\n",
                .{ std.unicode.fmtUtf8(replace_module_path), e },
            );
            return 1;
        };
        break :replace replaced_module.contents();
    } else wasm_buffer.bytes();

    defer if (arguments.@"replace-module" != null) replaced_module.deinit();

    @import("target").testOne(wasm, &scratch, allocator.allocator()) catch |e| switch (e) {
        error.SkipZigTest => {
            std.debug.print("test input rejected\n", .{});
            return 0;
        },
        else => return e,
    };

    return 0;
}

const std = @import("std");
const file_content = @import("file_content");
const cli_args = @import("cli_args");
const wasm_smith = @import("wasm-smith");
