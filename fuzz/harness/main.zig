const Arguments = cli_args.CliArgs(.{
    .description = "Standalone fuzz test case executor.",
    .flags = &[_]cli_args.Flag{
        cli_args.Flag.string(
            .{
                .long = "input",
                .short = 'i',
                .description = "Path to test input, - to use stdin",
            },
            "PATH",
        ).required(),
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
    },
});

const Input = union(enum) {
    stdin: StdinBuffer,
    file: file_content.FileContent,

    const StdinBuffer = std.ArrayListAligned(u8, .fromByteUnits(16));

    fn contents(input: *const Input) []const u8 {
        return switch (input.*) {
            .stdin => |*buf| buf.items,
            .file => |*file| file.contents(),
        };
    }

    fn deinit(input: *Input, allocator: std.mem.Allocator) void {
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
    ) !Input {
        return if (!std.mem.eql(u8, path, "-")) Input{
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

            break :stdin Input{ .stdin = buf };
        };
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

    if (std.mem.eql(u8, arguments.input, "-") and
        arguments.@"replace-module" != null and
        std.mem.eql(u8, arguments.@"replace-module".?, "-"))
    {
        std.debug.print("cannot use stdout for both --input and --replace-module\n", .{});
        return 1;
    }

    var io_threaded = std.Io.Threaded.init_single_threaded;
    const io = io_threaded.ioBasic();

    const cwd = std.Io.Dir.cwd();
    var input = Input.read(
        io,
        cwd,
        arguments.input,
        &scratch,
        allocator.allocator(),
    ) catch |e| {
        switch (e) {
            error.OutOfMemory => std.debug.panic(
                "oom reading {f}",
                .{std.unicode.fmtUtf8(arguments.input)},
            ),
            else => |err| std.debug.print(
                "failed to read file {f}: {t}",
                .{ std.unicode.fmtUtf8(arguments.input), err },
            ),
        }
        return 1;
    };

    defer input.deinit(allocator.allocator());

    _ = scratch.reset(.retain_capacity);

    // Generate the WASM module
    const configuration = wasm_smith.Configuration.fromTarget(target);
    var wasm_buffer: wasm_smith.ModuleBuffer = undefined;
    wasm_smith.generateModule(
        input.contents(),
        &wasm_buffer,
        &configuration,
    ) catch |e| return switch (e) {
        error.BadInput => error.SkipZigTest,
    };

    defer wasm_smith.freeModule(&wasm_buffer);

    if (arguments.@"save-module") |save_module_path| {
        const fmt_path = std.unicode.fmtUtf8(save_module_path);
        const save_stdout = std.mem.eql(u8, "-", save_module_path);
        const file = if (save_stdout)
            std.Io.File.stdout()
        else
            cwd.createFile(io, save_module_path, .{}) catch |e| {
                std.debug.print("error opening path to save module {f}: {t}\n", .{ fmt_path, e });
                return 1;
            };
        defer if (!save_stdout) file.close(io);

        var writer = std.fs.File.adaptFromNewApi(file).writerStreaming(&.{});
        writer.interface.writeAll(wasm_buffer.bytes()) catch {
            std.debug.print("error saving module to {f}: {t}", .{ fmt_path, writer.err.? });
            return 1;
        };
    }

    var replaced_module: Input = undefined;
    const wasm: []const u8 = if (arguments.@"replace-module") |replace_module_path| replace: {
        replaced_module = Input.read(
            io,
            cwd,
            replace_module_path,
            &scratch,
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

    defer if (arguments.@"replace-module" != null) replaced_module.deinit(allocator.allocator());

    target.testOne(wasm, &scratch, allocator.allocator()) catch |e| switch (e) {
        error.SkipZigTest => {
            std.debug.print("test input rejected\n", .{});
            return 0;
        },
        else => return e,
    };

    return 0;
}

const std = @import("std");
const target = @import("target");
const file_content = @import("file_content");
const cli_args = @import("cli_args");
const wasm_smith = @import("wasm-smith");
