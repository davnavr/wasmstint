const testOne: fn (
    []const u8,
    *std.heap.ArenaAllocator,
    std.mem.Allocator,
) anyerror!void = @import("target").testOne;

const Input = union(enum) {
    stdin,
    path: [:0]const u8,
};

pub fn main() !u8 {
    const input_source = input: {
        if (std.os.argv.len < 2) {
            std.debug.print("specify path to input file or - for stdin\n", .{});
            return 2;
        }

        const input_path: [:0]const u8 = std.mem.sliceTo(std.os.argv[1], 0);
        break :input if (std.mem.eql(u8, input_path, "-"))
            Input.stdin
        else
            Input{ .path = input_path };
    };

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

    testOne(input, &scratch, allocator.allocator()) catch |e| switch (e) {
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
