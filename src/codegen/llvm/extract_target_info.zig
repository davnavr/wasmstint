pub const std_options: std.Options = .{ .networking = false };

pub fn main(init: std.process.Init.Minimal) !void {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

    var cli_args = init.args.iterateAllocator(arena.allocator()) catch @panic("oom");
    _ = cli_args.next().?;

    const cwd = std.Io.Dir.cwd();
    const ll_file: []align(32) const u8 = file: {
        const path = cli_args.next().?;
        break :file cwd.readFileAllocOptions(
            io,
            path,
            std.heap.page_allocator,
            .limited(4096 * 4),
            .@"32",
            null,
        ) catch |e| {
            std.debug.panic("cannot read {s}: {t}", .{ path, e });
            return e;
        };
    };
    std.debug.assert(cli_args.next() == null);

    var stdout_buf: [4096]u8 align(16) = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    try std.zon.stringify.serialize(.{
        .data_layout = std.mem.cutScalar(
            u8,
            std.mem.cut(u8, ll_file, "target datalayout = \"").?.@"1",
            '\"',
        ).?.@"0",
        .triple = std.mem.cutScalar(
            u8,
            std.mem.cut(u8, ll_file, "target triple = \"").?.@"1",
            '\"',
        ).?.@"0",
        .cpu_features = std.mem.cutScalar(
            u8,
            std.mem.cut(u8, ll_file, "\"target-features\"=\"").?.@"1",
            '\"',
        ).?.@"0",
    }, .{ .whitespace = false }, &stdout.interface);

    try stdout.flush();
}

const std = @import("std");
