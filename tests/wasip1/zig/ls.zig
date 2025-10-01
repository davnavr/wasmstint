pub fn main() !void {
    var stdout_buf: [4096]u8 align(16) = undefined;
    var stdout_writer = std.fs.File.stdout().writerStreaming(&stdout_buf);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    const cwd = std.fs.cwd();
    {
        var prestat: wasi.prestat_t = undefined;
        switch (wasi.fd_prestat_get(cwd.fd, &prestat)) {
            .SUCCESS => {},
            else => |err| return std.posix.unexpectedErrno(err),
        }

        const name_buf = try std.heap.wasm_allocator.alignedAlloc(
            u8,
            .@"16",
            prestat.u.dir.pr_name_len,
        );
        // defer std.heap.wasm_allocator.free(name_buf);

        switch (wasi.fd_prestat_dir_name(cwd.fd, name_buf.ptr, name_buf.len)) {
            .SUCCESS => {},
            else => |err| return std.posix.unexpectedErrno(err),
        }

        try stdout.print("{s}\n", .{name_buf});
    }

    const kind_width = std.fmt.comptimePrint("{[width]}", .{
        .width = comptime width: {
            var max = 0;
            for (std.meta.fieldNames(std.fs.File.Kind)) |kind| {
                max = @max(max, kind.len);
            }
            break :width max;
        },
    });

    var iterator = cwd.iterateAssumeFirstIteration();
    try stdout.print("total {}\n", .{iterator.end_index - iterator.index});
    while (try iterator.next()) |entry| {
        try stdout.print(
            "{[kind]t: >" ++ kind_width ++ "} {[name]s}\n",
            .{ .kind = entry.kind, .name = entry.name },
        );
    }
}

const std = @import("std");
const wasi = std.os.wasi;
