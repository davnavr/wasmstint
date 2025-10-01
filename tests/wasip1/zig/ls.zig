pub fn main() !void {
    var stdout_buf: [512]u8 align(16) = undefined;
    var stdout_writer = std.fs.File.stdout().writerStreaming(&stdout_buf);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    const kind_width = std.fmt.comptimePrint("{[width]}", .{
        .width = comptime width: {
            var max = 0;
            for (std.meta.fieldNames(std.fs.File.Kind)) |kind| {
                max = @max(max, kind.len);
            }
            break :width max;
        },
    });

    var iterator = std.fs.cwd().iterate();
    while (try iterator.next()) |entry| {
        try stdout.print(
            "{[kind]t: >" ++ kind_width ++ "} {[name]f}\n",
            .{ .kind = entry.kind, .name = std.unicode.fmtUtf8(entry.name) },
        );
    }
}

const std = @import("std");
