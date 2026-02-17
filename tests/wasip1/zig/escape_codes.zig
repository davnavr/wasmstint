fn printColor(out: std.Io.Terminal, color: std.Io.Terminal.Color) !void {
    try out.setColor(color);
    try out.writer.print("{t}\n", .{color});
}

pub fn main() !void {
    var io_threaded = std.Io.Threaded.init_single_threaded;
    const io = io_threaded.ioBasic();

    const stdout = std.Io.File.stdout();
    var out_buf: [512]u8 align(16) = undefined;
    var out_writer = stdout.writerStreaming(io, &out_buf);
    defer out_writer.interface.flush() catch {};

    const out = std.Io.Terminal{
        .writer = &out_writer.interface,
        .mode = std.Io.Terminal.Mode.detect(io, stdout, false, false) catch |e| switch (e) {
            error.Canceled => unreachable,
        },
    };

    const colors = [_]std.Io.Terminal.Color{
        .red,
        .green,
        .yellow,
        .blue,
        .magenta,
        .cyan,
        .white,
        .bright_red,
        .bright_green,
        .bright_yellow,
        .bright_blue,
        .bright_magenta,
        .bright_cyan,
        .reset,
    };

    for (colors) |c| {
        try printColor(out, c);
    }

    try out.writer.writeAll(
        "URL test: \x1B]8;;https://dgl.cx/2023/09/ansi-terminal-security\x1B\\" ++
            "ANSI Terminal Security in 2023\x1B]8;;\x1B\\\n",
    );

    const decoded_message = "My Clipboard!";
    const encoded_message = comptime msg: {
        const encoder = std.base64.standard.Encoder;
        var dest: [encoder.calcSize(decoded_message.len)]u8 = undefined;
        break :msg encoder.encode(&dest, decoded_message);
    };

    try out.writer.writeAll(
        "Copy \"" ++ decoded_message ++ "\" to the clipboard\n" ++
            "\x1B]52;c;" ++ encoded_message ++ "\x07",
    );
    try out.writer.flush();

    try out.writer.writeAll(
        "\x1B]0;Title Change\x07" ++
            "Check for title and change\n",
    );
    try out.writer.flush();

    // std.Thread.sleep not yet supported
    for (0..1_000_000) |i| {
        var useless: u8 = 0;
        const thing: *volatile u8 = @volatileCast(&useless);
        thing.* = @truncate(i);
    }
}

const std = @import("std");
const Writer = std.Io.Writer;
