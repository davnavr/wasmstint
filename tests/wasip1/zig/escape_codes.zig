fn printColor(out: *Writer, color: std.Io.tty.Color) !void {
    const config: std.Io.tty.Config = .escape_codes;
    try config.setColor(out, color);
    try out.print("{t}\n", .{color});
}

pub fn main() !void {
    var out_buf: [512]u8 align(16) = undefined;
    var out = std.fs.File.stdout().writerStreaming(&out_buf);
    defer out.interface.flush() catch {};

    const colors = [_]std.Io.tty.Color{
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
        try printColor(&out.interface, c);
    }

    try out.interface.writeAll(
        "URL test: \x1B]8;;https://dgl.cx/2023/09/ansi-terminal-security\x1B\\" ++
            "ANSI Terminal Security in 2023\x1B]8;;\x1B\\\n",
    );

    const decoded_message = "My Clipboard!";
    const encoded_message = comptime msg: {
        const encoder = std.base64.standard.Encoder;
        var dest: [encoder.calcSize(decoded_message.len)]u8 = undefined;
        break :msg encoder.encode(&dest, decoded_message);
    };

    try out.interface.writeAll(
        "Copy \"" ++ decoded_message ++ "\" to the clipboard\n" ++
            "\x1B]52;c;" ++ encoded_message ++ "\x07",
    );
    try out.interface.flush();

    try out.interface.writeAll(
        "\x1B]0;Title Change\x07" ++
            "Check for title and change\n",
    );
    try out.interface.flush();

    // std.Thread.sleep not yet supported
    for (0..1_000_000) |i| {
        var useless: u8 = 0;
        const thing: *volatile u8 = @volatileCast(&useless);
        thing.* = @truncate(i);
    }
}

const std = @import("std");
const Writer = std.Io.Writer;
