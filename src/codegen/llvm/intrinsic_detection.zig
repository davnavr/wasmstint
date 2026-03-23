//! Checks whether assembly produced from an LLVM bitcode file contains calls to certain
//! `compiler_rt` functions.

pub const std_options: std.Options = .{ .networking = false };

const Results = struct {
    // Introduced in C23, yet LLVM happily emits calls to it when some CPU features (e.g. SSE4.1)
    // aren't enabled. Zig's `compiler_rt` also currently doesn't provide an implementation.
    //
    // Rust also wants to use `roundeven`, but may need to add their own
    // (implementations)[https://github.com/rust-lang/rust/issues/136459].
    roundeven: bool,
    roundevenf: bool,
};

pub fn main(init: std.process.Init.Minimal) !void {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

    var cli_args = try init.args.iterateAllocator(arena.allocator());
    _ = cli_args.next().?;

    const asm_text = text: {
        const path = cli_args.next().?;
        break :text std.Io.Dir.cwd().readFileAllocOptions(
            io,
            path,
            arena.allocator(),
            .limited(1 * 1024 * 1024),
            .@"16",
            0,
        ) catch |e| std.debug.panic("cannot open {s} for reading: {t}", .{ path, e });
    };

    std.debug.assert(cli_args.next() == null);

    const tokenizer_delimiters = comptime delimiters: {
        var delimiters: [256 - (std.ascii.letters.len + 11)]u8 = undefined;
        var i = 0;
        for (0..256) |c| {
            switch (c) {
                '0'...'9',
                'a'...'z',
                'A'...'Z',
                '_',
                => {},
                else => {
                    delimiters[i] = @intCast(c);
                    i += 1;
                },
            }
        }

        std.debug.assert(i == delimiters.len);
        break :delimiters delimiters;
    };

    var results = std.mem.zeroInit(Results, .{});
    var tokens = std.mem.splitAny(u8, asm_text, &tokenizer_delimiters);

    while (tokens.next()) |tok| {
        inline for (comptime std.meta.fieldNames(Results)) |func_name| {
            if (std.mem.eql(u8, func_name, tok)) {
                @field(results, func_name) = true;
            }
        }
    }

    var stdout = std.Io.File.stdout().writerStreaming(
        io,
        try arena.allocator().alignedAlloc(u8, .@"16", 256),
    );
    try std.zon.stringify.serialize(results, .{ .whitespace = false }, &stdout.interface);
    try stdout.flush();
}

const std = @import("std");
