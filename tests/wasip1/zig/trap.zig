const Action = enum {
    trap,
};

pub const std_options: std.Options = .{ .networking = false };

pub fn main(init: std.process.Init.Minimal) void {
    var args = init.args.iterateAllocator(std.heap.wasm_allocator) catch @panic("oom");
    defer args.deinit();

    _ = args.next() orelse @panic("no process name!");

    const action_str = args.next() orelse @panic("no argument provided");
    const action: Action = std.meta.stringToEnum(Action, action_str) orelse
        std.debug.panic("{s} is not a valid action", .{action_str});
    switch (action) {
        .trap => @trap(),
        // TODO: one for division by zero (find way to avoid comptime zig catching it, or use inline asm)
        // TODO: one for out-of-memory access
    }
}

const std = @import("std");
