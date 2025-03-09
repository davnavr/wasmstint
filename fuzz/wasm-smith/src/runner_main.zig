const std = @import("std");

extern fn LLVMFuzzerTestOneInput(data: [*]const u8, size: usize) callconv(.c) c_int;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const file: std.fs.File = input: {
        var args = try std.process.argsWithAllocator(arena.allocator());
        defer args.deinit();
        _ = args.next();

        break :input try std.fs.cwd().openFileZ(
            args.next() orelse @panic("no input file provided"),
            .{},
        );
    };

    _ = arena.reset(.retain_capacity);

    const bytes = try file.readToEndAlloc(arena.allocator(), 2 * (1024 * 1024));

    if (false) {
        if (@import("builtin").os.tag == .linux) {
            std.debug.print("Attach debugger to process {}\n", .{std.os.linux.getpid()});
        }

        var i: u32 = 0;
        for (0..100) |_| {
            std.Thread.sleep(1 * std.time.ns_per_s);

            if (@volatileCast(&i).* != 0) break;
        }
    }

    _ = LLVMFuzzerTestOneInput(bytes.ptr, bytes.len);
}
