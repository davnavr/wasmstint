const std = @import("std");
const wasmstint = @import("wasmstint");

const Arguments = struct {
    run: []const [:0]const u8,

    const Flag = enum {
        run,

        const lookup = std.StaticStringMap(Flag).initComptime(.{
            .{ "--run", .run },
            .{ "-r", .run },
        });
    };

    fn parse(
        arena: *std.heap.ArenaAllocator,
        scratch: *std.heap.ArenaAllocator,
    ) !Arguments {
        var arguments = Arguments{
            .run = &[0][:0]const u8{},
        };

        var run_paths = std.SegmentedList([:0]const u8, 4){};

        var iter = try std.process.argsWithAllocator(scratch.allocator());
        _ = iter.next(); // exe_name
        while (iter.next()) |arg| {
            const flag = Flag.lookup.get(arg) orelse {
                std.debug.print("Unknown flag: {s}\n", .{arg});
                return error.InvalidCommandLineArgument;
            };

            switch (flag) {
                .run => {
                    const script_path = try run_paths.addOne(scratch.allocator());
                    script_path.* = try arena.allocator().dupeZ(
                        u8,
                        iter.next() orelse return error.InvalidCommandLineArgument,
                    );
                },
            }
        }

        const run_paths_final = try arena.allocator().alloc([:0]const u8, run_paths.count());
        run_paths.writeToSlice(run_paths_final, 0);
        arguments.run = run_paths_final;

        return arguments;
    }
};

pub fn main() !u8 {
    var global_allocator = @import("GlobalAllocator").init();
    defer global_allocator.deinit();
    const gpa = global_allocator.allocator();

    var arguments_arena = std.heap.ArenaAllocator.init(gpa);
    defer arguments_arena.deinit();

    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();

    var file_arena = std.heap.ArenaAllocator.init(gpa);
    defer file_arena.deinit();

    const arguments = try Arguments.parse(&arguments_arena, &scratch);

    const cwd = std.fs.cwd();
    for (arguments.run) |script_path| {
        const script_buf: []const u8 = buf: {
            _ = file_arena.reset(.retain_capacity);

            const script_file = cwd.openFileZ(script_path, .{}) catch |e| {
                std.debug.print("Could not open script file {s}: {!}", .{ script_path, e });
                return e;
            };
            defer script_file.close();

            break :buf script_file.readToEndAlloc(
                file_arena.allocator(),
                @as(usize, 1) << 21, // 2 miB
            ) catch |e| {
                if (e != error.OutOfMemory) std.debug.print("Could not read script file {s}", .{script_path});
                return e;
            };
        };

        //const script_tokenizer = wasmstint.Wast.Lexer;

        _ = script_buf;
    }

    return 0;
}
