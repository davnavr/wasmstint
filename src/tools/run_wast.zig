const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
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

    fn parse(arena: *ArenaAllocator, scratch: *ArenaAllocator) !Arguments {
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

    var arguments_arena = ArenaAllocator.init(gpa);
    defer arguments_arena.deinit();

    var scratch = ArenaAllocator.init(gpa);
    defer scratch.deinit();

    const arguments = try Arguments.parse(&arguments_arena, &scratch);

    var file_arena = ArenaAllocator.init(gpa);
    defer file_arena.deinit();

    var parse_arena = ArenaAllocator.init(gpa);
    defer parse_arena.deinit();

    const file_max_bytes = @as(usize, 1) << 21; // 2 miB

    const cwd = std.fs.cwd();
    for (arguments.run) |script_path| {
        const script_buf: []const u8 = buf: {
            _ = file_arena.reset(.{ .retain_with_limit = file_max_bytes });

            const script_file = cwd.openFileZ(script_path, .{}) catch |e| {
                std.debug.print("Could not open script file {s}: {!}", .{ script_path, e });
                return e;
            };
            defer script_file.close();

            break :buf script_file.readToEndAlloc(file_arena.allocator(), file_max_bytes) catch |e| {
                if (e != error.OutOfMemory) std.debug.print("Could not read script file {s}", .{script_path});
                return e;
            };
        };

        _ = parse_arena.reset(.retain_capacity);
        _ = scratch.reset(.retain_capacity);
        var errors = wasmstint.Wast.Error.List.init(parse_arena.allocator());
        const script = wasmstint.Wast.parseFromSlice(script_buf, parse_arena.allocator(), &scratch, &errors) catch |e| {
            std.debug.print("Error parsing script file {s}", .{script_path});
            // TODO: Don't return, log that this script failed
            return e;
        };

        if (errors.list.count() > 0) {
            @branchHint(.unlikely);
            const raw_stderr = std.io.getStdErr();
            var buf_stderr = std.io.bufferedWriter(raw_stderr.writer());

            var w = buf_stderr.writer();
            var line_col = wasmstint.Wast.LineCol.FromOffset.init(script_buf);

            var errors_iter = errors.list.constIterator(0);
            while (errors_iter.next()) |err| {
                try w.print(
                    "{s}:{}: error: ",
                    .{
                        script_path,
                        // For some errors, use the "end" offset
                        line_col.locate(err.offset(&script.tree).start) catch unreachable,
                    },
                );

                try err.print(&script.tree, w);
                try w.writeByte('\n');
            }

            try buf_stderr.flush();
        }
    }

    return 0;
}
