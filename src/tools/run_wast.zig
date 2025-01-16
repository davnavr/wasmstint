const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");

const Arguments = struct {
    run: []const [:0]const u8,

    const Flag = enum {
        run,
        wait_for_debugger,

        const lookup = std.StaticStringMap(Flag).initComptime(.{
            .{ "--run", .run },
            .{ "-r", .run },
            .{ "--wait-for-debugger", .wait_for_debugger },
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
                .wait_for_debugger => if (builtin.target.os.tag == .windows) {
                    std.debug.print("Attach debugger to process {}\n", .{std.os.windows.GetCurrentProcessId()});

                    const debugapi = struct {
                        pub extern "kernel32" fn IsDebuggerPresent() callconv(.winapi) std.os.windows.BOOL;
                    };

                    while (debugapi.IsDebuggerPresent() == 0) {
                        std.Thread.sleep(100);
                    }
                } else {
                    if (builtin.target.os.tag == .linux) {
                        std.debug.print("Attach debugger to process {}\n", .{std.os.linux.getpid()});
                    }

                    var dbg: usize = 0;
                    const dbg_ptr: *volatile usize = &dbg;
                    while (dbg_ptr.* == 0) {
                        std.Thread.sleep(100);
                    }
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

    const color_config = std.io.tty.detectConfig(std.io.getStdErr());

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
        {
            // Try to allocate some space upfront.
            _ = parse_arena.allocator().alloc(u8, script_buf.len) catch {};
            _ = parse_arena.reset(.retain_capacity);
        }

        var errors = wasmstint.Wast.Error.List.init(parse_arena.allocator());

        _ = scratch.reset(.retain_capacity);
        const script_tree = try wasmstint.Wast.sexpr.Tree.parseFromSlice(script_buf, parse_arena.allocator(), &scratch, &errors);

        // TODO: Figure out if using an arena here might actually faster than using the GPA.
        var parse_array = wasmstint.Wast.Arena.init(parse_arena.allocator());
        var parse_caches = wasmstint.Wast.Caches.init(parse_arena.allocator());

        _ = scratch.reset(.retain_capacity);
        const script = wasmstint.Wast.parse(
            &script_tree,
            &parse_array,
            &parse_caches,
            &errors,
            &scratch,
        ) catch |e| {
            std.debug.print("Error parsing script file {s}", .{script_path});
            // TODO: Don't return, log that this script failed
            return e;
        };

        try runScript(
            &script,
            &script_tree,
            &parse_array,
            &parse_caches,
            &parse_arena,
            &errors,
        );

        if (errors.list.count() > 0) {
            @branchHint(.unlikely);
            const raw_stderr = std.io.getStdErr();
            var buf_stderr = std.io.bufferedWriter(raw_stderr.writer());

            var w = buf_stderr.writer();
            var line_col = wasmstint.Wast.LineCol.FromOffset.init(script_buf);

            var errors_iter = errors.list.constIterator(0);
            while (errors_iter.next()) |err| {
                try w.print(
                    "{s}:{}: ",
                    .{
                        script_path,
                        // For some errors, use the "end" offset
                        line_col.locate(err.offset(&script_tree).start) catch unreachable,
                    },
                );

                switch (color_config) {
                    .escape_codes => try w.writeAll("\x1B[31m" ++ "error" ++ "\x1B[39m"),
                    else => try w.writeAll("error"),
                }

                try w.writeAll(": ");
                try err.print(&script_tree, w);
                try w.writeByte('\n');
            }

            {
                if (color_config == .escape_codes) {
                    try w.writeAll("\x1B[31m");
                }

                try w.print("{} errors", .{errors.list.count()});

                if (color_config == .escape_codes) {
                    try w.writeAll("\x1B[39m");
                }

                try w.writeByte('\n');
            }

            try buf_stderr.flush();
        }
    }

    return 0;
}

fn runScript(
    script: *const wasmstint.Wast,
    script_tree: *const wasmstint.Wast.sexpr.Tree,
    script_arena: *const wasmstint.Wast.Arena,
    script_caches: *const wasmstint.Wast.Caches,
    run_arena: *ArenaAllocator, // Must not be reset for the lifetime of this function call.
    errors: *wasmstint.Wast.Error.List,
) std.mem.Allocator.Error!void {
    //var module_lookups = std.AutoHashMap(wasmstint.Wast.Ident.Interned, comptime V: type);
    var encoding_buffer = std.ArrayList(u8).init(run_arena.allocator());

    // Live until the next `module` command is executed.
    var next_module_arena = ArenaAllocator.init(run_arena.allocator());
    var current_module: ?[]const u8 = null; // TODO: Store a wasmstint.Module instead!

    // Live for the execution of a single command.
    var cmd_arena = ArenaAllocator.init(run_arena.allocator());
    for (script.commands.items(script_arena)) |cmd| {
        defer _ = cmd_arena.reset(.retain_capacity);

        switch (cmd.keyword.tag(script_tree)) {
            .keyword_module => {
                _ = next_module_arena.reset(.retain_capacity);
                const module: *const wasmstint.Wast.Module = cmd.inner.module.getPtr(script_arena);

                // const module_arena = if (module.name.some) run_arena else &next_module_arena;
                encoding_buffer.clearRetainingCapacity();
                try module.encode(
                    script_tree,
                    script_arena,
                    script_caches,
                    encoding_buffer.writer(),
                    errors,
                    &cmd_arena,
                );

                current_module = encoding_buffer.items;

                // TODO: Store modules with an ident into a hashmap and use the run_arena for both hashmap and module encoding
            },
            else => |bad| {
                std.debug.print("TODO: process command {}\n", .{bad});
                // unreachable
            },
        }
    }
}
