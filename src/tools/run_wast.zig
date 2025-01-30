const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const Wast = wasmstint.Wast;

const Arguments = struct {
    run: []const [:0]const u8,
    rng_seed: u256 = 42,

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

const file_max_bytes = @as(usize, 1) << 21; // 2 MiB

pub fn main() !u8 {
    var arguments_arena = ArenaAllocator.init(std.heap.page_allocator);
    defer arguments_arena.deinit();

    var scratch = ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    const arguments = try Arguments.parse(&arguments_arena, &scratch);

    var file_buffer = std.ArrayList(u8).init(std.heap.page_allocator);
    defer file_buffer.deinit();

    var encoding_buffer = std.ArrayList(u8).init(std.heap.page_allocator);
    defer encoding_buffer.deinit();

    var parse_arena = ArenaAllocator.init(std.heap.page_allocator);
    defer parse_arena.deinit();

    const color_config = std.io.tty.detectConfig(std.io.getStdErr());
    const cwd = std.fs.cwd();

    const initial_rng = rng: {
        var init = std.Random.Xoshiro256{ .s = undefined };
        init.s = @bitCast(arguments.rng_seed);
        break :rng init;
    };

    for (arguments.run) |script_path| {
        const script_buf: []const u8 = buf: {
            const script_file = cwd.openFileZ(script_path, .{}) catch |e| {
                std.debug.print("Could not open script file {s}: {!}", .{ script_path, e });
                return e;
            };

            defer script_file.close();

            file_buffer.clearRetainingCapacity();
            size_estimate: {
                const metadata = script_file.metadata() catch break :size_estimate;
                try file_buffer.ensureTotalCapacity(std.math.cast(usize, metadata.size()) orelse return error.OutOfMemory);
            }

            script_file.reader().readAllArrayList(&file_buffer, file_max_bytes) catch |e| {
                if (e != error.OutOfMemory) std.debug.print("Could not read script file {s}", .{script_path});
                return e;
            };

            break :buf file_buffer.items;
        };

        _ = parse_arena.reset(.retain_capacity);
        {
            // Try to allocate some space upfront.
            _ = parse_arena.allocator().alloc(u8, script_buf.len) catch {};
            _ = parse_arena.reset(.retain_capacity);
        }

        var errors = Wast.Error.List.init(parse_arena.allocator());

        _ = scratch.reset(.retain_capacity);
        const script_tree = try Wast.sexpr.Tree.parseFromSlice(
            script_buf,
            parse_arena.allocator(),
            &scratch,
            &errors,
        );

        // TODO: Figure out if using an arena here might actually faster than using the GPA.
        var parse_array = Wast.Arena.init(parse_arena.allocator());
        var parse_caches = Wast.Caches.init(parse_arena.allocator());

        _ = scratch.reset(.retain_capacity);
        const script = Wast.parse(
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

        var rng = initial_rng;
        try runScript(
            &script,
            rng.random(),
            &encoding_buffer,
            &parse_arena,
            &errors,
        );

        if (errors.list.count() > 0) {
            @branchHint(.unlikely);
            const raw_stderr = std.io.getStdErr();
            var buf_stderr = std.io.bufferedWriter(raw_stderr.writer());

            var w = buf_stderr.writer();
            var line_col = Wast.LineCol.FromOffset.init(script_buf);

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

const State = struct {
    /// Allocated in the `run_arena`.
    module_lookups: std.AutoHashMapUnmanaged(Wast.Ident.Interned, *ModuleInst) = .empty,

    /// Live until the next `module` command is executed.
    next_module_arena: ArenaAllocator,
    /// Allocated either in the `next_module_arena` or the `run_arena`.
    current_module: ?*ModuleInst = null,

    /// Live for the execution of a single command.
    cmd_arena: ArenaAllocator,

    const ModuleInst = wasmstint.runtime.ModuleInst;

    fn getModuleInst(state: *const State, id: Wast.Ident.Symbolic) ?*ModuleInst {
        return if (id.some)
            state.module_lookups.get(id.ident)
        else
            state.current_module;
    }
};

// TODO: What if arguments could be allocated directly in the Interpreter's value_stack?
fn allocateFunctionArguments(
    script: *const Wast,
    arguments: Wast.Command.Arguments,
    arena: *ArenaAllocator,
) std.mem.Allocator.Error![]const wasmstint.Interpreter.TaggedValue {
    const src_arguments: []const Wast.Command.Const = arguments.items(script.arena);
    const dst_values = try arena.allocator().alloc(wasmstint.Interpreter.TaggedValue, src_arguments.len);

    errdefer comptime unreachable;

    for (src_arguments, dst_values) |*src, *dst| {
        dst.* = switch (src.keyword.tag(script.tree)) {
            .@"keyword_i32.const" => .{ .i32 = src.value.i32 },
            else => unreachable,
        };
    }

    return dst_values;
}

fn runScript(
    script: *const Wast,
    rng: std.Random,
    encoding_buffer: *std.ArrayList(u8),
    run_arena: *ArenaAllocator, // Must not be reset for the lifetime of this function call.
    errors: *Wast.Error.List,
) std.mem.Allocator.Error!void {
    var store = wasmstint.runtime.ModuleAllocator.WithinArena{ .arena = run_arena };
    var state: State = .{
        .next_module_arena = ArenaAllocator.init(run_arena.allocator()),
        .cmd_arena = ArenaAllocator.init(run_arena.allocator()),
    };

    for (script.commands.items(script.arena)) |cmd| {
        defer _ = state.cmd_arena.reset(.retain_capacity);

        var fuel = wasmstint.Interpreter.Fuel{ .remaining = 2000 };
        var interp = try wasmstint.Interpreter.init(state.cmd_arena.allocator(), .{});
        defer interp.reset();

        switch (cmd.keyword.tag(script.tree)) {
            .keyword_module => {
                _ = state.next_module_arena.reset(.retain_capacity);
                const module: *const Wast.Module = cmd.inner.module.getPtr(script.arena);

                const module_arena = if (module.name.some) run_arena else &state.next_module_arena;
                encoding_buffer.clearRetainingCapacity();
                try module.encode(
                    script.tree,
                    script.arena.dataSlice(),
                    script.caches,
                    encoding_buffer.writer(),
                    errors,
                    &state.cmd_arena,
                );

                var module_contents: []const u8 = if (module.name.some)
                    try run_arena.allocator().dupe(u8, encoding_buffer.items)
                else
                    encoding_buffer.items;

                const parsed_module = try module_arena.allocator().create(wasmstint.Module);
                parsed_module.* = wasmstint.Module.parse(
                    module_arena.allocator(),
                    &module_contents,
                    &state.cmd_arena,
                    rng,
                    .{ .realloc_contents = true },
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => |parse_error| {
                        std.debug.print("TODO: Module parse error {}\n", .{parse_error});
                        if (@errorReturnTrace()) |err_trace| {
                            std.debug.dumpStackTrace(err_trace.*);
                        }

                        return;
                    },
                };
                //parsed_module.finishCodeValidationInParallel(state.cmd_arena, thread_pool)
                const validation_finished = parsed_module.finishCodeValidation(
                    module_arena.allocator(),
                    &state.cmd_arena,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => |validation_err| {
                        std.debug.print("TODO: Code validation error {}\n", .{validation_err});
                        if (@errorReturnTrace()) |err_trace| {
                            std.debug.dumpStackTrace(err_trace.*);
                        }

                        return;
                    },
                };

                std.debug.assert(validation_finished);

                // TODO: This is waiting on a proper module instantiation API.
                std.debug.assert(!parsed_module.inner.start.exists);

                const module_inst = try module_arena.allocator().create(wasmstint.runtime.ModuleInst);
                module_inst.* = wasmstint.runtime.ModuleInst.allocate(
                    parsed_module,
                    undefined, // TODO: Provide proper import_provider
                    module_arena.allocator(),
                    store.allocator(),
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => unreachable, // TODO: how to handle import errors?
                };

                // TODO: This is waiting on a proper module instantiation API.
                module_inst.instantiated = true;

                state.current_module = module_inst;

                if (module.name.some) {
                    // Are duplicate module names an error? or should it just overwrite?
                    _ = try state.module_lookups.fetchPut(
                        run_arena.allocator(),
                        module.name.ident,
                        module_inst,
                    );
                }
            },
            .keyword_assert_return => {
                const assert_return: *const Wast.Command.AssertReturn = cmd.inner.assert_return.getPtr(script.arena);

                // TODO: Move code that processess an invoke action to a separate function
                const action: *const Wast.Command.Action = assert_return.action.getPtr(script.arena);
                std.debug.assert(action.keyword.tag(script.tree) == .keyword_invoke);

                const module = state.getModuleInst(action.module) orelse {
                    std.debug.print(
                        "TODO: Missing module? {?s}\n",
                        .{if (action.module.some) script.identContents(action.module.ident) else null},
                    );
                    continue;
                };

                const export_name = script.nameContents(action.name.id);
                const target_export = module.findExport(export_name) catch |e| {
                    std.debug.print("TODO: bad export {s}, {?}\n", .{ export_name, e });
                    continue;
                };

                const callee = target_export.func;
                const arguments = try allocateFunctionArguments(
                    script,
                    action.target.invoke.arguments,
                    &state.cmd_arena,
                );

                interp.beginCall(state.cmd_arena.allocator(), callee, arguments, &fuel) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => unreachable,
                };

                const results = interp.copyResultValues(&state.cmd_arena) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => unreachable,
                };

                std.debug.print("TODO: process assert_return {any}\n", .{results});
            },
            else => |bad| {
                std.debug.print("TODO: process command {}\n", .{bad});
                // unreachable
            },
        }
    }
}
