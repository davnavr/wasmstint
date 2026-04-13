const max_interpreter_stack = 200_000;
const max_fuel = 20_000;

pub const wasm_smith_config = ffi.wasm_smith.Configuration{};

pub fn testOne(
    wasm_module: []const u8,
    input: *fuzz_data.Input,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) !void {
    var diagnostic_writer = std.Io.Writer.Allocating.init(allocator);
    defer diagnostic_writer.deinit();

    var wasm: []const u8 = wasm_module;
    const parsed_module = wasmstint.Module.parse(
        allocator,
        &wasm,
        scratch,
        .{ .diagnostics = .init(&diagnostic_writer.writer) },
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => std.debug.panic(
            "module validation error {t}: {s}",
            .{ e, diagnostic_writer.written() },
        ),
        error.WasmImplementationLimit => return,
    };
    defer parsed_module.deinit(allocator, allocator);

    const finished = parsed_module.finishCodeValidation(
        allocator,
        scratch,
        .init(&diagnostic_writer.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => std.debug.panic(
            "code validation error {t}: {s}",
            .{ e, diagnostic_writer.written() },
        ),
        error.WasmImplementationLimit => return,
    };

    if (!finished) {
        return error.ValidationOfCodeEntriesWasNotFinished;
    }

    var import_provider = ImportProvider{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .input = input,
        .functions = try std.ArrayList(wasmstint.runtime.FuncRef).initCapacity(
            allocator,
            parsed_module.funcImportTypes().len + parsed_module.exports().len,
        ),
        .memories = try std.ArrayList(wasmstint.runtime.MemInst.Mapped)
            .initCapacity(allocator, parsed_module.memImportTypes().len),
        .tables = try std.ArrayList(wasmstint.runtime.TableInst.Allocated)
            .initCapacity(allocator, parsed_module.tableImportTypes().len),
    };
    defer import_provider.deinit();

    var interp: wasmstint.Interpreter = undefined;
    const initial_state = try interp.init(allocator, .{
        .stack_reserve = input.uintInRangeInclusive(u32, 0, max_interpreter_stack),
    });
    defer interp.deinit(allocator);

    var fuel = wasmstint.Interpreter.Fuel{ .remaining = max_fuel };
    var module = module: {
        var module_alloc = allocate: {
            _ = scratch.reset(.retain_capacity);
            const defined_table_types = parsed_module.tableDefinedTypes();
            const defined_memory_types = parsed_module.memDefinedTypes();
            var definitions = wasmstint.runtime.ModuleAlloc.Definitions.Builder{
                .tables = try .initCapacity(scratch.allocator(), defined_table_types.len),
                .memories = try .initCapacity(scratch.allocator(), defined_memory_types.len),
            };
            errdefer definitions.definitions().deinit();

            const defined_table_insts = try scratch.allocator()
                .alloc(wasmstint.runtime.TableInst.Allocated, defined_table_types.len);
            const defined_memory_insts = try scratch.allocator()
                .alloc(wasmstint.runtime.MemInst.Mapped, defined_memory_types.len);

            for (defined_table_types, defined_table_insts) |*table_type, *table| {
                const config_max = wasm_smith_config.max_max_table_elements;
                if (table_type.limits.min > config_max) {
                    return error.OutOfMemory;
                }

                const min_elems: u32 = @intCast(table_type.limits.min);
                const limited_max = @min(table_type.limits.max, config_max);
                const chosen_max = input.uintInRangeInclusive(u32, min_elems, limited_max);
                const initial_cap = input.uintInRangeInclusive(u32, min_elems, chosen_max);
                table.* = try wasmstint.runtime.TableInst.Allocated.allocateFromType(
                    allocator,
                    table_type,
                    null,
                    initial_cap,
                    chosen_max,
                );
                definitions.tables.appendAssumeCapacity(&table.table);
            }

            for (defined_memory_types, defined_memory_insts) |*mem_type, *mem| {
                const min_bytes = mem_type.limits.min * wasm_page_size;
                const config_max = wasm_smith_config.max_max_memory_bytes;
                if (min_bytes > config_max) {
                    return error.OutOfMemory;
                }

                const limited_max = @min(mem_type.limits.max * wasm_page_size, config_max);
                const chosen_max = input.uintInRangeInclusive(usize, min_bytes, limited_max);
                const initial_cap = input.uintInRangeInclusive(usize, min_bytes, chosen_max);
                mem.* = try wasmstint.runtime.MemInst.Mapped
                    .allocateFromType(mem_type, initial_cap, chosen_max);
                definitions.memories.appendAssumeCapacity(&mem.memory);
            }

            var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
            break :allocate wasmstint.runtime.ModuleAlloc.allocateWithDefinitions(
                parsed_module,
                allocator,
                import_provider.importProvider(),
                &import_error,
                definitions.definitions(),
            ) catch |e| switch (e) {
                error.OutOfMemory => |oom| return oom,
                error.ImportFailure => |err| {
                    std.log.err("{f}", .{import_error});
                    return switch (import_error.reason) {
                        .error_returned => |captured| @as(
                            ImportProvider.Error,
                            @errorCast(captured),
                        ),
                        else => err,
                    };
                },
            };
        };
        var free_module_alloc = true;
        defer if (free_module_alloc) module_alloc.deinit(allocator);

        const instantiate_state = try initial_state.awaiting_host
            .instantiateModule(allocator, &module_alloc, &fuel);

        const start_results = mainLoop(
            instantiate_state,
            scratch,
            &fuel,
            input,
            import_provider.functions.items,
        ) catch |e| {
            std.log.warn("start function did not return: {t}", .{e});
            switch (e) {
                error.OutOfMemory => return e,
                error.OutOfFuel, error.CallStackExhaustion, error.Trapped => return,
            }
        };

        errdefer comptime unreachable;

        free_module_alloc = false;
        std.debug.assert(start_results.len == 0);
        break :module module_alloc.assumeInstantiated();
    };
    defer module.deinit(allocator);

    const exports = module.exports();
    var func_exports = try std.ArrayList(wasmstint.runtime.ModuleInst.Export)
        .initCapacity(allocator, exports.len);
    defer func_exports.deinit(allocator);
    for (0..exports.len) |i| {
        const e = exports.at(i);
        switch (e.val) {
            .func => |func| {
                func_exports.appendAssumeCapacity(e);
                import_provider.functions.appendAssumeCapacity(func);
            },
            else => {},
        }
    }

    for (func_exports.items) |e| {
        _ = scratch.reset(.retain_capacity);
        std.log.info("invoking {f}", .{e});
        const func = e.val.func;
        const param_types = func.signature().parameters();
        const params = try scratch.allocator().alloc(
            wasmstint.Interpreter.TaggedValue,
            param_types.len,
        );
        for (param_types, params) |param_ty, *dst| {
            dst.* = generateTaggedValue(input, param_ty, import_provider.functions.items);
        }

        std.log.info("parameters {f}", .{
            wasmstint.Interpreter.TaggedValue.sliceFormatter(params),
        });
        const results = mainLoop(
            try interp.reset().awaiting_host.beginCall(allocator, func.funcInst(), params, &fuel),
            scratch,
            &fuel,
            input,
            import_provider.functions.items,
        ) catch |err| {
            std.log.info("function did not return: {t}", .{err});
            continue;
        };

        std.log.info("function returned {f}", .{
            wasmstint.Interpreter.TaggedValue.sliceFormatter(results),
        });
    }
}

fn generateExternAddr(input: *fuzz_data.Input) wasmstint.runtime.ExternAddr {
    const Bits = packed struct(u32) {
        high: u4,
        low: u28,
    };

    const bits: Bits = @bitCast(input.int(u32));
    return if (bits.high == 0)
        .null
    else
        .{ .nat = wasmstint.runtime.ExternAddr.Nat.fromInt(bits.low) };
}

const ImportProvider = struct {
    arena: std.heap.ArenaAllocator,
    input: *fuzz_data.Input,
    functions: std.ArrayList(wasmstint.runtime.FuncRef),
    memories: std.ArrayList(wasmstint.runtime.MemInst.Mapped),
    tables: std.ArrayList(wasmstint.runtime.TableInst.Allocated),

    const Error = error{ OutOfMemory, BadInput };

    fn resolve(
        ctx: *anyopaque,
        module: wasmstint.Module.Name,
        name: wasmstint.Module.Name,
        desc: wasmstint.runtime.ImportProvider.Desc,
    ) Error!?wasmstint.runtime.ExternVal {
        const provider: *ImportProvider = @ptrCast(@alignCast(ctx));
        std.log.info("resolving (import {f} {f} {f})", .{ module, name, desc });
        return switch (desc) {
            .func => |func_type| .{ .func = func_ref: {
                const func = wasmstint.runtime.FuncRef.init(.{
                    .host = func: {
                        const func = try provider.arena.allocator()
                            .create(wasmstint.runtime.HostFunc);
                        func.* = .{ .signature = func_type.* };
                        break :func func;
                    },
                });

                provider.functions.appendAssumeCapacity(func);
                break :func_ref func;
            } },
            .mem => |mem_type| .{
                .mem = mem: {
                    const min_size = mem_type.limits.min * wasm_page_size;
                    if (min_size > wasm_smith_config.max_max_memory_bytes) {
                        return error.OutOfMemory; // memory min size too large
                    }

                    const max_size = provider.input.uintInRangeInclusive(
                        usize,
                        min_size,
                        @min(
                            mem_type.limits.max * wasm_page_size,
                            wasm_smith_config.max_max_memory_bytes,
                        ),
                    );
                    const provided_mem = try wasmstint.runtime.MemInst.Mapped.allocateFromType(
                        mem_type,
                        provider.input.uintInRangeInclusive(usize, min_size, max_size),
                        max_size,
                    );

                    const mem = provider.memories.addOneAssumeCapacity();
                    mem.* = provided_mem;
                    break :mem &mem.memory;
                },
            },
            .table => |table_type| .{
                .table = table: {
                    const limit_min: u32 = @intCast(table_type.limits.min);
                    if (limit_min > wasm_smith_config.max_max_table_elements) {
                        return error.OutOfMemory; // table min length too large
                    }

                    const max_elems = provider.input.uintInRangeInclusive(
                        u32,
                        limit_min,
                        @min(wasm_smith_config.max_max_table_elements, table_type.limits.max),
                    );
                    //const table = provider.tables.addOneAssumeCapacity();
                    //errdefer provider.tables.pop().?;
                    const initial_capacity = provider.input
                        .uintInRangeInclusive(u32, limit_min, max_elems);
                    const provided_table =
                        try wasmstint.runtime.TableInst.Allocated.allocateFromType(
                            provider.arena.child_allocator,
                            table_type,
                            null,
                            initial_capacity,
                            max_elems,
                        );

                    const table = provider.tables.addOneAssumeCapacity();
                    table.* = provided_table;
                    break :table &table.table;
                },
            },
            .global => |global_type| .{
                .global = wasmstint.runtime.GlobalAddr{
                    .global_type = global_type.*,
                    .value = switch (global_type.val_type) {
                        inline else => |val_type| val: {
                            const Val = wasmstint.runtime.GlobalAddr.Pointee(val_type);
                            const val = try provider.arena.allocator().create(Val);
                            val.* = switch (val_type) {
                                .i32, .i64 => provider.input.int(Val),
                                .f32, .f64 => provider.input.floatFromBits(Val),
                                .externref => generateExternAddr(provider.input),
                                .funcref => Val.null, // TODO: pick random funcref
                                .v128 => .{ .u8x16 = provider.input.vector(@Vector(16, u8)) },
                                // else => unreachable,
                            };

                            break :val val;
                        },
                    },
                },
            },
        };
    }

    fn importProvider(provider: *ImportProvider) wasmstint.runtime.ImportProvider {
        return .{ .ctx = provider, .resolve = resolve };
    }

    fn deinit(provider: *ImportProvider) void {
        for (provider.memories.items) |*mem| {
            mem.memory.free();
        }
        for (provider.tables.items) |*table| {
            table.table.free();
        }
        provider.functions.deinit(provider.arena.child_allocator);
        provider.memories.deinit(provider.arena.child_allocator);
        provider.tables.deinit(provider.arena.child_allocator);
        provider.arena.deinit();
        provider.* = undefined;
    }
};

fn generateTaggedValue(
    input: *fuzz_data.Input,
    ty: wasmstint.Module.ValType,
    functions: []const wasmstint.runtime.FuncRef,
) wasmstint.Interpreter.TaggedValue {
    return switch (ty) {
        .i32 => .{ .i32 = input.int(i32) },
        .i64 => .{ .i64 = input.int(i64) },
        .f32 => .{ .f32 = input.floatFromBits(f32) },
        .f64 => .{ .f64 = input.floatFromBits(f64) },
        .externref => .{ .externref = generateExternAddr(input) },
        .funcref => .{
            .funcref = if (input.boolean())
                @bitCast(input.choose(wasmstint.runtime.FuncRef, u32, functions))
            else
                .null,
        },
        .v128 => .{ .v128 = .{ .u8x16 = input.vector(@Vector(16, u8)) } },
        // else => unreachable,
    };
}

fn mainLoop(
    initial_state: wasmstint.Interpreter.State,
    scratch: *std.heap.ArenaAllocator,
    fuel: *wasmstint.Interpreter.Fuel,
    input: *fuzz_data.Input,
    functions: []const wasmstint.runtime.FuncRef,
) ![]const wasmstint.Interpreter.TaggedValue {
    var state = initial_state;
    var host_trap_code: ?u31 = null;
    while (true) {
        _ = scratch.reset(.retain_capacity);
        state = next: switch (state) {
            .awaiting_host => |*host| if (host.currentHostFunction()) |host_func| {
                // 3/4 probability
                if (input.int(u8) & 0b1100_0000 == 0) {
                    const result_types = host.hostSignature().results();
                    const results = try scratch.allocator().alloc(
                        wasmstint.Interpreter.TaggedValue,
                        result_types.len,
                    );
                    for (result_types, results) |result_ty, *dst| {
                        dst.* = generateTaggedValue(input, result_ty, functions);
                    }

                    std.log.info("fuel={d}, host {f} returning {f}", .{
                        fuel.remaining,
                        host_func,
                        wasmstint.Interpreter.TaggedValue.sliceFormatter(results),
                    });
                    break :next host.returnFromHost(results, fuel) catch
                        @panic("signature mismatch");
                } else {
                    const trap_code = input.int(u31);
                    host_trap_code = trap_code;
                    break :next host.trapWithHostCode(trap_code);
                }
            } else {
                return host.allocResults(scratch.allocator());
            },
            .awaiting_validation => @panic("awaiting validation"),
            .call_stack_exhaustion => return error.CallStackExhaustion,
            .interrupted => |*interrupt| {
                switch (interrupt.cause().*) {
                    .out_of_fuel => return error.OutOfFuel,
                    .memory_grow => |grow_request| {
                        const accepted = input.boolean() and // always consume input byte
                            grow_request.new_size <= wasm_smith_config.max_max_memory_bytes;

                        std.log.info("memory.grow from {[old]d} to {[new]d} {[status]s}", .{
                            .old = grow_request.old_size,
                            .new = grow_request.new_size,
                            .status = if (accepted) "accepted" else "denied",
                        });

                        if (accepted) {
                            try grow_request.grow();
                        }
                    },
                    .table_grow => |grow_request| {
                        const accepted = input.boolean() and // always consume input byte
                            grow_request.new_len <= wasm_smith_config.max_max_table_elements;

                        std.log.info("table.grow from {[old]d} to {[new]d} {[status]s}", .{
                            .old = grow_request.old_len,
                            .new = grow_request.new_len,
                            .status = if (accepted) "accepted" else "denied",
                        });

                        if (accepted) {
                            try grow_request.grow();
                        }
                    },
                }

                break :next interrupt.resumeExecution(fuel);
            },
            .trapped => |*trapped| {
                if (host_trap_code) |expected| {
                    const actual = trapped.trap().toHostCode();
                    if (expected != actual) {
                        std.debug.panic(
                            "expected host trap code {d}, got {any}",
                            .{ expected, actual },
                        );
                    }
                }

                std.log.warn("trap {f}", .{trapped.trap().code});
                return error.Trapped;
            },
        };
    }
}

const std = @import("std");
const wasmstint = @import("wasmstint");
const wasm_page_size = wasmstint.runtime.MemInst.page_size;
const ffi = @import("ffi");
const fuzz_data = @import("fuzz_data");
