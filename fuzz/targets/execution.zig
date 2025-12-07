const max_interpreter_stack = 200_000;
const max_fuel = 400_000;

pub const wasm_smith_config = ffi.wasm_smith.Configuration{};

pub fn testOne(
    wasm_module: []const u8,
    input: *ffi.Input,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var diagnostic_writer = std.Io.Writer.Allocating.init(allocator);
    defer diagnostic_writer.deinit();

    var wasm: []const u8 = wasm_module;
    const parsed_module = wasmstint.Module.parse(
        arena.allocator(),
        &wasm,
        scratch,
        .{ .diagnostics = .init(&diagnostic_writer.writer) },
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => |err| {
            std.debug.panic(
                "module validation error {t}: {s}",
                .{ e, diagnostic_writer.written() },
            );
            return err;
        },
        error.WasmImplementationLimit => return,
    };

    const finished = parsed_module.finishCodeValidation(
        arena.allocator(),
        scratch,
        .init(&diagnostic_writer.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => |err| {
            std.debug.print("code validation error {t}: {s}", .{ e, diagnostic_writer.written() });
            return err;
        },
        error.WasmImplementationLimit => return,
    };

    if (!finished) {
        return error.ValidationOfCodeEntriesWasNotFinished;
    }

    var import_provider = ImportProvider{
        .arena = &arena,
        .input = input,
        .memories = try std.ArrayList(wasmstint.runtime.MemInst.Mapped).initCapacity(
            arena.allocator(),
            parsed_module.memImportTypes().len,
        ),
        .tables = try std.ArrayList(wasmstint.runtime.TableInst.Allocated).initCapacity(
            arena.allocator(),
            parsed_module.tableImportTypes().len,
        ),
    };
    defer import_provider.deinit();

    var module_alloc = allocate: {
        _ = scratch.reset(.retain_capacity);
        const defined_table_types = parsed_module.tableDefinedTypes();
        const defined_tables = try arena.allocator().alloc(
            wasmstint.runtime.TableInst.Allocated,
            defined_table_types.len,
        );
        const defined_table_insts = try scratch.allocator().alloc(
            *wasmstint.runtime.TableInst,
            defined_table_types.len,
        );
        for (
            defined_table_types,
            defined_tables,
            defined_table_insts,
        ) |*table_type, *table, *table_inst| {
            if (table_type.limits.min > wasm_smith_config.max_max_table_elements) {
                return error.OutOfMemory;
            }

            const min_elems: u32 = @intCast(table_type.limits.min);
            const chosen_max = try input.uintInRangeInclusive(
                u32,
                min_elems,
                @min(table_type.limits.max, wasm_smith_config.max_max_table_elements),
            );
            table.* = try wasmstint.runtime.TableInst.Allocated.allocateFromType(
                arena.allocator(),
                table_type,
                null,
                try input.uintInRangeInclusive(u32, min_elems, chosen_max),
                chosen_max,
            );
            table_inst.* = &table.table;
        }

        const defined_memory_types = parsed_module.memDefinedTypes();
        const defined_memories = try arena.allocator().alloc(
            wasmstint.runtime.MemInst.Mapped,
            defined_memory_types.len,
        );
        const defined_memory_insts = try scratch.allocator().alloc(
            *wasmstint.runtime.MemInst,
            defined_memory_types.len,
        );
        for (
            defined_memory_types,
            defined_memories,
            defined_memory_insts,
        ) |*mem_type, *mem, *mem_inst| {
            const min_bytes = mem_type.limits.min * wasm_page_size;
            if (min_bytes > wasm_smith_config.max_max_memory_bytes) {
                return error.OutOfMemory;
            }

            const chosen_max = try input.uintInRangeInclusive(
                usize,
                min_bytes,
                @min(mem_type.limits.max * wasm_page_size, wasm_smith_config.max_max_memory_bytes),
            );
            mem.* = try wasmstint.runtime.MemInst.Mapped.allocateFromType(
                mem_type,
                try input.uintInRangeInclusive(usize, min_bytes, chosen_max),
                chosen_max,
            );
            mem_inst.* = &mem.memory;
        }

        var definitions = wasmstint.runtime.ModuleAlloc.Definitions{
            .tables = defined_table_insts,
            .memories = defined_memory_insts,
        };
        errdefer definitions.deinit();

        var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
        break :allocate wasmstint.runtime.ModuleAlloc.allocateWithDefinitions(
            parsed_module,
            arena.allocator(),
            import_provider.importProvider(),
            &import_error,
            definitions,
        ) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.ImportFailure => |err| if (import_provider.err) |actual| {
                return actual;
            } else {
                std.debug.print("{f}", .{import_error});
                return err;
            },
        };
    };

    var interp: wasmstint.Interpreter = undefined;
    const initial_state = try interp.init(
        allocator,
        .{ .stack_reserve = try input.uintInRangeInclusive(u32, 0, max_interpreter_stack) },
    );
    defer interp.deinit(allocator);

    var fuel = wasmstint.Interpreter.Fuel{ .remaining = max_fuel };
    {
        const instantiate_state = try initial_state.awaiting_host.instantiateModule(
            allocator,
            &module_alloc,
            &fuel,
        );

        const start_results = mainLoop(
            instantiate_state,
            scratch,
            &fuel,
            input,
        ) catch |e| switch (e) {
            error.OutOfMemory, error.OutOfFuel, error.BadInput, error.Trapped => {
                std.debug.print("start function did not return: {t}\n", .{e});
                return;
            },
        };

        std.debug.assert(start_results.len == 0);
    }

    const module = module_alloc.assumeInstantiated();
    const exports = module.exports();
    for (0..exports.len) |i| {
        _ = scratch.reset(.retain_capacity);
        const e = exports.at(i);
        switch (e.val) {
            .func => |func| {
                std.debug.print("invoking {f}\n", .{e});
                const param_types = func.signature().parameters();
                const params = try scratch.allocator().alloc(
                    wasmstint.Interpreter.TaggedValue,
                    param_types.len,
                );
                for (param_types, params) |param_ty, *dst| {
                    dst.* = try generateTaggedValue(input, param_ty);
                }

                std.debug.print(
                    "parameters {f}\n",
                    .{wasmstint.Interpreter.TaggedValue.sliceFormatter(params)},
                );
                const results = mainLoop(
                    try interp.reset().awaiting_host.beginCall(
                        allocator,
                        func,
                        params,
                        &fuel,
                    ),
                    scratch,
                    &fuel,
                    input,
                ) catch |err| {
                    std.debug.print("function did not return: {t}\n", .{err});
                    continue;
                };

                std.debug.print(
                    "function returned {f}\n",
                    .{wasmstint.Interpreter.TaggedValue.sliceFormatter(results)},
                );
            },
            else => {},
        }
    }
}

fn generateExternAddr(input: *ffi.Input) !wasmstint.runtime.ExternAddr {
    const Bits = packed struct(u32) {
        high: u4,
        low: u28,
    };
    const bits: Bits = @bitCast(try input.int(u32));
    return if (bits.high == 0)
        .null
    else
        .{ .nat = wasmstint.runtime.ExternAddr.Nat.fromInt(bits.low) };
}

const ImportProvider = struct {
    arena: *std.heap.ArenaAllocator,
    input: *ffi.Input,
    memories: std.ArrayList(wasmstint.runtime.MemInst.Mapped),
    tables: std.ArrayList(wasmstint.runtime.TableInst.Allocated),
    err: ?error{ OutOfMemory, BadInput } = null,

    fn resolve(
        ctx: *anyopaque,
        module: wasmstint.Module.Name,
        name: wasmstint.Module.Name,
        desc: wasmstint.runtime.ImportProvider.Desc,
    ) ?wasmstint.runtime.ExternVal {
        const provider: *ImportProvider = @ptrCast(@alignCast(ctx));
        if (provider.err != null) {
            return null;
        }

        const allocator = provider.arena.allocator();
        std.debug.print("resolving (import {f} {f} {f})\n", .{ module, name, desc });
        // TODO: Allow returning anyerror from ImportProvider
        return switch (desc) {
            .func => |func_type| .{
                .func = wasmstint.runtime.FuncAddr.init(.{
                    .host = func: {
                        const func = allocator.create(wasmstint.runtime.FuncAddr.Host) catch |e| {
                            provider.err = e;
                            return null;
                        };
                        func.* = .{ .signature = func_type.* };
                        break :func func;
                    },
                }),
            },
            .mem => |mem_type| .{
                .mem = mem: {
                    const min_size = mem_type.limits.min * wasm_page_size;
                    if (min_size > wasm_smith_config.max_max_memory_bytes) {
                        provider.err = error.OutOfMemory;
                        return null;
                    }

                    const max_size = provider.input.uintInRangeInclusive(
                        usize,
                        min_size,
                        @min(mem_type.limits.max * wasm_page_size, wasm_smith_config.max_max_memory_bytes),
                    ) catch |e| {
                        provider.err = e;
                        return null;
                    };
                    //const mem = provider.memories.addOneAssumeCapacity();
                    //errdefer provider.memories.pop().?;
                    const provided_mem = wasmstint.runtime.MemInst.Mapped.allocateFromType(
                        mem_type,
                        provider.input.uintInRangeInclusive(usize, min_size, max_size) catch |e| {
                            provider.err = e;
                            return null;
                        },
                        max_size,
                    ) catch |e| {
                        provider.err = e;
                        return null;
                    };

                    const mem = provider.memories.addOneAssumeCapacity();
                    mem.* = provided_mem;
                    break :mem &mem.memory;
                },
            },
            .table => |table_type| .{
                .table = wasmstint.runtime.TableAddr{
                    .elem_type = table_type.elem_type,
                    .table = table: {
                        const limit_min: u32 = @intCast(table_type.limits.min);
                        if (limit_min > wasm_smith_config.max_max_table_elements) {
                            provider.err = error.OutOfMemory;
                            return null;
                        }

                        const max_elems = provider.input.uintInRangeInclusive(
                            u32,
                            limit_min,
                            @min(wasm_smith_config.max_max_table_elements, table_type.limits.max),
                        ) catch |e| {
                            provider.err = e;
                            return null;
                        };
                        //const table = provider.tables.addOneAssumeCapacity();
                        //errdefer provider.tables.pop().?;
                        const provided_table =
                            wasmstint.runtime.TableInst.Allocated.allocateFromType(
                                allocator,
                                table_type,
                                null,
                                provider.input.uintInRangeInclusive(
                                    u32,
                                    limit_min,
                                    max_elems,
                                ) catch |e| {
                                    provider.err = e;
                                    return null;
                                },
                                max_elems,
                            ) catch |e| {
                                provider.err = e;
                                return null;
                            };

                        const table = provider.tables.addOneAssumeCapacity();
                        table.* = provided_table;
                        break :table &table.table;
                    },
                },
            },
            .global => |global_type| .{
                .global = wasmstint.runtime.GlobalAddr{
                    .global_type = global_type.*,
                    .value = switch (global_type.val_type) {
                        .v128 => unreachable,
                        inline else => |val_type| val: {
                            const Val = wasmstint.runtime.GlobalAddr.Pointee(val_type);
                            const val = allocator.create(Val) catch |e| {
                                provider.err = e;
                                return null;
                            };

                            val.* = switch (val_type) {
                                .i32, .i64 => provider.input.int(Val) catch |e| {
                                    provider.err = e;
                                    return null;
                                },
                                .f32, .f64 => provider.input.floatFromBits(Val) catch |e| {
                                    provider.err = e;
                                    return null;
                                },
                                .externref => generateExternAddr(provider.input) catch |e| {
                                    provider.err = e;
                                    return null;
                                },
                                .funcref => Val.null,
                                else => unreachable,
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
        provider.* = undefined;
    }
};

fn generateTaggedValue(
    input: *ffi.Input,
    ty: wasmstint.Module.ValType,
) !wasmstint.Interpreter.TaggedValue {
    return switch (ty) {
        .i32 => .{ .i32 = try input.int(i32) },
        .i64 => .{ .i64 = try input.int(i64) },
        .f32 => .{ .f32 = try input.floatFromBits(f32) },
        .f64 => .{ .f64 = try input.floatFromBits(f64) },
        .externref => .{ .externref = try generateExternAddr(input) },
        // TODO: Generate random funcref
        .funcref => .{ .funcref = .null },
        else => unreachable,
    };
}

fn mainLoop(
    initial_state: wasmstint.Interpreter.State,
    scratch: *std.heap.ArenaAllocator,
    fuel: *wasmstint.Interpreter.Fuel,
    input: *ffi.Input,
) ![]const wasmstint.Interpreter.TaggedValue {
    var state = initial_state;
    while (true) {
        _ = scratch.reset(.retain_capacity);
        state = next: switch (state) {
            .awaiting_host => |*host| if (host.currentHostFunction() != null) {
                const result_types = host.hostSignature().results();
                const results = try scratch.allocator().alloc(
                    wasmstint.Interpreter.TaggedValue,
                    result_types.len,
                );
                for (result_types, results) |result_ty, *dst| {
                    dst.* = try generateTaggedValue(input, result_ty);
                }

                std.debug.print("host {f} returning {f}\n", .{
                    host.currentHostFunction().?,
                    wasmstint.Interpreter.TaggedValue.sliceFormatter(results),
                });
                break :next host.returnFromHost(results, fuel) catch unreachable;
            } else {
                return host.allocResults(scratch.allocator());
            },
            .awaiting_validation => unreachable,
            .call_stack_exhaustion => return error.OutOfMemory,
            .interrupted => |*interrupt| {
                switch (interrupt.cause().*) {
                    .out_of_fuel => return error.OutOfFuel,
                    .memory_grow, .table_grow => {},
                }

                break :next interrupt.resumeExecution(fuel);
            },
            .trapped => |*trapped| {
                std.debug.print("trap {t}\n", .{trapped.trap().code});
                return error.Trapped;
            },
        };
    }
}

const std = @import("std");
const wasmstint = @import("wasmstint");
const wasm_page_size = wasmstint.runtime.MemInst.page_size;
const ffi = @import("ffi");
