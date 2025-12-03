const max_memory_size_in_bytes = wasm_page_size * 4096;
const max_table_elems = 1_000_000;
const max_interpreter_stack = 200_000;
const max_max_fuel = 3_000_000;

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
    };
    defer import_provider.deinit();

    var module_allocating = allocate: {
        var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
        break :allocate wasmstint.runtime.ModuleAllocating.begin(
            parsed_module,
            import_provider.importProvider(),
            arena.allocator(),
            &import_error,
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

    // TODO: Error during module allocation causes memory leak

    while (module_allocating.nextMemoryType()) |ty| {
        const min_in_bytes = ty.limits.min * wasm_page_size;
        if (min_in_bytes > max_memory_size_in_bytes) {
            return error.OutOfMemory;
        }

        const chosen_max = try input.uintInRangeInclusive(
            usize,
            min_in_bytes,
            @min(ty.limits.max * wasm_page_size, max_memory_size_in_bytes),
        );
        wasmstint.runtime.paged_memory.allocate(
            &module_allocating,
            try input.uintInRangeInclusive(usize, min_in_bytes, chosen_max),
            chosen_max,
        ) catch |e| switch (e) {
            error.LimitsMismatch => unreachable, // bad mem
            error.OutOfMemory => |oom| return oom, // mem
        };
    }

    while (module_allocating.nextTableType()) |ty| {
        if (ty.limits.min > max_table_elems) {
            return error.OutOfMemory;
        }

        wasmstint.runtime.table_allocator.allocateForModule(
            &module_allocating,
            arena.allocator(),
            try input.uintInRangeInclusive(
                usize,
                ty.limits.min,
                @min(ty.limits.max, max_table_elems),
            ),
        ) catch |e| switch (e) {
            error.LimitsMismatch => unreachable, // bad table
            error.OutOfMemory => |oom| return oom, // table
        };
    }

    var module_allocated = module_allocating.finish() catch unreachable;
    var interp: wasmstint.Interpreter = undefined;
    const initial_state = try interp.init(
        allocator,
        .{ .stack_reserve = try input.uintInRangeInclusive(u32, 0, max_interpreter_stack) },
    );
    defer interp.deinit(allocator);
    {
        var instantiate_fuel = wasmstint.Interpreter.Fuel{
            .remaining = try input.uintInRangeInclusive(u64, 1, max_max_fuel),
        };
        const instantiate_state = try initial_state.awaiting_host.instantiateModule(
            allocator,
            &module_allocated,
            &instantiate_fuel,
        );

        const start_results = mainLoop(
            instantiate_state,
            scratch,
            arena.allocator(),
            &instantiate_fuel,
            input,
        ) catch |e| switch (e) {
            error.OutOfMemory, error.OutOfFuel, error.BadInput, error.Trapped => {
                std.debug.print("start function did not return: {t}\n", .{e});
                return;
            },
        };

        std.debug.assert(start_results.len == 0);
    }

    const module = module_allocated.assumeInstantiated();
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

                var fuel = wasmstint.Interpreter.Fuel{
                    .remaining = try input.uintInRangeInclusive(u64, 1, max_max_fuel),
                };
                const results = mainLoop(
                    interp.reset(),
                    scratch,
                    arena.allocator(),
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
    allocated_mems: std.ArrayList(*wasmstint.runtime.MemInst) = .empty,
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
                    .host = .{
                        .func = func: {
                            const func = allocator.create(wasmstint.runtime.FuncAddr.Host) catch |e| {
                                provider.err = e;
                                return null;
                            };
                            func.* = .{ .signature = func_type.* };
                            break :func func;
                        },
                        .data = null,
                    },
                }),
            },
            .mem => |mem_type| .{
                .mem = mem: {
                    const mem = allocator.create(wasmstint.runtime.MemInst) catch |e| {
                        provider.err = e;
                        return null;
                    };

                    const min_size = mem_type.limits.min * wasm_page_size;
                    if (min_size > max_memory_size_in_bytes) {
                        provider.err = error.OutOfMemory;
                        return null;
                    }

                    const max_size = provider.input.uintInRangeInclusive(
                        usize,
                        min_size,
                        max_memory_size_in_bytes,
                    ) catch |e| {
                        provider.err = e;
                        return null;
                    };

                    mem.* = wasmstint.runtime.paged_memory.map(
                        mem_type,
                        provider.input.uintInRangeInclusive(usize, min_size, max_size) catch |e| {
                            provider.err = e;
                            return null;
                        },
                        max_size,
                    ) catch {
                        provider.err = error.OutOfMemory;
                        return null;
                    };
                    provider.allocated_mems.append(allocator, mem) catch |e| {
                        provider.err = e;
                        return null;
                    };

                    break :mem mem;
                },
            },
            .table => |table_type| .{
                .table = wasmstint.runtime.TableAddr{
                    .elem_type = table_type.elem_type,
                    .table = table: {
                        if (table_type.limits.min > max_table_elems) {
                            provider.err = error.OutOfMemory;
                            return null;
                        }

                        const max_elems = @min(max_table_elems, table_type.limits.max);
                        const table = allocator.create(wasmstint.runtime.TableInst) catch |e| {
                            provider.err = e;
                            return null;
                        };
                        table.* = wasmstint.runtime.table_allocator.allocate(
                            table_type,
                            allocator,
                            provider.input.uintInRangeInclusive(
                                usize,
                                table_type.limits.min,
                                max_elems,
                            ) catch |e| {
                                provider.err = e;
                                return null;
                            },
                        ) catch |e| switch (e) {
                            error.LimitsMismatch => unreachable, // bad table
                            error.OutOfMemory => |oom| {
                                provider.err = oom;
                                return null;
                            },
                        };
                        break :table table;
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
        for (provider.allocated_mems.items) |mem| {
            wasmstint.runtime.paged_memory.free(mem);
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
    allocator: std.mem.Allocator,
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
                    .memory_grow => |*grow| wasmstint.runtime.paged_memory.grow(grow),
                    .table_grow => |*grow| wasmstint.runtime.table_allocator.grow(
                        grow,
                        allocator,
                    ),
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
