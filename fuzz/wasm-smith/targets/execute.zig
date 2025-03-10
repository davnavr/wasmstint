const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const harness = @import("harness");
const Generator = harness.Generator;
const wasmstint = @import("wasmstint");

fn randomExternRef(gen: *Generator) Generator.Error!wasmstint.runtime.ExternAddr {
    return if (try gen.int(u3) == 0)
        .null
    else
        .{
            .nat = @enumFromInt(try gen.intRangeAtMost(
                usize,
                1,
                std.math.maxInt(usize),
            )),
        };
}

const HostFuncList = std.SegmentedList(wasmstint.runtime.FuncAddr.Host, 8);

fn randomHostFuncRef(gen: *Generator, list: *const HostFuncList) Generator.Error!wasmstint.runtime.FuncAddr {
    std.debug.assert(list.len > 0);
    const idx = try gen.uintLessThan(usize, list.len);
    return wasmstint.runtime.FuncAddr.init(.{
        .host = .{
            .func = @constCast(list.at(idx)),
            .data = undefined,
        },
    });
}

const ImportProvider = struct {
    arena: ArenaAllocator,
    gen: *Generator,
    gen_err: ?Generator.Error = null,
    host_funcs: HostFuncList = .{},
    mems: std.SegmentedList(wasmstint.runtime.MemInst, 1) = .{},
    tables: std.SegmentedList(wasmstint.runtime.TableInst, 2) = .{},
    // reuse_funcs = std.HashMapUnmanaged(*const FuncType, std.SegmentedList(*const wasmstint.runtime.FuncAddr.Host, 1));

    fn randomNullableFuncRef(self: *const ImportProvider) Generator.Error!wasmstint.runtime.FuncAddr.Nullable {
        return if (self.host_funcs.len == 0 or try self.gen.int(u3) == 0)
            .null
        else
            @bitCast(try randomHostFuncRef(self.gen, &self.host_funcs));
    }

    fn resolveImpl(
        self: *ImportProvider,
        desc: wasmstint.runtime.ImportProvider.Desc,
    ) (error{OutOfMemory} || Generator.Error)!wasmstint.runtime.ExternVal {
        switch (desc) {
            .func => |func_type| {
                const func = try self.host_funcs.addOne(self.arena.allocator());

                func.* = .{ .signature = func_type.* };
                return .{
                    .func = wasmstint.runtime.FuncAddr.init(.{
                        .host = .{
                            .data = undefined,
                            .func = func,
                        },
                    }),
                };
            },
            .mem => |mem_type| {
                const buf = try std.heap.page_allocator.alignedAlloc(
                    u8,
                    std.heap.page_size_min,
                    mem_type.limits.min * wasmstint.runtime.MemInst.page_size,
                );

                if (try self.gen.int(u3) == 0) {
                    @memcpy(buf, try self.gen.bytes(buf.len));
                } else {
                    @memset(buf, 0);
                }

                const mem = try self.mems.addOne(self.arena.allocator());

                mem.* = .{
                    .base = buf.ptr,
                    .size = buf.len,
                    .capacity = buf.len,
                    .limit = mem_type.limits.max * wasmstint.runtime.MemInst.page_size,
                };

                return .{ .mem = mem };
            },
            .table => |table_type| {
                const table_stride = wasmstint.runtime.TableStride.ofType(table_type.elem_type);
                const len: u32 = @intCast(table_type.limits.min);
                const buf = try std.heap.page_allocator.alignedAlloc(
                    u8,
                    std.heap.page_size_min,
                    len * table_stride.toBytes(),
                );

                const table_inst = try self.tables.addOne(self.arena.allocator());

                table_inst.* = wasmstint.runtime.TableInst{
                    .base = .{ .ptr = buf.ptr },
                    .stride = table_stride,
                    .len = len,
                    .capacity = len,
                    .limit = len,
                };

                if (try self.gen.int(u3) == 0) {
                    switch (table_type.elem_type) {
                        .externref => for (table_inst.base.extern_ref[0..len]) |*ref| {
                            ref.* = try randomExternRef(self.gen);
                        },
                        .funcref => for (table_inst.base.func_ref[0..len]) |*ref| {
                            ref.* = try self.randomNullableFuncRef();
                        },
                        else => unreachable,
                    }
                } else {
                    @memset(table_inst.bytes(), 0);
                }

                return .{
                    .table = wasmstint.runtime.TableAddr{
                        .elem_type = table_type.elem_type,
                        .table = table_inst,
                    },
                };
            },
            .global => |global_type| {
                const value: *anyopaque = value: switch (global_type.val_type) {
                    .i32, .f32 => {
                        const n32 = try self.arena.allocator().create(u32);
                        n32.* = try self.gen.int(u32);
                        break :value @ptrCast(n32);
                    },
                    .i64, .f64 => {
                        const n64 = try self.arena.allocator().create(u64);
                        n64.* = try self.gen.int(u64);
                        break :value @ptrCast(n64);
                    },
                    .externref => {
                        const ref = try self.arena.allocator().create(wasmstint.runtime.ExternAddr);
                        ref.* = try randomExternRef(self.gen);
                        break :value @ptrCast(ref);
                    },
                    .funcref => {
                        const ref = try self.arena.allocator().create(wasmstint.runtime.FuncAddr.Nullable);
                        ref.* = try self.randomNullableFuncRef();
                        break :value @ptrCast(ref);
                    },
                    .v128 => unreachable,
                };

                return .{
                    .global = wasmstint.runtime.GlobalAddr{
                        .global_type = global_type.*,
                        .value = value,
                    },
                };
            },
        }
    }

    fn resolve(
        ctx: *anyopaque,
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        desc: wasmstint.runtime.ImportProvider.Desc,
    ) ?wasmstint.runtime.ExternVal {
        const self: *ImportProvider = @ptrCast(@alignCast(ctx));
        _ = module;
        _ = name;
        return self.resolveImpl(desc) catch |e| switch (e) {
            error.OutOfMemory => @panic("TODO: allowing OOM error in import provider"),
            error.OutOfDataBytes => |err| {
                self.gen_err = err;
                return null;
            },
        };
    }

    fn provider(self: *ImportProvider) wasmstint.runtime.ImportProvider {
        return .{
            .ctx = @ptrCast(self),
            .resolve = resolve,
        };
    }

    fn deinit(self: ImportProvider) void {
        var iter_mems = self.mems.constIterator(0);
        while (iter_mems.next()) |mem| {
            std.heap.page_allocator.free(mem.base[0..mem.capacity]);
        }

        // TODO: Deinit tables

        self.arena.deinit();
    }
};

const FuncAddrList = []align(@sizeOf([2]usize)) const wasmstint.runtime.FuncAddr;

fn randomTaggedValues(
    gen: *Generator,
    funcs: FuncAddrList,
    host_funcs: *const HostFuncList,
    types: []const wasmstint.Module.ValType,
    values: []wasmstint.Interpreter.TaggedValue,
) Generator.Error!void {
    for (types, values) |ty, *val| {
        val.* = switch (ty) {
            .i32 => .{ .i32 = try gen.int(i32) },
            .i64 => .{ .i64 = try gen.int(i64) },
            .f32 => .{ .f32 = @bitCast(try gen.int(u32)) },
            .f64 => .{ .f64 = @bitCast(try gen.int(u64)) },
            .externref => .{ .externref = try randomExternRef(gen) },
            .funcref => .{
                .funcref = if (try gen.int(u4) == 0)
                    .null
                else if (host_funcs.len > 0 and try gen.int(u2) == 0)
                    @bitCast(try randomHostFuncRef(gen, host_funcs))
                else if (funcs.len > 0)
                    @bitCast(funcs[try gen.uintLessThan(usize, funcs.len)])
                else
                    .null,
            },
            .v128 => unreachable,
        };
    }
}

fn driveInterpreter(
    funcs: FuncAddrList,
    interp: *wasmstint.Interpreter,
    fuel: *wasmstint.Interpreter.Fuel,
    gen: *Generator,
    host_funcs: *const HostFuncList,
    arena: *ArenaAllocator,
    scratch: *ArenaAllocator,
) Generator.Error!void {
    while (true) {
        switch (interp.state) {
            .awaiting_host => |*awaiting| if (awaiting.currentHostFunction()) |host_func| {
                _ = scratch.reset(.retain_capacity);
                const result_types = host_func.func.signature.results();
                const results = scratch.allocator().alloc(
                    wasmstint.Interpreter.TaggedValue,
                    result_types.len,
                ) catch @panic("TODO: trap on OOM");

                // TODO: random chance to trap

                try randomTaggedValues(gen, funcs, host_funcs, result_types, results);

                _ = awaiting.returnFromHost(results, fuel) catch unreachable;
            } else return,
            .awaiting_validation => |*validation| {
                _ = scratch.reset(.retain_capacity);
                _ = validation.validate(arena.allocator(), scratch, fuel);
            },
            .interrupted => |*interrupt| {
                switch (interrupt.cause) {
                    .out_of_fuel => return,
                    .memory_grow, .table_grow => {},
                }

                _ = interrupt.resumeExecution(fuel);
            },
            .trapped, .call_stack_exhaustion => return,
        }
    }
}

/// Instantiates a randomly generated WebAssembly module, then invokes its exported functions.
pub fn target(input_bytes: []const u8) !harness.Result {
    // comptime {
    //     std.debug.assert(@import("builtin").fuzz);
    // }

    var main_pages = try wasmstint.PageBufferAllocator.init(1 * (1024 * 1024));
    defer main_pages.deinit();

    var scratch_pages = try wasmstint.PageBufferAllocator.init(512 * 1024);
    var scratch = ArenaAllocator.init(scratch_pages.allocator());
    defer scratch_pages.deinit();

    var gen = Generator.init(input_bytes);

    var rng = std.Random.Xoshiro256{ .s = undefined };
    std.mem.asBytes(&rng.s).* = (try gen.byteArray(32)).*;

    var wasm = try gen.validWasmModule();
    defer wasm.deinit();

    var wasm_parse: []const u8 = wasm.items.toSlice();
    var module = try wasmstint.Module.parse(
        main_pages.allocator(),
        &wasm_parse,
        &scratch,
        rng.random(),
        .{ .keep_custom_sections = false, .realloc_contents = true },
    );
    defer module.deinit(main_pages.allocator());

    var import_provider = ImportProvider{
        .arena = ArenaAllocator.init(main_pages.allocator()),
        .gen = &gen,
    };
    defer import_provider.deinit();

    var import_failure: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_alloc = wasmstint.runtime.ModuleAlloc.allocate(
        &module,
        import_provider.provider(),
        main_pages.allocator(),
        wasmstint.runtime.ModuleAllocator.page_allocator,
        &import_failure,
    ) catch |e| switch (e) {
        error.ImportFailure => if (import_provider.gen_err) |err| {
            return err;
        } else {
            std.debug.panic("{}", .{import_failure});
        },
        else => |err| return err,
    };

    defer module_alloc.requiring_instantiation.deinit(
        main_pages.allocator(),
        wasmstint.runtime.ModuleAllocator.page_allocator,
    );

    var interp = try wasmstint.Interpreter.init(
        std.heap.page_allocator,
        .{},
    );
    defer interp.deinit(std.heap.page_allocator);

    var code_arena = ArenaAllocator.init(main_pages.allocator());
    defer code_arena.deinit();

    const init_fuel = wasmstint.Interpreter.Fuel{ .remaining = 2_500_000 };
    {
        var fuel = init_fuel;
        _ = try interp.state.awaiting_host.instantiateModule(
            std.heap.page_allocator,
            &module_alloc,
            &fuel,
        );

        try driveInterpreter(
            &.{}, // Exported functions are not yet available!
            &interp,
            &fuel,
            &gen,
            &import_provider.host_funcs,
            &code_arena,
            &scratch,
        );

        interp.reset();
    }

    if (!module_alloc.instantiated) {
        std.debug.assert(interp.state != .awaiting_host);
        return .ok;
    }

    const module_inst = module_alloc.expectInstantiated();

    const exported_funcs: FuncAddrList = funcs: {
        _ = scratch.reset(.retain_capacity);
        var funcs = std.ArrayListAlignedUnmanaged(
            wasmstint.runtime.FuncAddr,
            @sizeOf([2]usize),
        ).empty;

        const exports = module_inst.exports();
        try funcs.ensureTotalCapacity(scratch.allocator(), exports.len);

        for (0..exports.len) |i| {
            const export_val = exports.at(i);
            switch (export_val.val) {
                .func => |func| try funcs.append(scratch.allocator(), func),
                else => {},
            }
        }

        const final_funcs = try main_pages.allocator().alignedAlloc(
            wasmstint.runtime.FuncAddr,
            @sizeOf([2]usize),
            funcs.items.len,
        );

        @memcpy(final_funcs, funcs.items);
        break :funcs final_funcs;
    };
    defer main_pages.allocator().free(exported_funcs);

    if (exported_funcs.len > 0) {
        const invoke_count = try gen.intRangeAtMost(u32, 1, @intCast(exported_funcs.len));
        for (0..invoke_count) |_| {
            defer interp.reset();

            const callee = exported_funcs[try gen.uintLessThan(usize, exported_funcs.len)];

            _ = scratch.reset(.retain_capacity);
            const arg_types = callee.signature().parameters();
            const args = scratch.allocator().alloc(
                wasmstint.Interpreter.TaggedValue,
                arg_types.len,
            ) catch break;

            randomTaggedValues(
                &gen,
                exported_funcs,
                &import_provider.host_funcs,
                arg_types,
                args,
            ) catch break;

            var fuel = init_fuel;
            _ = interp.state.awaiting_host.beginCall(
                std.heap.page_allocator,
                callee,
                args,
                &fuel,
            ) catch |e| switch (e) {
                error.ValueTypeOrCountMismatch => unreachable,
                error.OutOfMemory => break,
            };

            driveInterpreter(
                exported_funcs,
                &interp,
                &fuel,
                &gen,
                &import_provider.host_funcs,
                &code_arena,
                &scratch,
            ) catch break;
        }
    }

    return .ok;
}

comptime {
    harness.defineFuzzTarget(target);
}
