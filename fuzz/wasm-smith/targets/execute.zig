const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const harness = @import("harness");
const wasmstint = @import("wasmstint");

fn randomExternRef(rng: *std.Random.Xoshiro256) wasmstint.runtime.ExternAddr {
    return if (rng.random().int(u3) == 0)
        .null
    else
        .{
            .nat = @enumFromInt(rng.random().intRangeAtMost(
                usize,
                1,
                std.math.maxInt(usize),
            )),
        };
}

const HostFuncList = std.SegmentedList(wasmstint.runtime.FuncAddr.Host, 8);

fn randomHostFuncRef(rng: *std.Random.Xoshiro256, list: *const HostFuncList) wasmstint.runtime.FuncAddr {
    std.debug.assert(list.len > 0);
    const idx = rng.random().uintLessThan(usize, list.len);
    return wasmstint.runtime.FuncAddr.init(.{
        .host = .{
            .func = @constCast(list.at(idx)),
            .data = undefined,
        },
    });
}

const ImportProvider = struct {
    arena: ArenaAllocator,
    rng: *std.Random.Xoshiro256,
    host_funcs: HostFuncList = .{},
    mems: std.SegmentedList(wasmstint.runtime.MemInst, 1) = .{},
    tables: std.SegmentedList(wasmstint.runtime.TableInst, 2) = .{},

    fn randomNullableFuncRef(self: *const ImportProvider) wasmstint.runtime.FuncAddr.Nullable {
        return if (self.rng.random().int(u3) == 0 or self.host_funcs.len == 0)
            .null
        else
            @bitCast(randomHostFuncRef(self.rng, &self.host_funcs));
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
        switch (desc) {
            .func => |func_type| {
                const func = self.host_funcs.addOne(self.arena.allocator()) catch
                    @panic("TODO: consider allowing OOM error in import provider");

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
                const buf = std.heap.page_allocator.alignedAlloc(
                    u8,
                    std.heap.page_size_min,
                    mem_type.limits.min * wasmstint.runtime.MemInst.page_size,
                ) catch @panic("TODO: consider allowing OOM error in import provider");

                if (self.rng.random().int(u3) == 0) {
                    self.rng.random().bytes(buf);
                } else {
                    @memset(buf, 0);
                }

                const mem = self.mems.addOne(self.arena.allocator()) catch
                    @panic("TODO: consider allowing OOM error in import provider");

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
                const buf = std.heap.page_allocator.alignedAlloc(
                    u8,
                    std.heap.page_size_min,
                    len * table_stride.toBytes(),
                ) catch @panic("TODO: consider allowing OOM error in import provider");

                const table_inst = self.tables.addOne(self.arena.allocator()) catch
                    @panic("TODO: consider allowing OOM error in import provider");

                table_inst.* = wasmstint.runtime.TableInst{
                    .base = .{ .ptr = buf.ptr },
                    .stride = table_stride,
                    .len = len,
                    .capacity = len,
                    .limit = len,
                };

                if (self.rng.random().int(u3) == 0) {
                    switch (table_type.elem_type) {
                        .externref => for (table_inst.base.extern_ref[0..len]) |*ref| {
                            ref.* = randomExternRef(self.rng);
                        },
                        .funcref => for (table_inst.base.func_ref[0..len]) |*ref| {
                            ref.* = self.randomNullableFuncRef();
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
                        const n32 = self.arena.allocator().create(u32) catch
                            @panic("TODO: consider allowing OOM error in import provider");

                        n32.* = self.rng.random().int(u32);
                        break :value @ptrCast(n32);
                    },
                    .i64, .f64 => {
                        const n32 = self.arena.allocator().create(u32) catch
                            @panic("TODO: consider allowing OOM error in import provider");

                        n32.* = self.rng.random().int(u32);
                        break :value @ptrCast(n32);
                    },
                    .externref => {
                        const ref = self.arena.allocator().create(wasmstint.runtime.ExternAddr) catch
                            @panic("TODO: consider allowing OOM error in import provider");

                        ref.* = randomExternRef(self.rng);
                        break :value @ptrCast(ref);
                    },
                    .funcref => {
                        const ref = self.arena.allocator().create(wasmstint.runtime.FuncAddr.Nullable) catch
                            @panic("TODO: consider allowing OOM error in import provider");

                        ref.* = self.randomNullableFuncRef();
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
    rng: *std.Random.Xoshiro256,
    funcs: FuncAddrList,
    host_funcs: *const HostFuncList,
    types: []const wasmstint.Module.ValType,
    values: []wasmstint.Interpreter.TaggedValue,
) void {
    for (types, values) |ty, *val| {
        val.* = switch (ty) {
            .i32 => .{ .i32 = rng.random().int(i32) },
            .i64 => .{ .i64 = rng.random().int(i64) },
            .f32 => .{ .f32 = @bitCast(rng.random().int(u32)) },
            .f64 => .{ .f64 = @bitCast(rng.random().int(u64)) },
            .externref => .{ .externref = randomExternRef(rng) },
            .funcref => .{
                .funcref = if (rng.random().int(u4) == 0)
                    .null
                else if (host_funcs.len > 0 and rng.random().int(u2) == 0)
                    @bitCast(randomHostFuncRef(rng, host_funcs))
                else if (funcs.len > 0)
                    @bitCast(funcs[rng.random().uintLessThan(usize, funcs.len)])
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
    rng: *std.Random.Xoshiro256,
    host_funcs: *const HostFuncList,
    arena: *ArenaAllocator,
    scratch: *ArenaAllocator,
) void {
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

                randomTaggedValues(rng, funcs, host_funcs, result_types, results);

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
    var input = input_bytes;
    var wasm = try harness.generateValidModule(&input);
    defer wasm.deinit();

    if (input.len < 32) return .skip;

    var rng = std.Random.Xoshiro256{ .s = @bitCast(input[0..32].*) };
    input = input[32..];

    // comptime {
    //     std.debug.assert(@import("builtin").fuzz);
    // }

    var main_pages = try wasmstint.PageBufferAllocator.init(1 * (1024 * 1024));
    defer main_pages.deinit();

    var scratch_pages = try wasmstint.PageBufferAllocator.init(512 * 1024);
    var scratch = ArenaAllocator.init(scratch_pages.allocator());
    defer scratch_pages.deinit();

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
        .rng = &rng,
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
        error.ImportFailure => std.debug.panic("{}", .{import_failure}),
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

        driveInterpreter(
            &.{}, // Exported functions are not yet available!
            &interp,
            &fuel,
            &rng,
            &import_provider.host_funcs,
            &code_arena,
            &scratch,
        );
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

    for (exported_funcs) |callee| {
        interp.reset();

        _ = scratch.reset(.retain_capacity);
        const arg_types = callee.signature().parameters();
        const args = try scratch.allocator().alloc(
            wasmstint.Interpreter.TaggedValue,
            arg_types.len,
        );

        randomTaggedValues(
            &rng,
            exported_funcs,
            &import_provider.host_funcs,
            arg_types,
            args,
        );

        var fuel = init_fuel;
        _ = interp.state.awaiting_host.beginCall(
            std.heap.page_allocator,
            callee,
            args,
            &fuel,
        ) catch |e| switch (e) {
            error.ValueTypeOrCountMismatch => unreachable,
            else => |oom| return oom,
        };

        driveInterpreter(
            exported_funcs,
            &interp,
            &fuel,
            &rng,
            &import_provider.host_funcs,
            &code_arena,
            &scratch,
        );
    }

    interp.reset();

    return .ok;
}

comptime {
    harness.defineFuzzTarget(target);
}
