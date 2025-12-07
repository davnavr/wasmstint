//! Differential testing against the [`wasmi`] interpreter.
//!
//! [`wasmi`]: https://github.com/wasmi-labs/wasmi

const max_interpreter_stack = 4096 * 32;
const max_fuel = 250_000;
const stderr_buf_size = 512;

pub const wasm_smith_config = ffi.wasm_smith.Configuration{
    .canonicalize_nans = .enabled,
    .memory_max_size_required = .enabled,
    .table_max_size_required = .enabled,
};

const Execution = struct {
    const Inner = extern struct {
        unsafe_trap: Trap,
        func_export_count: u16,

        actions_len: u32,
        actions_ptr: ?[*]const Action,

        func_export_arities_ptr: [*]const FuncArities,

        func_import_arities_ptr: [*]const FuncArities,
        func_import_count: u32,

        global_import_count: u32,
        global_import_values_ptr: [*]const ArgumentVal,

        host_calls_len: usize,
        host_calls_ptr: [*]const HostCall,
        // Hidden fields...
    };

    inner: *const Inner,

    fn trap(exec: Execution) ?Trap {
        return if (exec.inner.actions_ptr == null)
            exec.inner.unsafe_trap
        else
            null;
    }

    fn actions(exec: Execution) []const Action {
        return exec.inner.actions_ptr.?[0..exec.inner.actions_len];
    }

    fn hostCalls(exec: Execution) []const HostCall {
        return exec.inner.host_calls_ptr[0..exec.inner.host_calls_len];
    }

    fn funcImportArities(exec: Execution) []const FuncArities {
        return exec.inner.func_import_arities_ptr[0..exec.inner.func_import_count];
    }

    fn funcExportArities(exec: Execution) []const FuncArities {
        std.debug.assert(exec.inner.actions_ptr != null);
        return exec.inner.func_export_arities_ptr[0..exec.inner.func_export_count];
    }

    fn globalImportVals(exec: Execution) []const ArgumentVal {
        return exec.inner.global_import_values_ptr[0..exec.inner.global_import_count];
    }

    const Trap = enum(u8) {
        unreachable_code_reached = 0,
        memory_access_out_of_bounds = 1,
        table_access_out_of_bounds = 2,
        indirect_call_to_null = 3,
        integer_division_by_zero = 4,
        integer_overflow = 5,
        invalid_conversion_to_integer = 6,
        stack_overflow = 7,
        bad_signature = 8,
        out_of_fuel = 9,

        fn toWasmstintTrapCode(
            trap_code: Trap,
        ) error{ StackOverflow, OutOfFuel }!wasmstint.Interpreter.Trap.Code {
            return switch (trap_code) {
                inline .unreachable_code_reached,
                .memory_access_out_of_bounds,
                .table_access_out_of_bounds,
                .indirect_call_to_null,
                .integer_division_by_zero,
                .integer_overflow,
                .invalid_conversion_to_integer,
                => |known| comptime @field(wasmstint.Interpreter.Trap.Code, @tagName(known)),
                .bad_signature => .indirect_call_signature_mismatch,
                .stack_overflow => error.StackOverflow,
                .out_of_fuel => error.OutOfFuel,
            };
        }
    };

    const MemoryId = packed struct(u16) {
        n: u16,
    };

    const FuncId = packed struct(u16) {
        n: u16,

        fn arities(id: FuncId, exec: Execution) FuncArities {
            return exec.funcExportArities()[id.n];
        }
    };

    const HostFuncId = packed struct(u16) {
        n: u16,

        fn arities(id: HostFuncId, exec: Execution) FuncArities {
            return exec.funcImportArities()[id.n];
        }
    };

    const FuncArities = extern struct {
        param_count: u16,
        result_count: u16,
    };

    const FuncRef = extern struct {
        tag: Tag,
        unsafe_id: FuncId,

        const Tag = enum(u16) { null = 0, ref = 1 };

        fn id(ref: FuncRef) ?FuncId {
            return switch (ref.tag) {
                .null => null,
                .ref => ref.unsafe_id,
            };
        }

        pub fn format(ref: FuncRef, w: *Writer) Writer.Error!void {
            if (ref.id()) |f| {
                try w.print("(ref.func $f{d})", .{f.n});
            } else {
                try w.writeAll("(ref.null func)");
            }
        }
    };

    const ExternRef = wasmstint.runtime.ExternAddr.Nat;

    const Action = extern union {
        tag: Tag,
        call: Call,
        hash_memory: HashMemory,

        const Tag = enum(u16) {
            call = 0,
            hash_memory = 1,
        };

        const Payload = union(Tag) {
            call: *const Call,
            hash_memory: *const HashMemory,
        };

        fn payload(action: *const Action) Payload {
            return switch (action.tag) {
                inline else => |tag| @unionInit(
                    Payload,
                    @tagName(tag),
                    &@field(action, @tagName(tag)),
                ),
            };
        }

        const Call = extern struct {
            tag: enum(u16) { call = 0 },
            func: FuncId,
            action: extern struct {
                unsafe_trap: Trap,
                args_ptr: [*]const ArgumentVal,
                results_ptr: ?[*]const ResultVal,
            },

            fn results(call: *const Call, exec: Execution) Results {
                return if (call.action.results_ptr) |results_ptr| .{
                    .values = results_ptr[0..call.func.arities(exec).result_count],
                } else .{ .trapped = call.action.unsafe_trap };
            }

            const Results = union(enum) {
                values: []const Execution.ResultVal,
                trapped: Trap,

                pub fn format(fmt: *const Results, w: *Writer) Writer.Error!void {
                    switch (fmt.*) {
                        .values => |result_values| try Execution.ResultVal
                            .sliceFormatter(result_values).format(w),
                        .trapped => |trap_code| try w.print("trapped {t}", .{trap_code}),
                    }
                }
            };
        };

        const HashMemory = extern struct {
            tag: enum(u16) { hash_memory = 1 },
            memory: MemoryId,
            hash: u64,
        };
    };

    fn memory_hasher(data_ptr: [*]const u8, data_len: usize) callconv(.c) u64 {
        const data = data_ptr[0..data_len];
        std.debug.assert(data.len % wasmstint.runtime.MemInst.page_size == 0);
        return std.hash.XxHash3.hash(
            8327219780915383169, // "chosen by fair dice roll."
            data,
        );
    }

    const ValTag = enum(u64) {
        i32 = 0,
        i64 = 1,
        f32 = 2,
        f64 = 3,
        funcref = 4,
        externref = 5,

        fn toValType(tag: ValTag) wasmstint.Module.ValType {
            return switch (tag) {
                inline else => |t| comptime @field(wasmstint.Module.ValType, @tagName(t)),
            };
        }
    };

    fn ValTagged(comptime T: type) type {
        return @Type(.{
            .@"union" = .{
                .decls = &.{},
                .layout = .auto,
                .tag_type = ValTag,
                .fields = fields: {
                    const Payload = @FieldType(T, "payload");
                    const tag_fields = @typeInfo(ValTag).@"enum".fields;
                    var fields: [tag_fields.len]std.builtin.Type.UnionField = undefined;
                    for (tag_fields, &fields) |tag, *f| {
                        const FieldType = @FieldType(Payload, tag.name);
                        f.* = .{
                            .name = tag.name,
                            .type = FieldType,
                            .alignment = @alignOf(FieldType),
                        };
                    }

                    break :fields &fields;
                },
            },
        });
    }

    fn valTagged(comptime T: type) (fn (*const T) ValTagged(T)) {
        return struct {
            fn tagged(val: *const T) ValTagged(T) {
                return switch (val.tag) {
                    inline else => |tag| @unionInit(
                        ValTagged(T),
                        @tagName(tag),
                        @field(val.payload, @tagName(tag)),
                    ),
                };
            }
        }.tagged;
    }

    fn formatRawVal(comptime T: type) (fn (*const T, *Writer) Writer.Error!void) {
        return struct {
            fn format(val: *const T, w: *Writer) Writer.Error!void {
                switch (valTagged(T)(val)) {
                    .i32 => |i| try w.print("(i32.const 0x{X:0>8} (;{d};))", .{ i, i }),
                    .i64 => |i| try w.print("(i64.const 0x{X:0>16} (;{d};))", .{ i, i }),
                    .f32 => |f| try w.print(
                        "(f32.const 0x{X:0>8} (;{d};))",
                        .{ @as(u32, @bitCast(f)), f },
                    ),
                    .f64 => |f| try w.print(
                        "(f64.const 0x{X:0>16} (;{d};))",
                        .{ @as(u64, @bitCast(f)), f },
                    ),
                    inline .funcref, .externref => |r| try r.format(w),
                }
            }
        }.format;
    }

    fn ValSliceFormatter(comptime T: type) type {
        return struct {
            vals: []const T,

            pub fn format(fmt: @This(), w: *Writer) Writer.Error!void {
                if (fmt.vals.len == 0) {
                    try w.writeAll("()");
                } else {
                    for (fmt.vals, 0..) |*v, i| {
                        if (i > 0) {
                            try w.writeByte(' ');
                        }

                        try formatRawVal(T)(v, w);
                    }
                }
            }
        };
    }

    fn valSliceFormatter(comptime T: type) (fn ([]const T) ValSliceFormatter(T)) {
        return struct {
            fn sliceFormatter(vals: []const T) ValSliceFormatter(T) {
                return .{ .vals = vals };
            }
        }.sliceFormatter;
    }

    const ArgumentVal = extern struct {
        tag: ValTag,
        payload: extern union {
            i32: i32,
            i64: i64,
            f32: f32,
            f64: f64,
            funcref: FuncRef,
            externref: ExternRef,
        },

        const tagged = valTagged(ArgumentVal);
        pub const format = formatRawVal(ArgumentVal);
        const sliceFormatter = valSliceFormatter(ArgumentVal);

        fn toWasmstintValue(
            val: *const ArgumentVal,
            func_imports: []const wasmstint.runtime.FuncAddr.Host,
        ) wasmstint.Interpreter.TaggedValue {
            return switch (val.tagged()) {
                inline .i32, .i64, .f32, .f64 => |n, tag| @unionInit(
                    wasmstint.Interpreter.TaggedValue,
                    @tagName(tag),
                    n,
                ),
                .externref => |r| .{ .externref = .{ .nat = r } },
                .funcref => |f| .{ .funcref = if (f.id()) |idx|
                    @bitCast(wasmstint.runtime.FuncAddr.init(.{ .host = &func_imports[idx.n] }))
                else
                    wasmstint.runtime.FuncAddr.Nullable.null },
            };
        }
    };

    const ResultFuncRef = extern struct {
        tag: Tag,
        unsafe_arities: FuncArities,

        const Tag = enum(u32) { null = 0, ref = 1 };

        fn arities(func_ref: ResultFuncRef) ?FuncArities {
            return switch (func_ref.tag) {
                .null => null,
                .ref => func_ref.unsafe_arities,
            };
        }

        pub fn format(ref: ResultFuncRef, w: *Writer) Writer.Error!void {
            if (ref.arities()) |a| {
                try w.print(
                    "(ref.func (; {d} params, {d} results ;))",
                    .{ a.param_count, a.result_count },
                );
            } else {
                try w.writeAll("(ref.null func)");
            }
        }
    };

    const ResultVal = extern struct {
        tag: ValTag,
        payload: extern union {
            i32: i32,
            i64: i64,
            f32: f32,
            f64: f64,
            funcref: ResultFuncRef,
            externref: ExternRef,
        },

        const tagged = valTagged(ResultVal);
        pub const format = formatRawVal(ResultVal);
        const sliceFormatter = valSliceFormatter(ResultVal);

        fn matchesWasmstintValue(
            result: *const ResultVal,
            value: *const wasmstint.Interpreter.TaggedValue,
        ) bool {
            return result.tag.toValType() == value.valueType() and switch (result.tagged()) {
                inline .i32, .i64 => |i, tag| @field(value, @tagName(tag)) == i,
                inline .f32, .f64 => |z, tag| eq: {
                    const Bits = std.meta.Int(.unsigned, @typeInfo(@TypeOf(z)).float.bits);
                    const result_bits: Bits = @bitCast(@field(value, @tagName(tag)));
                    break :eq result_bits == @as(Bits, @bitCast(z));
                },
                .externref => |extern_ref| value.externref
                    .eql(wasmstint.runtime.ExternAddr{ .nat = extern_ref }),
                .funcref => |pattern| eq: {
                    const actual = value.funcref.funcInst();
                    if (pattern.arities()) |arities| {
                        if (actual) |func_addr| {
                            const signature = func_addr.signature();
                            break :eq signature.param_count == arities.param_count and
                                signature.result_count == arities.result_count;
                        } else break :eq false;
                    } else {
                        break :eq actual == null;
                    }
                },
            };
        }
    };

    const HostCall = extern struct {
        func: HostFuncId,
        //trap: Trap,
        arguments_ptr: [*]const ResultVal,
        results_ptr: [*]const ArgumentVal,
    };

    fn run(
        wasm_module: []const u8,
        input: *ffi.Input,
        fuel: u64,
    ) !Execution {
        const diff = @extern(
            *const fn (
                input: *ffi.Input,
                wasm_ptr: [*]const u8,
                wasm_len: usize,
                fuel: u64,
                out: **const Inner,
                hasher: *const fn ([*]const u8, usize) callconv(.c) u64,
            ) callconv(.c) bool,
            .{ .is_dll_import = true, .name = "wasmstint_fuzz_wasmi_diff" },
        );

        var exec: *const Inner = undefined;
        return if (diff(input, wasm_module.ptr, wasm_module.len, fuel, &exec, memory_hasher))
            Execution{ .inner = exec }
        else
            error.BadInput;
    }

    fn deinit(exec: *Execution) void {
        const free = @extern(
            *const fn (exec: *const Inner) callconv(.c) void,
            .{ .is_dll_import = true, .name = "wasmstint_fuzz_wasmi_free" },
        );

        free(exec.inner);
        exec.* = undefined;
    }
};

const HostState = struct {
    call_count: usize,

    const Call = struct {
        number: usize,
        record: *const Execution.HostCall,
    };

    fn nextCall(state: *HostState, exec: Execution) Call {
        const host_calls = exec.hostCalls();
        const number = state.call_count;
        if (number >= host_calls.len) {
            std.debug.panic("too many host calls, expected {d}", .{host_calls.len});
        }

        const call = &host_calls[number];
        state.call_count += 1;
        return .{ .number = number, .record = call };
    }
};

const Exports = struct {
    memories: []const *const wasmstint.runtime.MemInst,
    functions: []const wasmstint.runtime.FuncAddr,

    fn resolve(
        module: wasmstint.runtime.ModuleInst,
        arena: *std.heap.ArenaAllocator,
        execution: Execution,
        scratch: *std.heap.ArenaAllocator,
    ) error{OutOfMemory}!Exports {
        const exports = exports: {
            const wasm_exports = module.exports();
            _ = scratch.reset(.retain_capacity);
            const exports_buf = try scratch.allocator().alloc(
                wasmstint.runtime.ModuleInst.ExportVals.Export,
                wasm_exports.len,
            );
            for (0.., exports_buf) |i, *dst| {
                dst.* = wasm_exports.at(i);
            }

            const ExportSorter = struct {
                fn lessThan(
                    _: @This(),
                    a: wasmstint.runtime.ModuleInst.ExportVals.Export,
                    b: wasmstint.runtime.ModuleInst.ExportVals.Export,
                ) bool {
                    return std.mem.lessThan(u8, a.name.bytes(), b.name.bytes());
                }
            };

            std.sort.pdq(
                wasmstint.runtime.ModuleInst.ExportVals.Export,
                exports_buf,
                ExportSorter{},
                ExportSorter.lessThan,
            );

            break :exports exports_buf;
        };

        var mem_exports = try std.ArrayList(*const wasmstint.runtime.MemInst).initCapacity(
            arena.allocator(),
            @min(exports.len, module.header().module.memTypes().len),
        );
        var func_exports = try std.ArrayList(wasmstint.runtime.FuncAddr).initCapacity(
            arena.allocator(),
            execution.inner.func_export_count,
        );
        for (exports) |*exp| {
            switch (exp.val) {
                .func => |func_export| {
                    std.debug.print(
                        "export function #{d}: {f}\n",
                        .{ func_exports.items.len, exp },
                    );

                    const target_signature = func_export.signature();
                    const expected_arity = execution.funcExportArities()[func_exports.items.len];
                    if (expected_arity.param_count != target_signature.param_count or
                        expected_arity.result_count != target_signature.result_count)
                    {
                        std.debug.panic(
                            "exported function #{d} {f} has incorrect signature, " ++
                                "expected {d} -> {d} but got {d} -> {d}\n",
                            .{
                                func_exports.items.len,
                                exp,
                                expected_arity.param_count,
                                expected_arity.result_count,
                                target_signature.param_count,
                                target_signature.result_count,
                            },
                        );
                    }

                    func_exports.appendBounded(func_export) catch std.debug.panic(
                        "too many function exports, expected only {d}",
                        .{execution.inner.func_export_count},
                    );
                },
                .mem => |mem_export| {
                    std.debug.print(
                        "export memory #{d}: {f}\n",
                        .{ mem_exports.items.len, exp },
                    );

                    mem_exports.appendAssumeCapacity(mem_export);
                },
                else => continue,
            }
        }

        if (func_exports.items.len != execution.inner.func_export_count) {
            std.debug.panic(
                "expected {d} function exports, but got {d}\n",
                .{ execution.inner.func_export_count, func_exports.items.len },
            );
        }

        return Exports{
            .memories = mem_exports.items,
            .functions = func_exports.items,
        };
    }
};

pub fn testOne(
    wasm_module: []const u8,
    input: *ffi.Input,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) !void {
    var execution = try Execution.run(wasm_module, input, max_fuel);
    defer execution.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var diagnostic_writer = Writer.Allocating.init(allocator);
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
    _ = scratch.reset(.retain_capacity);

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
    _ = scratch.reset(.retain_capacity);

    if (!finished) {
        return error.ValidationOfCodeEntriesWasNotFinished;
    }

    var import_provider = ImportProvider{
        .arena = &arena,
        .input = input,
        .global_import_vals = execution.globalImportVals(),
        .functions = try std.ArrayList(wasmstint.runtime.FuncAddr.Host).initCapacity(
            arena.allocator(),
            parsed_module.funcImportTypes().len,
        ),
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
            const min_bytes = mem_type.limits.min * wasmstint.runtime.MemInst.page_size;
            if (min_bytes > wasm_smith_config.max_max_memory_bytes) {
                return error.OutOfMemory;
            }

            const chosen_max = try input.uintInRangeInclusive(
                usize,
                min_bytes,
                @min(
                    mem_type.limits.max * wasmstint.runtime.MemInst.page_size,
                    wasm_smith_config.max_max_memory_bytes,
                ),
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

    if (import_provider.global_import_count != import_provider.global_import_vals.len) {
        const missing = import_provider.global_import_vals[import_provider.global_import_count..];
        const Formatter = struct {
            missing: []const Execution.ArgumentVal,

            pub fn format(fmt: @This(), w: *Writer) Writer.Error!void {
                for (fmt.missing) |val| {
                    try w.print("- {f}\n", .{val});
                }
            }
        };

        std.debug.panic(
            "expected {d} global imports, but got {d}; {d} are missing:\n{f}",
            .{
                import_provider.global_import_vals.len,
                import_provider.global_import_count,
                missing.len,
                Formatter{ .missing = missing },
            },
        );
    }

    var host_state = HostState{ .call_count = 0 };
    var interp: wasmstint.Interpreter = undefined;
    var fuel = wasmstint.Interpreter.Fuel{ .remaining = max_fuel };
    const initial_state = try interp.init(
        allocator,
        .{ .stack_reserve = max_interpreter_stack },
    );
    defer interp.deinit(allocator);
    {
        const instantiate_state = try initial_state.awaiting_host.instantiateModule(
            allocator,
            &module_alloc,
            &fuel,
        );

        const start_results = mainLoop(
            instantiate_state,
            execution,
            &host_state,
            scratch,
            import_provider.functions.items,
            &fuel,
        ) catch |e| switch (e) {
            error.OutOfFuel => |err| {
                std.debug.print("start function did not return: {t}\n", .{err});
                return error.BadInput;
            },
            error.OutOfMemory => |oom| return oom,
        };

        switch (start_results) {
            .values => |values| {
                std.debug.assert(values.len == 0);
                if (execution.trap()) |trap| {
                    _ = trap.toWasmstintTrapCode() catch |e| {
                        std.debug.print(
                            "wasmstint instantiated module, but wasmi failed: {t}",
                            .{e},
                        );
                        return error.BadInput;
                    };

                    std.debug.panic(
                        "wasmi trapped during instantiation {d} where wasmstint succeeded",
                        .{trap},
                    );
                }

                _ = scratch.reset(.retain_capacity);
            },
            .trapped => |trap_code| {
                std.debug.print("start function trapped: {t}\n", .{trap_code});
                if (execution.trap()) |wasmi_trap| {
                    const expected_trap = wasmi_trap.toWasmstintTrapCode() catch |e| {
                        std.debug.print(
                            "wasmstint trapped during module instantiation, but wasmi failed: {t}",
                            .{e},
                        );
                        return error.BadInput;
                    };

                    if (expected_trap != trap_code) {
                        std.debug.panic(
                            "expected trap {t} during module instantiation, but got {t}",
                            .{ expected_trap, trap_code },
                        );
                    }
                } else {
                    @panic("wasmi successfully instantiated module where wasmstint trapped");
                }

                return;
            },
        }
    }

    const module = module_alloc.assumeInstantiated();
    const exports = try Exports.resolve(module, &arena, execution, scratch);

    for (0.., execution.actions()) |action_num, *action| {
        switch (action.payload()) {
            .call => |call_action| {
                const target = exports.functions[call_action.func.n];
                const target_arities = call_action.func.arities(execution);
                const target_signature = target.signature();
                std.debug.assert(target_arities.param_count == target_signature.param_count);
                std.debug.assert(target_arities.result_count == target_signature.result_count);

                const provided_args = call_action.action.args_ptr[0..target_arities.param_count];
                const expected_results = call_action.results(execution);
                std.debug.print(
                    "action #{[num]d} - call #{[func]d} {[args]f} -> {[results]f}\n",
                    .{
                        .num = action_num,
                        .func = call_action.func.n,
                        .args = Execution.ArgumentVal.sliceFormatter(provided_args),
                        .results = expected_results,
                    },
                );

                const args_buf = try scratch.allocator().alloc(
                    wasmstint.Interpreter.TaggedValue,
                    target_signature.param_count,
                );
                for (args_buf, provided_args) |*dst, *src| {
                    dst.* = src.toWasmstintValue(import_provider.functions.items);
                }

                const call_result = mainLoop(
                    try interp.reset().awaiting_host.beginCall(allocator, target, args_buf, &fuel),
                    execution,
                    &host_state,
                    scratch,
                    import_provider.functions.items,
                    &fuel,
                ) catch |e| switch (e) {
                    error.OutOfFuel => |err| {
                        std.debug.print(
                            "function #{d} did not return: {t}\n",
                            .{ call_action.func.n, err },
                        );
                        return error.BadInput;
                    },
                    error.OutOfMemory => |oom| return oom,
                };

                switch (call_result) {
                    .values => |actual_results| {
                        const fmt_actual_results = wasmstint.Interpreter.TaggedValue
                            .sliceFormatter(actual_results);

                        const expected_values = switch (expected_results) {
                            .values => |v| v,
                            .trapped => |wasmi_trap| std.debug.panic(
                                "wasmstint succeeded {f}, but wasmi trapped {t}",
                                .{ fmt_actual_results, wasmi_trap },
                            ),
                        };

                        const fmt_expected_results = Execution.ResultVal
                            .sliceFormatter(expected_values);
                        if (expected_values.len != actual_results.len) {
                            std.debug.panic(
                                "result count mismatch, expected {d} but got {d}:\n" ++
                                    "expected: {f}\nactual: {f}\n",
                                .{
                                    expected_values.len,
                                    actual_results.len,
                                    fmt_expected_results,
                                    fmt_actual_results,
                                },
                            );
                        }

                        for (
                            expected_values,
                            actual_results,
                            0..,
                        ) |*expected_pat, *actual_val, pos| {
                            if (!expected_pat.matchesWasmstintValue(actual_val)) {
                                std.debug.panic(
                                    "result mismatch at position #{d}; " ++
                                        "expected {f}, but got {f}:\nexpected: {f}\nactual: {f}\n",
                                    .{
                                        pos,
                                        expected_pat,
                                        actual_val,
                                        fmt_expected_results,
                                        fmt_actual_results,
                                    },
                                );
                            }
                        }
                    },
                    .trapped => |actual_trap| {
                        const expected_trap = switch (expected_results) {
                            .values => std.debug.panic(
                                "wasmstint trapped {t}, but wasmi succeded",
                                .{actual_trap},
                            ),
                            .trapped => |wasmi_trap| wasmi_trap.toWasmstintTrapCode() catch |e| {
                                std.debug.print("wasmstint trapped, but wasmi failed: {t}", .{e});
                                return error.BadInput;
                            },
                        };

                        if (expected_trap != actual_trap) {
                            std.debug.panic(
                                "expected trap {t}, but got {t}",
                                .{ expected_trap, actual_trap },
                            );
                        }
                    },
                }

                _ = scratch.reset(.retain_capacity);
            },
            .hash_memory => |hash_memory| {
                std.debug.print(
                    "action #{[num]d} - hash memory #{[mem]d} -> {[hash]X:0>16}\n",
                    .{ .num = action_num, .mem = hash_memory.memory.n, .hash = hash_memory.hash },
                );

                const target_memory = exports.memories[hash_memory.memory.n];
                const target_bytes = target_memory.bytes();
                const actual_hash = Execution.memory_hasher(target_bytes.ptr, target_bytes.len);
                if (actual_hash != hash_memory.hash) {
                    std.debug.panic(
                        "memory hash mismatch, expected {X:0>16}, got {X:0>16}",
                        .{ hash_memory.hash, actual_hash },
                    );
                }
            },
        }
    }

    if (host_state.call_count != execution.hostCalls().len) {
        std.debug.panic(
            "expected {d} host calls, got {d} ({d} missing)\n",
            .{
                execution.hostCalls().len,
                host_state.call_count,
                execution.hostCalls().len - host_state.call_count,
            },
        );
    }
}

const CallResult = union(enum) {
    values: []const wasmstint.Interpreter.TaggedValue,
    trapped: wasmstint.Interpreter.Trap.Code,
};

fn mainLoop(
    initial_state: wasmstint.Interpreter.State,
    exec: Execution,
    host: *HostState,
    /// Also used to allocate the result values.
    scratch: *std.heap.ArenaAllocator,
    host_functions: []const wasmstint.runtime.FuncAddr.Host,
    fuel: *wasmstint.Interpreter.Fuel,
) !CallResult {
    var state = initial_state;
    while (true) {
        _ = scratch.reset(.retain_capacity);
        state = next: switch (state) {
            .awaiting_host => |*awaiting| if (awaiting.currentHostFunction()) |host_func| {
                const host_signature = awaiting.hostSignature();
                const param_types = host_signature.parameters();
                const result_types = host_signature.results();

                const vals_buf = try scratch.allocator().alloc(
                    wasmstint.Interpreter.TaggedValue,
                    param_types.len + result_types.len,
                );
                const actual_args = vals_buf[0..param_types.len];
                awaiting.copyParamsTo(actual_args);
                const results_buf = vals_buf[param_types.len..][0..result_types.len];

                const actual_host_id = Execution.HostFuncId{
                    .n = @intCast(host_func - host_functions.ptr),
                };
                std.debug.assert(actual_host_id.n <= host_functions.len);

                const host_call = host.nextCall(exec);
                const host_call_arities = host_call.record.func.arities(exec);
                const expected_args = host_call.record
                    .arguments_ptr[0..host_call_arities.param_count];
                const fmt_expected_args = Execution.ResultVal.sliceFormatter(expected_args);
                const provided_results = host_call.record
                    .results_ptr[0..host_call_arities.result_count];

                std.debug.print(
                    "host call #{d} {f} -> {f}\n",
                    .{
                        host_call.number,
                        fmt_expected_args,
                        Execution.ArgumentVal.sliceFormatter(provided_results),
                    },
                );

                const fmt_actual_args = wasmstint.Interpreter.TaggedValue
                    .sliceFormatter(actual_args);

                if (actual_args.len != expected_args.len) {
                    std.debug.panic(
                        "expected {d} arguments, received {d}:\nexpected: {f}\nactual: {f}\n",
                        .{
                            expected_args.len,
                            actual_args.len,
                            fmt_expected_args,
                            fmt_actual_args,
                        },
                    );
                }

                for (expected_args, actual_args, 0..) |*expected_pat, *actual_val, i| {
                    if (!expected_pat.matchesWasmstintValue(actual_val)) {
                        std.debug.panic(
                            "argument mismatch at position #{d}: expected {f}, got {f}\n",
                            .{ i, expected_pat, actual_val },
                        );
                    }
                }

                for (results_buf, provided_results) |*dst, *src| {
                    dst.* = src.toWasmstintValue(host_functions);
                }

                std.debug.print("host {f} returning {f}\n", .{
                    awaiting.currentHostFunction().?,
                    wasmstint.Interpreter.TaggedValue.sliceFormatter(results_buf),
                });
                break :next awaiting.returnFromHost(results_buf, fuel) catch unreachable;
            } else {
                return .{ .values = try awaiting.allocResults(scratch.allocator()) };
            },
            .awaiting_validation => unreachable,
            .call_stack_exhaustion => return error.OutOfMemory,
            .interrupted => |*interrupt| {
                switch (interrupt.cause().*) {
                    .out_of_fuel => return error.OutOfFuel,
                    // TODO: need way to know if grow fails, could get out of sync w/ wasmi
                    .memory_grow, .table_grow => {},
                }

                break :next interrupt.resumeExecution(fuel);
            },
            .trapped => |*trapped| return .{ .trapped = trapped.trap().code },
        };
    }
}

// TODO: Duplicate code taken from `./execution.zig` target.
const ImportProvider = struct {
    arena: *std.heap.ArenaAllocator,
    input: *ffi.Input,
    global_import_vals: []const Execution.ArgumentVal,
    global_import_count: u32 = 0,
    functions: std.ArrayList(wasmstint.runtime.FuncAddr.Host),
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
                        const func = provider.functions.addOneAssumeCapacity();
                        func.* = .{ .signature = func_type.* };
                        break :func func;
                    },
                }),
            },
            .mem => |mem_type| .{
                .mem = mem: {
                    const min_size = mem_type.limits.min * wasmstint.runtime.MemInst.page_size;
                    if (min_size > wasm_smith_config.max_max_memory_bytes) {
                        provider.err = error.OutOfMemory;
                        return null;
                    }

                    const max_size = @min(
                        mem_type.limits.max * wasmstint.runtime.MemInst.page_size,
                        wasm_smith_config.max_max_memory_bytes,
                    );
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

                        const max_elems = @min(
                            wasm_smith_config.max_max_table_elements,
                            table_type.limits.max,
                        );
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
                    .value = val: {
                        if (provider.global_import_count >= provider.global_import_vals.len) {
                            std.debug.panic(
                                "attempted to provide more than {d} global imports",
                                .{provider.global_import_vals.len},
                            );
                        }

                        const value = &provider.global_import_vals[provider.global_import_count];
                        const expected_type = value.tag.toValType();
                        if (global_type.val_type != expected_type) {
                            std.debug.panic(
                                "expected global import #{d} to be a {t}, got a {t}",
                                .{
                                    provider.global_import_count,
                                    expected_type,
                                    global_type.val_type,
                                },
                            );
                        }

                        switch (global_type.val_type) {
                            .v128 => unreachable,
                            inline else => |val_type| {
                                const Val = wasmstint.runtime.GlobalAddr.Pointee(val_type);
                                const val = allocator.create(Val) catch |e| {
                                    provider.err = e;
                                    return null;
                                };

                                val.* = @field(
                                    value.toWasmstintValue(provider.functions.items),
                                    @tagName(val_type),
                                );

                                provider.global_import_count += 1;
                                break :val val;
                            },
                        }
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

const std = @import("std");
const Writer = std.Io.Writer;
const wasmstint = @import("wasmstint");
const ffi = @import("ffi");
