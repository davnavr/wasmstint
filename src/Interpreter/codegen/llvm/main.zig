//! Generates an LLVM IR bitcode (`.bc`) file implementing wasmstint's opcode handlers.

pub fn main(init: std.process.Init.Minimal) Oom!void {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.ioBasic();

    var scratch = ArenaAllocator.init(std.heap.page_allocator);

    var cli_args = try init.args.iterateAllocator(scratch.allocator());
    _ = cli_args.next().?;

    var arena = ArenaAllocator.init(std.heap.page_allocator); // process lifetime

    const options = options: {
        const options_str = cli_args.next().?;
        break :options std.zon.parse.fromSliceAlloc(
            Builder.Options,
            arena.allocator(),
            options_str,
            null,
            .{ .free_on_error = false },
        ) catch |e| switch (e) {
            error.ParseZon => std.debug.panic("invalid options:\n{s}\n", .{options_str}),
            else => |err| return err,
        };
    };

    const cwd = std.Io.Dir.cwd();
    const target_info = target: {
        const path = cli_args.next().?;
        const contents = cwd.readFileAllocOptions(
            io,
            path,
            scratch.allocator(),
            .limited(4096 * 4),
            .@"16",
            0,
        ) catch |e| std.debug.panic("cannot open {s}: {t}", .{ path, e });

        break :target std.zon.parse.fromSliceAlloc(
            Builder.TargetInfo,
            arena.allocator(),
            contents,
            null,
            .{ .free_on_error = false },
        ) catch |e| switch (e) {
            error.ParseZon => std.debug.panic("error parsing target info:\n{s}\n", .{contents}),
            else => |err| return err,
        };
    };

    const bc_file = file: {
        const path = cli_args.next().?;
        break :file cwd.createFile(io, path, .{}) catch |e|
            std.debug.panic("cannot open {s}: {t}", .{ path, e });
    };

    std.debug.assert(cli_args.next() == null);

    const target_query = std.Target.Query.parse(.{
        .arch_os_abi = options.target.triple,
        .cpu_features = options.target.cpu_features,
    }) catch |e| switch (e) {
        error.UnknownCpuFeature => std.debug.panic(
            "unknown cpu flag in {s}",
            .{options.target.cpu_features},
        ),
        else => |err| std.debug.panic(
            "invalid target triple {s}: {t}",
            .{ options.target.triple, err },
        ),
    };
    const target = std.zig.system.resolveTargetQuery(io, target_query) catch |e| std.debug.panic(
        "{t}: could not resolve target query {s}{s}",
        .{ e, options.target.triple, options.target.cpu_features },
    );

    var gpa = std.heap.DebugAllocator(.{}).init;
    _ = scratch.reset(.retain_capacity);
    var builder: Builder = undefined;
    try builder.init(gpa.allocator(), &scratch, .{
        .options = options,
        .target_info = target_info,
        .target = &target,
    });
    try buildLlvmModule(&builder);

    const bitcode: []const u32 = try builder.module.toBitcode(std.heap.page_allocator, .{
        .name = "wasmstint-codegen-llvm",
        .version = .{ .major = 0, .minor = 0, .patch = 0 },
    });

    bc_file.writeStreamingAll(io, @ptrCast(bitcode)) catch |e| std.debug.panic(
        "cannot write bitcode: {t}",
        .{e},
    );
}

const Builder = struct {
    const Options = struct {
        optimize: std.builtin.OptimizeMode,
        symbol_prefix: []const u8,
        strip: bool,
        use_llvm: bool,
        target: struct {
            triple: []const u8,
            cpu_features: []const u8,
        },
    };

    const TargetInfo = struct {
        data_layout: []const u8,
        triple: []const u8,
    };

    options: Options,
    target: *const std.Target,
    /// In bytes.
    cache_line_size: u16,
    /// `@sizeOf(*anyopaque)`, in bytes.
    ptr_size_bytes: u16,
    /// `usize`.
    size_type: Type = .none,
    target_info: TargetInfo,
    float_info: [2]FloatInfo = undefined,

    scratch: *ArenaAllocator,
    module: llvm.Builder,

    ffi_call_conv: CallConv,
    string_constants: struct {
        @"target-cpu": String = .none,
        @"target-features": String = .none,
    } = .{},
    target_cpu: String = .none,
    target_features: String = .none,

    opcode_handler: struct {
        call_conv: CallConv,
        type: Type,
        fn_attrs: FunctionAttributes,
    },
    dispatch_tables: struct {
        byte: Global.Index = .none,
    } = .{},
    byte_opcode_lookup: std.EnumSet(ByteOpcode) = .initEmpty(),

    out_of_fuel_handler: Function.Index = .none,
    skip_leb_idx: Function.Index = .none,
    decode_uleb_idx: Function.Index = .none,
    trap_with_numeric_code: Function.Index = .none,
    trap_memory_access_oob: Function.Index = .none,

    opcode_handler_writing_lock: std.debug.SafetyLock = .{},
    mem_inst: Type = .none,
    side_table_entry: Type = .none,
    value_structs: struct {
        i64: Type = .none,
    } = .{},
    /// For `memset` of values.
    value_set: struct { attributes: FunctionAttributes, overload: [2]Type } = undefined,
    /// For `memcpy`/`memmove` of values.
    value_copy: struct { attributes: FunctionAttributes, overload: [3]Type } = undefined,

    fn init(
        b: *Builder,
        gpa: std.mem.Allocator,
        scratch: *ArenaAllocator,
        config: struct {
            options: Options,
            target: *const std.Target,
            target_info: TargetInfo,
        },
    ) Oom!void {
        const ptr_bit_size = config.target.ptrBitWidth();
        b.* = Builder{
            .options = config.options,
            .target = config.target,
            .cache_line_size = std.atomic.cacheLineForCpu(config.target.cpu),
            .ptr_size_bytes = @divExact(ptr_bit_size, 8),
            .target_info = config.target_info,
            .scratch = scratch,
            .module = try llvm.Builder.init(.{
                .allocator = gpa,
                .strip = config.options.strip,
                .name = "wasmstint.interpreter",
                .target = config.target,
                .triple = config.target_info.triple,
            }),
            .ffi_call_conv = if (config.target.cpu.arch == .x86_64 and config.options.use_llvm)
                .x86_regcallcc // Zig's x86 backend doesn't support regcall
            else
                .ccc,
            .opcode_handler = undefined,
        };

        b.float_info = try FloatInfo.init(&b.module);

        inline for (comptime std.meta.fieldNames(@FieldType(Builder, "string_constants"))) |name| {
            @field(b.string_constants, name) = try b.module.string(name);
        }

        if (b.target.cpu.model.llvm_name) |name| {
            b.target_cpu = try b.module.string(name);
        }

        var target_features = try std.ArrayList(u8).initCapacity(
            scratch.allocator(),
            b.options.target.cpu_features.len,
        );

        const all_features = b.target.cpu.arch.allFeaturesList();
        for (all_features) |feat| {
            const idx: std.Target.Cpu.Feature.Set.Index = feat.index;
            const feat_name = feat.llvm_name orelse continue;
            const prefix: u8 = if (b.target.cpu.features.isEnabled(idx))
                '+'
            else
                '-';

            const not_first = target_features.items.len > 0;
            try target_features.ensureUnusedCapacity(
                scratch.allocator(),
                @as(usize, @intFromBool(not_first)) + 1 + feat_name.len,
            );

            if (not_first) {
                try target_features.append(scratch.allocator(), ',');
            }
            target_features.appendAssumeCapacity(prefix);
            target_features.appendSliceAssumeCapacity(feat_name);
        }

        b.target_features = try b.module.string(target_features.items);
        b.size_type = try b.module.intType(ptr_bit_size);
        b.opcode_handler = .{
            .call_conv = switch (config.target.cpu.arch) {
                .x86_64, .aarch64, .riscv64 => .ghccc,
                else => .tailcc,
            },
            .type = try b.fnType(.i32, &@as([10]Type, @splat(Type.ptr))),
            .fn_attrs = attrs: {
                var attrs = FunctionAttributes.Wip{};
                defer attrs.deinit(&b.module);
                try b.commonFnAttributes(&attrs);
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse });
                for (std.enums.values(OpcodeHandlerParam)) |param| {
                    const idx = @intFromEnum(param);
                    for (&[3]Attribute{ .nonnull, .nofree, .noundef }) |attr| {
                        try attrs.addParamAttr(idx, attr, &b.module);
                    }

                    const alignment: ?u16 = switch (param) {
                        .locals, .vsp => 16,
                        .module => b.cache_line_size,
                        // TODO: read datalayout to determine alignment of u64 Fuel/STP
                        .memories, .ctx => b.ptr_size_bytes,
                        else => null,
                    };

                    if (alignment) |a| {
                        try attrs.addParamAttr(idx, .{ .@"align" = .fromByteUnits(a) }, &b.module);
                    }

                    switch (param) {
                        .locals, .vsp, .fuel, .stp, .disp => {
                            try attrs.addParamAttr(idx, .@"noalias", &b.module);
                        },
                        else => {},
                    }

                    const dereferenceable: ?u32 = switch (param) {
                        .fuel => 8,
                        .disp => @as(u32, b.ptr_size_bytes) * 256,
                        // .module // don't know size of ModuleInst in advance
                        else => null,
                    };

                    if (dereferenceable) |size| {
                        try attrs.addParamAttr(idx, .{ .dereferenceable = size }, &b.module);
                    }

                    switch (param) {
                        .ctx, .vip, .stp, .eip, .disp => {
                            try attrs.addParamAttr(idx, .readonly, &b.module);
                        },
                        else => {},
                    }
                }
                break :attrs try attrs.finish(&b.module);
            },
        };

        b.mem_inst = try b.module.structType(.normal, &.{
            .ptr,
            b.size_type,
            b.size_type,
            b.size_type,
            .ptr,
        });
        b.side_table_entry = try b.module.structType(.@"packed", &.{ .i32, .i16, .i8, .i8 });
        b.value_structs = .{
            .i64 = try b.module.structType(.normal, &.{ .i64, .i64 }),
        };
        b.value_set = .{
            .attributes = attrs: {
                var attrs = FunctionAttributes.Wip{};
                defer attrs.deinit(&b.module);
                try attrs.addParamAttr(0, .{ .@"align" = value_stack_alignment }, &b.module);
                break :attrs try attrs.finish(&b.module);
            },
            .overload = [2]Type{ .ptr, b.size_type },
        };
        b.value_copy = .{
            .attributes = attrs: {
                var attrs = FunctionAttributes.Wip{};
                defer attrs.deinit(&b.module);
                for (0..2) |i| {
                    try attrs.addParamAttr(i, .{ .@"align" = value_stack_alignment }, &b.module);
                    try attrs.addParamAttr(i, .noundef, &b.module);
                    try attrs.addParamAttr(i, .nonnull, &b.module);
                    try attrs.addParamAttr(i, .{ .dereferenceable = 16 }, &b.module);
                }
                break :attrs try attrs.finish(&b.module);
            },
            .overload = [3]Type{ .ptr, .ptr, b.size_type },
        };
    }

    fn strtabStringConcat(b: *Builder, s: []const []const u8) Oom!StrtabString {
        _ = b.scratch.reset(.retain_capacity);
        return try b.module.strtabString(try std.mem.concat(b.scratch.allocator(), u8, s));
    }

    fn strtabStringSymbolPrefixed(b: *Builder, name: []const u8) Oom!StrtabString {
        return try b.strtabStringConcat(&.{ b.options.symbol_prefix, name });
    }

    /// `wasmstint` does not use `varargs`.
    fn fnType(b: *Builder, ret_type: Type, param_types: []const Type) Oom!Type {
        return try b.module.fnType(ret_type, param_types, .normal);
    }

    const FunctionOptions = struct {
        linkage: llvm.Builder.Linkage = .external,
        preemption: llvm.Builder.Preemption = .dso_preemptable,
    };

    fn fnAttributes(
        b: *Builder,
        wip: *FunctionAttributes.Wip,
        attributes: []const Attribute,
    ) Oom!void {
        for (attributes) |attr| {
            try wip.addFnAttr(attr, &b.module);
        }
    }

    fn setFnAttributes(b: *Builder, func: Function.Index, wip: *FunctionAttributes.Wip) Oom!void {
        func.setAttributes(try wip.finish(&b.module), &b.module);
    }

    fn commonFnAttributes(b: *Builder, wip: *FunctionAttributes.Wip) Oom!void {
        try wip.addFnAttr(.nounwind, &b.module);

        // This is what the Zig compiler does
        if (b.options.optimize == .ReleaseSmall) {
            try b.fnAttributes(wip, &.{ .minsize, .optsize });
        }

        if (b.target_cpu != .none) {
            try b.fnAttributes(wip, &.{
                .{
                    .string = .{
                        .kind = b.string_constants.@"target-cpu",
                        .value = b.target_cpu,
                    },
                },
            });
        }

        if (b.target_features != .empty) {
            try b.fnAttributes(wip, &.{
                .{
                    .string = .{
                        .kind = b.string_constants.@"target-features",
                        .value = b.target_features,
                    },
                },
            });
        }

        // TODO: bool option for uwtable
        if (b.target.cpu.arch == .x86_64 and b.target.os.tag == .linux) {
            try b.fnAttributes(wip, &.{.{ .uwtable = .async }});
        }
    }

    fn addFunction(
        b: *Builder,
        name: StrtabString,
        ty: Type,
        call_conv: CallConv,
        options: FunctionOptions,
    ) Oom!Function.Index {
        const func = try b.module.addFunction(ty, name, .default);
        func.setCallConv(call_conv, &b.module);
        func.setLinkage(options.linkage, &b.module);
        func.ptr(&b.module).global.ptr(&b.module).preemption = options.preemption;
        return func;
    }

    fn addFfiFunction(
        b: *Builder,
        name: []const u8,
        param_types: []const Type,
        ret_type: Type,
    ) Oom!Function.Index {
        return try b.addFunction(
            try b.strtabStringSymbolPrefixed(name),
            try b.fnType(ret_type, param_types),
            b.ffi_call_conv,
            .{ .preemption = .dso_local },
        );
    }

    fn wipFunction(b: *Builder, func: Function.Index) Oom!WipFunction {
        return try .init(&b.module, .{ .function = func, .strip = b.options.strip });
    }

    fn addDispatchTable(b: *Builder, name: []const u8, len: u16) Oom!Global.Index {
        const name_str = try b.strtabStringSymbolPrefixed(name);
        const ty = try b.module.arrayType(len, .ptr);
        const variable = try b.module.addVariable(name_str, ty, .default);
        variable.setAlignment(.fromByteUnits(b.cache_line_size), &b.module);
        variable.setUnnamedAddr(.local_unnamed_addr, &b.module);
        variable.setMutability(.constant, &b.module);
        return try b.module.addGlobal(name_str, .{
            .preemption = .dso_local,
            .type = ty,
            .kind = .{ .variable = variable },
            .unnamed_addr = .local_unnamed_addr,
        });
    }

    fn setDispatchTableInitializer(b: *Builder, comptime E: type) Oom!void {
        const invalid_handler: Function.Index = if (b.options.optimize == .ReleaseSmall)
            .none
        else handler: switch (E) {
            ByteOpcode => {
                const handler = try b.addFfiFunction(
                    "panicInvalidByteOpcode",
                    &@as([2]Type, @splat(.ptr)),
                    .void,
                );
                var attrs = FunctionAttributes.Wip{};
                try b.commonFnAttributes(&attrs);
                try attrs.addFnAttr(.noreturn, &b.module);
                try b.setFnAttributes(handler, &attrs);

                break :handler handler;
            },
            else => @compileError(@typeName(E)),
        };

        const invalid: Constant = if (invalid_handler == .none)
            try b.module.undefConst(.ptr)
        else
            invalid_handler.toConst(&b.module);

        const table_global_idx: Global.Index = switch (E) {
            ByteOpcode => b.dispatch_tables.byte,
            else => @compileError(@typeName(E)),
        };

        const table_global = table_global_idx.ptrConst(&b.module);
        const table_var = table_global.kind.variable;
        const len = table_global.type.aggregateLen(&b.module);
        const set: *const std.EnumSet(E) = switch (E) {
            ByteOpcode => &b.byte_opcode_lookup,
            else => @compileError(@typeName(E)),
        };

        _ = b.scratch.reset(.retain_capacity);
        const values = try b.scratch.allocator().alloc(Constant, len);
        var name_arena = ArenaAllocator.init(b.scratch.allocator());
        for (values, 0..len) |*v, i| {
            v.* = val: {
                invalid: {
                    const opcode = std.enums.fromInt(E, i) orelse break :invalid;
                    if (!set.contains(opcode)) break :invalid;

                    _ = name_arena.reset(.retain_capacity);
                    const handler_name = try b.module.strtabString(try std.mem.concat(
                        name_arena.allocator(),
                        u8,
                        &.{ b.options.symbol_prefix, @tagName(opcode) },
                    ));

                    break :val b.module.getGlobal(handler_name).?.toConst();
                }

                break :val invalid;
            };
        }

        try table_var.setInitializer(
            try b.module.arrayConst(table_global.type, values),
            &b.module,
        );
    }

    fn opcodeHandler(b: *Builder, opcode: Opcode) Oom!OpcodeHandler {
        switch (opcode) {
            inline else => |value, kind| {
                const set: *std.EnumSet(@TypeOf(value)) = switch (kind) {
                    .byte => &b.byte_opcode_lookup,
                };

                if (set.contains(value)) std.debug.panic("duplicate handler for {t}", .{value});

                set.insert(value);
            },
        }

        const func = try b.addFunction(
            try b.strtabStringSymbolPrefixed(opcode.name()),
            b.opcode_handler.type,
            b.opcode_handler.call_conv,
            .{ .linkage = .internal, .preemption = .dso_local },
        );
        func.setAttributes(b.opcode_handler.fn_attrs, &b.module);
        if (b.target.cpu.arch.isX86()) {
            func.setAlignment(.fromByteUnits(16), &b.module);
        }
        b.opcode_handler_writing_lock.lock();
        return .{
            .wip = try WipFunction.init(
                &b.module,
                .{ .function = func, .strip = b.options.strip },
            ),
        };
    }

    fn opcodeHandlerFromPrefixedName(
        b: *Builder,
        comptime E: type,
        prefix: []const u8,
        name: []const u8,
    ) Oom!OpcodeHandler {
        return try b.opcodeHandler(try .fromPrefixedName(E, b.scratch, prefix, name));
    }

    /// Yields an `{ i32, ptr }` containing the decoded index and updated VIP value.
    fn callDecodeUlebIdx(b: *Builder, wip: *WipFunction, vip: Value) Oom!Value {
        return wip.call(
            .normal,
            b.decode_uleb_idx.ptr(&b.module).call_conv,
            .none,
            b.decode_uleb_idx.typeOf(&b.module),
            b.decode_uleb_idx.toValue(&b.module),
            &.{vip},
            "",
        );
    }

    /// Yields the updated `VIP` value (a `ptr`).
    fn callSkipUlebIdx(b: *Builder, wip: *WipFunction, vip: Value) Oom!Value {
        std.debug.assert(vip.typeOfWip(wip) == .ptr);
        return wip.call(
            .normal,
            b.skip_leb_idx.ptr(&b.module).call_conv,
            .none,
            b.skip_leb_idx.typeOf(&b.module),
            b.skip_leb_idx.toValue(&b.module),
            &.{vip},
            "",
        );
    }

    fn sizeIntValue(b: *Builder, value: i64) Oom!Value {
        return try b.module.intValue(b.size_type, value);
    }
};

const Opcode = union(enum) {
    byte: ByteOpcode,
    // fc: opcodes.FCPrefixOpcode,
    // fd: opcodes.FDPrefixOpcode,

    fn init(comptime E: type, opcode: E) Opcode {
        return @unionInit(
            Opcode,
            switch (E) {
                ByteOpcode => "byte",
                // opcodes.FCPrefixOpcode => "fc",
                // opcodes.FDPrefixOpcode => "fd",
                else => @compileError(@typeName(Type)),
            },
            opcode,
        );
    }

    fn name(opcode: Opcode) []const u8 {
        return switch (opcode) {
            .byte => |byte| if (byte != .@"select t") @tagName(byte) else "select_t",
            // inline else => |n| @tagName(n),
        };
    }

    fn fromName(comptime E: type, s: []const u8) Opcode {
        return .init(
            E,
            std.meta.stringToEnum(E, s) orelse
                std.debug.panic("no opcode {s} in " ++ @typeName(E), .{s}),
        );
    }

    fn fromPrefixedName(
        comptime E: type,
        scratch: *ArenaAllocator,
        prefix: []const u8,
        s: []const u8,
    ) Oom!Opcode {
        _ = scratch.reset(.retain_capacity);
        return .fromName(E, try std.mem.concat(scratch.allocator(), u8, &.{ prefix, ".", s }));
    }
};

const byte_alignment = llvm.Builder.Alignment.fromByteUnits(1);
const value_stack_alignment = llvm.Builder.Alignment.fromByteUnits(16);

const MemInstField = enum(u8) {
    base,
    size,
    capacity,
    limit,
    vtable,

    /// Obtains a `ptr` to a field of a `ptr` to a `MemInst`.
    fn gep(field: MemInstField, wip: *WipFunction, b: *Builder, ptr: Value) Oom!Value {
        std.debug.assert(ptr.typeOfWip(wip) == .ptr);
        const field_ptr = try wip.gep(
            .inbounds,
            b.mem_inst,
            ptr,
            &.{ .@"0", try b.module.intValue(.i32, @intFromEnum(field)) },
            "",
        );
        std.debug.assert(field_ptr.typeOfWip(wip) == .ptr);
        return field_ptr;
    }

    fn typeOf(field: MemInstField, b: *Builder) Type {
        return switch (field) {
            .base, .vtable => .ptr,
            .size, .capacity, .limit => b.size_type,
        };
    }

    /// Loads a field given a `ptr` to a `MemInst`.
    fn load(field: MemInstField, wip: *WipFunction, b: *Builder, ptr: Value) Oom!Value {
        return try wip.load(.normal, field.typeOf(b), try field.gep(wip, b, ptr), .default, "");
    }
};

const OpcodeHandler = struct {
    wip: WipFunction,

    /// Finishes the basic block `wip` is positioned at.
    fn jmpToNextHandler(
        handler: *OpcodeHandler,
        b: *Builder,
        updates: struct {
            vsp: Value,
            vip: Value,
            stp: Value,
        },
    ) Oom!void {
        const wip = &handler.wip;
        const next_opcode_byte = try wip.load(.normal, .i8, updates.vip, .default, "");
        const next_handler_offset = try wip.cast(.zext, next_opcode_byte, b.size_type, "");
        const next_handler = try wip.load(
            .normal,
            .ptr,
            try wip.gep(
                .inbounds,
                .ptr,
                OpcodeHandlerParam.disp.arg(wip),
                &.{next_handler_offset},
                "",
            ),
            .fromByteUnits(b.ptr_size_bytes),
            "",
        );
        const after_next_ip_byte = try wip.gep(
            .inbounds,
            .i8,
            updates.vip,
            &.{try b.sizeIntValue(1)},
            "",
        );

        var args: [10]Value = undefined;
        for (&args, std.enums.values(OpcodeHandlerParam)) |*a, param| {
            a.* = switch (param) {
                .vsp => updates.vsp,
                .vip => after_next_ip_byte,
                .stp => updates.stp,
                else => param.arg(wip),
            };
        }
        _ = try wip.ret(
            try wip.call(
                .musttail,
                b.opcode_handler.call_conv,
                .none,
                b.opcode_handler.type,
                next_handler,
                &args,
                "",
            ),
        );
    }

    fn adjustVspBy(handler: *OpcodeHandler, b: *Builder, amt: i64) Oom!Value {
        std.debug.assert(amt != 0);
        return try handler.wip.gep(
            .inbounds,
            b.value_structs.i64,
            OpcodeHandlerParam.vsp.arg(&handler.wip),
            &.{try b.sizeIntValue(amt)},
            "",
        );
    }

    /// Obtains a `ptr` value containing the address of the given stack operand.
    ///
    /// Note that this is based on the value of `vsp` on function entry.
    fn operandAt(
        handler: *OpcodeHandler,
        b: *Builder,
        /// `0` means the value on top of the stack, `1` the value below that, and so on.
        ///
        /// Negative values are used to push new values onto the top of the stack, though the VSP
        /// must be adjusted correctly before jumping to the next opcode handler.
        index: i9,
    ) Oom!Value {
        const offset = -@as(i64, index) - 1;
        return try handler.wip.gep(
            .inbounds,
            b.value_structs.i64,
            OpcodeHandlerParam.vsp.arg(&handler.wip),
            &.{try b.sizeIntValue(offset)},
            "",
        );
    }

    const BinOpOperands = struct {
        c_2: Value,
        c_1: Value,
        /// A `ptr` where the result of the operation is written.
        result: Value,

        fn writeResult(op: BinOpOperands, handler: *OpcodeHandler, result: Value) Oom!void {
            _ = try handler.wip.store(.normal, result, op.result, value_stack_alignment);
        }
    };

    /// Loads two operands of type `ty` from the operand stack, and calculates the `ptr`
    /// where the result is written.
    fn binOp(handler: *OpcodeHandler, b: *Builder, ty: Type) Oom!BinOpOperands {
        const c_2_addr = try handler.operandAt(b, 0);
        const c_1_addr = try handler.operandAt(b, 1);
        return .{
            .c_2 = try handler.wip.load(.normal, ty, c_2_addr, value_stack_alignment, ""),
            .c_1 = try handler.wip.load(.normal, ty, c_1_addr, value_stack_alignment, ""),
            .result = c_1_addr,
        };
    }

    const UnOpOperands = struct {
        c_1: Value,
        /// A `ptr` where the result of the operation is written.
        result: Value,

        fn writeResult(op: UnOpOperands, handler: *OpcodeHandler, result: Value) Oom!void {
            _ = try handler.wip.store(.normal, result, op.result, value_stack_alignment);
        }
    };

    fn unOp(handler: *OpcodeHandler, b: *Builder, ty: Type) Oom!UnOpOperands {
        const result = try handler.operandAt(b, 0);
        return .{
            .c_1 = try handler.wip.load(.normal, ty, result, value_stack_alignment, ""),
            .result = result,
        };
    }

    const TestOpOperands = struct {
        c_1: Value,
        /// A `ptr` where the `i32` result of the test is written.
        result: Value,

        fn writeResult(op: TestOpOperands, handler: *OpcodeHandler, result: Value) Oom!void {
            std.debug.assert(result.typeOfWip(&handler.wip) == .i32);
            _ = try handler.wip.store(.normal, result, op.result, value_stack_alignment);
        }
    };

    fn testOp(handler: *OpcodeHandler, b: *Builder, ty: Type) Oom!TestOpOperands {
        const result = try handler.operandAt(b, 0);
        return .{
            .c_1 = try handler.wip.load(.normal, ty, result, value_stack_alignment, ""),
            .result = result,
        };
    }

    /// Finishes the basic block `wip` is positioned at.
    fn jmpTrapWithNumericCode(
        handler: *OpcodeHandler,
        b: *Builder,
        trap_ip: Value,
        trap_code: Value,
    ) Oom!void {
        const params = args: {
            var args: [6]Value = undefined;
            args[0] = trap_ip;
            for (args[1..5], [4]OpcodeHandlerParam{ .vsp, .eip, .stp, .ctx }) |*a, param| {
                a.* = param.arg(&handler.wip);
            }
            args[5] = trap_code;
            break :args args;
        };

        _ = try handler.wip.ret(
            try handler.wip.call(
                .normal,
                b.ffi_call_conv,
                .none,
                b.trap_with_numeric_code.typeOf(&b.module),
                b.trap_with_numeric_code.toValue(&b.module),
                &params,
                "",
            ),
        );
    }

    /// Assumes that the `memarg` is located at `OpcodeHandlerParam.vip`
    fn linearMemoryAccess(
        handler: *OpcodeHandler,
        b: *Builder,
        /// Offset from VSP to `i32` memory offset, where `0` is the top of the stack.
        offset_idx: u8,
        /// The size, in bytes, of the memory being accessed.
        access_size: std.mem.Alignment,
        /// Where control flow goes after the bounds check is successful.
        ///
        /// The cursor of the `WipFunction` is set to this value.
        bounds_check_success: Function.Block.Index,
    ) Oom!LinearMemoryAccess {
        const wip = &handler.wip;
        const vip_after_align = try b.callSkipUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
        const decode_offset = try b.callDecodeUlebIdx(wip, vip_after_align);

        const vip_after_offset = try wip.extractValue(decode_offset, &.{1}, "");
        const imm_offset = try wip.extractValue(decode_offset, &.{0}, "");

        const arg_offset = try wip.load(
            .normal,
            .i32,
            try handler.operandAt(b, offset_idx),
            value_stack_alignment,
            "",
        );

        const add_offsets = try wip.callIntrinsic(
            .normal,
            .none,
            .@"uadd.with.overflow",
            &.{.i32},
            &.{ imm_offset, arg_offset },
            "",
        );
        const load_offset = try wip.extractValue(add_offsets, &.{0}, "");
        const end_offset = try wip.callIntrinsic(
            .normal,
            .none,
            .@"uadd.with.overflow",
            &.{.i32},
            &.{ load_offset, try b.module.intValue(.i32, access_size.toByteUnits()) },
            "",
        );
        const final_offset = try wip.cast(.zext, load_offset, b.size_type, "");

        const mem_inst_ptr = try wip.load(
            .normal,
            .ptr,
            // Would need GEP here to support multi-memory
            OpcodeHandlerParam.memories.arg(wip),
            .default,
            "",
        );
        const oob = try wip.block(2, "MemoryAccessOob");
        const no_offset_overflow = try wip.block(1, "NoOffsetOverflow");
        _ = try wip.brCond(
            try wip.bin(
                .@"or",
                try wip.extractValue(add_offsets, &.{1}, ""),
                try wip.extractValue(end_offset, &.{1}, ""),
                "",
            ),
            oob,
            no_offset_overflow,
            .else_likely,
        );

        {
            wip.cursor = .{ .block = no_offset_overflow };
            const mem_size = try MemInstField.size.load(wip, b, mem_inst_ptr);
            _ = try wip.brCond(
                try wip.icmp(
                    .ule,
                    try wip.cast(
                        .zext,
                        try wip.extractValue(end_offset, &.{0}, ""),
                        b.size_type,
                        "",
                    ),
                    mem_size,
                    "",
                ),
                bounds_check_success,
                oob,
                .then_likely,
            );
        }

        wip.cursor = .{ .block = oob };
        _ = try wip.callIntrinsicAssumeCold();
        _ = try wip.ret(
            try wip.call(
                .tail,
                b.ffi_call_conv,
                .none,
                b.trap_memory_access_oob.typeOf(&b.module),
                b.trap_memory_access_oob.toValue(&b.module),
                &.{
                    try wip.gep(
                        .inbounds,
                        .i8,
                        OpcodeHandlerParam.vip.arg(wip),
                        &.{try b.sizeIntValue(-1)},
                        "",
                    ), // TODO: provide u8, usize pair so trap handler can call calculateTrapIp
                    OpcodeHandlerParam.vsp.arg(wip),
                    OpcodeHandlerParam.eip.arg(wip),
                    OpcodeHandlerParam.stp.arg(wip),
                    OpcodeHandlerParam.ctx.arg(wip),
                    mem_inst_ptr,
                    try b.module.intValue(b.size_type, 0), // memidx
                    try wip.cast(.zext, arg_offset, b.size_type, ""), // address
                    try wip.cast(.zext, imm_offset, b.size_type, ""), // offset
                    try b.module.intValue(b.size_type, @intFromEnum(access_size)), // size
                },
                "",
            ),
        );

        wip.cursor = .{ .block = bounds_check_success };
        const final_ptr = try wip.gep(
            .inbounds,
            .i8,
            try MemInstField.base.load(wip, b, mem_inst_ptr),
            &.{final_offset},
            "",
        );
        std.debug.assert(final_ptr.typeOfWip(wip) == .ptr);
        return .{ .ptr = final_ptr, .vip = vip_after_offset };
    }

    const SideTableEntryField = enum(u2) {
        delta_ip,
        delta_stp,
        copy_count,
        pop_count,

        fn typeOf(field: SideTableEntryField) Type {
            return switch (field) {
                .delta_ip => .i32,
                .delta_stp => .i16,
                .copy_count, .pop_count => .i8,
            };
        }

        fn load(
            field: SideTableEntryField,
            handler: *OpcodeHandler,
            b: *Builder,
            stp: Value,
        ) Oom!Value {
            const field_idx = try b.module.intValue(.i32, @intFromEnum(field));
            return try handler.wip.load(
                .normal,
                field.typeOf(),
                try handler.wip.gep(.inbounds, b.side_table_entry, stp, &.{ .@"0", field_idx }, ""),
                .default,
                "",
            );
        }
    };

    const TakeBranch = struct {
        vip: Value,
        vsp: Value,
        stp: Value,
    };

    fn takeBranch(handler: *OpcodeHandler, b: *Builder, info: struct {
        branch_ip: Value,
        vsp: Value,
        stp: Value = .none,
    }) Oom!TakeBranch {
        const wip = &handler.wip;
        const stp = if (info.stp == .none) OpcodeHandlerParam.stp.arg(wip) else info.stp;

        const delta_ip = try SideTableEntryField.delta_ip.load(handler, b, stp);
        const copy_count_in_values = try wip.cast(
            .zext,
            try SideTableEntryField.copy_count.load(handler, b, stp),
            b.size_type,
            "",
        );
        const pop_count_in_values = try wip.cast(
            .zext,
            try SideTableEntryField.pop_count.load(handler, b, stp),
            b.size_type,
            "",
        );
        const delta_stp = try SideTableEntryField.delta_stp.load(handler, b, stp);

        // Should perform signed subtraction
        const new_vip = try wip.gep(.inbounds, .i8, info.branch_ip, &.{delta_ip}, "");
        const new_stp = try wip.gep(.inbounds, b.side_table_entry, stp, &.{delta_stp}, "");

        const size_0 = try b.sizeIntValue(0);
        const dst_vsp = try wip.gep(.inbounds, b.value_structs.i64, info.vsp, &.{
            try wip.bin(.@"sub nsw", size_0, pop_count_in_values, "negate"),
        }, "");
        const src_vsp = try wip.gep(.inbounds, b.value_structs.i64, info.vsp, &.{
            try wip.bin(.@"sub nsw", size_0, copy_count_in_values, "negate"),
        }, "");

        const new_vsp = try wip.gep(
            .inbounds,
            b.value_structs.i64,
            dst_vsp,
            &.{copy_count_in_values},
            "",
        );

        {
            const copy_count_in_bytes = try wip.bin(
                .@"shl nsw",
                copy_count_in_values,
                try b.sizeIntValue(4),
                "",
            );

            // Want fast path to be copying <= 1 values
            _ = try wip.callIntrinsic(
                .normal,
                attrs: {
                    var attrs = try b.value_copy.attributes.toWip(&b.module);
                    defer attrs.deinit(&b.module);
                    for (0..2) |i| {
                        _ = try attrs.removeParamAttr(i, .dereferenceable);
                    }
                    break :attrs try attrs.finish(&b.module);
                },
                .memmove,
                &b.value_copy.overload,
                &.{ dst_vsp, src_vsp, copy_count_in_bytes, .false },
                "",
            );
        }

        return .{ .vip = new_vip, .vsp = new_vsp, .stp = new_stp };
    }

    fn finish(handler: *OpcodeHandler, b: *Builder) Oom!void {
        try handler.wip.finish();
        handler.wip.deinit();
        b.opcode_handler_writing_lock.unlock();
    }
};

const LinearMemoryAccess = struct {
    /// A `ptr` into WASM linear memory.
    ptr: Value,
    /// Refers to the first byte after the `memarg`
    vip: Value,
};

const OpcodeHandlerParam = enum(u4) {
    locals,
    vsp,
    module,
    fuel,
    memories,
    ctx,
    vip,
    stp,
    eip,
    disp,

    fn arg(param: OpcodeHandlerParam, wip: *WipFunction) Value {
        return wip.arg(@intFromEnum(param));
    }
};

fn enumFieldCount(comptime E: type) comptime_int {
    return @typeInfo(E).@"enum".fields.len;
}

fn buildLlvmModule(b: *Builder) Oom!void {
    b.module.data_layout = try b.module.string(b.target_info.data_layout);
    try b.module.functions.ensureUnusedCapacity(
        b.module.gpa,
        enumFieldCount(ByteOpcode) + enumFieldCount(opcodes.FCPrefixOpcode),
    );
    try b.module.globals.ensureUnusedCapacity(b.module.gpa, 3);

    b.dispatch_tables.byte = try b.addDispatchTable("byte_dispatch_table", 256);

    {
        const trampoline = try b.addFfiFunction(
            "opcodeHandlerTrampoline",
            &[10]Type{
                .ptr, // locals
                .ptr, // sp
                .ptr, // module
                .ptr, // fuel
                .ptr, // memories
                .ptr, // interpreter
                .ptr, // ip
                .ptr, // stp
                .ptr, // eip
                .ptr, // handler
            },
            .i32,
        );
        {
            var attributes = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attributes);
            try attributes.addFnAttr(.norecurse, &b.module);
            try b.setFnAttributes(trampoline, &attributes);
        }
        var wip = try b.wipFunction(trampoline);
        defer wip.deinit();

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const call_params: [10]Value = params: {
            var params: [10]Value = undefined;
            for (0..9) |i| {
                params[i] = wip.arg(@intCast(i));
            }

            params[9] = b.dispatch_tables.byte.ptrConst(&b.module).kind.variable.toValue(&b.module);
            break :params params;
        };
        const result = try wip.call(
            .tail,
            b.opcode_handler.call_conv,
            .none,
            b.opcode_handler.type,
            wip.arg(9),
            &call_params,
            "",
        );
        _ = try wip.ret(result);
        try wip.finish();

        // try wip.callIntrinsic(.normal, attrs: {
        //     var trap_attrs = FunctionAttributes.Wip{};
        //     defer trap_attrs.deinit(&b.module);
        //     try b.fnAttributes(&trap_attrs, .{
        //         .function = &[2]Attribute{ .cold, .noreturn, .nounwind },
        //     });
        //     break :attrs trap_attrs.finish();
        // }, .trap, &.{}, .{}, "");
    }
    {
        b.out_of_fuel_handler = try b.addFunction(
            try b.strtabStringSymbolPrefixed("outOfFuelHandler"),
            b.opcode_handler.type,
            b.opcode_handler.call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = try b.opcode_handler.fn_attrs.toWip(&b.module);
            try b.fnAttributes(&attrs, &.{ .mustprogress, .cold });
            try b.setFnAttributes(b.out_of_fuel_handler, &attrs);
        }
        var wip = try b.wipFunction(b.out_of_fuel_handler);
        defer wip.deinit();

        const helper = try b.addFunction(
            try b.strtabStringSymbolPrefixed("interruptOutOfFuel"),
            try b.fnType(.i32, &@as([5]Type, @splat(.ptr))),
            b.ffi_call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attrs);
            try b.setFnAttributes(helper, &attrs);
        }

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const call_params: [5]Value = params: {
            var params: [5]Value = undefined;
            for (&params, [5]OpcodeHandlerParam{ .vip, .eip, .vsp, .stp, .ctx }) |*p, arg| {
                p.* = wip.arg(@intFromEnum(arg));
            }

            break :params params;
        };
        const result = try wip.call(
            .tail,
            b.ffi_call_conv,
            .none,
            helper.typeOf(&b.module),
            helper.toValue(&b.module),
            &call_params,
            "",
        );
        _ = try wip.ret(result);
        try wip.finish();
    }
    const uleb_helper_attrs = attrs: {
        var attrs = FunctionAttributes.Wip{};
        try b.commonFnAttributes(&attrs);
        try b.fnAttributes(&attrs, &.{ .mustprogress, .willreturn, .norecurse });
        for (&[6]Attribute{
            .readonly,
            .nonnull,
            .noundef,
            .{ .dereferenceable = 1 },
            .@"noalias",
            .nofree,
        }) |a| {
            try attrs.addParamAttr(0, a, &b.module);
        }
        break :attrs try attrs.finish(&b.module);
    };
    const uleb_cont_mask = try b.module.intValue(.i8, 0x80);
    const size_1 = try b.sizeIntValue(1);
    {
        b.skip_leb_idx = try b.addFunction(
            try b.strtabStringSymbolPrefixed("skipLebIndex"),
            try b.fnType(.ptr, &.{.ptr}),
            if (b.target.cpu.arch == .x86_64) .preserve_mostcc else .fastcc,
            .{ .linkage = .internal, .preemption = .dso_local },
        );
        b.skip_leb_idx.setAttributes(uleb_helper_attrs, &b.module);

        var wip = try b.wipFunction(b.skip_leb_idx);
        defer wip.deinit();

        const entry_blk = try wip.block(0, "Entry");
        const ret_blk = try wip.block(2, "ReturnCommon");
        const loop_body = try wip.block(2, "LoopBody");
        wip.cursor = .{ .block = entry_blk };
        const byte_0 = try wip.load(.normal, .i8, wip.arg(0), .default, "");
        const vip_1 = try wip.gep(.inbounds, .i8, wip.arg(0), &.{size_1}, "");
        _ = try wip.brCond(
            try wip.icmp(.ult, byte_0, uleb_cont_mask, ""),
            ret_blk,
            loop_body,
            .then_likely,
        );

        wip.cursor = .{ .block = loop_body };
        const current_vip = try wip.phi(.ptr, "");
        _ = try wip.callIntrinsicAssumeCold();
        const current_byte = try wip.load(.normal, .i8, current_vip.toValue(), .default, "");
        const next_vip = try wip.gep(.inbounds, .i8, current_vip.toValue(), &.{size_1}, "");
        current_vip.finish(&.{ vip_1, next_vip }, &.{ entry_blk, loop_body }, &wip);
        _ = try wip.brCond(
            try wip.icmp(.ult, current_byte, uleb_cont_mask, ""),
            ret_blk,
            loop_body,
            .then_likely,
        );

        {
            wip.cursor = .{ .block = ret_blk };
            const ret_phi = try wip.phi(.ptr, "");
            ret_phi.finish(&.{ vip_1, next_vip }, &.{ entry_blk, loop_body }, &wip);
            _ = try wip.ret(ret_phi.toValue());
        }

        try wip.finish();
    }
    {
        const ret_ty = try b.module.structType(.normal, &.{ .i32, .ptr });
        b.decode_uleb_idx = try b.addFunction(
            try b.strtabStringSymbolPrefixed("decodeUlebIndex"),
            try b.fnType(ret_ty, &.{.ptr}),
            if (b.target.cpu.arch == .x86_64) .preserve_mostcc else .fastcc,
            .{ .linkage = .internal, .preemption = .dso_local },
        );
        b.decode_uleb_idx.setAttributes(uleb_helper_attrs, &b.module);

        var wip = try b.wipFunction(b.decode_uleb_idx);
        defer wip.deinit();

        const entry_blk = try wip.block(0, "Entry");
        wip.cursor = .{ .block = entry_blk };
        const vip_0 = wip.arg(0);
        const byte_0 = try wip.load(.normal, .i8, vip_0, .default, "");
        const vip_1 = try wip.gep(.inbounds, .i8, vip_0, &.{size_1}, "");
        const ret_single_byte = try wip.block(1, "ReturnSingleByte");
        const loop_body = try wip.block(2, "LoopBody");
        const acc_0 = try wip.cast(.zext, byte_0, .i32, "");
        _ = try wip.brCond(
            try wip.icmp(.ult, byte_0, uleb_cont_mask, ""),
            ret_single_byte,
            loop_body,
            .then_likely,
        );

        {
            wip.cursor = .{ .block = ret_single_byte };
            _ = try wip.ret(try wip.buildAggregate(ret_ty, &.{ acc_0, vip_1 }, ""));
        }

        const shift_7 = try b.module.intValue(.i32, 7);

        // LLVM partial inlining seems to be working properly here
        wip.cursor = .{ .block = loop_body };
        const acc_phi = try wip.phi(.i32, "");
        const shift_phi = try wip.phi(.i32, "");
        const vip_phi = try wip.phi(.ptr, "");
        _ = try wip.callIntrinsicAssumeCold();
        _ = try wip.callIntrinsic(
            .normal,
            .none,
            .assume,
            &.{},
            &.{try wip.icmp(.ule, shift_phi.toValue(), try b.module.intValue(.i32, 28), "")},
            "",
        );

        const next_byte = try wip.load(.normal, .i8, vip_phi.toValue(), .default, "");
        const next_value_bits = try wip.bin(.@"and", next_byte, try b.module.intValue(.i8, 0x7F), "");
        const next_acc = try wip.bin(
            .@"or",
            try wip.bin(
                .@"shl nuw",
                try wip.cast(.zext, next_value_bits, .i32, ""),
                shift_phi.toValue(),
                "",
            ),
            acc_phi.toValue(),
            "",
        );
        // TODO(zig): `add nuw nsw` not supported
        const next_shift = try wip.bin(.@"add nsw", shift_phi.toValue(), shift_7, "");
        const next_vip = try wip.gep(.inbounds, .i8, vip_phi.toValue(), &.{size_1}, "");
        const loop_ret = try wip.block(1, "ReturnMultiByte");
        _ = try wip.brCond(
            try wip.icmp(.ult, next_byte, uleb_cont_mask, ""),
            loop_ret,
            loop_body,
            .then_likely,
        );

        acc_phi.finish(&.{ acc_0, next_acc }, &.{ entry_blk, loop_body }, &wip);
        shift_phi.finish(&.{ shift_7, next_shift }, &.{ entry_blk, loop_body }, &wip);
        vip_phi.finish(&.{ vip_1, next_vip }, &.{ entry_blk, loop_body }, &wip);

        {
            wip.cursor = .{ .block = loop_ret };
            _ = try wip.ret(try wip.buildAggregate(ret_ty, &.{ next_acc, next_vip }, ""));
        }
        try wip.finish();
    }
    {
        b.trap_with_numeric_code = try b.addFunction(
            try b.strtabStringSymbolPrefixed("trapWithNumericCode"),
            try b.fnType(.i32, &.{ .ptr, .ptr, .ptr, .ptr, .ptr, b.size_type }),
            b.ffi_call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        var attrs = FunctionAttributes.Wip{};
        try b.commonFnAttributes(&attrs);
        try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .cold });
        try b.setFnAttributes(b.trap_with_numeric_code, &attrs);
    }
    {
        b.trap_memory_access_oob = try b.addFunction(
            try b.strtabStringSymbolPrefixed("trapMemoryAccessOutOfBounds"),
            try b.fnType(
                .i32,
                &[10]Type{
                    .ptr,
                    .ptr,
                    .ptr,
                    .ptr,
                    .ptr,
                    .ptr,
                    b.size_type,
                    b.size_type,
                    b.size_type,
                    b.size_type,
                },
            ),
            b.ffi_call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        var attrs = FunctionAttributes.Wip{};
        try b.commonFnAttributes(&attrs);
        try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .cold });
        try b.setFnAttributes(b.trap_memory_access_oob, &attrs);
    }

    try buildNopOpcodeHandlers(b);
    try buildControlOpcodeHandlers(b);
    try buildParametricOpcodeHandlers(b);
    try buildLocalOpcodeHandlers(b);
    try buildMemoryLoadOpcodeHandlers(b);
    try buildMemoryStoreOpcodeHandlers(b);
    try buildIntegerOpcodeHandlers(b);
    try buildFloatOpcodeHandlers(b);

    try b.setDispatchTableInitializer(ByteOpcode);
}

const NumericTrapCode = enum(u8) {
    unreachable_code_reached = 0,
    integer_division_by_zero = 2,
    integer_overflow = 3,
    invalid_conversion_to_integer = 4,

    fn toValue(code: NumericTrapCode, b: *Builder) Oom!Value {
        return b.sizeIntValue(@intFromEnum(code));
    }
};

fn buildNopOpcodeHandlers(b: *Builder) Oom!void {
    for (&[_]ByteOpcode{
        .nop,
        .@"i32.reinterpret_f32",
        .@"i64.reinterpret_f64",
        .@"f32.reinterpret_i32",
        .@"f64.reinterpret_i64",
    }) |opcode| {
        // LLVM could maybe deduplicate these
        var nop = try b.opcodeHandler(.{ .byte = opcode });
        nop.wip.cursor = .{ .block = try nop.wip.block(0, "Entry") };
        try nop.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&nop.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&nop.wip),
            .stp = OpcodeHandlerParam.stp.arg(&nop.wip),
        });
        try nop.finish(b);
    }
}

fn buildControlOpcodeHandlers(b: *Builder) Oom!void {
    const size_neg_1 = try b.sizeIntValue(-1);
    const i32_0 = try b.module.intValue(.i32, 0);
    for (&[2]ByteOpcode{ .block, .loop }) |opcode| {
        var block = try b.opcodeHandler(.{ .byte = opcode });
        block.wip.cursor = .{ .block = try block.wip.block(0, "Entry") };
        const new_vip = try b.callSkipUlebIdx(&block.wip, OpcodeHandlerParam.vip.arg(&block.wip));
        try block.jmpToNextHandler(b, .{
            .vip = new_vip,
            .vsp = OpcodeHandlerParam.vsp.arg(&block.wip),
            .stp = OpcodeHandlerParam.stp.arg(&block.wip),
        });
        try block.finish(b);
    }

    const return_handler: Function.Index = ret: {
        var ret = try b.opcodeHandler(.{ .byte = .@"return" });
        const index = ret.wip.function;

        const helper = try b.addFunction(
            try b.strtabStringSymbolPrefixed("returnFromWasm"),
            try b.fnType(.i32, &@as([10]Type, @splat(.ptr))),
            b.ffi_call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attrs);
            try b.setFnAttributes(helper, &attrs);
        }

        ret.wip.cursor = .{ .block = try ret.wip.block(0, "Entry") };
        const args = args: {
            var args: [10]Value = undefined;
            const dummy = try b.module.poisonValue(.ptr);
            for (&args, std.enums.values(OpcodeHandlerParam)) |*a, param| {
                a.* = switch (param) {
                    .vsp, .module, .fuel, .ctx, .eip => param.arg(&ret.wip),
                    else => dummy,
                };
            }
            break :args args;
        };
        _ = try ret.wip.ret(
            try ret.wip.call(
                .tail,
                b.ffi_call_conv,
                .none,
                helper.typeOf(&b.module),
                helper.toValue(&b.module),
                &args,
                "",
            ),
        );

        try ret.finish(b);
        break :ret index;
    };
    {
        var br = try b.opcodeHandler(.{ .byte = .@"if" });
        br.wip.cursor = .{ .block = try br.wip.block(0, "Entry") };
        const initial_vip = OpcodeHandlerParam.vip.arg(&br.wip);
        const condition_ptr = try br.operandAt(b, 0);
        const condition = try br.wip.icmp(
            .ne,
            try br.wip.load(.normal, .i32, condition_ptr, value_stack_alignment, ""),
            i32_0,
            "",
        );
        const true_blk = try br.wip.block(1, "True");
        const false_blk = try br.wip.block(1, "False");
        const jmp_blk = try br.wip.block(2, "JmpToNextHandler");
        _ = try br.wip.brCond(condition, true_blk, false_blk, .unpredictable);

        br.wip.cursor = .{ .block = false_blk };
        // No need to read the block type
        const branch = try br.takeBranch(b, .{
            .branch_ip = try br.wip.gep(.inbounds, .i8, initial_vip, &.{size_neg_1}, ""),
            .vsp = condition_ptr,
        });
        _ = try br.wip.br(jmp_blk);

        br.wip.cursor = .{ .block = true_blk };
        const vip_after_block_type = try b.callSkipUlebIdx(&br.wip, initial_vip);
        const false_stp = try br.wip.gep(
            .inbounds,
            b.side_table_entry,
            OpcodeHandlerParam.stp.arg(&br.wip),
            &.{try b.sizeIntValue(1)},
            "",
        );
        _ = try br.wip.br(jmp_blk);

        br.wip.cursor = .{ .block = jmp_blk };
        const new_vip = try br.wip.phi(.ptr, "vip");
        const new_vsp = try br.wip.phi(.ptr, "vsp");
        const new_stp = try br.wip.phi(.ptr, "stp");
        const phi_blocks = [2]Function.Block.Index{ true_blk, false_blk };
        new_vip.finish(&.{ vip_after_block_type, branch.vip }, &phi_blocks, &br.wip);
        new_vsp.finish(&.{ condition_ptr, branch.vsp }, &phi_blocks, &br.wip);
        new_stp.finish(&.{ false_stp, branch.stp }, &phi_blocks, &br.wip);
        try br.jmpToNextHandler(b, .{
            .vip = new_vip.toValue(),
            .vsp = new_vsp.toValue(),
            .stp = new_stp.toValue(),
        });
        try br.finish(b);
    }
    {
        // LLVM could maybe deduplicate this with the `br` handler
        var br = try b.opcodeHandler(.{ .byte = .@"else" });
        br.wip.cursor = .{ .block = try br.wip.block(0, "Entry") };
        // end of true branch of if, so jump to end
        const branch = try br.takeBranch(b, .{
            .branch_ip = try br.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&br.wip),
                &.{size_neg_1},
                "",
            ),
            .vsp = OpcodeHandlerParam.vsp.arg(&br.wip),
        });
        try br.jmpToNextHandler(b, .{ .vip = branch.vip, .vsp = branch.vsp, .stp = branch.stp });
        try br.finish(b);
    }
    {
        var end = try b.opcodeHandler(.{ .byte = .end });
        end.wip.cursor = .{ .block = try end.wip.block(0, "Entry") };
        const is_return = try end.wip.icmp(
            .eq,
            try end.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&end.wip),
                &.{size_neg_1},
                "",
            ),
            OpcodeHandlerParam.eip.arg(&end.wip),
            "",
        );
        const ret = try end.wip.block(1, "Return");
        const cont = try end.wip.block(1, "Continue");
        _ = try end.wip.brCond(is_return, ret, cont, .none);

        {
            end.wip.cursor = .{ .block = ret };
            const ret_args = args: {
                var args: [10]Value = undefined;
                for (&args, std.enums.values(OpcodeHandlerParam)) |*a, param| {
                    a.* = param.arg(&end.wip);
                }
                break :args args;
            };
            _ = try end.wip.ret(
                try end.wip.call(
                    .musttail,
                    b.opcode_handler.call_conv,
                    .none,
                    b.opcode_handler.type,
                    return_handler.toValue(&b.module),
                    &ret_args,
                    "",
                ),
            );
        }

        end.wip.cursor = .{ .block = cont };
        try end.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&end.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&end.wip),
            .stp = OpcodeHandlerParam.stp.arg(&end.wip),
        });
        try end.finish(b);
    }
    {
        var br = try b.opcodeHandler(.{ .byte = .br });
        br.wip.cursor = .{ .block = try br.wip.block(0, "Entry") };
        // No need to read label idx
        const branch = try br.takeBranch(b, .{
            .branch_ip = try br.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&br.wip),
                &.{size_neg_1},
                "",
            ),
            .vsp = OpcodeHandlerParam.vsp.arg(&br.wip),
        });

        try br.jmpToNextHandler(b, .{ .vip = branch.vip, .vsp = branch.vsp, .stp = branch.stp });
        try br.finish(b);
    }
    {
        // Basically the `if` handler, with the condition reversed.
        var br_if = try b.opcodeHandler(.{ .byte = .br_if });
        br_if.wip.cursor = .{ .block = try br_if.wip.block(0, "Entry") };
        const initial_vip = OpcodeHandlerParam.vip.arg(&br_if.wip);
        const condition_ptr = try br_if.operandAt(b, 0);
        const condition = try br_if.wip.icmp(
            .ne,
            try br_if.wip.load(.normal, .i32, condition_ptr, value_stack_alignment, ""),
            i32_0,
            "",
        );
        const true_blk = try br_if.wip.block(1, "True");
        const false_blk = try br_if.wip.block(1, "False");
        const jmp_blk = try br_if.wip.block(2, "JmpToNextHandler");
        _ = try br_if.wip.brCond(condition, true_blk, false_blk, .unpredictable);

        br_if.wip.cursor = .{ .block = true_blk };
        // No need to read label
        const branch = try br_if.takeBranch(b, .{
            .branch_ip = try br_if.wip.gep(.inbounds, .i8, initial_vip, &.{size_neg_1}, ""),
            .vsp = condition_ptr,
        });
        _ = try br_if.wip.br(jmp_blk);

        br_if.wip.cursor = .{ .block = false_blk };
        const vip_after_block_type = try b.callSkipUlebIdx(&br_if.wip, initial_vip);
        const false_stp = try br_if.wip.gep(
            .inbounds,
            b.side_table_entry,
            OpcodeHandlerParam.stp.arg(&br_if.wip),
            &.{try b.sizeIntValue(1)},
            "",
        );
        _ = try br_if.wip.br(jmp_blk);

        br_if.wip.cursor = .{ .block = jmp_blk };
        const new_vip = try br_if.wip.phi(.ptr, "vip");
        const new_vsp = try br_if.wip.phi(.ptr, "vsp");
        const new_stp = try br_if.wip.phi(.ptr, "stp");
        const phi_blocks = [2]Function.Block.Index{ true_blk, false_blk };
        new_vip.finish(&.{ branch.vip, vip_after_block_type }, &phi_blocks, &br_if.wip);
        new_vsp.finish(&.{ branch.vsp, condition_ptr }, &phi_blocks, &br_if.wip);
        new_stp.finish(&.{ branch.stp, false_stp }, &phi_blocks, &br_if.wip);
        try br_if.jmpToNextHandler(b, .{
            .vip = new_vip.toValue(),
            .vsp = new_vsp.toValue(),
            .stp = new_stp.toValue(),
        });
        try br_if.finish(b);
    }
    {
        var br_table = try b.opcodeHandler(.{ .byte = .br_table });
        const wip = &br_table.wip;
        wip.cursor = .{ .block = try br_table.wip.block(0, "Entry") };
        const initial_vip = OpcodeHandlerParam.vip.arg(wip);
        const decoded_label_count = try b.callDecodeUlebIdx(wip, initial_vip);
        const label_count = try wip.extractValue(decoded_label_count, &.{0}, "");
        // No need to actually read label indices

        const n_ptr = try br_table.operandAt(b, 0);
        const n_unsafe = try wip.load(.normal, .i32, n_ptr, value_stack_alignment, "");
        const n = try wip.callIntrinsic(
            .normal,
            .none,
            .umin,
            &.{.i32},
            &.{ n_unsafe, label_count }, // if label_count is 0, only default target is available
            "",
        );

        const chosen_stp_entry = try wip.gep(
            .inbounds,
            b.side_table_entry,
            OpcodeHandlerParam.stp.arg(wip),
            &.{
                // Likely to hit OOM before overflow could happen, but validation could could
                // check to ensure a limit is not exceeded
                n,
            },
            "",
        );

        const branch = try br_table.takeBranch(b, .{
            .branch_ip = try br_table.wip.gep(.inbounds, .i8, initial_vip, &.{size_neg_1}, ""),
            .vsp = n_ptr,
            .stp = chosen_stp_entry,
        });

        try br_table.jmpToNextHandler(b, .{
            .vip = branch.vip,
            .vsp = branch.vsp,
            .stp = branch.stp,
        });
        try br_table.finish(b);
    }
    {
        const helper = try b.addFunction(
            try b.strtabStringSymbolPrefixed("invokeWithinWasm"),
            try b.fnType(
                .i32,
                &[10]Type{ .ptr, .ptr, .ptr, .ptr, b.size_type, .ptr, .ptr, .ptr, .ptr, .ptr },
            ),
            b.ffi_call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attrs);
            try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse });
            try b.setFnAttributes(helper, &attrs);
        }

        var call = try b.opcodeHandler(.{ .byte = .call });
        call.wip.cursor = .{ .block = try call.wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(&call.wip);
        const call_ip = try call.wip.gep(.inbounds, .i8, start_vip, &.{size_neg_1}, "");

        const decode_func_idx = try b.callDecodeUlebIdx(&call.wip, start_vip);
        const new_vip = try call.wip.extractValue(decode_func_idx, &.{1}, "vip");
        const func_idx = try call.wip.cast(
            .zext,
            try call.wip.extractValue(decode_func_idx, &.{0}, "func_idx"),
            b.size_type,
            "",
        );

        var helper_args = [10]Value{
            if (b.options.optimize == .Debug)
                OpcodeHandlerParam.locals.arg(&call.wip)
            else
                try b.module.undefValue(.ptr),
            OpcodeHandlerParam.vsp.arg(&call.wip),
            OpcodeHandlerParam.module.arg(&call.wip),
            OpcodeHandlerParam.fuel.arg(&call.wip),
            func_idx,
            OpcodeHandlerParam.ctx.arg(&call.wip),
            new_vip,
            OpcodeHandlerParam.stp.arg(&call.wip),
            OpcodeHandlerParam.eip.arg(&call.wip),
            call_ip,
        };
        _ = try call.wip.ret(
            try call.wip.call(
                .tail,
                b.ffi_call_conv,
                .none,
                helper.typeOf(&b.module),
                helper.toValue(&b.module),
                &helper_args,
                "",
            ),
        );

        try call.finish(b);
    }
}

fn writeSelectHandler(b: *Builder, select: *OpcodeHandler) Oom!Value {
    const condition_ptr = try select.operandAt(b, 0);
    const condition_value = try select.wip.load(
        .normal,
        .i32,
        condition_ptr,
        value_stack_alignment,
        "",
    );

    const value_size_bytes = try b.sizeIntValue(16);

    if (b.options.optimize == .Debug) {
        _ = try select.wip.callIntrinsic(
            .normal,
            b.value_set.attributes,
            .@"memset.inline",
            &b.value_set.overload,
            &.{ condition_ptr, try b.module.intValue(.i8, 0xCC), value_size_bytes, .false },
            "",
        );
    }

    const condition = try select.wip.cast(
        .zext,
        // Inverted, `0` if condition was `true`
        try select.wip.icmp(.eq, condition_value, try b.module.intValue(.i32, 0), ""),
        .i32,
        "",
    );
    // If `true`, value already in result location is kept the same.
    const dst_ptr = try select.operandAt(b, 2);
    const src_ptr = try select.wip.gep(
        .inbounds,
        b.value_structs.i64,
        dst_ptr,
        // If `true`, offset is `0`; otherwise, offset is `1`
        &.{condition},
        "",
    );

    _ = try select.wip.callIntrinsic(
        .normal,
        b.value_copy.attributes,
        .memmove,
        &b.value_copy.overload,
        &.{ dst_ptr, src_ptr, value_size_bytes, .false },
        "",
    );

    return try select.adjustVspBy(b, -2);
}

fn buildParametricOpcodeHandlers(b: *Builder) Oom!void {
    {
        var drop = try b.opcodeHandler(.{ .byte = .drop });
        drop.wip.cursor = .{ .block = try drop.wip.block(0, "Entry") };

        if (b.options.optimize == .Debug) {
            _ = try drop.wip.callIntrinsic(
                .normal,
                b.value_set.attributes,
                .@"memset.inline",
                &b.value_set.overload,
                &.{
                    try drop.operandAt(b, 0),
                    try b.module.intValue(.i8, 0xCC),
                    try b.sizeIntValue(16),
                    .false,
                },
                "",
            );
        }

        const new_vsp = try drop.adjustVspBy(b, -1);
        try drop.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&drop.wip),
            .vsp = new_vsp,
            .stp = OpcodeHandlerParam.stp.arg(&drop.wip),
        });
        try drop.finish(b);
    }
    {
        var select = try b.opcodeHandler(.{ .byte = .select });
        select.wip.cursor = .{ .block = try select.wip.block(0, "Entry") };
        const new_vsp = try writeSelectHandler(b, &select);
        try select.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&select.wip),
            .vsp = new_vsp,
            .stp = OpcodeHandlerParam.stp.arg(&select.wip),
        });
        try select.finish(b);
    }
}

fn buildMemoryLoadOpcodeHandlers(b: *Builder) Oom!void {
    const extending_loads = [6]struct {
        WipFunction.Instruction.Tag,
        std.mem.Alignment,
        Type,
        []const u8,
    }{
        .{ .zext, .@"1", .i8, "load8_u" },
        .{ .sext, .@"1", .i8, "load8_s" },
        .{ .zext, .@"2", .i16, "load16_u" },
        .{ .sext, .@"2", .i16, "load16_s" },
        .{ .zext, .@"4", .i32, "load32_u" },
        .{ .sext, .@"4", .i32, "load32_s" },
    };

    for (&[2]Type{ .i32, .i64 }, &[2][]const u8{ "f32", "f64" }) |int_ty, float_name| {
        for (extending_loads[0..(if (int_ty == .i64) 6 else 4)]) |info| {
            const cast, const access_size, const load_ty, const name = info;
            var load = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);

            load.wip.cursor = .{ .block = try load.wip.block(0, "Entry") };
            const perform_load = try load.wip.block(1, "Load");
            const access = try load.linearMemoryAccess(b, 0, access_size, perform_load);
            const loaded_value = try load.wip.cast(
                cast,
                try load.wip.load(.normal, load_ty, access.ptr, byte_alignment, ""),
                int_ty,
                "",
            );

            _ = try load.wip.store(
                .normal,
                loaded_value,
                try load.operandAt(b, 0),
                value_stack_alignment,
            );

            try load.jmpToNextHandler(b, .{
                .vip = access.vip,
                .vsp = OpcodeHandlerParam.vsp.arg(&load.wip),
                .stp = OpcodeHandlerParam.stp.arg(&load.wip),
            });
            try load.finish(b);
        }

        // On ReleaseSmall, f32/f64 memory loads can just be aliases for i32/i64 versions
        // LLVM might have function deduplication to handle this
        for ([2][]const u8{ @tagName(int_ty), float_name }) |name| {
            var load = try b.opcodeHandlerFromPrefixedName(ByteOpcode, name, "load");

            load.wip.cursor = .{ .block = try load.wip.block(0, "Entry") };
            const perform_load = try load.wip.block(1, "Load");
            const access = try load.linearMemoryAccess(
                b,
                0,
                .fromByteUnits(@divExact(int_ty.scalarBits(&b.module), 8)),
                perform_load,
            );

            _ = try load.wip.store(
                .normal,
                try load.wip.load(.normal, int_ty, access.ptr, byte_alignment, ""),
                try load.operandAt(b, 0),
                value_stack_alignment,
            );

            try load.jmpToNextHandler(b, .{
                .vip = access.vip,
                .vsp = OpcodeHandlerParam.vsp.arg(&load.wip),
                .stp = OpcodeHandlerParam.stp.arg(&load.wip),
            });
            try load.finish(b);
        }
    }
}

fn buildMemoryStoreOpcodeHandlers(b: *Builder) Oom!void {
    const extending_stores = [3]struct { std.mem.Alignment, Type, []const u8 }{
        .{ .@"1", .i8, "store8" },
        .{ .@"2", .i16, "store16" },
        .{ .@"4", .i32, "store32" },
    };

    for (&[2]Type{ .i32, .i64 }, &[2][]const u8{ "f32", "f64" }) |int_ty, float_name| {
        // value to store is on top of the stack, with the address below that
        for (extending_stores[0..(if (int_ty == .i64) 3 else 2)]) |info| {
            const access_size, const store_ty, const name = info;
            var store = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);

            store.wip.cursor = .{ .block = try store.wip.block(0, "Entry") };
            const perform_store = try store.wip.block(1, "Store");
            const access = try store.linearMemoryAccess(
                b,
                1,
                access_size,
                perform_store,
            );

            _ = try store.wip.store(
                .normal,
                try store.wip.cast(.trunc, try store.wip.load(
                    .normal,
                    int_ty,
                    try store.operandAt(b, 0),
                    value_stack_alignment,
                    "",
                ), store_ty, ""),
                access.ptr,
                byte_alignment,
            );

            const new_vsp = try store.adjustVspBy(b, -2);
            try store.jmpToNextHandler(b, .{
                .vip = access.vip,
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&store.wip),
            });
            try store.finish(b);
        }

        // LLVM might have function deduplication to deal with float versions
        for ([2][]const u8{ @tagName(int_ty), float_name }) |name| {
            var store = try b.opcodeHandlerFromPrefixedName(ByteOpcode, name, "store");

            store.wip.cursor = .{ .block = try store.wip.block(0, "Entry") };
            const perform_store = try store.wip.block(1, "Store");
            const access = try store.linearMemoryAccess(
                b,
                1,
                .fromByteUnits(@divExact(int_ty.scalarBits(&b.module), 8)),
                perform_store,
            );

            _ = try store.wip.store(
                .normal,
                try store.wip.load(
                    .normal,
                    int_ty,
                    try store.operandAt(b, 0),
                    value_stack_alignment,
                    "",
                ),
                access.ptr,
                byte_alignment,
            );

            const new_vsp = try store.adjustVspBy(b, -2);
            try store.jmpToNextHandler(b, .{
                .vip = access.vip,
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&store.wip),
            });
            try store.finish(b);
        }
    }
}

fn buildLocalOpcodeHandlers(b: *Builder) Oom!void {
    const value_size_bytes = try b.sizeIntValue(16);
    {
        var local_get = try b.opcodeHandler(.{ .byte = .@"local.get" });
        const wip = &local_get.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const decode_result = try b.callDecodeUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
        const new_vip = try wip.extractValue(decode_result, &.{1}, "");
        const src_addr = try wip.gep(
            .inbounds,
            b.value_structs.i64,
            OpcodeHandlerParam.locals.arg(wip),
            &.{try wip.extractValue(decode_result, &.{0}, "")},
            "",
        );
        _ = try wip.callIntrinsic(
            .normal,
            b.value_copy.attributes,
            .memcpy,
            &b.value_copy.overload,
            &.{ OpcodeHandlerParam.vsp.arg(wip), src_addr, value_size_bytes, .false },
            "",
        );

        const new_vsp = try local_get.adjustVspBy(b, 1);
        try local_get.jmpToNextHandler(b, .{
            .vip = new_vip,
            .vsp = new_vsp,
            .stp = OpcodeHandlerParam.stp.arg(wip),
        });
        try local_get.finish(b);
    }
    for (&[2]ByteOpcode{ .@"local.set", .@"local.tee" }) |opcode| {
        var local_set = try b.opcodeHandler(.{ .byte = opcode });
        const wip = &local_set.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const decode_result = try b.callDecodeUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
        const new_vip = try wip.extractValue(decode_result, &.{1}, "");
        const dst_addr = try wip.gep(
            .inbounds,
            b.value_structs.i64,
            OpcodeHandlerParam.locals.arg(wip),
            &.{try wip.extractValue(decode_result, &.{0}, "")},
            "",
        );
        _ = try wip.callIntrinsic(
            .normal,
            b.value_copy.attributes,
            .memcpy,
            &b.value_copy.overload,
            &.{ dst_addr, try local_set.operandAt(b, 0), value_size_bytes, .false },
            "",
        );

        const new_vsp = switch (opcode) {
            .@"local.set" => try local_set.adjustVspBy(b, -1),
            .@"local.tee" => OpcodeHandlerParam.vsp.arg(wip),
            else => unreachable,
        };
        try local_set.jmpToNextHandler(b, .{
            .vip = new_vip,
            .vsp = new_vsp,
            .stp = OpcodeHandlerParam.stp.arg(wip),
        });
        try local_set.finish(b);
    }
}

fn buildIntegerOpcodeHandlers(b: *Builder) Oom!void {
    const size_1 = try b.sizeIntValue(1);
    const leb_continue_bit = try b.module.intValue(.i8, 0x80);
    const leb_value_bits = try b.module.intValue(.i8, 0x7F);
    for (
        &[2]Type{ .i32, .i64 },
        &[2]u7{ 32, 64 },
        &[2]u8{ 5, 10 },
    ) |int_ty, bit_width, max_leb_size| {
        const zero = try b.module.intValue(int_ty, 0);
        {
            const max_shift = try b.module.intValue(int_ty, (max_leb_size - 1) * 7);
            var op = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), "const");
            const entry_blk = try op.wip.block(0, "Entry");
            op.wip.cursor = .{ .block = entry_blk };

            const loop_body = try op.wip.block(2, "LoopBody");
            _ = try op.wip.br(loop_body);

            op.wip.cursor = .{ .block = loop_body };
            const current_vip = try op.wip.phi(.ptr, "VIP");
            const current_acc = try op.wip.phi(int_ty, "");
            const current_shift = try op.wip.phi(int_ty, "shift");
            _ = try op.wip.callIntrinsic(.normal, .none, .assume, &.{}, &.{
                try op.wip.icmp(.ule, current_shift.toValue(), max_shift, ""),
            }, "");

            const loaded_byte = try op.wip.load(
                .normal,
                .i8,
                current_vip.toValue(),
                .default,
                "byte",
            );
            const new_bits = try op.wip.bin(.@"and", loaded_byte, leb_value_bits, "");
            const acc_with_current_byte = try op.wip.bin(
                .@"or",
                current_acc.toValue(),
                try op.wip.bin(
                    .shl,
                    try op.wip.cast(.zext, new_bits, int_ty, ""),
                    current_shift.toValue(),
                    "",
                ),
                "",
            );

            const has_more = try op.wip.icmp(
                .eq,
                try op.wip.bin(.@"and", loaded_byte, leb_continue_bit, ""),
                leb_continue_bit,
                "",
            );
            const new_vip = try op.wip.gep(.inbounds, .i8, current_vip.toValue(), &.{size_1}, "");
            current_vip.finish(
                &.{ OpcodeHandlerParam.vip.arg(&op.wip), new_vip },
                &.{ entry_blk, loop_body },
                &op.wip,
            );
            const new_shift = try op.wip.bin(
                .@"add nsw",
                current_shift.toValue(),
                try b.module.intValue(int_ty, 7),
                "",
            );
            current_shift.finish(&.{ zero, new_shift }, &.{ entry_blk, loop_body }, &op.wip);
            current_acc.finish(
                &.{ zero, acc_with_current_byte },
                &.{ entry_blk, loop_body },
                &op.wip,
            );

            const decoded = try op.wip.block(1, "ConstDecoded");
            _ = try op.wip.brCond(has_more, loop_body, decoded, .else_likely);

            const done = try op.wip.block(2, "Done");
            op.wip.cursor = .{ .block = decoded };
            const sign_ext = try op.wip.block(1, "SignExtend");
            const needs_sign_extension = try op.wip.icmp(.ult, new_shift, max_shift, "");
            _ = try op.wip.brCond(needs_sign_extension, sign_ext, done, .none);

            op.wip.cursor = .{ .block = sign_ext };
            const ext_shift_amt = try op.wip.bin(
                .@"sub nuw",
                try b.module.intValue(int_ty, bit_width),
                new_shift,
                "",
            );
            const acc_sign_extended = try op.wip.bin(
                .@"ashr exact",
                try op.wip.bin(.@"shl nuw", acc_with_current_byte, ext_shift_amt, ""),
                ext_shift_amt,
                "",
            );
            _ = try op.wip.br(done);

            op.wip.cursor = .{ .block = done };
            const result = try op.wip.phi(int_ty, "c");
            result.finish(
                &.{ acc_with_current_byte, acc_sign_extended },
                &.{ decoded, sign_ext },
                &op.wip,
            );

            _ = try op.wip.store(
                .normal,
                result.toValue(),
                OpcodeHandlerParam.vsp.arg(&op.wip),
                value_stack_alignment,
            );
            const new_vsp = try op.adjustVspBy(b, 1);
            try op.jmpToNextHandler(b, .{
                .vip = new_vip,
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }

        for (&[6]WipFunction.Instruction.Tag{
            .add,
            .sub,
            .mul,
            .@"and",
            .@"or",
            .xor,
        }) |op_tag| {
            var op = try b.opcodeHandlerFromPrefixedName(
                ByteOpcode,
                @tagName(int_ty),
                @tagName(op_tag),
            );
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, int_ty);
            try bin_op.writeResult(&op, try op.wip.bin(op_tag, bin_op.c_1, bin_op.c_2, ""));
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }
        const min_int = try b.module.intValue(
            int_ty,
            @as(i64, switch (int_ty) {
                .i32 => std.math.minInt(i32),
                .i64 => std.math.minInt(i64),
                else => unreachable,
            }),
        );
        const neg_one = try b.module.intValue(int_ty, -1);
        {
            var div_s = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), "div_s");
            const entry = try div_s.wip.block(0, "Entry");
            div_s.wip.cursor = .{ .block = entry };
            const trap_ip = try div_s.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&div_s.wip),
                &.{try b.sizeIntValue(-1)},
                "",
            );
            const bin_op = try div_s.binOp(b, int_ty);
            const trap = try div_s.wip.block(2, "Trap");
            const non_zero_divisor = try div_s.wip.block(1, "NonZeroDivisor");
            _ = try div_s.wip.brCond(
                try div_s.wip.icmp(.eq, bin_op.c_2, zero, ""),
                trap,
                non_zero_divisor,
                .else_likely,
            );

            div_s.wip.cursor = .{ .block = non_zero_divisor };
            const no_trap = try div_s.wip.block(1, "NoTrap");
            _ = try div_s.wip.brCond(
                try div_s.wip.bin(
                    .@"and",
                    try div_s.wip.icmp(.eq, bin_op.c_1, min_int, ""),
                    try div_s.wip.icmp(.eq, bin_op.c_2, neg_one, ""),
                    "",
                ),
                trap,
                no_trap,
                .else_likely,
            );

            div_s.wip.cursor = .{ .block = no_trap };
            try bin_op.writeResult(&div_s, try div_s.wip.bin(.sdiv, bin_op.c_1, bin_op.c_2, ""));
            const new_vsp = try div_s.adjustVspBy(b, -1);
            try div_s.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&div_s.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&div_s.wip),
            });

            div_s.wip.cursor = .{ .block = trap };
            const trap_code = (try div_s.wip.phi(b.size_type, ""));
            trap_code.finish(
                &.{
                    try NumericTrapCode.integer_division_by_zero.toValue(b),
                    try NumericTrapCode.integer_overflow.toValue(b),
                },
                &.{ entry, non_zero_divisor },
                &div_s.wip,
            );
            try div_s.jmpTrapWithNumericCode(b, trap_ip, trap_code.toValue());
            try div_s.finish(b);
        }
        for (&[2]struct { WipFunction.Instruction.Tag, []const u8 }{
            .{ .udiv, "div_u" },
            .{ .urem, "rem_u" },
        }) |info| {
            const op_tag, const name = info;
            var op = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);
            const entry = try op.wip.block(0, "Entry");
            op.wip.cursor = .{ .block = entry };
            const trap_ip = try op.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&op.wip),
                &.{try b.sizeIntValue(-1)},
                "",
            );
            const bin_op = try op.binOp(b, int_ty);
            const trap = try op.wip.block(1, "TrapDivisonByZero");
            const non_zero_divisor = try op.wip.block(1, "NonZeroDivisor");
            _ = try op.wip.brCond(
                try op.wip.icmp(.eq, bin_op.c_2, zero, ""),
                trap,
                non_zero_divisor,
                .else_likely,
            );

            op.wip.cursor = .{ .block = non_zero_divisor };
            try bin_op.writeResult(&op, try op.wip.bin(op_tag, bin_op.c_1, bin_op.c_2, ""));
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });

            op.wip.cursor = .{ .block = trap };
            try op.jmpTrapWithNumericCode(
                b,
                trap_ip,
                try NumericTrapCode.integer_division_by_zero.toValue(b),
            );

            try op.finish(b);
        }
        {
            var rem_s = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), "rem_s");
            const entry = try rem_s.wip.block(0, "Entry");
            rem_s.wip.cursor = .{ .block = entry };
            const trap_ip = try rem_s.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&rem_s.wip),
                &.{try b.sizeIntValue(-1)},
                "",
            );
            const bin_op = try rem_s.binOp(b, int_ty);
            const trap = try rem_s.wip.block(1, "TrapZeroDivisor");
            const non_zero_divisor = try rem_s.wip.block(1, "NonZeroDivisor");
            _ = try rem_s.wip.brCond(
                try rem_s.wip.icmp(.eq, bin_op.c_2, zero, ""),
                trap,
                non_zero_divisor,
                .else_likely,
            );

            rem_s.wip.cursor = .{ .block = non_zero_divisor };
            const no_overflow = try rem_s.wip.block(1, "NoOverflow");
            const store_result = try rem_s.wip.block(2, "StoreResult");
            _ = try rem_s.wip.brCond(
                try rem_s.wip.bin(
                    .@"and",
                    try rem_s.wip.icmp(.eq, bin_op.c_1, min_int, ""),
                    try rem_s.wip.icmp(.eq, bin_op.c_2, neg_one, ""),
                    "",
                ),
                store_result,
                no_overflow,
                .else_likely,
            );

            rem_s.wip.cursor = .{ .block = no_overflow };
            const result_no_overflow = try rem_s.wip.bin(.srem, bin_op.c_1, bin_op.c_2, "");
            _ = try rem_s.wip.br(store_result);

            rem_s.wip.cursor = .{ .block = store_result };
            const result_phi = try rem_s.wip.phi(int_ty, "");
            result_phi.finish(
                &.{ result_no_overflow, zero },
                &.{ no_overflow, non_zero_divisor },
                &rem_s.wip,
            );
            try bin_op.writeResult(&rem_s, result_phi.toValue());
            const new_vsp = try rem_s.adjustVspBy(b, -1);
            try rem_s.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&rem_s.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&rem_s.wip),
            });

            rem_s.wip.cursor = .{ .block = trap };
            try rem_s.jmpTrapWithNumericCode(
                b,
                trap_ip,
                try NumericTrapCode.integer_division_by_zero.toValue(b),
            );

            try rem_s.finish(b);
        }
        const shift_mask = try b.module.intValue(int_ty, int_ty.scalarBits(&b.module) - 1);
        for (&[3]struct { WipFunction.Instruction.Tag, []const u8 }{
            .{ .shl, "shl" },
            .{ .ashr, "shr_s" },
            .{ .lshr, "shr_u" },
        }) |info| {
            const op_tag, const name = info;
            var op = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, int_ty);
            const shift_amt = try op.wip.bin(.@"and", bin_op.c_2, shift_mask, "");
            try bin_op.writeResult(&op, try op.wip.bin(op_tag, bin_op.c_1, shift_amt, ""));
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }
        for ([2]struct { Intrinsic, []const u8 }{
            .{ .fshl, "rotl" },
            .{ .fshr, "rotr" },
        }) |info| {
            const intrin, const name = info;
            var op = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, int_ty);
            try bin_op.writeResult(
                &op,
                try op.wip.callIntrinsic(
                    .normal,
                    .none,
                    intrin,
                    &.{int_ty},
                    &.{ bin_op.c_1, bin_op.c_1, bin_op.c_2 },
                    "",
                ),
            );
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }
        for ([2]struct { Intrinsic, []const u8 }{
            .{ .ctlz, "clz" },
            .{ .cttz, "ctz" },
        }) |info| {
            const intrin, const name = info;
            var op = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const un_op = try op.unOp(b, int_ty);
            try un_op.writeResult(
                &op,
                try op.wip.callIntrinsic(
                    .normal,
                    .none,
                    intrin,
                    &.{int_ty},
                    &.{ un_op.c_1, .false },
                    "",
                ),
            );
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&op.wip),
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }
        {
            var popcnt = try b.opcodeHandlerFromPrefixedName(
                ByteOpcode,
                @tagName(int_ty),
                "popcnt",
            );
            popcnt.wip.cursor = .{ .block = try popcnt.wip.block(0, "Entry") };
            const un_op = try popcnt.unOp(b, int_ty);
            try un_op.writeResult(
                &popcnt,
                try popcnt.wip.callIntrinsic(.normal, .none, .ctpop, &.{int_ty}, &.{un_op.c_1}, ""),
            );
            try popcnt.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&popcnt.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&popcnt.wip),
                .stp = OpcodeHandlerParam.stp.arg(&popcnt.wip),
            });
            try popcnt.finish(b);
        }

        const extend_signed = [3]struct { Type, []const u8 }{
            .{ .i8, "extend8_s" },
            .{ .i16, "extend16_s" },
            .{ .i32, "extend32_s" },
        };
        const extend_signed_len: usize = switch (int_ty) {
            .i32 => 2,
            .i64 => 3,
            else => unreachable,
        };
        for (extend_signed[0..extend_signed_len]) |info| {
            const src_ty, const name = info;
            var extend = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);
            extend.wip.cursor = .{ .block = try extend.wip.block(0, "Entry") };
            const un_op = try extend.unOp(b, int_ty);
            try un_op.writeResult(
                &extend,
                try extend.wip.cast(
                    .sext,
                    try extend.wip.cast(.trunc, un_op.c_1, src_ty, ""),
                    int_ty,
                    "",
                ),
            );
            try extend.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&extend.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&extend.wip),
                .stp = OpcodeHandlerParam.stp.arg(&extend.wip),
            });
            try extend.finish(b);
        }

        {
            var eqz = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), "eqz");
            eqz.wip.cursor = .{ .block = try eqz.wip.block(0, "Entry") };
            const test_op = try eqz.testOp(b, int_ty);
            try test_op.writeResult(
                &eqz,
                try eqz.wip.cast(.zext, try eqz.wip.icmp(.eq, test_op.c_1, zero, ""), .i32, ""),
            );
            try eqz.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&eqz.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&eqz.wip),
                .stp = OpcodeHandlerParam.stp.arg(&eqz.wip),
            });
            try eqz.finish(b);
        }
        for ([10]struct { llvm.Builder.IntegerCondition, []const u8 }{
            .{ .eq, "eq" },
            .{ .ne, "ne" },
            .{ .slt, "lt_s" },
            .{ .ult, "lt_u" },
            .{ .sgt, "gt_s" },
            .{ .ugt, "gt_u" },
            .{ .sle, "le_s" },
            .{ .ule, "le_u" },
            .{ .sge, "ge_s" },
            .{ .uge, "ge_u" },
        }) |info| {
            const cond, const name = info;
            var cmp = try b.opcodeHandlerFromPrefixedName(ByteOpcode, @tagName(int_ty), name);
            cmp.wip.cursor = .{ .block = try cmp.wip.block(0, "Entry") };
            const rel_op = try cmp.binOp(b, int_ty);
            try rel_op.writeResult(
                &cmp,
                try cmp.wip.cast(
                    .zext,
                    try cmp.wip.icmp(cond, rel_op.c_1, rel_op.c_2, ""),
                    .i32,
                    "",
                ),
            );
            const new_vsp = try cmp.adjustVspBy(b, -1);
            try cmp.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&cmp.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&cmp.wip),
            });
            try cmp.finish(b);
        }
    }
}

const FloatInfo = struct {
    float_ty: Type,
    int_ty: Type,
    prefix: []const u8,
    canonical_nan: Value,
    /// Of type `int_ty`.
    sign_bit: Value,
    /// Of type `int_ty`.
    magnitude_mask: Value,

    fn init(b: *llvm.Builder) Oom![2]FloatInfo {
        return [2]FloatInfo{
            .{
                .float_ty = .float,
                .int_ty = .i32,
                .prefix = "f32",
                .canonical_nan = try b.floatValue(@bitCast(@as(u32, 0x7FC0_0000))),
                .sign_bit = try b.intValue(.i32, 0x8000_0000),
                .magnitude_mask = try b.intValue(.i32, 0x7FFF_FFFF),
            },
            .{
                .float_ty = .double,
                .int_ty = .i64,
                .prefix = "f64",
                .canonical_nan = try b.doubleValue(@bitCast(@as(u64, 0x7FF8_0000_0000_0000))),
                .sign_bit = try b.intValue(.i64, 0x8000_0000_0000_0000),
                .magnitude_mask = try b.intValue(.i64, 0x7FFF_FFFF_FFFF_FFFF),
            },
        };
    }

    fn floatBounds(b: *llvm.Builder, min: u32, max: u32) Oom!struct { Value, Value } {
        return .{ try b.floatValue(@bitCast(min)), try b.floatValue(@bitCast(max)) };
    }

    fn doubleBounds(b: *llvm.Builder, min: u64, max: u64) Oom!struct { Value, Value } {
        return .{ try b.doubleValue(@bitCast(min)), try b.doubleValue(@bitCast(max)) };
    }
};

fn buildFloatOpcodeHandlers(b: *Builder) Oom!void {
    for (@as([]const FloatInfo, &b.float_info)) |*float_info| {
        const float_ty = float_info.float_ty;
        const int_ty = float_info.int_ty;
        const prefix = float_info.prefix;

        {
            const byte_width = @divExact(float_ty.scalarBits(&b.module), 8);
            var c = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, "const");
            c.wip.cursor = .{ .block = try c.wip.block(0, "Entry") };
            const vip_0 = OpcodeHandlerParam.vip.arg(&c.wip);
            const imm = try c.wip.load(.normal, int_ty, vip_0, byte_alignment, "");
            const new_vip = try c.wip.gep(
                .inbounds,
                .i8,
                vip_0,
                &.{try b.sizeIntValue(byte_width)},
                "",
            );

            _ = try c.wip.store(
                .normal,
                imm,
                OpcodeHandlerParam.vsp.arg(&c.wip),
                value_stack_alignment,
            );
            const new_vsp = try c.adjustVspBy(b, 1);
            try c.jmpToNextHandler(b, .{
                .vip = new_vip,
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&c.wip),
            });
            try c.finish(b);
        }

        for (&[6]struct { llvm.Builder.FloatCondition, []const u8 }{
            .{ .oeq, "eq" },
            .{ .une, "ne" },
            .{ .olt, "lt" },
            .{ .ogt, "gt" },
            .{ .ole, "le" },
            .{ .oge, "ge" },
        }) |info| {
            const cond, const name = info;
            var cmp = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, name);
            cmp.wip.cursor = .{ .block = try cmp.wip.block(0, "Entry") };
            const bin_op = try cmp.binOp(b, float_ty);
            try bin_op.writeResult(
                &cmp,
                try cmp.wip.cast(
                    .zext,
                    try cmp.wip.fcmp(.normal, cond, bin_op.c_1, bin_op.c_2, ""),
                    .i32,
                    "",
                ),
            );
            const new_vsp = try cmp.adjustVspBy(b, -1);
            try cmp.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&cmp.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&cmp.wip),
            });
            try cmp.finish(b);
        }

        for (&[4]WipFunction.Instruction.Tag{
            .fadd,
            .fsub,
            .fmul,
            .fdiv,
        }) |op_tag| {
            var op = try b.opcodeHandlerFromPrefixedName(
                ByteOpcode,
                prefix,
                @tagName(op_tag)[1..],
            );
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, float_ty);
            try bin_op.writeResult(&op, try op.wip.bin(op_tag, bin_op.c_1, bin_op.c_2, ""));
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }

        for (&[2]Intrinsic{ .minimum, .maximum }) |intrin| {
            var op = try b.opcodeHandlerFromPrefixedName(
                ByteOpcode,
                prefix,
                @tagName(intrin)[0..3],
            );
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, float_ty);
            const chosen = try op.wip.callIntrinsic(
                .normal,
                .none,
                intrin,
                &.{float_ty},
                &.{ bin_op.c_1, bin_op.c_2 },
                "",
            );
            const is_nan = try op.wip.fcmp(.normal, .uno, chosen, chosen, "");
            try bin_op.writeResult(
                &op,
                try op.wip.select(.normal, is_nan, float_info.canonical_nan, chosen, ""),
            );
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }
        {
            var sqrt = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, "sqrt");
            sqrt.wip.cursor = .{ .block = try sqrt.wip.block(0, "Entry") };
            const un_op = try sqrt.unOp(b, float_ty);
            try un_op.writeResult(
                &sqrt,
                try sqrt.wip.callIntrinsic(.normal, .none, .sqrt, &.{float_ty}, &.{un_op.c_1}, ""),
            );
            try sqrt.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&sqrt.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&sqrt.wip),
                .stp = OpcodeHandlerParam.stp.arg(&sqrt.wip),
            });
            try sqrt.finish(b);
        }
        for (&[4]Intrinsic{ .ceil, .floor, .trunc, .roundeven }) |intrin| {
            var op = try b.opcodeHandlerFromPrefixedName(
                ByteOpcode,
                prefix,
                if (intrin == .roundeven) "nearest" else @tagName(intrin),
            );
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const un_op = try op.unOp(b, float_ty);
            const rounded = try op.wip.callIntrinsic(
                .normal,
                .none,
                intrin,
                &.{float_ty},
                &.{un_op.c_1},
                "",
            );
            const is_nan = try op.wip.fcmp(.normal, .uno, rounded, rounded, "");
            try un_op.writeResult(
                &op,
                try op.wip.select(.normal, is_nan, float_info.canonical_nan, rounded, ""),
            );
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&op.wip),
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }

        {
            var op = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, "copysign");
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            // Less instructions if done the scalar way instead of calling the .copysign intrinsic
            const bin_op = try op.binOp(b, int_ty);
            try bin_op.writeResult(
                &op,
                try op.wip.bin(
                    .@"or",
                    try op.wip.bin(.@"and", bin_op.c_1, float_info.magnitude_mask, ""),
                    try op.wip.bin(.@"and", bin_op.c_2, float_info.sign_bit, ""),
                    "",
                ),
            );
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
                .stp = OpcodeHandlerParam.stp.arg(&op.wip),
            });
            try op.finish(b);
        }
        {
            var abs = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, "abs");
            abs.wip.cursor = .{ .block = try abs.wip.block(0, "Entry") };
            const un_op = try abs.unOp(b, int_ty);
            // Less instructions if done the scalar way instead of calling the .abs intrinsic
            try un_op.writeResult(
                &abs,
                try abs.wip.bin(.@"and", un_op.c_1, float_info.magnitude_mask, ""),
            );
            try abs.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&abs.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&abs.wip),
                .stp = OpcodeHandlerParam.stp.arg(&abs.wip),
            });
            try abs.finish(b);
        }
        {
            var neg = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, "neg");
            neg.wip.cursor = .{ .block = try neg.wip.block(0, "Entry") };
            const un_op = try neg.unOp(b, float_ty);
            try un_op.writeResult(&neg, try neg.wip.un(.fneg, un_op.c_1, ""));
            try neg.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&neg.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&neg.wip),
                .stp = OpcodeHandlerParam.stp.arg(&neg.wip),
            });
            try neg.finish(b);
        }

        for ([4]struct { WipFunction.Instruction.Tag, Type, []const u8 }{
            .{ .sitofp, .i32, "convert_i32_s" },
            .{ .uitofp, .i32, "convert_i32_u" },
            .{ .sitofp, .i64, "convert_i64_s" },
            .{ .uitofp, .i64, "convert_i64_u" },
        }) |info| {
            const cast, const to_int_ty, const name = info;
            var conv = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, name);
            conv.wip.cursor = .{ .block = try conv.wip.block(0, "Entry") };
            const un_op = try conv.unOp(b, to_int_ty);
            try un_op.writeResult(
                &conv,
                try conv.wip.cast(cast, un_op.c_1, float_ty, ""),
            );
            try conv.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&conv.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&conv.wip),
                .stp = OpcodeHandlerParam.stp.arg(&conv.wip),
            });
            try conv.finish(b);
        }
        for ([4]struct { WipFunction.Instruction.Tag, Type }{
            .{ .fptosi, .i32 },
            .{ .fptoui, .i32 },
            .{ .fptosi, .i64 },
            .{ .fptoui, .i64 },
        }) |info| {
            const cast, const to_int_ty = info;
            _ = b.scratch.reset(.retain_capacity);
            var conv = try b.opcodeHandler(
                Opcode.fromName(
                    ByteOpcode,
                    try std.fmt.allocPrint(b.scratch.allocator(), "{t}.trunc_{s}_{c}", .{
                        to_int_ty,
                        float_info.prefix,
                        @tagName(cast)[4],
                    }),
                ),
            );
            const entry_blk = try conv.wip.block(0, "Entry");
            conv.wip.cursor = .{ .block = entry_blk };
            const un_op = try conv.unOp(b, float_ty);
            const trap = try conv.wip.block(2, "Trap");

            const min_bound, const max_bound = switch (float_ty) {
                .float => switch (to_int_ty) {
                    .i32 => try FloatInfo.floatBounds(
                        &b.module,
                        switch (cast) {
                            .fptosi => 0xCF00_0000, // -2_147_483_648
                            .fptoui => 0xBF7F_FFFF, // -0.99...
                            else => unreachable,
                        },
                        switch (cast) {
                            .fptosi => 0x4EFF_FFFF,
                            .fptoui => 0x4F7F_FFFF,
                            else => unreachable,
                        },
                    ),
                    .i64 => try FloatInfo.floatBounds(
                        &b.module,
                        switch (cast) {
                            .fptosi => 0xDF00_0000, // -9_223_372_036_854_776_000
                            .fptoui => 0xBF7F_FFFF, // -0.9999...
                            else => unreachable,
                        },
                        switch (cast) {
                            .fptosi => 0x5EFF_FFFF, // 9_223_371_487_098_962_000
                            .fptoui => 0x5F7F_FFFF, // 18_446_742_974_197_924_000
                            else => unreachable,
                        },
                    ),
                    else => unreachable,
                },
                .double => switch (to_int_ty) {
                    .i32 => try FloatInfo.doubleBounds(
                        &b.module,
                        switch (cast) {
                            .fptosi => 0xC1E0_0000_001F_FFFF,
                            .fptoui => 0xBFEF_FFFF_FFFF_FFFF, // -0.99...
                            else => unreachable,
                        },
                        switch (cast) {
                            .fptosi => 0x41DF_FFFF_FFFF_FFFF,
                            .fptoui => 0x41EF_FFFF_FFFF_FFFF, // 4_294_967_295.99...
                            else => unreachable,
                        },
                    ),
                    .i64 => try FloatInfo.doubleBounds(
                        &b.module,
                        switch (cast) {
                            .fptosi => 0xC3E0_0000_0000_0000, // -9_223_372_036_854_776_000
                            .fptoui => 0xBFEF_FFFF_FFFF_FFFF, // -0.9999999999999999...
                            else => unreachable,
                        },
                        switch (cast) {
                            .fptosi => 0x43DF_FFFF_FFFF_FFFF, // 9_223_372_036_854_775_000
                            .fptoui => 0x43EF_FFFF_FFFF_FFFF, // 18_446_744_073_709_550_000
                            else => unreachable,
                        },
                    ),
                    else => unreachable,
                },
                else => unreachable,
            };
            const above_min_bound = try conv.wip.block(1, "InBounds");
            _ = try conv.wip.brCond(
                try conv.wip.fcmp(.normal, .oge, un_op.c_1, min_bound, ""),
                above_min_bound,
                trap,
                .then_likely,
            );

            const in_bounds = try conv.wip.block(1, "InBounds");
            conv.wip.cursor = .{ .block = above_min_bound };
            _ = try conv.wip.brCond(
                try conv.wip.fcmp(.normal, .ole, un_op.c_1, max_bound, ""),
                in_bounds,
                trap,
                .then_likely,
            );

            conv.wip.cursor = .{ .block = in_bounds };
            try un_op.writeResult(&conv, try conv.wip.cast(cast, un_op.c_1, to_int_ty, ""));
            try conv.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&conv.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&conv.wip),
                .stp = OpcodeHandlerParam.stp.arg(&conv.wip),
            });

            conv.wip.cursor = .{ .block = trap };
            _ = try conv.wip.callIntrinsicAssumeCold();
            const trap_ip = try conv.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&conv.wip),
                &.{try b.sizeIntValue(-1)},
                "",
            );
            const is_nan = try conv.wip.fcmp(.normal, .uno, un_op.c_1, un_op.c_1, "");
            try conv.jmpTrapWithNumericCode(b, trap_ip, try conv.wip.select(
                .normal,
                is_nan,
                try NumericTrapCode.invalid_conversion_to_integer.toValue(b),
                try NumericTrapCode.integer_overflow.toValue(b),
                "",
            ));
            try conv.finish(b);
        }
    }
    {
        var demote = try b.opcodeHandler(.{ .byte = .@"f32.demote_f64" });
        demote.wip.cursor = .{ .block = try demote.wip.block(0, "Entry") };
        const un_op = try demote.unOp(b, .double);
        try un_op.writeResult(&demote, try demote.wip.cast(.fptrunc, un_op.c_1, .float, ""));
        try demote.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&demote.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&demote.wip),
            .stp = OpcodeHandlerParam.stp.arg(&demote.wip),
        });
        try demote.finish(b);
    }
    {
        var promote = try b.opcodeHandler(.{ .byte = .@"f64.promote_f32" });
        promote.wip.cursor = .{ .block = try promote.wip.block(0, "Entry") };
        const un_op = try promote.unOp(b, .float);
        try un_op.writeResult(&promote, try promote.wip.cast(.fpext, un_op.c_1, .double, ""));
        try promote.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&promote.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&promote.wip),
            .stp = OpcodeHandlerParam.stp.arg(&promote.wip),
        });
        try promote.finish(b);
    }
}

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;
const opcodes = @import("opcodes");
const ByteOpcode = opcodes.ByteOpcode;

const llvm = std.zig.llvm;
const Attribute = llvm.Builder.Attribute;
const CallConv = llvm.Builder.CallConv;
const Constant = llvm.Builder.Constant;
const Global = llvm.Builder.Global;
const Function = llvm.Builder.Function;
const FunctionAttributes = llvm.Builder.FunctionAttributes;
const Intrinsic = llvm.Builder.Intrinsic;
const String = llvm.Builder.String;
const StrtabString = llvm.Builder.StrtabString;
const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const Variable = llvm.Builder.Variable;
const WipFunction = llvm.Builder.WipFunction;
