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
    decode_uleb_idx: Function.Index = .none,
    trap_with_numeric_code: Function.Index = .none,

    opcode_handler_writing_lock: std.debug.SafetyLock = .{},
    value_structs: struct {
        i64: Type = .none,
    } = .{},

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

                    switch (param) {
                        .fuel => try attrs.addParamAttr(idx, .{ .dereferenceable = 8 }, &b.module),
                        // .module // don't know size of ModuleInst in advance
                        else => {},
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

        b.value_structs = .{
            .i64 = try b.module.structType(.normal, &.{ .i64, .i64 }),
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

    fn callDecodeUlebIdx(b: *Builder, wip: *WipFunction, ip: Value) Oom!Value {
        return wip.call(
            .normal,
            b.decode_uleb_idx.ptr(&b.module).call_conv,
            .none,
            b.decode_uleb_idx.typeOf(&b.module),
            b.decode_uleb_idx.toValue(&b.module),
            &.{ip},
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

const value_stack_alignment = llvm.Builder.Alignment.fromByteUnits(16);

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
        index: u8,
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

    fn finish(handler: *OpcodeHandler, b: *Builder) Oom!void {
        try handler.wip.finish();
        handler.wip.deinit();
        b.opcode_handler_writing_lock.unlock();
    }
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
            try b.fnAttributes(&attrs, &.{ .mustprogress, .willreturn, .cold });
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
            try attrs.addFnAttr(.willreturn, &b.module);
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
    {
        const ret_ty = try b.module.structType(.normal, &.{ .i32, .ptr });
        b.decode_uleb_idx = try b.addFunction(
            try b.strtabStringSymbolPrefixed("decodeUlebIndex"),
            try b.fnType(ret_ty, &.{.ptr}),
            if (b.target.cpu.arch == .x86_64) .preserve_mostcc else .fastcc,
            .{ .linkage = .internal, .preemption = .dso_local },
        );
        const param_attrs = [6]Attribute{
            .readonly,
            .nonnull,
            .noundef,
            .{ .dereferenceable = 1 },
            .@"noalias",
            .nofree,
        };
        {
            var attrs = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attrs);
            try b.fnAttributes(&attrs, &.{ .mustprogress, .willreturn, .norecurse });
            for (&param_attrs) |a| {
                try attrs.addParamAttr(0, a, &b.module);
            }
            try b.setFnAttributes(b.decode_uleb_idx, &attrs);
        }

        var wip = try b.wipFunction(b.decode_uleb_idx);
        defer wip.deinit();

        const cont_mask = try b.module.intValue(.i8, 0x80);

        const entry_blk = try wip.block(0, "Entry");
        wip.cursor = .{ .block = entry_blk };
        const vip_0 = wip.arg(0);
        const byte_0 = try wip.load(.normal, .i8, vip_0, .default, "");
        const vip_1 = try wip.gep(
            .inbounds,
            .i8,
            vip_0,
            &.{try b.sizeIntValue(1)},
            "",
        );
        const ret_single_byte = try wip.block(1, "ReturnSingleByte");
        const loop_body = try wip.block(2, "LoopBody");
        const acc_0 = try wip.cast(.zext, byte_0, .i32, "");
        _ = try wip.brCond(
            try wip.icmp(.ult, byte_0, cont_mask, ""),
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
        const next_vip = try wip.gep(
            .inbounds,
            .i8,
            vip_phi.toValue(),
            &.{try b.sizeIntValue(1)},
            "",
        );
        const loop_ret = try wip.block(1, "ReturnMultiByte");
        _ = try wip.brCond(
            try wip.icmp(.ult, next_byte, cont_mask, ""),
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
        try b.fnAttributes(&attrs, &.{ .mustprogress, .willreturn, .norecurse });
        try b.setFnAttributes(b.decode_uleb_idx, &attrs);
    }

    try buildControlOpcodeHandlers(b);
    try buildLocalOpcodeHandlers(b);
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

fn buildControlOpcodeHandlers(b: *Builder) Oom!void {
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
            try attrs.addFnAttr(.willreturn, &b.module);
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
        var end = try b.opcodeHandler(.{ .byte = .end });
        end.wip.cursor = .{ .block = try end.wip.block(0, "Entry") };
        const is_return = try end.wip.icmp(
            .eq,
            try end.wip.gep(
                .inbounds,
                .i8,
                OpcodeHandlerParam.vip.arg(&end.wip),
                &.{try b.sizeIntValue(-1)},
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
}

fn buildLocalOpcodeHandlers(b: *Builder) Oom!void {
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
            attrs: {
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
            .memmove,
            &.{ .ptr, .ptr, b.size_type },
            &.{
                OpcodeHandlerParam.vsp.arg(wip),
                src_addr,
                try b.sizeIntValue(16),
                .false,
            },
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
}

fn buildIntegerOpcodeHandlers(b: *Builder) Oom!void {
    for (&[2]Type{ .i32, .i64 }) |int_ty| {
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
        const zero = try b.module.intValue(int_ty, 0);
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
            const imm = try c.wip.load(.normal, int_ty, vip_0, .fromByteUnits(1), "");
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
}

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;
const opcodes = @import("opcodes");
const ByteOpcode = opcodes.ByteOpcode;

const llvm = std.zig.llvm;
const Attribute = llvm.Builder.Attribute;
const Block = llvm.Builder.Block;
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
