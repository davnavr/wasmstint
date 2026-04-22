pub const Options = struct {
    optimize: std.builtin.OptimizeMode,
    symbol_prefix: []const u8,
    strip: bool,
    target: struct {
        triple: []const u8,
        cpu_features: []const u8,
    },
    wasm_features: struct {
        simd128: bool,
        tail_call: bool,
    },
};

pub const TargetInfo = struct {
    data_layout: []const u8,
    triple: []const u8,
    cpu_features: []const u8,
};

pub const DetectedIntrinsics = packed struct {
    roundeven: bool,
    roundevenf: bool,
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
detected_intrinsics: DetectedIntrinsics,
float_info: [2]FloatInfo = undefined,

scratch: *ArenaAllocator,
module: llvm.Builder,

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
    invoke_attrs: FunctionAttributes,
    panic_invalid_attrs: FunctionAttributes,
},
dispatch_tables: struct {
    byte: Global.Index = .none,
    fc: Global.Index = .none,
    fd: Global.Index = .none,
} = .{},
byte_opcode_lookup: EnumSet(opcodes.ByteOpcode) = .initEmpty(),
fc_prefix_opcode_lookup: EnumSet(opcodes.FCPrefixOpcode) = .initEmpty(),
fd_prefix_opcode_lookup: EnumSet(opcodes.FDPrefixOpcode) = .initEmpty(),

round_even_attrs: FunctionAttributes = .none,
out_of_fuel_handler: Function.Index = .none,
skip_leb_idx: Function.Index = .none,
decode_uleb_idx: Function.Index = .none,
trap_with_numeric_code: Function.Index = .none,
trap_memory_access_oob: Function.Index = .none,
panic_invalid_prefixed_opcode: Function.Index = .none,
fill_table_elements: Function.Index = .none,
move_values_for_branch: Function.Index = .none,

opcode_handler_writing_lock: std.debug.SafetyLock = .{},
func_type: Type = .none,
mem_inst: Type = .none,
table_inst: Type = .none,
side_table_entry: Type = .none,
module_info: Type = .none,
module_inst: Type = .none,
struct_3_ptrs: Type = .none,
value_structs: struct {
    i64: Type = .none,
} = .{},
/// For `memset` of values.
value_set: struct { attributes: FunctionAttributes, overload: [2]Type } = undefined,
/// For `memcpy`/`memmove` of values.
value_copy: struct {
    attributes: FunctionAttributes,
    overload: [3]Type,
    attributes_src_unaligned: FunctionAttributes,
    attributes_dst_unaligned: FunctionAttributes,
} = undefined,

const Builder = @This();

pub const value_stack_alignment = llvm.Builder.Alignment.fromByteUnits(16);

pub fn init(
    b: *Builder,
    gpa: std.mem.Allocator,
    scratch: *ArenaAllocator,
    config: struct {
        options: Options,
        target: *const std.Target,
        target_info: TargetInfo,
        detected_intrinsics: DetectedIntrinsics,
    },
) Oom!void {
    const ptr_bit_size = config.target.ptrBitWidth();
    b.* = Builder{
        .options = config.options,
        .target = config.target,
        .cache_line_size = std.atomic.cacheLineForCpu(config.target.cpu),
        .ptr_size_bytes = @divExact(ptr_bit_size, 8),
        .target_info = config.target_info,
        .detected_intrinsics = config.detected_intrinsics,
        .scratch = scratch,
        .module = try llvm.Builder.init(.{
            .allocator = gpa,
            .strip = config.options.strip,
            .name = "wasmstint.interpreter",
            .target = config.target,
            .triple = config.target_info.triple,
        }),
        .opcode_handler = undefined,
    };

    b.float_info = try FloatInfo.init(&b.module);

    inline for (comptime std.meta.fieldNames(@FieldType(Builder, "string_constants"))) |name| {
        @field(b.string_constants, name) = try b.module.string(name);
    }

    if (b.target.cpu.model.llvm_name) |name| {
        b.target_cpu = try b.module.string(name);
    }
    b.module.data_layout = try b.module.string(config.target_info.data_layout);
    if (config.target_info.cpu_features.len > 0) {
        b.target_features = try b.module.string(config.target_info.cpu_features);
    }

    b.size_type = try b.module.intType(ptr_bit_size);
    const opcode_handler_param_attrs = attrs: {
        var attrs = FunctionAttributes.Wip{};
        defer attrs.deinit(&b.module);
        for (std.enums.values(OpcodeHandlerParam)) |param| {
            const idx = @intFromEnum(param);
            for (&[3]Attribute{ .nonnull, .nofree, .noundef }) |attr| {
                try attrs.addParamAttr(idx, attr, &b.module);
            }

            const alignment: ?u16 = switch (param) {
                .locals, .vsp => 16,
                .module => b.cache_line_size,
                // TODO: read datalayout to determine alignment of u64 Fuel/STP
                .memories, .ctx, .disp => b.ptr_size_bytes,
                .stp => 8,
                else => null,
            };

            if (alignment) |a| {
                try attrs.addParamAttr(idx, .{ .@"align" = .wrap(.fromByteUnits(a)) }, &b.module);
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
                .module => @as(u32, b.ptr_size_bytes) * 32,
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
    };

    b.round_even_attrs = attrs: {
        var attrs = FunctionAttributes.Wip{};
        defer attrs.deinit(&b.module);
        for (&[_]Attribute{
            .nocallback,
            .nofree,
            .nosync,
            .nounwind,
            .speculatable,
            .willreturn,
            .{ .memory = .{} },
        }) |a| {
            try attrs.addFnAttr(a, &b.module);
        }
        break :attrs try attrs.finish(&b.module);
    };

    b.opcode_handler = .{
        .call_conv = switch (config.target.cpu.arch) {
            // When invoking `afl-clang-lto`, `lld` fails with `error: Interference usage of base
            // pointer/frame pointer.` when `ghccc` is used.
            //
            // This seems to be caused by the GHC calling convention using the `rbp` register,
            // conflicting with register spilling code. The `alignstack` function attribute also
            // doesn't fix the problem. To avoid this problem, `preserve_none` is used instead.
            //
            // For more information, see https://gitlab.haskell.org/ghc/ghc/-/issues/26595
            .x86_64, .aarch64 => @enumFromInt(21), // not available in Zig
            // .riscv64 => .ghccc,
            else => .tailcc,
        },
        .type = try b.fnType(.i32, &@as([10]Type, @splat(Type.ptr))),
        .fn_attrs = attrs: {
            var attrs = try opcode_handler_param_attrs.toWip(&b.module);
            defer attrs.deinit(&b.module);
            try b.commonFnAttributes(&attrs);
            try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse });
            break :attrs try attrs.finish(&b.module);
        },
        .invoke_attrs = attrs: {
            var attrs = try opcode_handler_param_attrs.toWip(&b.module);
            try b.fnAttributes(&attrs, &.{ .mustprogress, .nounwind, .norecurse });
            break :attrs try attrs.finish(&b.module);
        },
        .panic_invalid_attrs = attrs: {
            var attrs = try opcode_handler_param_attrs.toWip(&b.module);
            defer attrs.deinit(&b.module);
            try b.commonFnAttributes(&attrs);
            try b.fnAttributes(&attrs, &.{ .noreturn, .norecurse, .cold });
            break :attrs try attrs.finish(&b.module);
        },
    };

    b.func_type = try b.module.structType(.normal, &.{ .ptr, .i16, .i16 });
    b.mem_inst = try b.module.structType(.normal, &.{
        .ptr,
        b.size_type,
        b.size_type,
        b.size_type,
        .ptr,
    });
    b.table_inst = try b.module.structType(.normal, &.{
        .ptr,
        .i8,
        .i32,
        .i32,
        .i32,
        .ptr,
    });
    b.side_table_entry = try b.module.structType(.@"packed", &.{ .i32, .i16, .i8, .i8 });
    b.module_info = try b.module.structType(.normal, &.{
        .ptr, // types
        .i32, // types_count
        .i32, // custom_sections_count
        .ptr, // custom_sections
        .ptr, // func_types
        .i32, // func_import_count
        .i32, // code_count
        .ptr, // code_section
        .ptr, // code_entries
        .ptr, // code
        .ptr, // global_section
        .ptr, // global_exprs
        .ptr, // global_types
        .ptr, // table_types
        .ptr, // mem_types
        .i32, // start
        .i8, // table_count
        .i8, // table_import_count
        .i8, // mem_count
        .i8, // mem_import_count
        .i32, // global_count
        .i32, // global_import_count
        .ptr, // import_section
        .ptr, // func_imports
        .ptr, // table_imports
        .ptr, // mem_imports
        .ptr, // global_imports
        .ptr, // export_section
        .i16, // init_max_stack
        .i8, // has_data_count_section
        .ptr, // elem_section
        .ptr, // elems
        .ptr, // active_elems
        .ptr, // non_declarative_elems_mask
        .i16, // elems_count
        .i16, // active_elems_count
        .i16, // active_datas_count
        .i16, // datas_count
        .ptr, // data_section
        .ptr, // datas_ptrs
        .ptr, // datas_lens
        .ptr, // active_datas
    });
    b.module_inst = try b.module.structType(.normal, &.{
        b.size_type, // buffer_len
        .ptr, // module
        .ptr, // func_imports
        .ptr, // func_blocks
        .ptr, // mems
        .ptr, // tables
        .ptr, // globals
        .ptr, // datas_drop_mask
        .ptr, // elems_drop_mask
    });
    b.struct_3_ptrs = try b.module.structType(.normal, &@as([3]Type, @splat(Type.ptr)));
    b.value_structs = .{
        .i64 = try b.module.structType(.normal, &.{ .i64, .i64 }),
    };
    b.value_set = .{
        .attributes = attrs: {
            var attrs = FunctionAttributes.Wip{};
            defer attrs.deinit(&b.module);
            try attrs.addParamAttr(0, .{ .@"align" = .wrap(value_stack_alignment) }, &b.module);
            break :attrs try attrs.finish(&b.module);
        },
        .overload = [2]Type{ .ptr, b.size_type },
    };
    const value_copy_attrs_template = attrs: {
        var attrs = FunctionAttributes.Wip{};
        defer attrs.deinit(&b.module);
        for (0..2) |i| {
            for (&[3]Attribute{ .noundef, .nonnull, .{ .dereferenceable = 16 } }) |a| {
                try attrs.addParamAttr(i, a, &b.module);
            }
        }
        break :attrs try attrs.finish(&b.module);
    };
    const byte_alignment = llvm.Builder.Alignment.fromByteUnits(1);
    b.value_copy = .{
        .attributes = attrs: {
            var attrs = try value_copy_attrs_template.toWip(&b.module);
            defer attrs.deinit(&b.module);
            for (0..2) |i| {
                try attrs.addParamAttr(i, .{ .@"align" = .wrap(value_stack_alignment) }, &b.module);
            }
            break :attrs try attrs.finish(&b.module);
        },
        .attributes_src_unaligned = attrs: {
            var attrs = try value_copy_attrs_template.toWip(&b.module);
            defer attrs.deinit(&b.module);
            try attrs.addParamAttr(0, .{ .@"align" = .wrap(value_stack_alignment) }, &b.module);
            try attrs.addParamAttr(1, .{ .@"align" = .wrap(byte_alignment) }, &b.module);
            break :attrs try attrs.finish(&b.module);
        },
        .attributes_dst_unaligned = attrs: {
            var attrs = try value_copy_attrs_template.toWip(&b.module);
            defer attrs.deinit(&b.module);
            try attrs.addParamAttr(0, .{ .@"align" = .wrap(byte_alignment) }, &b.module);
            try attrs.addParamAttr(1, .{ .@"align" = .wrap(value_stack_alignment) }, &b.module);
            break :attrs try attrs.finish(&b.module);
        },
        .overload = [3]Type{ .ptr, .ptr, b.size_type },
    };
}

pub fn strtabStringConcat(b: *Builder, s: []const []const u8) Oom!StrtabString {
    _ = b.scratch.reset(.retain_capacity);
    return try b.module.strtabString(try std.mem.concat(b.scratch.allocator(), u8, s));
}

pub fn strtabStringSymbolPrefixed(b: *Builder, name: []const u8) Oom!StrtabString {
    return try b.strtabStringConcat(&.{ b.options.symbol_prefix, name });
}

/// `wasmstint` does not use `varargs`.
pub fn fnType(b: *Builder, ret_type: Type, param_types: []const Type) Oom!Type {
    return try b.module.fnType(ret_type, param_types, .normal);
}

pub fn hasX86Feature(b: *Builder, feature: std.Target.x86.Feature) bool {
    return b.target.cpu.arch.isX86() and
        std.Target.x86.featureSetHas(b.target.cpu.features, feature);
}

pub fn hasAarch64Feature(b: *Builder, feature: std.Target.aarch64.Feature) bool {
    return b.target.cpu.arch.isAARCH64() and
        std.Target.aarch64.featureSetHas(b.target.cpu.features, feature);
}

const FunctionOptions = struct {
    linkage: llvm.Builder.Linkage = .external,
    preemption: llvm.Builder.Preemption = .dso_preemptable,
};

pub fn fnAttributes(
    b: *Builder,
    wip: *FunctionAttributes.Wip,
    attributes: []const Attribute,
) Oom!void {
    for (attributes) |attr| {
        try wip.addFnAttr(attr, &b.module);
    }
}

pub fn setFnAttributes(b: *Builder, func: Function.Index, wip: *FunctionAttributes.Wip) Oom!void {
    func.setAttributes(try wip.finish(&b.module), &b.module);
}

pub fn commonFnAttributes(b: *Builder, wip: *FunctionAttributes.Wip) Oom!void {
    try wip.addFnAttr(.nounwind, &b.module);

    // This is what the Zig compiler does
    if (b.options.optimize == .ReleaseSmall) {
        try b.fnAttributes(wip, &.{ .minsize, .optsize });
    }

    if (b.target_cpu != .none) {
        try b.fnAttributes(wip, &.{
            .{
                .string = .{ .kind = b.string_constants.@"target-cpu", .value = b.target_cpu },
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

pub fn addFunction(
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

pub fn wipFunction(b: *Builder, func: Function.Index) Oom!WipFunction {
    return try .init(&b.module, .{ .function = func, .strip = b.options.strip });
}

pub fn addDispatchTable(b: *Builder, name: []const u8, len: u16, options: struct {
    linkage: llvm.Builder.Linkage = .internal,
}) Oom!Global.Index {
    const name_str = try b.strtabStringSymbolPrefixed(name);
    const ty = try b.module.arrayType(len, .ptr);
    const variable = try b.module.addVariable(name_str, ty, .default);
    variable.setAlignment(.fromByteUnits(b.cache_line_size), &b.module);
    variable.setMutability(.constant, &b.module);
    const global = variable.ptrConst(&b.module).global;
    const global_ptr = global.ptr(&b.module);
    global_ptr.unnamed_addr = .local_unnamed_addr;
    global_ptr.preemption = .dso_local;
    global_ptr.linkage = options.linkage;
    return global;
}

pub fn setDispatchTableInitializer(b: *Builder, comptime E: type) Oom!void {
    const invalid_handler: Function.Index = if (b.options.optimize == .ReleaseSmall)
        .none
    else handler: switch (E) {
        opcodes.ByteOpcode => {
            const panic = try b.addFunction(
                try b.strtabStringSymbolPrefixed("panicInvalidByteOpcode"),
                try b.fnType(.void, &@as([2]Type, @splat(.ptr))),
                .ccc,
                .{ .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .noreturn, .norecurse, .nounwind });
                try b.setFnAttributes(panic, &attrs);
            }

            const func = try b.addFunction(
                try b.strtabStringSymbolPrefixed("invalidByteOpcode"),
                b.opcode_handler.type,
                b.opcode_handler.call_conv,
                .{ .linkage = .internal, .preemption = .dso_local },
            );
            func.setAttributes(b.opcode_handler.panic_invalid_attrs, &b.module);

            var wip = try WipFunction.init(&b.module, .{
                .function = func,
                .strip = b.options.strip,
            });

            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            _ = try wip.call(
                .tail,
                .ccc,
                .none,
                panic.typeOf(&b.module),
                panic.toValue(&b.module),
                &[2]Value{ OpcodeHandlerParam.vip.arg(&wip), OpcodeHandlerParam.eip.arg(&wip) },
                "",
            );
            _ = try wip.@"unreachable"();
            try wip.finish();

            break :handler func;
        },
        opcodes.FCPrefixOpcode, opcodes.FDPrefixOpcode => {
            const enum_type_name = @typeName(E);
            const func = try b.addFunction(
                try b.strtabStringSymbolPrefixed(
                    "invalid" ++ enum_type_name[(enum_type_name.len - 14)..],
                ),
                b.opcode_handler.type,
                b.opcode_handler.call_conv,
                .{ .linkage = .internal, .preemption = .dso_local },
            );
            func.setAttributes(b.opcode_handler.panic_invalid_attrs, &b.module);

            var wip = try WipFunction.init(&b.module, .{
                .function = func,
                .strip = b.options.strip,
            });

            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            _ = try wip.call(
                .tail,
                .ccc,
                .none,
                b.panic_invalid_prefixed_opcode.typeOf(&b.module),
                b.panic_invalid_prefixed_opcode.toValue(&b.module),
                &[3]Value{
                    OpcodeHandlerParam.vip.arg(&wip),
                    OpcodeHandlerParam.eip.arg(&wip),
                    try b.sizeIntValue(switch (E) {
                        opcodes.FCPrefixOpcode => 0xFC,
                        opcodes.FDPrefixOpcode => 0xFD,
                        else => comptime unreachable,
                    }),
                },
                "",
            );
            _ = try wip.@"unreachable"();
            try wip.finish();

            break :handler func;
        },
        else => @compileError(@typeName(E)),
    };

    const invalid: Constant = if (invalid_handler == .none)
        try b.module.undefConst(.ptr)
    else
        invalid_handler.ptrConst(&b.module).global.toConst();

    const table_global_idx: Global.Index = switch (E) {
        opcodes.ByteOpcode => b.dispatch_tables.byte,
        opcodes.FCPrefixOpcode => b.dispatch_tables.fc,
        opcodes.FDPrefixOpcode => b.dispatch_tables.fd,
        else => @compileError("no dispatch table for " ++ @typeName(E)),
    };

    const table_global = table_global_idx.ptrConst(&b.module);
    const table_var = table_global.kind.variable;
    const len = table_global.type.aggregateLen(&b.module);
    const set: *const EnumSet(E) = switch (E) {
        opcodes.ByteOpcode => &b.byte_opcode_lookup,
        opcodes.FCPrefixOpcode => &b.fc_prefix_opcode_lookup,
        opcodes.FDPrefixOpcode => &b.fd_prefix_opcode_lookup,
        else => @compileError("no lookup for " ++ @typeName(E)),
    };

    _ = b.scratch.reset(.retain_capacity);
    const values = try b.scratch.allocator().alloc(Constant, len);
    var name_arena = ArenaAllocator.init(b.scratch.allocator());
    var opcode_count: usize = 0;
    for (values, 0..len) |*v, i| {
        v.* = val: {
            invalid: {
                const opcode = std.enums.fromInt(E, i) orelse break :invalid;
                if (!set.contains(opcode)) break :invalid;

                defer opcode_count += 1;

                _ = name_arena.reset(.retain_capacity);
                const handler_name_bytes = try std.mem.concat(name_arena.allocator(), u8, &.{
                    b.options.symbol_prefix,
                    Opcode.init(E, opcode).name(),
                });
                const handler_name = try b.module.strtabString(handler_name_bytes);

                if (b.module.getGlobal(handler_name)) |handler_global| {
                    break :val handler_global.toConst();
                } else {
                    std.debug.panic(
                        "unable to find handler global for {s}",
                        .{handler_name_bytes},
                    );
                }
            }

            break :val invalid;
        };
    }

    std.debug.assert(opcode_count == set.count()); // check that length is correct

    try table_var.setInitializer(
        try b.module.arrayConst(table_global.type, values),
        &b.module,
    );
}

pub fn opcodeHandler(b: *Builder, opcode: Opcode) Oom!OpcodeHandler {
    switch (opcode) {
        inline else => |value, kind| {
            const set: *EnumSet(@TypeOf(value)) = switch (kind) {
                .byte => &b.byte_opcode_lookup,
                .fc => &b.fc_prefix_opcode_lookup,
                .fd => &b.fd_prefix_opcode_lookup,
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
    return OpcodeHandler{
        .opcode = opcode,
        .wip = try WipFunction.init(
            &b.module,
            .{ .function = func, .strip = b.options.strip },
        ),
    };
}

pub fn opcodeHandlerFromPrefixedName(
    b: *Builder,
    comptime E: type,
    prefix: []const u8,
    name: []const u8,
) Oom!OpcodeHandler {
    return try b.opcodeHandler(try .fromPrefixedName(E, b.scratch, prefix, name));
}

/// Yields an `{ i32, ptr }` containing the decoded index and updated VIP value.
pub fn callDecodeUlebIdx(b: *Builder, wip: *WipFunction, vip: Value) Oom!Value {
    return wip.call(
        .normal,
        b.decode_uleb_idx.ptrConst(&b.module).call_conv,
        .none,
        b.decode_uleb_idx.typeOf(&b.module),
        b.decode_uleb_idx.toValue(&b.module),
        &.{vip},
        "",
    );
}

/// Yields the updated `VIP` value (a `ptr`).
pub fn callSkipUlebIdx(b: *Builder, wip: *WipFunction, vip: Value) Oom!Value {
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

pub fn sizeIntValue(b: *Builder, value: i64) Oom!Value {
    return try b.module.intValue(b.size_type, value);
}

const std = @import("std");
const EnumSet = @import("enum_set").EnumSet;
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;
const opcodes = @import("opcodes");
const llvm = std.zig.llvm;

const FloatInfo = @import("FloatInfo.zig");
const Opcode = @import("opcode.zig").Opcode;
const OpcodeHandler = @import("OpcodeHandler.zig");
const OpcodeHandlerParam = @import("opcode_handler_param.zig").OpcodeHandlerParam;

const Attribute = llvm.Builder.Attribute;
const CallConv = llvm.Builder.CallConv;
const Constant = llvm.Builder.Constant;
const Function = llvm.Builder.Function;
const FunctionAttributes = llvm.Builder.FunctionAttributes;
const Global = llvm.Builder.Global;
const String = llvm.Builder.String;
const StrtabString = llvm.Builder.StrtabString;
const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const WipFunction = llvm.Builder.WipFunction;
