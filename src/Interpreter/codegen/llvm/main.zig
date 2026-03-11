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

const byte_alignment = llvm.Builder.Alignment.fromByteUnits(1);
const value_stack_alignment = Builder.value_stack_alignment;

const TableInstField = enum {
    base,
    elem_type,
    len,
    capacity,
    limit,

    fn gep(field: TableInstField, wip: *WipFunction, b: *Builder, table: Value) Oom!Value {
        std.debug.assert(table.typeOfWip(wip) == .ptr);
        const field_ptr = try wip.gep(
            .inbounds,
            b.table_inst,
            table,
            &.{ .@"0", try b.module.intValue(.i32, @intFromEnum(field)) },
            "",
        );
        return field_ptr;
    }

    fn typeOf(field: TableInstField) Type {
        return switch (field) {
            .base => .ptr,
            .elem_type => .i8,
            .len, .capacity, .limit => .i32,
        };
    }

    fn load(field: TableInstField, wip: *WipFunction, b: *Builder, table: Value) Oom!Value {
        return try wip.load(.normal, field.typeOf(), try field.gep(wip, b, table), .default, "");
    }
};

const ModuleInfoField = enum(u6) {
    types,
    types_count,
    custom_sections_count,
    custom_sections,
    func_types,
    func_import_count,
    code_count,
    code_section,
    code_entries,
    code,
    global_section,
    global_exprs,
    global_types,
    table_types,
    mem_types,
    start,
    table_count,
    table_import_count,
    mem_count,
    mem_import_count,
    global_count,
    global_import_count,
    import_section,
    func_imports,
    table_imports,
    mem_imports,
    global_imports,
    export_section,
    exports,
    export_count,
    init_max_stack,
    has_data_count_section,
    elem_section,
    elems,
    active_elems,
    non_declarative_elems_mask,
    elems_count,
    active_elems_count,
    active_datas_count,
    datas_count,
    data_section,
    datas_ptrs,
    datas_lens,
    active_datas,

    /// Obtains a `ptr` to a field within the `ModuleInst`.
    fn gep(field: ModuleInfoField, wip: *WipFunction, b: *const Builder) Oom!Value {
        return try wip.gepStruct(
            b.module_info,
            try ModuleInstField.module.load(wip, b),
            @intFromEnum(field),
            @tagName(field),
        );
    }

    fn typeOf(field: ModuleInfoField) Type {
        return switch (field) {
            .types_count,
            .custom_sections_count,
            .func_import_count,
            .code_count,
            .start,
            .global_count,
            .global_import_count,
            .export_count,
            => .i32,
            .table_count,
            .table_import_count,
            .mem_count,
            .mem_import_count,
            .has_data_count_section,
            => .i8,
            .init_max_stack,
            .elems_count,
            .active_elems_count,
            .active_datas_count,
            .datas_count,
            => .i16,
            .types,
            .custom_sections,
            .func_types,
            .code_section,
            .code_entries,
            .code,
            .global_section,
            .global_exprs,
            .global_types,
            .table_types,
            .mem_types,
            .import_section,
            .func_imports,
            .table_imports,
            .mem_imports,
            .global_imports,
            .export_section,
            .exports,
            .elem_section,
            .elems,
            .active_elems,
            .non_declarative_elems_mask,
            .data_section,
            .datas_ptrs,
            .datas_lens,
            .active_datas,
            => .ptr,
        };
    }

    fn load(field: ModuleInfoField, wip: *WipFunction, b: *const Builder) Oom!Value {
        return try wip.load(
            .normal,
            field.typeOf(),
            try field.gep(wip, b),
            .default,
            @tagName(field),
        );
    }
};

fn enumFieldCount(comptime E: type) comptime_int {
    return @typeInfo(E).@"enum".fields.len;
}

fn buildLlvmModule(b: *Builder) Oom!void {
    b.module.data_layout = try b.module.string(b.target_info.data_layout);
    try b.module.functions.ensureUnusedCapacity(
        b.module.gpa,
        enumFieldCount(ByteOpcode) +
            enumFieldCount(opcodes.FCPrefixOpcode) +
            enumFieldCount(opcodes.FDPrefixOpcode),
    );
    try b.module.globals.ensureTotalCapacity(b.module.gpa, 6);
    try b.module.type_extra.ensureTotalCapacity(b.module.gpa, 1024);

    b.dispatch_tables.byte = try b.addDispatchTable("byte_dispatch_table", 256, .{
        .linkage = .external,
    });
    b.dispatch_tables.fc = try b.addDispatchTable(
        "fc_prefix_dispatch_table",
        switch (b.options.optimize) {
            .Debug, .ReleaseSafe => 64,
            .ReleaseSmall, .ReleaseFast => 18,
        },
        .{},
    );
    b.dispatch_tables.fd = try b.addDispatchTable("fd_prefix_dispatch_table", 256, .{});

    {
        const trampoline = try b.addFunction(
            try b.strtabStringSymbolPrefixed("opcodeHandlerTrampoline"),
            try b.fnType(.i32, &[9]Type{
                .ptr, // locals
                .ptr, // vsp
                .ptr, // module
                .ptr, // fuel
                .ptr, // ctx
                .ptr, // vip
                .ptr, // stp
                .ptr, // eip
                .ptr, // handler
            }),
            .ccc,
            .{ .preemption = .dso_local },
        );
        {
            var attributes = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attributes);
            try attributes.addFnAttr(.norecurse, &b.module);
            for (0..2) |i| {
                try attributes.addParamAttr(i, .{ .@"align" = value_stack_alignment }, &b.module);
            }
            for (0..9) |i| {
                for (&[3]Attribute{ .nonnull, .nofree, .noundef }) |attr| {
                    try attributes.addParamAttr(i, attr, &b.module);
                }
            }
            try b.setFnAttributes(trampoline, &attributes);
        }
        var wip = try b.wipFunction(trampoline);
        defer wip.deinit();

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const memories = try wip.load(
            .normal,
            .ptr,
            try wip.gepStruct(b.module_inst, wip.arg(2), @intFromEnum(ModuleInstField.mems), ""),
            .default,
            "memories",
        );
        const call_params = [10]Value{
            wip.arg(0), // locals
            wip.arg(1), // vsp
            wip.arg(2), // module
            wip.arg(3), // fuel
            memories,
            wip.arg(4), // ctx
            wip.arg(5), // vip
            wip.arg(6), // stp
            wip.arg(7), // eip
            b.dispatch_tables.byte.ptrConst(&b.module).kind.variable.toValue(&b.module),
        };
        const result = try wip.call(
            .tail,
            b.opcode_handler.call_conv,
            b.opcode_handler.invoke_attrs,
            b.opcode_handler.type,
            wip.arg(8),
            &call_params,
            "",
        );
        _ = try wip.ret(result);
        try wip.finish();
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
            .ccc,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = FunctionAttributes.Wip{};
            try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
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
            .ccc,
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
        const value_bits_mask = try b.module.intValue(.i8, 0x7F);
        const acc_0 = try wip.cast(
            .zext,
            try wip.bin(.@"and", byte_0, value_bits_mask, ""),
            .i32,
            "acc.0",
        );
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

        const next_byte = try wip.load(.normal, .i8, vip_phi.toValue(), .default, "next_byte");
        const next_value_bits = try wip.bin(.@"and", next_byte, value_bits_mask, "");
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
            .ccc,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        var attrs = FunctionAttributes.Wip{};
        try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .cold, .nounwind });
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
            .ccc,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        var attrs = FunctionAttributes.Wip{};
        try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .cold, .nounwind });
        try b.setFnAttributes(b.trap_memory_access_oob, &attrs);
    }
    {
        b.panic_invalid_prefixed_opcode = try b.addFunction(
            try b.strtabStringSymbolPrefixed("panicInvalidPrefixedOpcode"),
            try b.fnType(.void, &[3]Type{ .ptr, .ptr, b.size_type }),
            .ccc,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        var attrs = FunctionAttributes.Wip{};
        try b.fnAttributes(&attrs, &.{ .norecurse, .cold, .nounwind, .noreturn });
        try b.setFnAttributes(b.panic_invalid_prefixed_opcode, &attrs);
    }
    {
        // Equivalent to `llvm.experimental.memset.pattern`
        b.fill_table_elements = try b.addFunction(
            try b.strtabStringSymbolPrefixed("fillTableElements"),
            try b.fnType(.void, &.{ .ptr, b.size_type, .i32 }),
            if (b.target.cpu.arch == .x86_64) .preserve_mostcc else .fastcc,
            .{ .linkage = .internal, .preemption = .dso_local },
        );
        const size_alignment = llvm.Builder.Alignment.fromByteUnits(b.ptr_size_bytes);
        {
            var attrs = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attrs);
            try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .willreturn, .nocallback });

            for (&[_]Attribute{
                .@"noalias",
                .noundef,
                .nonnull,
                .nofree,
                .writeonly,
                .{ .@"align" = size_alignment },
            }) |a| {
                try attrs.addParamAttr(0, a, &b.module);
            }
            try b.setFnAttributes(b.fill_table_elements, &attrs);
        }

        var wip = try b.wipFunction(b.fill_table_elements);
        defer wip.deinit();

        const entry_block = try wip.block(0, "Entry");
        const check_done = try wip.block(2, "CheckDone");
        wip.cursor = .{ .block = entry_block };
        const base = wip.arg(0);
        const elem = wip.arg(1);
        const len = try wip.cast(.zext, wip.arg(2), b.size_type, "len");
        _ = try wip.br(check_done);

        wip.cursor = .{ .block = check_done };
        var current_index = try wip.phi(b.size_type, "current_index"); // 0 when coming from entry block
        const fill_elem = try wip.block(1, "FillElem");
        const done = try wip.block(1, "Return");
        _ = try wip.brCond(
            try wip.icmp(.ult, current_index.toValue(), len, "is_done"),
            fill_elem,
            done,
            .none,
        );

        {
            wip.cursor = .{ .block = fill_elem };
            const index = current_index.toValue();
            const dst_ptr = try wip.gep(.inbounds, b.size_type, base, &.{index}, "dst_ptr");
            _ = try wip.store(.normal, elem, dst_ptr, size_alignment);

            const new_index = try wip.bin(.@"add nuw", index, try b.sizeIntValue(1), "new_index");
            current_index.finish(
                &.{ try b.sizeIntValue(0), new_index },
                &.{ entry_block, fill_elem },
                &wip,
            );
            _ = try wip.br(check_done);
        }

        wip.cursor = .{ .block = done };
        _ = try wip.retVoid();

        try wip.finish();
    }

    try buildNopOpcodeHandlers(b);
    try buildControlOpcodeHandlers(b);
    try buildParametricOpcodeHandlers(b);
    try buildLocalOpcodeHandlers(b);
    try buildGlobalOpcodeHandlers(b);
    try buildMemoryLoadOpcodeHandlers(b);
    try buildMemoryStoreOpcodeHandlers(b);
    try buildMemoryManagementOpcodeHandlers(b);
    try buildTableAccessOpcodeHandlers(b);
    try buildTableManagementOpcodeHandlers(b);
    try buildBulkMemoryOpcodeHandlers(b);
    try buildBulkTableOpcodeHandlers(b);
    try buildBulkDropOpcodeHandlers(b);
    try buildIntegerOpcodeHandlers(b);
    try buildFloatOpcodeHandlers(b);
    try buildReferenceOpcodeHandlers(b);
    try buildPrefixOpcodeHandlers(b);
    try @import("simd.zig").buildOpcodeHandlers(b);

    inline for ([3]type{
        ByteOpcode,
        opcodes.FCPrefixOpcode,
        opcodes.FDPrefixOpcode,
    }) |OpcodeType| {
        try b.setDispatchTableInitializer(OpcodeType);
    }
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
        .@"i32.wrap_i64",
    }) |opcode| {
        // LLVM could maybe deduplicate these
        var nop = try b.opcodeHandler(.{ .byte = opcode });
        nop.wip.cursor = .{ .block = try nop.wip.block(0, "Entry") };
        try nop.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&nop.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&nop.wip),
        });
        try nop.finish(b);
    }
}

fn buildControlOpcodeHandlers(b: *Builder) Oom!void {
    {
        var trap = try b.opcodeHandler(.{ .byte = .@"unreachable" });
        trap.wip.cursor = .{ .block = try trap.wip.block(0, "Entry") };
        const trap_ip = try trap.wip.gep(
            .inbounds,
            .i8,
            OpcodeHandlerParam.vip.arg(&trap.wip),
            &.{try b.sizeIntValue(-1)},
            "",
        );

        try trap.jmpTrapWithNumericCode(b, trap_ip, try b.sizeIntValue(0));
        try trap.finish(b);
    }

    const size_neg_1 = try b.sizeIntValue(-1);
    const i32_0 = try b.module.intValue(.i32, 0);
    for (&[2]ByteOpcode{ .block, .loop }) |opcode| {
        var block = try b.opcodeHandler(.{ .byte = opcode });
        block.wip.cursor = .{ .block = try block.wip.block(0, "Entry") };
        const new_vip = try b.callSkipUlebIdx(&block.wip, OpcodeHandlerParam.vip.arg(&block.wip));
        try block.jmpToNextHandler(b, .{
            .vip = new_vip,
            .vsp = OpcodeHandlerParam.vsp.arg(&block.wip),
        });
        try block.finish(b);
    }

    const return_handler: Function.Index = ret: {
        var ret = try b.opcodeHandler(.{ .byte = .@"return" });
        const index = ret.wip.function;

        const helper = try b.addFunction(
            try b.strtabStringSymbolPrefixed("returnFromWasm"),
            try b.fnType(.ptr, &@as([4]Type, @splat(.ptr))),
            .ccc,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = FunctionAttributes.Wip{};
            try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
            try b.setFnAttributes(helper, &attrs);
        }

        ret.wip.cursor = .{ .block = try ret.wip.block(0, "Entry") };
        const out_alloca = try ret.wip.alloca(
            .normal,
            b.struct_3_ptrs,
            try b.sizeIntValue(1),
            .default,
            .default,
            "",
        );

        const wasm_frame = call: {
            const args = [4]Value{
                out_alloca,
                OpcodeHandlerParam.vsp.arg(&ret.wip),
                OpcodeHandlerParam.ctx.arg(&ret.wip),
                if (b.options.optimize == .Debug)
                    OpcodeHandlerParam.eip.arg(&ret.wip)
                else
                    try b.module.undefValue(.ptr),
            };
            var attrs = FunctionAttributes.Wip{};
            try attrs.addRetAttr(.{ .dereferenceable_or_null = 3 * b.ptr_size_bytes }, &b.module);
            try attrs.addParamAttr(0, .writeonly, &b.module);
            for (0..2) |i| {
                for ([3]Attribute{ .nonnull, .noundef, .nofree }) |attr| {
                    try attrs.addParamAttr(i, attr, &b.module);
                }
            }
            break :call try ret.wip.call(
                .normal,
                .ccc,
                try attrs.finish(&b.module),
                helper.typeOf(&b.module),
                helper.toValue(&b.module),
                &args,
                "",
            );
        };

        try ret.jmpToHostOrNextHandler(b, out_alloca, wasm_frame);
        try ret.finish(b);
        break :ret index;
    };
    {
        var br = try b.opcodeHandler(.{ .byte = .@"if" });
        br.wip.cursor = .{ .block = try br.wip.block(0, "Entry") };
        const initial_vip = OpcodeHandlerParam.vip.arg(&br.wip);
        const condition_ptr = try br.gepOperandAt(b, 0);
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
        const condition_ptr = try br_if.gepOperandAt(b, 0);
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
        const label_count = try wip.extractValue(decoded_label_count, &.{0}, "label_count");
        // No need to actually read label indices

        const n_ptr = try br_table.gepOperandAt(b, 0);
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
                // Likely to hit OOM before this is interpreted as negative, but validation could
                // could check to ensure a limit is not exceeded
                try wip.cast(.zext, n, b.size_type, ""),
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

    const invoke_helper_attrs = attrs: {
        var attrs = FunctionAttributes.Wip{};
        try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
        break :attrs try attrs.finish(&b.module);
    };

    for (&[2]ByteOpcode{ .call, .return_call }) |opcode| {
        const helper_name: []const u8, const helper_params: []const Type = switch (opcode) {
            .call => .{ "invokeWithinWasm", &@as([9]Type, @as([8]Type, @splat(.ptr)) ++ .{.i32}) },
            .return_call => .{
                "tailCallWithinWasm",
                &@as([8]Type, @as([7]Type, @splat(.ptr)) ++ .{.i32}),
            },
            else => unreachable,
        };
        const helper = try b.addFunction(
            try b.strtabStringSymbolPrefixed(helper_name),
            try b.fnType(.ptr, helper_params),
            .ccc,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        helper.setAttributes(invoke_helper_attrs, &b.module);

        var call = try b.opcodeHandler(.{ .byte = opcode });
        call.wip.cursor = .{ .block = try call.wip.block(0, "Entry") };
        const out_alloca = try call.wip.alloca(
            .normal,
            b.struct_3_ptrs,
            try b.sizeIntValue(1),
            .default,
            .default,
            "",
        );

        const start_vip = OpcodeHandlerParam.vip.arg(&call.wip);
        const call_ip = try call.wip.gep(.inbounds, .i8, start_vip, &.{size_neg_1}, "");

        const decode_func_idx = try b.callDecodeUlebIdx(&call.wip, start_vip);
        const new_vip = try call.wip.extractValue(decode_func_idx, &.{1}, "vip");
        const func_idx = try call.wip.extractValue(decode_func_idx, &.{0}, "func_idx");

        const wasm_frame = call: {
            var args_buf: [10]Value = undefined;
            var args = std.ArrayList(Value).initBuffer(&args_buf);
            args.appendSliceAssumeCapacity(&.{
                out_alloca,
                call_ip,
                OpcodeHandlerParam.vsp.arg(&call.wip),
                OpcodeHandlerParam.module.arg(&call.wip),
                OpcodeHandlerParam.ctx.arg(&call.wip),
            });

            switch (opcode) {
                .call => args.appendAssumeCapacity(new_vip),
                .return_call => {},
                else => unreachable,
            }

            args.appendSliceAssumeCapacity(&.{
                OpcodeHandlerParam.stp.arg(&call.wip),
                OpcodeHandlerParam.eip.arg(&call.wip),
                func_idx,
            });

            std.debug.assert(args.items.len == helper_params.len);

            var attrs = FunctionAttributes.Wip{};
            try attrs.addRetAttr(.{ .dereferenceable_or_null = 3 * b.ptr_size_bytes }, &b.module);
            try attrs.addParamAttr(0, .writeonly, &b.module);
            const param_attrs = [3]Attribute{ .nonnull, .noundef, .nofree };

            for (0..(args.items.len - 1)) |i| {
                for (&param_attrs) |attr| {
                    try attrs.addParamAttr(i, attr, &b.module);
                }
            }

            break :call try call.wip.call(
                .normal,
                .ccc,
                try attrs.finish(&b.module),
                helper.typeOf(&b.module),
                helper.toValue(&b.module),
                args.items,
                "",
            );
        };

        try call.jmpToHostOrNextHandler(b, out_alloca, wasm_frame);
        try call.finish(b);
    }

    // Indirect function calls (via table)
    const trap_helper_type = try b.fnType(
        .i32,
        &[6]Type{ .ptr, .ptr, .ptr, .ptr, b.size_type, .ptr },
    );
    const trap_helper_attrs = attrs: {
        var attrs = FunctionAttributes.Wip{};
        try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind, .cold });
        break :attrs try attrs.finish(&b.module);
    };
    const trap_call_indirect_access_oob = try b.addFunction(
        try b.strtabStringSymbolPrefixed("trapCallIndirectAccessOob"),
        trap_helper_type,
        .ccc,
        .{ .linkage = .external, .preemption = .dso_local },
    );
    const trap_indirect_call_to_null = try b.addFunction(
        try b.strtabStringSymbolPrefixed("trapIndirectCallToNull"),
        trap_helper_type,
        .ccc,
        .{ .linkage = .external, .preemption = .dso_local },
    );

    for (&[2]ByteOpcode{ .call_indirect, .return_call_indirect }) |opcode| {
        var call = try b.opcodeHandler(.{ .byte = opcode });
        call.wip.cursor = .{ .block = try call.wip.block(0, "Entry") };
        const out_alloca = try call.wip.alloca(
            .normal,
            b.struct_3_ptrs,
            try b.sizeIntValue(1),
            .default,
            .default,
            "",
        );

        const start_vip = OpcodeHandlerParam.vip.arg(&call.wip);
        const initial_vsp = OpcodeHandlerParam.vsp.arg(&call.wip);
        const ctx = OpcodeHandlerParam.ctx.arg(&call.wip);
        const eip = OpcodeHandlerParam.eip.arg(&call.wip);
        const stp = OpcodeHandlerParam.stp.arg(&call.wip);
        const call_ip = try call.wip.gep(.inbounds, .i8, start_vip, &.{size_neg_1}, "");

        const decode_type_idx = try b.callDecodeUlebIdx(&call.wip, start_vip);
        const vip_after_type_idx = try call.wip.extractValue(decode_type_idx, &.{1}, "");
        const type_idx = try call.wip.extractValue(decode_type_idx, &.{0}, "type_idx");

        const decode_table_idx = try b.callDecodeUlebIdx(&call.wip, vip_after_type_idx);
        const vip_after_table_idx = try call.wip.extractValue(decode_table_idx, &.{1}, "");
        const table_idx = try call.wip.extractValue(decode_table_idx, &.{0}, "table_idx");

        const table_ptr = try call.tableInstPtr(b, table_idx);
        const table_len = try TableInstField.len.load(&call.wip, b, table_ptr);

        const elem_idx = try call.loadOperandAt(b, .i32, 0, "elem_idx");
        const in_bounds = try call.wip.block(1, "InBounds");
        const out_of_bounds = try call.wip.block(1, "OutOfBounds");
        _ = try call.wip.brCond(
            try call.wip.icmp(.ult, elem_idx, table_len, ""),
            in_bounds,
            out_of_bounds,
            .then_likely,
        );

        call.wip.cursor = .{ .block = in_bounds };
        const expected_signature_ptr = try call.wip.gep(
            .inbounds,
            b.func_type,
            try ModuleInfoField.types.load(&call.wip, b),
            &.{type_idx},
            "",
        );

        const func_ref = try call.wip.load(
            .normal,
            .ptr,
            try call.wip.gep(
                .inbounds,
                .ptr,
                try call.wip.load(.normal, .ptr, table_ptr, .default, "base"),
                // Index cannot be interpreted as negative
                &.{try call.wip.cast(.zext, elem_idx, b.size_type, "")},
                "",
            ),
            .default,
            "",
        );

        const null_elem = try call.wip.block(1, "Null");
        const call_helper = try call.wip.block(1, "Invoke");
        _ = try call.wip.brCond(
            try call.wip.icmp(.ne, func_ref, try b.module.nullValue(.ptr), ""),
            call_helper,
            null_elem,
            .then_likely,
        );

        call.wip.cursor = .{ .block = call_helper };
        const wasm_frame = call: {
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed(switch (opcode) {
                    .call_indirect => "invokeWithinWasmIndirect",
                    .return_call_indirect => "tailCallWithinWasmIndirect",
                    else => unreachable,
                }),
                try b.fnType(.ptr, &@as([9]Type, @splat(.ptr))),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            helper.setAttributes(invoke_helper_attrs, &b.module);

            const args = [9]Value{
                out_alloca,
                call_ip,
                initial_vsp,
                func_ref,
                ctx,
                vip_after_table_idx,
                stp,
                eip,
                expected_signature_ptr,
            };

            var attrs = FunctionAttributes.Wip{};
            try attrs.addRetAttr(.{ .dereferenceable_or_null = 3 * b.ptr_size_bytes }, &b.module);
            try attrs.addParamAttr(0, .writeonly, &b.module);
            for (0..args.len) |i| {
                for ([3]Attribute{ .nonnull, .noundef, .nofree }) |attr| {
                    try attrs.addParamAttr(i, attr, &b.module);
                }
            }

            break :call try call.wip.call(
                .normal,
                .ccc,
                try attrs.finish(&b.module),
                helper.typeOf(&b.module),
                helper.toValue(&b.module),
                &args,
                "",
            );
        };
        try call.jmpToHostOrNextHandler(b, out_alloca, wasm_frame);

        call.wip.cursor = .{ .block = out_of_bounds };
        var trap_helper_args = [6]Value{
            call_ip,
            initial_vsp,
            eip,
            stp,
            try call.wip.cast(.zext, table_idx, b.size_type, ""),
            ctx,
        };
        _ = try call.wip.callIntrinsicAssumeCold();
        _ = try call.wip.ret(
            try call.wip.call(
                .tail,
                .ccc,
                trap_helper_attrs,
                trap_helper_type,
                trap_call_indirect_access_oob.toValue(&b.module),
                &trap_helper_args,
                "",
            ),
        );

        call.wip.cursor = .{ .block = null_elem };
        _ = try call.wip.callIntrinsicAssumeCold();
        trap_helper_args[4] = try call.wip.cast(.zext, elem_idx, b.size_type, "");
        _ = try call.wip.ret(
            try call.wip.call(
                .tail,
                .ccc,
                trap_helper_attrs,
                trap_helper_type,
                trap_indirect_call_to_null.toValue(&b.module),
                &trap_helper_args,
                "",
            ),
        );

        try call.finish(b);
    }
}

fn writeSelectHandler(b: *Builder, select: *OpcodeHandler) Oom!Value {
    const condition_ptr = try select.gepOperandAt(b, 0);
    const condition_value = try select.wip.load(
        .normal,
        .i32,
        condition_ptr,
        value_stack_alignment,
        "condition",
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
    const dst_ptr = try select.gepOperandAt(b, 2);
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
                    try drop.gepOperandAt(b, 0),
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
        });
        try select.finish(b);
    }
    {
        var select = try b.opcodeHandler(.{ .byte = .@"select t" });
        const wip = &select.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const decode_type_count = try b.callDecodeUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
        const type_count = try wip.extractValue(decode_type_count, &.{0}, "type_count");
        const vip_after_type_count = try wip.extractValue(
            decode_type_count,
            &.{1},
            "vip_after_type_count",
        );

        const bad_type_count = try wip.block(1, "BadTypeCount");
        const good_type_count = try wip.block(1, "Select");
        _ = try wip.brCond(
            try wip.icmp(.eq, type_count, try b.module.intValue(.i32, 1), ""),
            good_type_count,
            bad_type_count,
            .then_likely,
        );

        wip.cursor = .{ .block = bad_type_count };
        if (b.options.optimize != .ReleaseSmall) {
            _ = try wip.callIntrinsic(.normal, .none, .trap, &.{}, &.{}, "");
        }
        _ = try wip.@"unreachable"();

        wip.cursor = .{ .block = good_type_count };
        const vip_after_val_type = try b.callSkipUlebIdx(wip, vip_after_type_count);
        const new_vsp = try writeSelectHandler(b, &select);
        try select.jmpToNextHandler(b, .{ .vip = vip_after_val_type, .vsp = new_vsp });
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
                try load.gepOperandAt(b, 0),
                value_stack_alignment,
            );

            try load.jmpToNextHandler(b, .{
                .vip = access.vip,
                .vsp = OpcodeHandlerParam.vsp.arg(&load.wip),
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
                try load.gepOperandAt(b, 0),
                value_stack_alignment,
            );

            try load.jmpToNextHandler(b, .{
                .vip = access.vip,
                .vsp = OpcodeHandlerParam.vsp.arg(&load.wip),
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
                try store.wip.cast(.trunc, try store.loadOperandAt(b, int_ty, 0, ""), store_ty, ""),
                access.ptr,
                byte_alignment,
            );

            const new_vsp = try store.adjustVspBy(b, -2);
            try store.jmpToNextHandler(b, .{ .vip = access.vip, .vsp = new_vsp });
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
                try store.loadOperandAt(b, int_ty, 0, "value"),
                access.ptr,
                byte_alignment,
            );

            const new_vsp = try store.adjustVspBy(b, -2);
            try store.jmpToNextHandler(b, .{ .vip = access.vip, .vsp = new_vsp });
            try store.finish(b);
        }
    }
}

fn buildMemoryManagementOpcodeHandlers(b: *Builder) Oom!void {
    const page_size = try b.module.intValue(.i32, 65536);
    {
        var size = try b.opcodeHandler(.{ .byte = .@"memory.size" });
        const wip = &size.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const decode_mem_idx = try b.callDecodeUlebIdx(wip, start_vip);
        // const mem_idx = try wip.extractValue(decode_mem_idx, &.{0}, "mem_idx");
        const vip_after_mem_idx = try wip.extractValue(decode_mem_idx, &.{1}, "vip_after_mem_idx");
        const mem_ptr = try wip.load(
            .normal,
            .ptr,
            // Would need GEP here to support multi-memory
            OpcodeHandlerParam.memories.arg(wip),
            .default,
            "",
        );
        const mem_size = try wip.cast(.trunc, try MemInstField.size.load(wip, b, mem_ptr), .i32, "");
        _ = try wip.store(
            .normal,
            try wip.bin(.@"udiv exact", mem_size, page_size, ""),
            try size.gepOperandAt(b, -1),
            value_stack_alignment,
        );

        const new_vsp = try size.adjustVspBy(b, 1);
        try size.jmpToNextHandler(b, .{ .vip = vip_after_mem_idx, .vsp = new_vsp });
        try size.finish(b);
    }
    {
        const size_neg_one = try b.module.intValue(.i32, -1);
        const size_ty = switch (b.ptr_size_bytes) {
            4 => try b.module.intType(33),
            8 => b.size_type,
            else => unreachable,
        };

        var grow = try b.opcodeHandler(.{ .byte = .@"memory.grow" });
        const wip = &grow.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const stack_top = try grow.gepOperandAt(b, 0);

        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(wip);
        const initial_vsp = OpcodeHandlerParam.vsp.arg(wip);

        const decode_mem_idx = try b.callDecodeUlebIdx(wip, start_vip);
        // const mem_idx = try wip.extractValue(decode_mem_idx, &.{0}, "mem_idx");
        const vip_after_mem_idx = try wip.extractValue(decode_mem_idx, &.{1}, "vip_after_mem_idx");

        // Assumes 32-bit memories
        const delta_in_pages = try wip.load(
            .normal,
            .i32,
            stack_top,
            value_stack_alignment,
            "delta_in_pages",
        );
        const try_delta_in_bytes = try wip.callIntrinsic(
            .normal,
            .none,
            .@"umul.with.overflow",
            &.{.i32},
            &.{ delta_in_pages, page_size },
            "",
        );

        const delta_in_bytes = try wip.extractValue(try_delta_in_bytes, &.{0}, "delta_in_bytes");
        const delta_would_overflow = try wip.extractValue(try_delta_in_bytes, &.{1}, "");

        const delta_no_overflow = try wip.block(1, "CheckAgainstLimit");
        const growth_failed = try wip.block(2, "GrowthFailed");
        _ = try wip.brCond(delta_would_overflow, growth_failed, delta_no_overflow, .else_likely);

        wip.cursor = .{ .block = delta_no_overflow };
        const mem_ptr = try wip.load(
            .normal,
            .ptr,
            // Would need GEP here to support multi-memory
            OpcodeHandlerParam.memories.arg(wip),
            .default,
            "",
        );
        const old_mem_size = try MemInstField.size.load(wip, b, mem_ptr);
        const old_mem_size_ext = try wip.cast(.zext, old_mem_size, size_ty, "");
        const mem_limit_ext = try wip.cast(
            .zext,
            try MemInstField.limit.load(wip, b, mem_ptr),
            size_ty,
            "",
        );

        // Assumed to be never exceed `std.math.maxInt(u33) - 1`
        const desired_size_ext = try wip.bin(
            .@"add nuw",
            old_mem_size_ext,
            try wip.cast(.zext, delta_in_bytes, size_ty, ""),
            "",
        );

        const within_limit = try wip.block(1, "WithinLimit");
        _ = try wip.brCond(
            try wip.icmp(.ule, desired_size_ext, mem_limit_ext, ""),
            within_limit,
            growth_failed,
            .then_likely,
        );

        wip.cursor = .{ .block = within_limit };
        const mem_capacity_ext = try wip.cast(
            .zext,
            try MemInstField.capacity.load(wip, b, mem_ptr),
            size_ty,
            "",
        );

        const within_capacity = try wip.block(1, "WithinCapacity");
        const needs_reallocation = try wip.block(1, "Reallocate");
        _ = try wip.brCond(
            try wip.icmp(.ule, desired_size_ext, mem_capacity_ext, ""),
            within_capacity,
            needs_reallocation,
            .none,
        );

        wip.cursor = .{ .block = within_capacity };
        // Currently assumes bytes past capacity are always zero (page allocator),
        // will need memset otherwise
        _ = try wip.store(
            .normal,
            try wip.bin(
                .@"udiv exact",
                try wip.cast(.trunc, old_mem_size, .i32, ""),
                page_size,
                "",
            ),
            stack_top,
            value_stack_alignment,
        );
        _ = try wip.store(
            .normal,
            try wip.cast(.trunc, desired_size_ext, b.size_type, "desired_size"),
            try MemInstField.size.gep(wip, b, mem_ptr),
            .default,
        );
        const jmp_to_next = try wip.block(2, "JumpToNextOpcode");
        _ = try wip.br(jmp_to_next);

        {
            wip.cursor = .{ .block = needs_reallocation };
            _ = try wip.store(.normal, size_neg_one, stack_top, value_stack_alignment);

            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("memoryGrowReallocate"),
                try b.fnType(.i32, &([1]Type{b.size_type} ++ @as([6]Type, @splat(.ptr)))),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            const args = [7]Value{
                try wip.cast(.zext, desired_size_ext, b.size_type, "new_size"),
                initial_vsp,
                vip_after_mem_idx,
                OpcodeHandlerParam.eip.arg(wip),
                mem_ptr,
                OpcodeHandlerParam.ctx.arg(wip),
                stp,
            };

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (1..7) |i| {
                            for ([3]Attribute{ .nonnull, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        try attrs.addParamAttr(
                            4,
                            .{ .dereferenceable = b.ptr_size_bytes * 5 },
                            &b.module,
                        );
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &args,
                    "",
                ),
            );
        }

        wip.cursor = .{ .block = growth_failed };
        _ = try wip.callIntrinsicAssumeCold();
        _ = try wip.store(.normal, size_neg_one, stack_top, value_stack_alignment);
        _ = try wip.br(jmp_to_next);

        wip.cursor = .{ .block = jmp_to_next };
        try grow.jmpToNextHandler(b, .{
            .vsp = initial_vsp,
            .vip = vip_after_mem_idx,
            .stp = stp,
        });

        try grow.finish(b);
    }
}

fn buildTableAccessOpcodeHandlers(b: *Builder) Oom!void {
    const gep_index_ty = switch (b.ptr_size_bytes) {
        4 => b.size_type,
        8 => try b.module.intType(33),
        else => unreachable,
    };

    const trap_oob_helper_ty = try b.fnType(
        .i32,
        &[8]Type{ .ptr, .ptr, .ptr, .ptr, .ptr, .ptr, .i32, .i8 },
    );
    const trap_oob_helper = try b.addFunction(
        try b.strtabStringSymbolPrefixed("trapTableAccessOutOfBounds"),
        trap_oob_helper_ty,
        .ccc,
        .{ .linkage = .external, .preemption = .dso_local },
    );
    const trap_oob_helper_value = trap_oob_helper.toValue(&b.module);
    {
        var attrs = FunctionAttributes.Wip{};
        try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .cold, .nounwind });
        try b.setFnAttributes(trap_oob_helper, &attrs);
    }
    const trap_oob_helper_attrs = attrs: {
        var attrs = FunctionAttributes.Wip{};
        for (0..6) |i| {
            for (&[3]Attribute{ .noundef, .readonly, .nonnull }) |a| {
                try attrs.addParamAttr(i, a, &b.module);
            }
        }
        break :attrs try attrs.finish(&b.module);
    };

    {
        var get = try b.opcodeHandler(.{ .byte = .@"table.get" });
        const wip = &get.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&get.wip);
        const start_vsp = OpcodeHandlerParam.vsp.arg(wip);

        const decode_table_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const table_idx = try wip.extractValue(decode_table_idx, &.{0}, "table_idx");
        const vip_after_table_idx = try wip.extractValue(
            decode_table_idx,
            &.{1},
            "vip_after_table_idx",
        );

        const stack_top = try get.gepOperandAt(b, 0);
        const index = try wip.load(.normal, .i32, stack_top, value_stack_alignment, "index");

        const table_ptr = try get.tableInstPtr(b, table_idx);

        const in_bounds = try wip.block(1, "Load");
        const out_of_bounds = try wip.block(1, "OutOfBounds");
        _ = try wip.brCond(
            try wip.icmp(
                .ult,
                index,
                try TableInstField.len.load(wip, b, table_ptr),
                "bounds_check",
            ),
            in_bounds,
            out_of_bounds,
            .then_likely,
        );

        {
            wip.cursor = .{ .block = in_bounds };
            const src_ptr = try wip.gep(
                .inbounds,
                .ptr,
                try TableInstField.base.load(wip, b, table_ptr),
                &.{try wip.cast(.zext, index, gep_index_ty, "")},
                "src_ptr",
            );

            const elem = try wip.load(.normal, .ptr, src_ptr, .default, "elem");
            _ = try wip.store(.normal, elem, stack_top, value_stack_alignment);

            try get.jmpToNextHandler(b, .{
                .vsp = start_vsp,
                .vip = vip_after_table_idx,
                .stp = stp,
            });
        }

        {
            wip.cursor = .{ .block = out_of_bounds };
            _ = try wip.callIntrinsicAssumeCold();
            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    trap_oob_helper_attrs,
                    trap_oob_helper_ty,
                    trap_oob_helper_value,
                    &[8]Value{
                        start_vip,
                        start_vsp,
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        OpcodeHandlerParam.ctx.arg(wip),
                        table_ptr,
                        index,
                        // Bit 7 set to 0 to indicate table.get
                        try wip.cast(.trunc, table_idx, .i8, ""),
                    },
                    "",
                ),
            );
        }

        try get.finish(b);
    }
    {
        var set = try b.opcodeHandler(.{ .byte = .@"table.set" });
        const wip = &set.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&set.wip);

        const decode_table_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const table_idx = try wip.extractValue(decode_table_idx, &.{0}, "table_idx");
        const vip_after_table_idx = try wip.extractValue(
            decode_table_idx,
            &.{1},
            "vip_after_table_idx",
        );

        const index = try set.loadOperandAt(b, .i32, 1, "index");
        const table_ptr = try set.tableInstPtr(b, table_idx);

        const in_bounds = try wip.block(1, "Load");
        const out_of_bounds = try wip.block(1, "OutOfBounds");
        _ = try wip.brCond(
            try wip.icmp(
                .ult,
                index,
                try TableInstField.len.load(wip, b, table_ptr),
                "bounds_check",
            ),
            in_bounds,
            out_of_bounds,
            .then_likely,
        );

        {
            wip.cursor = .{ .block = in_bounds };
            const dst_ptr = try wip.gep(
                .inbounds,
                .ptr,
                try TableInstField.base.load(wip, b, table_ptr),
                &.{try wip.cast(.zext, index, gep_index_ty, "")},
                "dst_ptr",
            );

            const stack_top = try set.gepOperandAt(b, 0);
            const elem = try wip.load(.normal, .ptr, stack_top, value_stack_alignment, "elem");
            _ = try wip.store(.normal, elem, dst_ptr, .default);

            const new_vsp = try set.adjustVspBy(b, -2);
            try set.jmpToNextHandler(b, .{
                .vsp = new_vsp,
                .vip = vip_after_table_idx,
                .stp = stp,
            });
        }

        {
            wip.cursor = .{ .block = out_of_bounds };
            _ = try wip.callIntrinsicAssumeCold();
            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    trap_oob_helper_attrs,
                    trap_oob_helper_ty,
                    trap_oob_helper_value,
                    &[8]Value{
                        start_vip,
                        OpcodeHandlerParam.vsp.arg(wip),
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        OpcodeHandlerParam.ctx.arg(wip),
                        table_ptr,
                        index,
                        // Bit 7 set to 1 to indicate table.set
                        try wip.bin(
                            .@"and",
                            try wip.cast(.trunc, table_idx, .i8, ""),
                            try b.module.intValue(.i8, 0x80),
                            "",
                        ),
                    },
                    "",
                ),
            );
        }

        try set.finish(b);
    }
}

fn buildTableManagementOpcodeHandlers(b: *Builder) Oom!void {
    {
        var size = try b.opcodeHandler(.{ .fc = .@"table.size" });
        const wip = &size.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const decode_table_idx = try b.callDecodeUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
        const table_idx = try wip.extractValue(decode_table_idx, &.{0}, "table_idx");
        const vip_after_table_idx = try wip.extractValue(
            decode_table_idx,
            &.{1},
            "vip_after_table_idx",
        );

        const table_ptr = try size.tableInstPtr(b, table_idx);
        _ = try wip.store(
            .normal,
            try TableInstField.len.load(wip, b, table_ptr),
            try size.gepOperandAt(b, -1),
            value_stack_alignment,
        );

        const new_vsp = try size.adjustVspBy(b, 1);
        try size.jmpToNextHandler(b, .{ .vip = vip_after_table_idx, .vsp = new_vsp });
        try size.finish(b);
    }
    const idx_ty = try b.module.intType(33);
    {
        var grow = try b.opcodeHandler(.{ .fc = .@"table.grow" });
        const wip = &grow.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(wip);
        // const initial_vsp = OpcodeHandlerParam.vsp.arg(wip);

        const decode_table_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const table_idx = try wip.extractValue(decode_table_idx, &.{0}, "table_idx");
        const vip_after_table_idx = try wip.extractValue(
            decode_table_idx,
            &.{1},
            "vip_after_table_idx",
        );

        const table_ptr = try grow.tableInstPtr(b, table_idx);

        const delta_ptr = try grow.gepOperandAt(b, 0);
        const delta = try wip.load(
            .normal,
            .i32,
            delta_ptr,
            value_stack_alignment,
            "delta",
        );
        const elem_or_result_ptr = try grow.gepOperandAt(b, 1);
        const elem = try wip.load(
            .normal,
            b.size_type,
            elem_or_result_ptr,
            value_stack_alignment,
            "elem",
        );

        const old_size = try TableInstField.len.load(wip, b, table_ptr);
        const new_size_extended = try wip.bin(
            .@"add nuw",
            try wip.cast(.zext, old_size, idx_ty, ""),
            try wip.cast(.zext, delta, idx_ty, ""),
            "new_size.0",
        );

        const within_limit = try wip.block(1, "WithinLimit");
        const growth_failed = try wip.block(1, "GrowthFailed");
        _ = try wip.brCond(
            try wip.icmp(
                .ule,
                new_size_extended,
                try wip.cast(
                    .zext,
                    try TableInstField.limit.load(wip, b, table_ptr),
                    idx_ty,
                    "limit",
                ),
                "within_limit",
            ),
            within_limit,
            growth_failed,
            .then_likely,
        );

        wip.cursor = .{ .block = within_limit };
        const new_size = try wip.cast(.trunc, new_size_extended, .i32, "new_size.1");

        const within_capacity = try wip.block(1, "WithinCapacity");
        const reallocation_needed = try wip.block(1, "ReallocationNeeded");
        _ = try wip.brCond(
            try wip.icmp(
                .ule,
                new_size,
                try TableInstField.capacity.load(wip, b, table_ptr),
                "within_capacity",
            ),
            within_capacity,
            reallocation_needed,
            .none,
        );

        const jmp_to_next = try wip.block(2, "JumpToNextOpcode");
        {
            wip.cursor = .{ .block = within_capacity };
            _ = try wip.call(
                .normal,
                b.fill_table_elements.ptrConst(&b.module).call_conv,
                .none,
                b.fill_table_elements.typeOf(&b.module),
                b.fill_table_elements.toValue(&b.module),
                &.{
                    try wip.gep(
                        .inbounds,
                        b.size_type,
                        try TableInstField.base.load(wip, b, table_ptr),
                        &.{try wip.cast(.zext, old_size, b.size_type, "old_size")},
                        "",
                    ),
                    elem,
                    try wip.bin(.@"sub nuw", new_size, old_size, "uninit_len"),
                },
                "",
            );

            _ = try wip.store(
                .normal,
                new_size,
                try TableInstField.len.gep(wip, b, table_ptr),
                .default,
            );

            _ = try wip.store(.normal, old_size, elem_or_result_ptr, value_stack_alignment);
            _ = try wip.br(jmp_to_next);
        }
        {
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("tableGrowReallocate"),
                try b.fnType(.i32, &([1]Type{.i32} ++ @as([6]Type, @splat(.ptr)))),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            wip.cursor = .{ .block = reallocation_needed };
            const args = [7]Value{
                new_size,
                delta_ptr,
                vip_after_table_idx,
                OpcodeHandlerParam.eip.arg(wip),
                stp,
                OpcodeHandlerParam.ctx.arg(wip),
                table_ptr,
            };

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (1..7) |i| {
                            for ([3]Attribute{ .nonnull, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &args,
                    "",
                ),
            );
        }

        wip.cursor = .{ .block = growth_failed };
        _ = try wip.callIntrinsicAssumeCold();
        const growth_failed_value = try b.module.intValue(.i32, -1);
        _ = try wip.store(.normal, growth_failed_value, elem_or_result_ptr, value_stack_alignment);
        _ = try wip.br(jmp_to_next);

        wip.cursor = .{ .block = jmp_to_next };
        const new_vsp = try grow.adjustVspBy(b, -1);
        try grow.jmpToNextHandler(b, .{
            .vip = vip_after_table_idx,
            .vsp = new_vsp,
            .stp = stp,
        });

        try grow.finish(b);
    }
}

fn buildBulkMemoryOpcodeHandlers(b: *Builder) Oom!void {
    const addr_ty = switch (b.ptr_size_bytes) {
        4 => try b.module.intType(33),
        8 => b.size_type,
        else => unreachable,
    };
    {
        var fill = try b.opcodeHandler(.{ .fc = .@"memory.fill" });
        const wip = &fill.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&fill.wip);
        const decode_mem_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const mem_idx = try wip.extractValue(decode_mem_idx, &.{0}, "mem_idx");
        const vip_after_mem_idx = try wip.extractValue(decode_mem_idx, &.{1}, "vip_after_mem_idx");
        const mem_ptr = try wip.load(
            .normal,
            .ptr,
            // Would need GEP here to support multi-memory
            OpcodeHandlerParam.memories.arg(wip),
            .default,
            "",
        );
        const mem_size = try wip.cast(
            .zext,
            try MemInstField.size.load(wip, b, mem_ptr),
            addr_ty,
            "",
        );

        const n = try fill.loadOperandAt(b, .i32, 0, "n");
        const dupe = try wip.cast(.trunc, try fill.loadOperandAt(b, .i32, 1, ""), .i8, "dupe");
        const offset = try fill.loadOperandAt(b, .i32, 2, "offset");

        const fill_blk = try wip.block(1, "Fill");
        const oob_blk = try wip.block(1, "OutOfBounds");
        _ = try wip.brCond(
            try wip.icmp(
                .ule,
                try wip.bin(
                    .@"add nuw",
                    try wip.cast(.zext, offset, addr_ty, ""),
                    try wip.cast(.zext, n, addr_ty, ""),
                    "",
                ),
                mem_size,
                "",
            ),
            fill_blk,
            oob_blk,
            .then_likely,
        );

        {
            wip.cursor = .{ .block = fill_blk };
            const dst_ptr = try wip.gep(
                .inbounds,
                .i8,
                try MemInstField.base.load(wip, b, mem_ptr),
                &.{try wip.cast(.zext, offset, b.size_type, "")},
                "dst_ptr",
            );
            _ = try wip.callIntrinsic(
                .normal,
                .none,
                .memset,
                &.{ .ptr, b.size_type },
                &.{
                    dst_ptr,
                    dupe,
                    try wip.cast(.zext, n, b.size_type, "len"),
                    .false,
                },
                "",
            );

            const new_vsp = try fill.adjustVspBy(b, -3);
            try fill.jmpToNextHandler(b, .{
                .vip = vip_after_mem_idx,
                .vsp = new_vsp,
                .stp = stp,
            });
        }
        {
            wip.cursor = .{ .block = oob_blk };
            _ = try wip.callIntrinsicAssumeCold();
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("trapMemoryFillOutOfBounds"),
                try b.fnType(.i32, &[6]Type{ .ptr, .ptr, .ptr, .ptr, b.size_type, .ptr }),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (0..6) |i| {
                            if (i == 4) continue;

                            for (&[3]Attribute{ .nonnull, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &[6]Value{
                        start_vip,
                        OpcodeHandlerParam.vsp.arg(wip),
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        try wip.cast(.zext, mem_idx, b.size_type, ""),
                        OpcodeHandlerParam.ctx.arg(wip),
                    },
                    "",
                ),
            );
        }

        try fill.finish(b);
    }
    {
        var copy = try b.opcodeHandler(.{ .fc = .@"memory.copy" });
        const wip = &copy.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&copy.wip);

        const decode_dst_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const dst_idx = try wip.extractValue(decode_dst_idx, &.{0}, "dst_idx");
        const vip_after_dst_idx = try wip.extractValue(decode_dst_idx, &.{1}, "vip_after_dst_idx");

        const decode_src_idx = try b.callDecodeUlebIdx(wip, vip_after_dst_idx);
        const src_idx = try wip.extractValue(decode_src_idx, &.{0}, "src_idx");
        const vip_after_src_idx = try wip.extractValue(decode_src_idx, &.{1}, "vip_after_src_idx");

        const src_mem = try wip.load(
            .normal,
            .ptr,
            // Would need GEP here to support multi-memory
            OpcodeHandlerParam.memories.arg(wip),
            .default,
            "",
        );
        const dst_mem = src_mem;

        const n = try copy.loadOperandAt(b, .i32, 0, "n");
        const src_offset = try copy.loadOperandAt(b, .i32, 1, "src_offset");
        const dst_offset = try copy.loadOperandAt(b, .i32, 2, "dst_offset");

        const copy_blk = try wip.block(1, "Copy");
        const oob_blk = try wip.block(1, "OutOfBounds");
        {
            const src_size = try wip.cast(
                .zext,
                try MemInstField.size.load(wip, b, src_mem),
                addr_ty,
                "",
            );
            const dst_size = src_size;

            const len = try wip.cast(.zext, n, addr_ty, "");
            const src_in_bounds = try wip.icmp(
                .ule,
                try wip.bin(
                    .@"add nuw",
                    try wip.cast(.zext, src_offset, addr_ty, ""),
                    len,
                    "",
                ),
                src_size,
                "",
            );
            const dst_in_bounds = try wip.icmp(
                .ule,
                try wip.bin(
                    .@"add nuw",
                    try wip.cast(.zext, dst_offset, addr_ty, ""),
                    len,
                    "",
                ),
                dst_size,
                "",
            );

            _ = try wip.brCond(
                try wip.bin(.@"and", src_in_bounds, dst_in_bounds, ""),
                copy_blk,
                oob_blk,
                .then_likely,
            );
        }
        {
            wip.cursor = .{ .block = copy_blk };
            const dst_ptr = try wip.gep(
                .inbounds,
                .i8,
                try MemInstField.base.load(wip, b, dst_mem),
                &.{try wip.cast(.zext, dst_offset, b.size_type, "")},
                "dst_ptr",
            );
            const src_ptr = try wip.gep(
                .inbounds,
                .i8,
                try MemInstField.base.load(wip, b, src_mem),
                &.{try wip.cast(.zext, src_offset, b.size_type, "")},
                "src_ptr",
            );
            _ = try wip.callIntrinsic(
                .normal,
                .none,
                .memmove, // maybe use "llvm.memmove.element.unordered.atomic"
                &.{ .ptr, .ptr, b.size_type },
                &.{
                    dst_ptr,
                    src_ptr,
                    try wip.cast(.zext, n, b.size_type, "len"),
                    .false,
                },
                "",
            );

            const new_vsp = try copy.adjustVspBy(b, -3);
            try copy.jmpToNextHandler(b, .{
                .vip = vip_after_src_idx,
                .vsp = new_vsp,
                .stp = stp,
            });
        }
        {
            wip.cursor = .{ .block = oob_blk };
            _ = try wip.callIntrinsicAssumeCold();
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("trapMemoryCopyOutOfBounds"),
                try b.fnType(
                    .i32,
                    &[7]Type{ .ptr, .ptr, .ptr, .ptr, .ptr, b.size_type, b.size_type },
                ),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (0..5) |i| {
                            for (&[3]Attribute{ .nonnull, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &[7]Value{
                        start_vip,
                        OpcodeHandlerParam.vsp.arg(wip),
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        OpcodeHandlerParam.ctx.arg(wip),
                        try wip.cast(.zext, src_idx, b.size_type, ""),
                        try wip.cast(.zext, dst_idx, b.size_type, ""),
                    },
                    "",
                ),
            );
        }

        try copy.finish(b);
    }
    const drop_flag_size = try b.module.intValue(.i32, 32);
    const drop_flag_bit_index_mask = try b.module.intValue(.i32, 32 - 1);
    {
        var init = try b.opcodeHandler(.{ .fc = .@"memory.init" });
        const wip = &init.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&init.wip);

        const decode_data_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const data_idx = try wip.extractValue(decode_data_idx, &.{0}, "data_idx");
        const vip_after_data_idx = try wip.extractValue(
            decode_data_idx,
            &.{1},
            "vip_after_data_idx",
        );

        const decode_mem_idx = try b.callDecodeUlebIdx(wip, vip_after_data_idx);
        const mem_idx = try wip.extractValue(decode_mem_idx, &.{0}, "mem_idx");
        const vip_after_mem_idx = try wip.extractValue(decode_mem_idx, &.{1}, "vip_after_mem_idx");

        const mem_ptr = try wip.load(
            .normal,
            .ptr,
            // Would need GEP here to support multi-memory
            OpcodeHandlerParam.memories.arg(wip),
            .default,
            "",
        );

        const n = try init.loadOperandAt(b, .i32, 0, "n");
        const src_offset = try init.loadOperandAt(b, .i32, 1, "src_offset");
        const dst_offset = try init.loadOperandAt(b, .i32, 2, "dst_offset");

        const data_len = len: {
            const len = try wip.load(
                .normal,
                .i32,
                try wip.gep(
                    .inbounds,
                    .i32,
                    try ModuleInfoField.datas_lens.load(wip, b),
                    &.{data_idx},
                    "",
                ),
                .default,
                "",
            );

            const flag_word = try wip.load(
                .normal,
                .i32,
                try wip.gep(
                    .inbounds,
                    .i32,
                    try ModuleInstField.datas_drop_mask.load(wip, b),
                    &.{try wip.cast(
                        .zext,
                        try wip.bin(.udiv, data_idx, drop_flag_size, ""),
                        b.size_type,
                        "",
                    )},
                    "",
                ),
                .default,
                "flag_word",
            );

            const flag_bit = try wip.cast(
                .trunc,
                try wip.bin(
                    .lshr,
                    flag_word,
                    try wip.bin(.@"and", data_idx, drop_flag_bit_index_mask, ""),
                    "",
                ),
                .i1,
                "flag_bit",
            );

            break :len try wip.bin(
                .@"and",
                len,
                try wip.cast(.sext, flag_bit, .i32, ""),
                "",
            );
        };

        const copy_blk = try wip.block(1, "Copy");
        const oob_blk = try wip.block(1, "OutOfBounds");
        {
            const len = try wip.cast(.zext, n, addr_ty, "");
            const src_size = try wip.cast(.zext, data_len, addr_ty, "");
            const dst_size = try wip.cast(
                .zext,
                try MemInstField.size.load(wip, b, mem_ptr),
                addr_ty,
                "",
            );

            const src_in_bounds = try wip.icmp(
                .ule,
                try wip.bin(.@"add nuw", try wip.cast(.zext, src_offset, addr_ty, ""), len, ""),
                src_size,
                "src_in_bounds",
            );
            const dst_in_bounds = try wip.icmp(
                .ule,
                try wip.bin(.@"add nuw", try wip.cast(.zext, dst_offset, addr_ty, ""), len, ""),
                dst_size,
                "dst_in_bounds",
            );

            _ = try wip.brCond(
                try wip.bin(.@"and", src_in_bounds, dst_in_bounds, ""),
                copy_blk,
                oob_blk,
                .then_likely,
            );
        }

        {
            wip.cursor = .{ .block = copy_blk };
            const data_base = try wip.load(
                .normal,
                .ptr,
                try wip.gep(
                    .inbounds,
                    .ptr,
                    try ModuleInfoField.datas_ptrs.load(wip, b),
                    &.{data_idx},
                    "",
                ),
                .default,
                "",
            );

            const src_ptr = try wip.gep(
                .inbounds,
                .i8,
                data_base,
                &.{try wip.cast(.zext, src_offset, b.size_type, "")},
                "",
            );

            const dst_ptr = try wip.gep(
                .inbounds,
                .i8,
                try MemInstField.base.load(wip, b, mem_ptr),
                &.{try wip.cast(.zext, dst_offset, b.size_type, "")},
                "",
            );

            _ = try wip.callIntrinsic(
                .normal,
                .none,
                .memcpy,
                &.{ .ptr, .ptr, b.size_type },
                &.{ dst_ptr, src_ptr, try wip.cast(.zext, n, b.size_type, ""), .false },
                "",
            );
            const new_vsp = try init.adjustVspBy(b, -3);
            try init.jmpToNextHandler(b, .{
                .vip = vip_after_mem_idx,
                .vsp = new_vsp,
                .stp = stp,
            });
        }
        {
            wip.cursor = .{ .block = oob_blk };
            _ = try wip.callIntrinsicAssumeCold();
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("trapMemoryInitOutOfBounds"),
                try b.fnType(
                    .i32,
                    &[7]Type{ .ptr, .ptr, .ptr, .ptr, .ptr, b.size_type, b.size_type },
                ),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (0..5) |i| {
                            for (&[4]Attribute{ .nonnull, .readonly, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &[7]Value{
                        start_vip,
                        OpcodeHandlerParam.vsp.arg(wip),
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        OpcodeHandlerParam.ctx.arg(wip),
                        try wip.cast(.zext, mem_idx, b.size_type, ""),
                        try wip.cast(.zext, data_idx, b.size_type, ""),
                    },
                    "",
                ),
            );
        }
        try init.finish(b);
    }
}

fn buildBulkTableOpcodeHandlers(b: *Builder) Oom!void {
    const addr_ty = try b.module.intType(33);
    {
        var init = try b.opcodeHandler(.{ .fc = .@"table.init" });
        const wip = &init.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&init.wip);

        const decode_elem_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const data_idx = try wip.extractValue(decode_elem_idx, &.{0}, "elem_idx");
        const vip_after_elem_idx = try wip.extractValue(
            decode_elem_idx,
            &.{1},
            "vip_after_elem_idx",
        );

        const decode_table_idx = try b.callDecodeUlebIdx(wip, vip_after_elem_idx);
        const table_idx = try wip.extractValue(decode_table_idx, &.{0}, "table_idx");
        const vip_after_table_idx = try wip.extractValue(
            decode_table_idx,
            &.{1},
            "vip_after_table_idx",
        );

        {
            // DataIdx is currently a `u16`.
            const max_elem_idx = try b.module.intValue(.i32, std.math.maxInt(u16));
            const elem_idx_range = try wip.icmp(.ule, data_idx, max_elem_idx, "");
            _ = try wip.callIntrinsic(.normal, .none, .assume, &.{}, &.{elem_idx_range}, "");
        }

        const n = try init.loadOperandAt(b, .i32, 0, "n");
        const src_offset = try init.loadOperandAt(b, .i32, 1, "src_offset");
        const dst_offset = try init.loadOperandAt(b, .i32, 2, "dst_offset");
        const new_vsp = try init.adjustVspBy(b, -3);

        const success = try wip.block(1, "JmpToNextHandler");
        const oob = try wip.block(1, "OutOfBounds");
        const status = status: {
            const arg_count = 7;
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("tableInit"),
                try b.fnType(
                    b.size_type,
                    &[arg_count]Type{ .i32, .i32, .i32, .ptr, .ptr, .i32, .i32 },
                ),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            break :status try wip.call(
                .normal,
                .ccc,
                attrs: {
                    var attrs = FunctionAttributes.Wip{};
                    for (3..5) |i| {
                        for (&[3]Attribute{ .noundef, .nonnull, .nofree }) |a| {
                            try attrs.addParamAttr(i, a, &b.module);
                        }
                    }
                    break :attrs try attrs.finish(&b.module);
                },
                helper.typeOf(&b.module),
                helper.toValue(&b.module),
                &[arg_count]Value{
                    n,
                    src_offset,
                    dst_offset,
                    new_vsp,
                    OpcodeHandlerParam.module.arg(wip),
                    table_idx,
                    data_idx,
                },
                "",
            );
        };
        _ = try wip.brCond(
            try wip.icmp(.eq, status, try b.sizeIntValue(0), "check_status"),
            success,
            oob,
            .then_likely,
        );

        {
            wip.cursor = .{ .block = success };
            try init.jmpToNextHandler(b, .{
                .vip = vip_after_table_idx,
                .vsp = new_vsp,
                .stp = stp,
            });
        }
        {
            wip.cursor = .{ .block = oob };
            _ = try wip.callIntrinsicAssumeCold();
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("trapTableInitOutOfBounds"),
                try b.fnType(.i32, &[7]Type{ .ptr, .ptr, .ptr, .ptr, .ptr, .i32, .i32 }),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (0..5) |i| {
                            for (&[4]Attribute{ .nonnull, .readonly, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &[7]Value{
                        start_vip,
                        OpcodeHandlerParam.vsp.arg(wip),
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        OpcodeHandlerParam.ctx.arg(wip),
                        table_idx,
                        data_idx,
                    },
                    "",
                ),
            );
        }
        try init.finish(b);
    }
    {
        var copy = try b.opcodeHandler(.{ .fc = .@"table.copy" });
        const wip = &copy.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&copy.wip);

        const decode_dst_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const dst_idx = try wip.extractValue(decode_dst_idx, &.{0}, "dst_idx");
        const vip_after_dst_idx = try wip.extractValue(decode_dst_idx, &.{1}, "vip_after_dst_idx");

        const decode_src_idx = try b.callDecodeUlebIdx(wip, vip_after_dst_idx);
        const src_idx = try wip.extractValue(decode_src_idx, &.{0}, "src_idx");
        const vip_after_src_idx = try wip.extractValue(decode_src_idx, &.{1}, "vip_after_src_idx");

        const dst_table = try copy.tableInstPtr(b, dst_idx);
        const src_table = try copy.tableInstPtr(b, src_idx);

        const n = try copy.loadOperandAt(b, .i32, 0, "n");
        const src_offset = try copy.loadOperandAt(b, .i32, 1, "src_offset");
        const dst_offset = try copy.loadOperandAt(b, .i32, 2, "dst_offset");

        const copy_blk = try wip.block(1, "Copy");
        const oob_blk = try wip.block(1, "OutOfBounds");
        {
            const src_len = try wip.cast(
                .zext,
                try TableInstField.len.load(wip, b, src_table),
                addr_ty,
                "src_len",
            );
            const dst_len = try wip.cast(
                .zext,
                try TableInstField.len.load(wip, b, dst_table),
                addr_ty,
                "dst_len",
            );

            const len = try wip.cast(.zext, n, addr_ty, "");
            const src_in_bounds = try wip.icmp(
                .ule,
                try wip.bin(
                    .@"add nuw",
                    try wip.cast(.zext, src_offset, addr_ty, ""),
                    len,
                    "",
                ),
                src_len,
                "",
            );
            const dst_in_bounds = try wip.icmp(
                .ule,
                try wip.bin(
                    .@"add nuw",
                    try wip.cast(.zext, dst_offset, addr_ty, ""),
                    len,
                    "",
                ),
                dst_len,
                "",
            );

            _ = try wip.brCond(
                try wip.bin(.@"and", src_in_bounds, dst_in_bounds, ""),
                copy_blk,
                oob_blk,
                .then_likely,
            );
        }
        {
            wip.cursor = .{ .block = copy_blk };
            const dst_ptr = try wip.gep(
                .inbounds,
                .ptr,
                try TableInstField.base.load(wip, b, dst_table),
                &.{try wip.cast(.zext, dst_offset, b.size_type, "")},
                "dst_ptr",
            );
            const src_ptr = try wip.gep(
                .inbounds,
                .ptr,
                try TableInstField.base.load(wip, b, src_table),
                &.{try wip.cast(.zext, src_offset, b.size_type, "")},
                "src_ptr",
            );
            _ = try wip.callIntrinsic(
                .normal,
                attrs: {
                    var attrs = FunctionAttributes.Wip{};
                    for (&[3]Attribute{
                        .{ .@"align" = llvm.Builder.Alignment.fromByteUnits(b.ptr_size_bytes) },
                        .nonnull,
                        .noundef,
                    }) |a| {
                        for (0..2) |i| {
                            try attrs.addParamAttr(i, a, &b.module);
                        }
                    }
                    break :attrs try attrs.finish(&b.module);
                },
                .memmove,
                &.{ .ptr, .ptr, b.size_type },
                &.{
                    dst_ptr,
                    src_ptr,
                    try wip.bin(
                        .@"mul nuw",
                        try wip.cast(.zext, n, b.size_type, "len"),
                        try b.sizeIntValue(b.ptr_size_bytes),
                        "",
                    ),
                    .false,
                },
                "",
            );

            const new_vsp = try copy.adjustVspBy(b, -3);
            try copy.jmpToNextHandler(b, .{
                .vip = vip_after_src_idx,
                .vsp = new_vsp,
                .stp = stp,
            });
        }
        {
            wip.cursor = .{ .block = oob_blk };
            _ = try wip.callIntrinsicAssumeCold();
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("trapTableCopyOutOfBounds"),
                try b.fnType(
                    .i32,
                    &[7]Type{ .ptr, .ptr, .ptr, .ptr, .ptr, .i32, .i32 },
                ),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (0..5) |i| {
                            for (&[3]Attribute{ .nonnull, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &[7]Value{
                        start_vip,
                        OpcodeHandlerParam.vsp.arg(wip),
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        OpcodeHandlerParam.ctx.arg(wip),
                        src_idx,
                        dst_idx,
                    },
                    "",
                ),
            );
        }

        try copy.finish(b);
    }
    {
        var fill = try b.opcodeHandler(.{ .fc = .@"table.fill" });
        const wip = &fill.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const stp = OpcodeHandlerParam.stp.arg(&fill.wip);
        const decode_table_idx = try b.callDecodeUlebIdx(wip, start_vip);
        const table_idx = try wip.extractValue(decode_table_idx, &.{0}, "table_idx");
        const vip_after_table_idx = try wip.extractValue(
            decode_table_idx,
            &.{1},
            "vip_after_table_idx",
        );
        const table_ptr = try fill.tableInstPtr(b, table_idx);

        const n = try fill.loadOperandAt(b, .i32, 0, "n");
        const dupe = try fill.loadOperandAt(b, b.size_type, 1, "dupe");
        const offset = try fill.loadOperandAt(b, .i32, 2, "offset");

        const fill_blk = try wip.block(1, "Fill");
        const oob_blk = try wip.block(1, "OutOfBounds");
        {
            const end_offset = try wip.bin(
                .@"add nuw",
                try wip.cast(.zext, offset, addr_ty, ""),
                try wip.cast(.zext, n, addr_ty, ""),
                "",
            );
            const table_len = try wip.cast(
                .zext,
                try TableInstField.len.load(wip, b, table_ptr),
                addr_ty,
                "len",
            );

            _ = try wip.brCond(
                try wip.icmp(.ule, end_offset, table_len, ""),
                fill_blk,
                oob_blk,
                .then_likely,
            );
        }
        {
            wip.cursor = .{ .block = fill_blk };
            const dst_ptr = try wip.gep(
                .inbounds,
                .ptr,
                try TableInstField.base.load(wip, b, table_ptr),
                &.{try wip.cast(.zext, offset, b.size_type, "")},
                "dst_ptr",
            );
            _ = try wip.call(
                .normal,
                b.fill_table_elements.ptrConst(&b.module).call_conv,
                .none,
                b.fill_table_elements.typeOf(&b.module),
                b.fill_table_elements.toValue(&b.module),
                &.{ dst_ptr, dupe, n },
                "",
            );

            const new_vsp = try fill.adjustVspBy(b, -3);
            try fill.jmpToNextHandler(b, .{
                .vip = vip_after_table_idx,
                .vsp = new_vsp,
                .stp = stp,
            });
        }
        {
            wip.cursor = .{ .block = oob_blk };
            _ = try wip.callIntrinsicAssumeCold();
            const helper = try b.addFunction(
                try b.strtabStringSymbolPrefixed("trapTableFillOutOfBounds"),
                try b.fnType(.i32, &[6]Type{ .ptr, .ptr, .ptr, .ptr, .ptr, .i32 }),
                .ccc,
                .{ .linkage = .external, .preemption = .dso_local },
            );
            {
                var attrs = FunctionAttributes.Wip{};
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                try b.setFnAttributes(helper, &attrs);
            }

            _ = try wip.ret(
                try wip.call(
                    .tail,
                    .ccc,
                    attrs: {
                        var attrs = FunctionAttributes.Wip{};
                        for (0..5) |i| {
                            for (&[3]Attribute{ .nonnull, .noundef, .nofree }) |a| {
                                try attrs.addParamAttr(i, a, &b.module);
                            }
                        }
                        break :attrs try attrs.finish(&b.module);
                    },
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &[6]Value{
                        start_vip,
                        OpcodeHandlerParam.vsp.arg(wip),
                        OpcodeHandlerParam.eip.arg(wip),
                        stp,
                        OpcodeHandlerParam.ctx.arg(wip),
                        table_idx,
                    },
                    "",
                ),
            );
        }

        try fill.finish(b);
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
        try local_get.jmpToNextHandler(b, .{ .vip = new_vip, .vsp = new_vsp });
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
            &.{ dst_addr, try local_set.gepOperandAt(b, 0), value_size_bytes, .false },
            "",
        );

        const new_vsp = switch (opcode) {
            .@"local.set" => try local_set.adjustVspBy(b, -1),
            .@"local.tee" => OpcodeHandlerParam.vsp.arg(wip),
            else => unreachable,
        };
        try local_set.jmpToNextHandler(b, .{ .vip = new_vip, .vsp = new_vsp });
        try local_set.finish(b);
    }
}

fn buildGlobalOpcodeHandlers(b: *Builder) Oom!void {
    const global_val_type_field_idx = try b.module.intValue(.i32, 0);
    const global_type = try b.module.structType(.normal, &.{ .i8, .i8 });

    const i3_ty = try b.module.intType(3);
    const block_jmp_lookup_len = 17;
    const block_jmp_lookup = try b.module.addVariable(
        try b.strtabStringSymbolPrefixed("global_val_type_size"),
        try b.module.arrayType(block_jmp_lookup_len, i3_ty),
        .default,
    );
    {
        block_jmp_lookup.setLinkage(.internal, &b.module);
        block_jmp_lookup.setUnnamedAddr(.local_unnamed_addr, &b.module);
        block_jmp_lookup.setMutability(.constant, &b.module);
        block_jmp_lookup.ptrConst(&b.module).global.ptr(&b.module).preemption = .dso_local;
        const size_undef = try b.module.undefConst(i3_ty);
        var entries: [block_jmp_lookup_len]llvm.Builder.Constant = @splat(size_undef);
        const size_4 = try b.module.intConst(i3_ty, 0);
        const size_8 = try b.module.intConst(i3_ty, 1);
        // Currently assumes that a future 32-bit port uses 64-bit references
        entries[0] = size_8; // externref
        entries[1] = size_8; // funcref

        entries[12] = try b.module.intConst(i3_ty, 2); // v128
        entries[13] = size_8; // f64
        entries[14] = size_4; // f32
        entries[15] = size_8; // i64
        entries[16] = size_4; // i32

        try block_jmp_lookup.setInitializer(
            try b.module.arrayConst(block_jmp_lookup.typeOf(&b.module), &entries),
            &b.module,
        );
    }

    for (&[2]ByteOpcode{ .@"global.get", .@"global.set" }) |opcode| {
        var op = try b.opcodeHandler(.{ .byte = opcode });
        const func_idx = op.wip.function;
        const wip = &op.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const idx_result = try b.callDecodeUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
        const new_vip = try wip.extractValue(idx_result, &.{1}, "");
        const global_idx = try wip.extractValue(idx_result, &.{0}, "");
        const value_ptr = try wip.load(
            .normal,
            .ptr,
            try wip.gep(
                .inbounds,
                .ptr,
                try ModuleInstField.globals.load(wip, b),
                &.{global_idx},
                "",
            ),
            .default,
            "",
        );
        const global_val_type = try wip.load(
            .normal,
            .i8,
            try wip.gep(
                .inbounds,
                global_type,
                try ModuleInfoField.global_types.load(wip, b),
                &.{ global_idx, global_val_type_field_idx },
                "",
            ),
            .default,
            "val_type",
        );
        const chosen_blk = try wip.load(.normal, i3_ty, try wip.gep(
            .inbounds,
            i3_ty,
            block_jmp_lookup.toValue(&b.module),
            &.{try wip.bin(.@"sub nuw", global_val_type, try b.module.intValue(.i8, 0x6F), "")},
            "",
        ), .default, "");

        const new_vsp, const src_ptr, const src_align, const dst_ptr, const dst_align =
            ptrs: switch (opcode) {
                .@"global.get" => .{
                    try op.adjustVspBy(b, 1),
                    value_ptr,
                    .default,
                    try op.gepOperandAt(b, -1),
                    value_stack_alignment,
                },
                .@"global.set" => {
                    const src = try op.gepOperandAt(b, 0);
                    break :ptrs .{ src, src, value_stack_alignment, value_ptr, .default };
                },
                else => unreachable,
            };

        var block_indices: [3]Function.Block.Index = undefined;
        for (&block_indices, [3][]const u8{ "Store4", "Store8", "Store16" }) |*blk, name| {
            blk.* = try wip.block(1, name);
        }

        const block_array = try b.module.addVariable(
            try b.strtabStringConcat(&.{ b.options.symbol_prefix, @tagName(opcode), "_blocks" }),
            try b.module.arrayType(3, .ptr),
            .default,
        );
        block_array.setLinkage(.internal, &b.module);
        block_array.setUnnamedAddr(.local_unnamed_addr, &b.module);
        block_array.setMutability(.constant, &b.module);
        block_array.ptrConst(&b.module).global.ptr(&b.module).preemption = .dso_local;

        _ = try wip.indirectbr(
            try wip.load(
                .normal,
                .ptr,
                try wip.gep(.normal, .ptr, block_array.toValue(&b.module), &.{chosen_blk}, ""),
                .default,
                "",
            ),
            &block_indices,
        );

        for (block_indices, [3]Type{ .i32, .i64, b.value_structs.i64 }) |blk, ty| {
            wip.cursor = .{ .block = blk };
            _ = try wip.store(
                .normal,
                try wip.load(.normal, ty, src_ptr, src_align, ""),
                dst_ptr,
                dst_align,
            );
            try op.jmpToNextHandler(b, .{ .vip = new_vip, .vsp = new_vsp });
        }

        try op.finish(b);

        var block_constants: [3]llvm.Builder.Constant = undefined;
        for (block_indices, &block_constants) |blk_idx, *c| {
            c.* = try b.module.blockAddrConst(func_idx, blk_idx);
        }
        try block_array.setInitializer(
            try b.module.arrayConst(block_array.typeOf(&b.module), &block_constants),
            &b.module,
        );
    }
}

fn buildBulkDropOpcodeHandlers(b: *Builder) Oom!void {
    const drop_flag_size = try b.module.intValue(.i32, 32);
    const drop_flag_bit_index_mask = try b.module.intValue(.i32, 32 - 1);
    const xor_not_mask = try b.module.intValue(.i32, -1);
    const one_to_shift = try b.module.intValue(.i32, 1);
    for (
        &[2]opcodes.FCPrefixOpcode{ .@"data.drop", .@"elem.drop" },
        &[2]ModuleInstField{ .datas_drop_mask, .elems_drop_mask },
    ) |opcode, drop_flags_field| {
        var drop = try b.opcodeHandler(.{ .fc = opcode });
        const wip = &drop.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const decode_idx = try b.callDecodeUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
        const idx = try wip.extractValue(decode_idx, &.{0}, "idx");
        const vip_after_idx = try wip.extractValue(decode_idx, &.{1}, "vip_after_idx");

        const flag_word_ptr = try wip.gep(
            .inbounds,
            .i32,
            try drop_flags_field.load(wip, b),
            &.{try wip.cast(.zext, try wip.bin(.udiv, idx, drop_flag_size, ""), b.size_type, "")},
            "",
        );

        const flag_word = try wip.load(.normal, .i32, flag_word_ptr, .default, "flag_word");

        const flag_word_bit_idx = try wip.bin(.@"and", idx, drop_flag_bit_index_mask, "");
        const unset_flag_bit_mask = try wip.bin(
            .xor,
            try wip.bin(.@"shl nuw", one_to_shift, flag_word_bit_idx, ""),
            xor_not_mask,
            "unset_flag_bit",
        );

        const unset_flag_bit = try wip.bin(.@"and", flag_word, unset_flag_bit_mask, "");
        _ = try wip.store(.normal, unset_flag_bit, flag_word_ptr, .default);
        try drop.jmpToNextHandler(b, .{
            .vip = vip_after_idx,
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try drop.finish(b);
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
            try op.jmpToNextHandler(b, .{ .vip = new_vip, .vsp = new_vsp });
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
            });
            try cmp.finish(b);
        }
    }

    for (&[2]struct { WipFunction.Instruction.Tag, u7 }{
        .{ .sext, 's' },
        .{ .zext, 'u' },
    }) |info| {
        const cast, const suffix = info;
        var name_buf = "i64.extend_i32_?".*;
        name_buf[name_buf.len - 1] = suffix;

        var extend = try b.opcodeHandler(.fromName(ByteOpcode, &name_buf));
        extend.wip.cursor = .{ .block = try extend.wip.block(0, "Entry") };
        const un_op = try extend.unOp(b, .i32);
        try un_op.writeResult(&extend, try extend.wip.cast(cast, un_op.c_1, .i64, ""));
        try extend.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&extend.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&extend.wip),
        });
        try extend.finish(b);
    }
}

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
            try c.jmpToNextHandler(b, .{ .vip = new_vip, .vsp = new_vsp });
            try c.finish(b);
        }

        for (&[6]llvm.Builder.FloatCondition{ .oeq, .une, .olt, .ogt, .ole, .oge }) |cond| {
            var cmp = try b.opcodeHandlerFromPrefixedName(ByteOpcode, prefix, @tagName(cond)[1..]);
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
        for ([4]struct { u7, Type }{
            .{ 's', .i32 },
            .{ 'u', .i32 },
            .{ 's', .i64 },
            .{ 'u', .i64 },
        }) |info| {
            const signedness, const to_int_ty = info;
            _ = b.scratch.reset(.retain_capacity);
            var conv = try b.opcodeHandler(
                Opcode.fromName(
                    opcodes.FCPrefixOpcode,
                    try std.fmt.allocPrint(b.scratch.allocator(), "{t}.trunc_sat_{s}_{c}", .{
                        to_int_ty,
                        float_info.prefix,
                        signedness,
                    }),
                ),
            );
            const entry_blk = try conv.wip.block(0, "Entry");
            conv.wip.cursor = .{ .block = entry_blk };
            const un_op = try conv.unOp(b, float_ty);

            const helper = try b.addFunction(
                try b.module.strtabString(
                    try std.fmt.allocPrint(
                        b.scratch.allocator(),
                        "llvm.fpto{[sign]c}i.sat.{[int]t}.{[float]s}",
                        .{ .sign = signedness, .int = to_int_ty, .float = float_info.prefix },
                    ),
                ),
                try b.fnType(to_int_ty, &.{float_info.float_ty}),
                .default,
                .{},
            );

            try un_op.writeResult(
                &conv,
                try conv.wip.call(
                    .normal,
                    .default,
                    .none,
                    helper.typeOf(&b.module),
                    helper.toValue(&b.module),
                    &.{un_op.c_1},
                    "",
                ),
            );
            try conv.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&conv.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&conv.wip),
            });
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
        });
        try promote.finish(b);
    }
}

fn buildReferenceOpcodeHandlers(b: *Builder) Oom!void {
    const null_zero = try b.sizeIntValue(0);
    {
        var op = try b.opcodeHandler(.{ .byte = .@"ref.null" });
        const wip = &op.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const new_vip = try b.callSkipUlebIdx(&op.wip, OpcodeHandlerParam.vip.arg(&op.wip));
        _ = try wip.store(
            .normal,
            null_zero,
            OpcodeHandlerParam.vsp.arg(&op.wip),
            value_stack_alignment,
        );

        const new_vsp = try op.adjustVspBy(b, 1);
        try op.jmpToNextHandler(b, .{ .vip = new_vip, .vsp = new_vsp });
        try op.finish(b);
    }
    {
        var is_null = try b.opcodeHandler(.{ .byte = .@"ref.is_null" });
        const wip = &is_null.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const stack_top = try is_null.gepOperandAt(b, 0);
        const elem = try wip.load(.normal, b.size_type, stack_top, value_stack_alignment, "elem");
        _ = try wip.store(
            .normal,
            try wip.cast(.zext, try wip.icmp(.eq, elem, null_zero, ""), .i32, ""),
            stack_top,
            value_stack_alignment,
        );

        try is_null.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&is_null.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&is_null.wip),
        });
        try is_null.finish(b);
    }
    {
        var func = try b.opcodeHandler(.{ .byte = .@"ref.func" });
        const wip = &func.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const decode_func_idx = try b.callDecodeUlebIdx(wip, OpcodeHandlerParam.vip.arg(&func.wip));
        const vip_after_func_idx = try wip.extractValue(decode_func_idx, &.{1}, "");
        const func_idx = try wip.extractValue(decode_func_idx, &.{0}, "func_idx");

        const helper = try b.addFunction(
            try b.strtabStringSymbolPrefixed("constructFuncRef"),
            try b.fnType(b.size_type, &.{ .i32, .ptr }),
            .ccc,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = FunctionAttributes.Wip{};
            try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
            try b.setFnAttributes(helper, &attrs);
        }

        const ref = try wip.call(
            .normal,
            .ccc,
            attrs: {
                var attrs = FunctionAttributes.Wip{};
                for (&[3]Attribute{ .nonnull, .noundef, .readonly }) |a| {
                    try attrs.addParamAttr(1, a, &b.module);
                }
                break :attrs try attrs.finish(&b.module);
            },
            helper.typeOf(&b.module),
            helper.toValue(&b.module),
            &[2]Value{ func_idx, OpcodeHandlerParam.module.arg(&func.wip) },
            "ref",
        );

        _ = try wip.store(
            .normal,
            ref,
            OpcodeHandlerParam.vsp.arg(&func.wip),
            value_stack_alignment,
        );

        const new_vsp = try func.adjustVspBy(b, 1);
        try func.jmpToNextHandler(b, .{ .vip = vip_after_func_idx, .vsp = new_vsp });
        try func.finish(b);
    }
}

fn buildPrefixOpcodeHandlers(b: *Builder) Oom!void {
    const size_1 = try b.sizeIntValue(1);
    const continuation = try b.module.intValue(.i8, 0x80);
    const value_mask = try b.module.intValue(.i8, 0x7F);

    for (&[2]struct { ByteOpcode, llvm.Builder.Global.Index }{
        .{ .@"0xFC", b.dispatch_tables.fc },
        .{ .@"0xFD", b.dispatch_tables.fd },
    }) |info| {
        var handler = try b.opcodeHandler(.{ .byte = info.@"0" });
        const wip = &handler.wip;

        const jmp_args_template: [10]Value = args: {
            var args: [10]Value = undefined;
            for (std.enums.values(OpcodeHandlerParam), &args) |p, *a| {
                a.* = switch (p) {
                    .vip => undefined,
                    else => p.arg(wip),
                };
            }
            break :args args;
        };

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const table = llvm.Builder.Global.Index.ptrConst(info.@"1", &b.module)
            .kind.variable.toValue(&b.module);

        var blocks: [6]Function.Block.Index = undefined;
        {
            var name_buf: [7]u8 = "Length1".*;
            for (blocks[0..5]) |*blk| {
                defer name_buf[name_buf.len - 1] += 1;
                blk.* = try wip.block(1, &name_buf);
            }
        }

        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const first_byte = try wip.load(.normal, .i8, start_vip, .default, "first_byte");
        const vip_after_byte_0 = try wip.gep(.inbounds, .i8, start_vip, &.{size_1}, "");
        const after_first_byte = try wip.block(1, "AfterFirstByte");
        _ = try wip.brCond(
            try wip.icmp(.ult, first_byte, continuation, ""),
            blocks[0],
            after_first_byte,
            .then_likely,
        );

        wip.cursor = .{ .block = blocks[0] };
        {
            const target = try wip.load(
                .normal,
                .ptr,
                try wip.gep(
                    .inbounds,
                    .ptr,
                    table,
                    &.{try wip.cast(.zext, first_byte, b.size_type, "")},
                    "",
                ),
                .default,
                "",
            );
            var args = jmp_args_template;
            args[@intFromEnum(OpcodeHandlerParam.vip)] = vip_after_byte_0;

            _ = try wip.ret(
                try wip.call(
                    .musttail,
                    b.opcode_handler.call_conv,
                    b.opcode_handler.invoke_attrs,
                    b.opcode_handler.type,
                    target,
                    &args,
                    "",
                ),
            );
        }

        wip.cursor = .{ .block = after_first_byte };
        var accumulator = try wip.cast(
            .zext,
            try wip.bin(.@"and", first_byte, value_mask, ""),
            b.size_type,
            "",
        );
        _ = try wip.br(blocks[1]);

        var current_vip = vip_after_byte_0;
        var jmp_to_handler_name = "JumpToHandlerLength2".*;
        for (1..5, blocks[1..5], blocks[2..6]) |i, current_blk, next_blk| {
            wip.cursor = .{ .block = current_blk };
            if (i >= 3) {
                _ = try wip.callIntrinsicAssumeCold();
            }

            const next_byte = try wip.load(.normal, .i8, current_vip, .default, "");
            const vip_after_next_byte = try wip.gep(.inbounds, .i8, current_vip, &.{size_1}, "");
            defer current_vip = vip_after_next_byte;
            accumulator = try wip.bin(
                .@"or",
                try wip.bin(
                    .@"shl nuw",
                    try wip.cast(
                        .zext,
                        try wip.bin(.@"and", next_byte, value_mask, ""),
                        b.size_type,
                        "",
                    ),
                    try b.sizeIntValue(@intCast(i * 7)),
                    "",
                ),
                // Having this as first argument causes "Invalid record" LLVM error?
                accumulator,
                "",
            );

            if (i < 4) {
                const jmp_to_handler = try wip.block(1, &jmp_to_handler_name);
                defer jmp_to_handler_name[jmp_to_handler_name.len - 1] += 1;
                _ = try wip.brCond(
                    try wip.icmp(.ult, next_byte, continuation, ""),
                    jmp_to_handler,
                    next_blk,
                    .then_likely,
                );

                wip.cursor = .{ .block = jmp_to_handler };
            }

            const target = try wip.load(
                .normal,
                .ptr,
                try wip.gep(.inbounds, .ptr, table, &.{accumulator}, ""),
                .default,
                "",
            );
            var args = jmp_args_template;
            args[@intFromEnum(OpcodeHandlerParam.vip)] = vip_after_next_byte;

            _ = try wip.ret(
                try wip.call(
                    .musttail,
                    b.opcode_handler.call_conv,
                    b.opcode_handler.invoke_attrs,
                    b.opcode_handler.type,
                    target,
                    &args,
                    "",
                ),
            );
        }

        try handler.finish(b);
    }
}

const std = @import("std");
const EnumSet = @import("enum_set").EnumSet;
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;
const opcodes = @import("opcodes");
const ByteOpcode = opcodes.ByteOpcode;
const Builder = @import("Builder.zig");
const FloatInfo = @import("FloatInfo.zig");
const Opcode = @import("opcode.zig").Opcode;
const OpcodeHandler = @import("OpcodeHandler.zig");
const ModuleInstField = OpcodeHandler.ModuleInstField;
const MemInstField = OpcodeHandler.MemInstField;
const OpcodeHandlerParam = @import("opcode_handler_param.zig").OpcodeHandlerParam;

const llvm = std.zig.llvm;
const Attribute = llvm.Builder.Attribute;
const Function = llvm.Builder.Function;
const FunctionAttributes = llvm.Builder.FunctionAttributes;
const Intrinsic = llvm.Builder.Intrinsic;
const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const Variable = llvm.Builder.Variable;
const WipFunction = llvm.Builder.WipFunction;
