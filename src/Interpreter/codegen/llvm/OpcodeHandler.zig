wip: WipFunction,

const OpcodeHandler = @This();

/// Finishes the basic block `wip` is positioned at.
pub fn jmpToNextHandler(
    handler: *OpcodeHandler,
    b: *Builder,
    updates: struct {
        vsp: Value,
        vip: Value,
        stp: Value = .none,
        // Used in function calls.
        locals: Value = .none,
        module: Value = .none,
        memories: Value = .none,
        eip: Value = .none,
    },
) Oom!void {
    const wip = &handler.wip;
    const after_next_ip_byte = try wip.gep(
        .inbounds,
        .i8,
        updates.vip,
        &.{try b.sizeIntValue(1)},
        "after_next_ip_byte",
    );

    const next_handler_args = args: {
        var args: [10]Value = undefined;
        for (&args, std.enums.values(OpcodeHandlerParam)) |*a, param| {
            a.* = arg: {
                switch (param) {
                    .vsp => break :arg updates.vsp,
                    .vip => break :arg after_next_ip_byte,
                    inline .stp,
                    .locals,
                    .module,
                    .memories,
                    .eip,
                    => |tag| if (@field(updates, @tagName(tag)) != .none) {
                        break :arg @field(updates, @tagName(tag));
                    },
                    else => {},
                }

                break :arg param.arg(wip);
            };
        }

        break :args args;
    };

    const fuel_ptr = OpcodeHandlerParam.fuel.arg(wip);
    const current_fuel = try wip.load(.normal, .i64, fuel_ptr, .default, "current_fuel");
    const next_opcode = try wip.block(1, "NextOpcode");
    const out_of_fuel = try wip.block(1, "OutOfFuel");
    _ = try wip.brCond(
        try wip.icmp(.ugt, current_fuel, try b.module.intValue(.i64, 0), "has_fuel"),
        next_opcode,
        out_of_fuel,
        .then_likely,
    );

    {
        wip.cursor = .{ .block = next_opcode };
        const new_fuel = try wip.bin(
            .@"sub nuw",
            current_fuel,
            try b.module.intValue(.i64, 1),
            "new_fuel",
        );
        _ = try wip.store(.normal, new_fuel, fuel_ptr, .default);

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
        _ = try wip.ret(
            try wip.call(
                .musttail,
                b.opcode_handler.call_conv,
                b.opcode_handler.invoke_attrs,
                b.opcode_handler.type,
                next_handler,
                &next_handler_args,
                "",
            ),
        );
    }

    wip.cursor = .{ .block = out_of_fuel };
    _ = try wip.callIntrinsicAssumeCold();
    _ = try wip.ret(
        try wip.call(
            .musttail,
            b.opcode_handler.call_conv,
            attrs: {
                var attrs = try b.opcode_handler.invoke_attrs.toWip(&b.module);
                try attrs.addFnAttr(.@"noinline", &b.module);
                break :attrs try attrs.finish(&b.module);
            },
            b.opcode_handler.type,
            b.out_of_fuel_handler.toValue(&b.module),
            &args: {
                var args = next_handler_args;
                args[@intFromEnum(OpcodeHandlerParam.vip)] = updates.vip;
                break :args args;
            },
            "",
        ),
    );
}

pub const ModuleInstField = enum(u4) {
    buffer_len,
    module,
    func_imports,
    func_blocks,
    mems,
    tables,
    globals,
    datas_drop_mask,
    elems_drop_mask,

    /// Obtains a `ptr` to a field within the `ModuleInst`.
    pub fn gep(field: ModuleInstField, wip: *WipFunction, b: *const Builder) Oom!Value {
        return try wip.gepStruct(
            b.module_inst,
            OpcodeHandlerParam.module.arg(wip),
            @intFromEnum(field),
            @tagName(field),
        );
    }

    pub fn typeOf(field: ModuleInstField, b: *const Builder) Type {
        return switch (field) {
            .buffer_len => b.size_type,
            .module,
            .func_imports,
            .func_blocks,
            .mems,
            .tables,
            .globals,
            .datas_drop_mask,
            .elems_drop_mask,
            => .ptr,
        };
    }

    pub fn load(field: ModuleInstField, wip: *WipFunction, b: *const Builder) Oom!Value {
        return try wip.load(
            .normal,
            field.typeOf(b),
            try field.gep(wip, b),
            .default,
            @tagName(field),
        );
    }
};

/// Cursor of `wip` should be in the same basic block as the call to the helper function
/// that produced the `wasm_frame`.
pub fn jmpToHostOrNextHandler(
    handler: *OpcodeHandler,
    b: *Builder,
    out_alloca: Value,
    /// A `null` value indicates that a transition to the host should be performed.
    wasm_frame: Value,
) Oom!void {
    std.debug.assert(out_alloca.typeOfWip(&handler.wip) == .ptr);
    std.debug.assert(wasm_frame.typeOfWip(&handler.wip) == .ptr);
    const returned_to_wasm = try handler.wip.block(1, "ReturnedToWasm");
    const returned_to_host = try handler.wip.block(1, "ReturnedToHost");
    _ = try handler.wip.brCond(
        try handler.wip.icmp(.ne, wasm_frame, try b.module.nullValue(.ptr), ""),
        returned_to_wasm,
        returned_to_host,
        .none,
    );

    const alloca_ty = b.struct_3_ptrs;
    const wasm_frame_ty = b.struct_3_ptrs;
    handler.wip.cursor = .{ .block = returned_to_wasm };
    const new_module = try handler.wip.load(
        .normal,
        .ptr,
        try handler.wip.gepStruct(alloca_ty, out_alloca, 2, ""),
        .default,
        "module",
    );
    try handler.jmpToNextHandler(b, .{
        .vsp = try handler.wip.load(
            .normal,
            .ptr,
            try handler.wip.gepStruct(alloca_ty, out_alloca, 1, ""),
            .default,
            "VSP",
        ),
        .vip = try handler.wip.load(.normal, .ptr, wasm_frame, .default, "VIP"),
        .stp = try handler.wip.load(
            .normal,
            .ptr,
            try handler.wip.gepStruct(wasm_frame_ty, wasm_frame, 2, ""),
            .default,
            "STP",
        ),
        .locals = try handler.wip.load(.normal, .ptr, out_alloca, .default, "locals"),
        .module = new_module,
        .memories = try handler.wip.load(
            .normal,
            .ptr,
            try handler.wip.gepStruct(
                b.module_inst,
                new_module,
                @intFromEnum(ModuleInstField.mems),
                "",
            ),
            .default,
            "mems",
        ),
        .eip = try handler.wip.load(
            .normal,
            .ptr,
            try handler.wip.gepStruct(wasm_frame_ty, wasm_frame, 1, ""),
            .default,
            "EIP",
        ),
    });

    handler.wip.cursor = .{ .block = returned_to_host };
    _ = try handler.wip.ret(try handler.wip.load(.normal, .i32, out_alloca, .default, ""));
}

pub fn adjustVspBy(handler: *OpcodeHandler, b: *Builder, amt: i8) Oom!Value {
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
pub fn gepOperandAt(
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

pub fn loadOperandAt(
    handler: *OpcodeHandler,
    b: *Builder,
    ty: Type,
    /// `0` refers to the value currently on the top of the stack.
    index: u8,
    name: []const u8,
) Oom!Value {
    return try handler.wip.load(
        .normal,
        ty,
        try handler.gepOperandAt(b, index),
        value_stack_alignment,
        name,
    );
}

const BinOpOperands = struct {
    c_2: Value,
    c_1: Value,
    /// A `ptr` where the result of the operation is written.
    result: Value,

    pub fn writeResult(op: BinOpOperands, handler: *OpcodeHandler, result: Value) Oom!void {
        _ = try handler.wip.store(.normal, result, op.result, value_stack_alignment);
    }
};

/// Loads two operands of type `ty` from the operand stack, and calculates the `ptr`
/// where the result is written.
pub fn binOp(handler: *OpcodeHandler, b: *Builder, ty: Type) Oom!BinOpOperands {
    const c_1_addr = try handler.gepOperandAt(b, 1);
    return .{
        .c_2 = try handler.loadOperandAt(b, ty, 0, "c_2"),
        .c_1 = try handler.wip.load(.normal, ty, c_1_addr, value_stack_alignment, "c_1"),
        .result = c_1_addr,
    };
}

const UnOpOperands = struct {
    c_1: Value,
    /// A `ptr` where the result of the operation is written.
    result: Value,

    pub fn writeResult(op: UnOpOperands, handler: *OpcodeHandler, result: Value) Oom!void {
        _ = try handler.wip.store(.normal, result, op.result, value_stack_alignment);
    }
};

pub fn unOp(handler: *OpcodeHandler, b: *Builder, ty: Type) Oom!UnOpOperands {
    const result = try handler.gepOperandAt(b, 0);
    return .{
        .c_1 = try handler.wip.load(.normal, ty, result, value_stack_alignment, "c_1"),
        .result = result,
    };
}

const TestOpOperands = struct {
    c_1: Value,
    /// A `ptr` where the `i32` result of the test is written.
    result: Value,

    pub fn writeResult(op: TestOpOperands, handler: *OpcodeHandler, result: Value) Oom!void {
        std.debug.assert(result.typeOfWip(&handler.wip) == .i32);
        _ = try handler.wip.store(.normal, result, op.result, value_stack_alignment);
    }
};

pub fn testOp(handler: *OpcodeHandler, b: *Builder, ty: Type) Oom!TestOpOperands {
    const result = try handler.gepOperandAt(b, 0);
    return .{
        .c_1 = try handler.wip.load(.normal, ty, result, value_stack_alignment, "c_1"),
        .result = result,
    };
}

/// Finishes the basic block `wip` is positioned at.
pub fn jmpTrapWithNumericCode(
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

    _ = try handler.wip.callIntrinsicAssumeCold();
    _ = try handler.wip.ret(
        try handler.wip.call(
            .tail,
            .ccc,
            attrs: {
                var attrs = try b.value_copy.attributes.toWip(&b.module);
                try b.fnAttributes(&attrs, &.{ .mustprogress, .norecurse, .nounwind });
                break :attrs try attrs.finish(&b.module);
            },
            b.trap_with_numeric_code.typeOf(&b.module),
            b.trap_with_numeric_code.toValue(&b.module),
            &params,
            "",
        ),
    );
}

/// Produces a `ptr` to a `TableInst`.
pub fn tableInstPtr(handler: *OpcodeHandler, b: *Builder, table_idx: Value) Oom!Value {
    const wip = &handler.wip;
    // TableIdx is currently a `u7`.
    const max_table_idx = try b.module.intValue(table_idx.typeOfWip(wip), std.math.maxInt(u7));
    const table_idx_range = try wip.icmp(.ule, table_idx, max_table_idx, "");
    _ = try wip.callIntrinsic(.normal, .none, .assume, &.{}, &.{table_idx_range}, "");

    const table_ptr_ptr = try wip.gep(
        .inbounds,
        .ptr,
        try ModuleInstField.tables.load(wip, b),
        &.{table_idx},
        "",
    );

    return try wip.load(.normal, .ptr, table_ptr_ptr, .default, "table");
}

pub const LinearMemoryAccess = struct {
    /// A `ptr` into WASM linear memory.
    ptr: Value,
    /// Refers to the first byte after the `memarg`
    vip: Value,
};

pub const MemInstField = enum(u8) {
    base,
    size,
    capacity,
    limit,
    vtable,

    /// Obtains a `ptr` to a field of a `ptr` to a `MemInst`.
    pub fn gep(field: MemInstField, wip: *WipFunction, b: *Builder, ptr: Value) Oom!Value {
        std.debug.assert(ptr.typeOfWip(wip) == .ptr);
        const field_ptr = try wip.gep(
            .inbounds,
            b.mem_inst,
            ptr,
            &.{ .@"0", try b.module.intValue(.i32, @intFromEnum(field)) },
            "",
        );
        return field_ptr;
    }

    pub fn typeOf(field: MemInstField, b: *const Builder) Type {
        return switch (field) {
            .base, .vtable => .ptr,
            .size, .capacity, .limit => b.size_type,
        };
    }

    /// Loads a field given a `ptr` to a `MemInst`.
    pub fn load(field: MemInstField, wip: *WipFunction, b: *Builder, ptr: Value) Oom!Value {
        return try wip.load(.normal, field.typeOf(b), try field.gep(wip, b, ptr), .default, "");
    }
};

/// Assumes that the `memarg` is located at `OpcodeHandlerParam.vip`
pub fn linearMemoryAccess(
    handler: *OpcodeHandler,
    b: *Builder,
    /// Offset from VSP to `i32` memory offset, where `0` is the top of the stack.
    offset_idx: u8,
    /// The size, in bytes, of the memory being accessed.
    access_size: std.mem.Alignment,
    /// Where control flow goes after the bounds check is successful.
    ///
    /// The cursor of the `WipFunction` is set to this value.
    bounds_check_success: llvm.Builder.Function.Block.Index,
) Oom!LinearMemoryAccess {
    const wip = &handler.wip;
    const vip_after_align = try b.callSkipUlebIdx(wip, OpcodeHandlerParam.vip.arg(wip));
    const decode_offset = try b.callDecodeUlebIdx(wip, vip_after_align);

    const vip_after_offset = try wip.extractValue(decode_offset, &.{1}, "");
    // Assumes that only 32-bit memories are supported.
    // Not i33, since end offset calculation could overflow that
    const addr_ty = try b.module.intType(34);

    const imm_offset = try wip.cast(
        .zext,
        try wip.extractValue(decode_offset, &.{0}, ""),
        addr_ty,
        "",
    );
    const arg_offset = try wip.cast(
        .zext,
        try handler.loadOperandAt(b, .i32, offset_idx, "offset"),
        addr_ty,
        "",
    );

    const load_offset = try wip.bin(.@"add nuw", imm_offset, arg_offset, "load_offset");
    const end_offset = try wip.bin(
        .@"add nuw",
        load_offset,
        try b.module.intValue(addr_ty, access_size.toByteUnits()),
        "end_offset",
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
    const oob = try wip.block(1, "MemoryAccessOob");
    const mem_size = try MemInstField.size.load(wip, b, mem_inst_ptr);
    _ = try wip.brCond(
        try wip.icmp(
            .ule,
            try wip.cast(.zext, end_offset, b.size_type, ""),
            mem_size,
            "",
        ),
        bounds_check_success,
        oob,
        .then_likely,
    );

    wip.cursor = .{ .block = oob };
    _ = try wip.callIntrinsicAssumeCold();
    _ = try wip.ret(
        try wip.call(
            .tail,
            .ccc,
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

pub const SideTableEntryField = enum(u2) {
    delta_ip,
    delta_stp,
    copy_count,
    pop_count,

    pub fn typeOf(field: SideTableEntryField) Type {
        return switch (field) {
            .delta_ip => .i32,
            .delta_stp => .i16,
            .copy_count, .pop_count => .i8,
        };
    }

    pub fn load(
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

/// Callers can assume that `handler.wip` will still refer to the same basic block as it was
/// before `takeBranch()` was called.
pub fn takeBranch(handler: *OpcodeHandler, b: *Builder, info: struct {
    branch_ip: Value,
    vsp: Value,
    stp: Value = .none,
}) Oom!TakeBranch {
    const wip = &handler.wip;
    const stp = if (info.stp == .none) OpcodeHandlerParam.stp.arg(wip) else info.stp;

    const delta_ip = try SideTableEntryField.delta_ip.load(handler, b, stp);
    const copy_count_in_values = try SideTableEntryField.copy_count.load(handler, b, stp);
    const copy_count_in_values_ext = try wip.cast(
        .zext,
        copy_count_in_values,
        b.size_type,
        "copy_count_ext",
    );
    const pop_count_in_values = try wip.cast(
        .zext,
        try SideTableEntryField.pop_count.load(handler, b, stp),
        b.size_type,
        "pop_count",
    );
    const delta_stp = try SideTableEntryField.delta_stp.load(handler, b, stp);

    // These GEPs must perform signed subtraction
    const new_vip = try wip.gep(.inbounds, .i8, info.branch_ip, &.{delta_ip}, "");
    const new_stp = try wip.gep(.inbounds, b.side_table_entry, stp, &.{delta_stp}, "");

    const size_0 = try b.sizeIntValue(0);
    const dst_vsp = try wip.gep(
        .inbounds,
        b.value_structs.i64,
        info.vsp,
        &.{try wip.bin(.@"sub nsw", size_0, pop_count_in_values, "negate")},
        "dst_vsp",
    );
    const src_vsp = try wip.gep(
        .inbounds,
        b.value_structs.i64,
        info.vsp,
        &.{try wip.bin(.@"sub nsw", size_0, copy_count_in_values_ext, "negate")},
        "src_vsp",
    );

    const new_vsp = try wip.gep(
        .inbounds,
        b.value_structs.i64,
        dst_vsp,
        &.{copy_count_in_values_ext},
        "",
    );

    {
        // Too much of a hassle to create a new branch, as callers already assume that the
        // current basic block remains the same (for PHI nodes).
        _ = try wip.call(
            .normal,
            b.move_values_for_branch.ptrConst(&b.module).call_conv,
            .none,
            b.move_values_for_branch.typeOf(&b.module),
            b.move_values_for_branch.toValue(&b.module),
            &.{ dst_vsp, src_vsp, copy_count_in_values },
            "",
        );
    }

    return .{ .vip = new_vip, .vsp = new_vsp, .stp = new_stp };
}

pub fn finish(handler: *OpcodeHandler, b: *Builder) Oom!void {
    try handler.wip.finish();
    handler.wip.deinit();
    b.opcode_handler_writing_lock.unlock();
}

const std = @import("std");
const Oom = std.mem.Allocator.Error;
const llvm = std.zig.llvm;

const Builder = @import("Builder.zig");
const value_stack_alignment = Builder.value_stack_alignment;
const OpcodeHandlerParam = @import("opcode_handler_param.zig").OpcodeHandlerParam;

const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const WipFunction = llvm.Builder.WipFunction;
