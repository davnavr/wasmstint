//! Writes definitions for all 128-bit SIMD opcode handlers.

pub fn buildOpcodeHandlers(b: *Builder) Oom!void {
    try buildMemoryLoadOpcodeHandlers(b);
    try buildBitwiseOpcodeHandlers(b);
    try buildIntegerOpcodeHandlers(b);
}

const Interpretation = enum(u3) {
    i8x16,
    i16x8,
    i32x4,
    i64x2,
    f32x4,
    f64x2,

    fn laneType(i: Interpretation) Type {
        return switch (i) {
            .i8x16 => .i8,
            .i16x8 => .i16,
            .i32x4 => .i32,
            .i64x2 => .i64,
            .f32x4 => .float,
            .f64x2 => .double,
        };
    }

    fn laneCount(i: Interpretation) u5 {
        return switch (i) {
            .i8x16 => 16,
            .i16x8 => 8,
            .i32x4, .f32x4 => 4,
            .i64x2, .f64x2 => 2,
        };
    }

    fn vectorType(i: Interpretation, b: *Builder) Oom!Type {
        return try b.module.vectorType(.normal, i.laneCount(), i.laneType());
    }
};

const byte_alignment = llvm.Builder.Alignment.fromByteUnits(1);

fn buildMemoryLoadOpcodeHandlers(b: *Builder) Oom!void {
    const i8x16 = try Interpretation.i8x16.vectorType(b);
    {
        var load = try b.opcodeHandler(.{ .fd = .@"v128.load" });

        load.wip.cursor = .{ .block = try load.wip.block(0, "Entry") };
        const perform_load = try load.wip.block(1, "Load");
        const access = try load.linearMemoryAccess(b, 0, .@"16", perform_load);
        const loaded_value = try load.wip.load(
            .normal,
            i8x16,
            access.ptr,
            byte_alignment,
            "loaded_value",
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
}

fn buildBitwiseOpcodeHandlers(b: *Builder) Oom!void {
    {
        var op = try b.opcodeHandler(.{ .fd = .@"v128.not" });
        op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
        const un_op = try op.unOp(b, .i128);
        try un_op.writeResult(
            &op,
            try op.wip.bin(.xor, un_op.c_1, try b.module.intValue(.i128, -1), "not"),
        );
        try op.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&op.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&op.wip),
        });
        try op.finish(b);
    }
    for (&[3]WipFunction.Instruction.Tag{ .@"and", .@"or", .xor }) |instr| {
        var op = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, "v128", @tagName(instr));
        op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
        const bin_op = try op.binOp(b, .i128);
        try bin_op.writeResult(&op, try op.wip.bin(instr, bin_op.c_1, bin_op.c_2, ""));
        const new_vsp = try op.adjustVspBy(b, -1);
        try op.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&op.wip),
            .vsp = new_vsp,
        });
        try op.finish(b);
    }
}

fn buildIntegerOpcodeHandlers(b: *Builder) Oom!void {
    for (&[4]Interpretation{ .i8x16, .i16x8, .i32x4, .i64x2 }) |interp| {
        const lane_ty = interp.laneType();
        const vector_ty = try interp.vectorType(b);

        const shift_mask = try b.module.intValue(.i32, lane_ty.scalarBits(&b.module) - 1);
        for (&[3]struct { WipFunction.Instruction.Tag, []const u8 }{
            .{ .shl, "shl" },
            .{ .ashr, "shr_s" },
            .{ .lshr, "shr_u" },
        }) |info| {
            const op_tag, const name = info;
            var op = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), name);
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const shift_amt = try op.wip.splatVector(
                vector_ty,
                try op.wip.cast(
                    if (lane_ty == .i64) .zext else .trunc,
                    try op.wip.bin(
                        .@"and",
                        try op.loadOperandAt(b, .i32, 0, "c_2"),
                        shift_mask,
                        "",
                    ),
                    lane_ty,
                    "shift_amt",
                ),
                "shift_amt_splat",
            );
            const result_ptr = try op.gepOperandAt(b, 1);
            const to_shift = try op.wip.load(
                .normal,
                vector_ty,
                result_ptr,
                value_stack_alignment,
                "c_1",
            );
            _ = try op.wip.store(
                .normal,
                try op.wip.bin(op_tag, to_shift, shift_amt, "to_shift"),
                result_ptr,
                value_stack_alignment,
            );
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(
                b,
                .{ .vip = OpcodeHandlerParam.vip.arg(&op.wip), .vsp = new_vsp },
            );
            try op.finish(b);
        }
    }
}

const std = @import("std");
const llvm = std.zig.llvm;
const Oom = std.mem.Allocator.Error;
const FDPrefixOpcode = @import("opcodes").FDPrefixOpcode;
const OpcodeHandlerParam = @import("opcode_handler_param.zig").OpcodeHandlerParam;

const Builder = @import("Builder.zig");
const value_stack_alignment = Builder.value_stack_alignment;

const Constant = llvm.Builder.Constant;
const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const WipFunction = llvm.Builder.WipFunction;
