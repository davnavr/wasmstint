//! Writes definitions for all 128-bit SIMD opcode handlers.

pub fn buildOpcodeHandlers(b: *Builder) Oom!void {
    try buildMemoryLoadOpcodeHandlers(b);
    try buildBitwiseOpcodeHandlers(b);
    try buildBooleanOpcodeHandlers(b);
    try buildConstructionOpcodeHandlers(b);
    try buildConversionOpcodeHandlers(b);

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
    const all_ones_i128 = try b.module.intValue(.i128, -1);
    const i8x16 = try b.module.vectorType(.normal, 16, .i8);
    const all_ones_i8x16 = try b.module.vectorValue(
        i8x16,
        &@as([16]Constant, @splat(try b.module.intConst(.i8, -1))),
    );
    {
        var op = try b.opcodeHandler(.{ .fd = .@"v128.not" });
        op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
        const un_op = try op.unOp(b, .i128);
        try un_op.writeResult(
            &op,
            try op.wip.bin(.xor, un_op.c_1, all_ones_i128, "not"),
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
        const bin_op = try op.binOp(b, i8x16);
        try bin_op.writeResult(&op, try op.wip.bin(instr, bin_op.c_1, bin_op.c_2, ""));
        const new_vsp = try op.adjustVspBy(b, -1);
        try op.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&op.wip),
            .vsp = new_vsp,
        });
        try op.finish(b);
    }

    {
        var op = try b.opcodeHandler(.{ .fd = .@"v128.andnot" });
        op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
        const bin_op = try op.binOp(b, i8x16);
        try bin_op.writeResult(
            &op,
            try op.wip.bin(
                .@"and",
                bin_op.c_1,
                try op.wip.bin(.xor, bin_op.c_2, all_ones_i8x16, "not"),
                "and",
            ),
        );

        const new_vsp = try op.adjustVspBy(b, -1);
        try op.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&op.wip),
            .vsp = new_vsp,
        });
        try op.finish(b);
    }

    // https://github.com/WebAssembly/relaxed-simd/issues/17
    // - ARM NEON has `bsl`
    // - PowerPC AltiVec has `xxsel`
    {
        var sel = try b.opcodeHandler(.{ .fd = .@"v128.bitselect" });
        sel.wip.cursor = .{ .block = try sel.wip.block(0, "Entry") };
        const result_ptr = try sel.gepOperandAt(b, 2);
        const op_a = try sel.wip.load(.normal, i8x16, result_ptr, value_stack_alignment, "a");
        const op_b = try sel.loadOperandAt(b, i8x16, 1, "b");
        const mask = try sel.loadOperandAt(b, i8x16, 0, "mask");
        const result = try sel.wip.bin(
            .@"or",
            try sel.wip.bin(.@"and", op_a, mask, ""),
            try sel.wip.bin(
                .@"and",
                op_b,
                try sel.wip.bin(.xor, all_ones_i8x16, mask, "not_mask"),
                "",
            ),
            "result",
        );
        _ = try sel.wip.store(.normal, result, result_ptr, value_stack_alignment);

        const new_vsp = try sel.adjustVspBy(b, -2);
        try sel.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&sel.wip),
            .vsp = new_vsp,
        });
        try sel.finish(b);
    }
}

fn buildBooleanOpcodeHandlers(b: *Builder) Oom!void {
    {
        var any_true = try b.opcodeHandler(.{ .fd = .@"v128.any_true" });
        any_true.wip.cursor = .{ .block = try any_true.wip.block(0, "Entry") };
        const un_op = try any_true.unOp(b, .i128);
        const any_bit_set = try any_true.wip.icmp(
            .ne,
            un_op.c_1,
            try b.module.intValue(.i128, 0),
            "any_bit_set",
        );
        try un_op.writeResult(&any_true, try any_true.wip.cast(.zext, any_bit_set, .i32, "result"));
        try any_true.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&any_true.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&any_true.wip),
        });
        try any_true.finish(b);
    }

    for (&[4]Interpretation{ .i8x16, .i16x8, .i32x4, .i64x2 }) |interp| {
        const vec_ty = try interp.vectorType(b);
        const int_ty = interp.laneType();
        const lane_count_int = try b.module.intType(interp.laneCount());
        {
            const splat_zero_lanes = try b.module.splatValue(
                vec_ty,
                try b.module.intConst(int_ty, 0),
            );

            var all_true = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                "all_true",
            );
            all_true.wip.cursor = .{ .block = try all_true.wip.block(0, "Entry") };
            const un_op = try all_true.unOp(b, vec_ty);
            const lane_is_zero = try all_true.wip.icmp(
                .eq,
                un_op.c_1,
                splat_zero_lanes,
                "lane_is_zero.0",
            );
            const lane_is_zero_int = try all_true.wip.cast(
                .bitcast,
                lane_is_zero,
                lane_count_int,
                "lane_is_zero.1",
            );
            const non_zero = try all_true.wip.icmp(
                .eq,
                lane_is_zero_int,
                try b.module.intValue(lane_count_int, 0),
                "non_zero",
            );
            try un_op.writeResult(
                &all_true,
                try all_true.wip.cast(.zext, non_zero, .i32, "result"),
            );
            try all_true.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&all_true.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&all_true.wip),
            });
            try all_true.finish(b);
        }
        {
            const splat_shift_lanes = try b.module.splatValue(
                vec_ty,
                try b.module.intConst(int_ty, int_ty.scalarBits(&b.module) - 1),
            );

            // On x86, should compile down to `pmovmskb`/`movmskps`/`movmskpd`.
            var bitmask = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                "bitmask",
            );
            const wip = &bitmask.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const un_op = try bitmask.unOp(b, vec_ty);
            const shifted_high_bit = try wip.bin(
                .lshr,
                un_op.c_1,
                splat_shift_lanes,
                "shifted_high_bit",
            );
            const high_bit = try wip.cast(
                .trunc,
                shifted_high_bit,
                try b.module.vectorType(.normal, interp.laneCount(), .i1),
                "high_bit",
            );
            const high_bit_int = try wip.cast(.bitcast, high_bit, lane_count_int, "");
            try un_op.writeResult(&bitmask, try wip.cast(.zext, high_bit_int, .i32, ""));
            try bitmask.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(wip),
                .vsp = OpcodeHandlerParam.vsp.arg(wip),
            });
            try bitmask.finish(b);
        }
    }
}

fn buildConstructionOpcodeHandlers(b: *Builder) Oom!void {
    {
        var op = try b.opcodeHandler(.{ .fd = .@"v128.const" });
        const wip = &op.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const initial_vip = OpcodeHandlerParam.vip.arg(&op.wip);
        const value_size_bytes = try b.sizeIntValue(16);
        const vip_after_imm = try wip.gep(
            .inbounds,
            .i8,
            initial_vip,
            &.{value_size_bytes},
            "vip_after_imm",
        );
        _ = try wip.callIntrinsic(
            .normal,
            attrs: {
                var attrs = llvm.Builder.FunctionAttributes.Wip{};
                defer attrs.deinit(&b.module);
                for (
                    0..2,
                    [2]llvm.Builder.Alignment{ value_stack_alignment, byte_alignment },
                ) |i, a| {
                    for ([4]llvm.Builder.Attribute{
                        .{ .@"align" = a },
                        .noundef,
                        .nonnull,
                        .{ .dereferenceable = 16 },
                    }) |attr| {
                        try attrs.addParamAttr(i, attr, &b.module);
                    }
                }
                break :attrs try attrs.finish(&b.module);
            },
            .@"memcpy.inline",
            &b.value_copy.overload,
            &.{ OpcodeHandlerParam.vsp.arg(wip), initial_vip, value_size_bytes, .false },
            "",
        );

        const new_vsp = try op.adjustVspBy(b, 1);
        try op.jmpToNextHandler(b, .{ .vsp = new_vsp, .vip = vip_after_imm });
        try op.finish(b);
    }
}

fn buildConversionOpcodeHandlers(b: *Builder) Oom!void {
    const i32x4_vec = try Interpretation.i32x4.vectorType(b);
    const f32x4_vec = try Interpretation.f32x4.vectorType(b);
    for ([2]struct { WipFunction.Instruction.Tag, []const u8 }{
        .{ .sitofp, "convert_i32x4_s" },
        .{ .uitofp, "convert_i32x4_u" },
    }) |info| {
        const cast, const name = info;
        var conv = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, "f32x4", name);
        const wip = &conv.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const un_op = try conv.unOp(b, i32x4_vec);
        try un_op.writeResult(&conv, try conv.wip.cast(cast, un_op.c_1, f32x4_vec, "result"));
        try conv.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try conv.finish(b);
    }

    const f64x2_vec = try Interpretation.f64x2.vectorType(b);
    const i32x2_vec = try b.module.vectorType(.normal, 2, .i32);
    for ([2]struct { WipFunction.Instruction.Tag, []const u8 }{
        .{ .sitofp, "convert_low_i32x4_s" },
        .{ .uitofp, "convert_low_i32x4_u" },
    }) |info| {
        const cast, const name = info;
        var conv = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, "f64x2", name);
        const wip = &conv.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const un_op = try conv.unOp(b, i32x4_vec);
        const low_i32x2 = try wip.callIntrinsic(
            .normal,
            .none,
            .@"vector.extract",
            &.{ i32x2_vec, i32x4_vec },
            &.{ un_op.c_1, try b.module.intValue(.i64, 0) },
            "low_i32x2",
        );
        try un_op.writeResult(&conv, try wip.cast(cast, low_i32x2, f64x2_vec, "floats"));
        try conv.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try conv.finish(b);
    }

    const f32x2_vec = try b.module.vectorType(.normal, 2, .float);
    {
        var demote = try b.opcodeHandler(.{ .fd = .@"f32x4.demote_f64x2_zero" });
        const wip = &demote.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const un_op = try demote.unOp(b, f64x2_vec);
        const low_result = try wip.cast(.fptrunc, un_op.c_1, f32x2_vec, "low_result");
        const result = try wip.shuffleVector(
            low_result,
            try wip.splatVector(
                try b.module.vectorType(.normal, 2, .float),
                try b.module.floatValue(0.0),
                "zeroes",
            ),
            try b.module.vectorValue(
                i32x4_vec,
                &indices: {
                    var indices: [4]Constant = undefined;
                    for (&indices, &[4]u2{ 0, 1, 2, 2 }) |*i, lane| {
                        i.* = try b.module.intConst(.i32, lane);
                    }
                    break :indices indices;
                },
            ),
            "result",
        );
        try un_op.writeResult(&demote, result);
        try demote.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try demote.finish(b);
    }
    {
        var promote = try b.opcodeHandler(.{ .fd = .@"f64x2.promote_low_f32x4" });
        const wip = &promote.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const un_op = try promote.unOp(b, f32x4_vec);
        const low_f32x2 = try wip.callIntrinsic(
            .normal,
            .none,
            .@"vector.extract",
            &.{ f32x2_vec, f32x4_vec },
            &.{ un_op.c_1, try b.module.intValue(.i64, 0) },
            "low_i32x2",
        );
        try un_op.writeResult(&promote, try wip.cast(.fpext, low_f32x2, f64x2_vec, "result"));
        try promote.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try promote.finish(b);
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

        for (&[2]WipFunction.Instruction.Tag{ .add, .sub }) |instr| {
            var op = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                @tagName(instr),
            );
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, vector_ty);
            try bin_op.writeResult(&op, try op.wip.bin(instr, bin_op.c_1, bin_op.c_2, ""));
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&op.wip),
                .vsp = new_vsp,
            });
            try op.finish(b);
        }

        const zeroes = try b.module.splatConst(vector_ty, try b.module.intConst(lane_ty, 0));
        {
            var neg = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), "neg");
            neg.wip.cursor = .{ .block = try neg.wip.block(0, "Entry") };
            const un_op = try neg.unOp(b, vector_ty);
            try un_op.writeResult(&neg, try neg.wip.bin(.sub, zeroes.toValue(), un_op.c_1, ""));
            try neg.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&neg.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&neg.wip),
            });
            try neg.finish(b);
        }
    }

    const i8x16 = try Interpretation.i8x16.vectorType(b);

    {
        var popcnt = try b.opcodeHandler(.{ .fd = .@"i8x16.popcnt" });
        popcnt.wip.cursor = .{ .block = try popcnt.wip.block(0, "Entry") };
        const un_op = try popcnt.unOp(b, i8x16);
        try un_op.writeResult(
            &popcnt,
            try popcnt.wip.callIntrinsic(.normal, .none, .ctpop, &.{i8x16}, &.{un_op.c_1}, ""),
        );
        try popcnt.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(&popcnt.wip),
            .vsp = OpcodeHandlerParam.vsp.arg(&popcnt.wip),
        });
        try popcnt.finish(b);
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
