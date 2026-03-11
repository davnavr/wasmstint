//! Writes definitions for all 128-bit SIMD opcode handlers.

pub fn buildOpcodeHandlers(b: *Builder) Oom!void {
    try buildMemoryLoadOpcodeHandlers(b);
    try buildMemoryStoreOpcodeHandlers(b);
    try buildBitwiseOpcodeHandlers(b);
    try buildBooleanOpcodeHandlers(b);
    try buildConstructionOpcodeHandlers(b);
    try buildConversionOpcodeHandlers(b);
    try buildLaneAccessOpcodeHandlers(b);
    try buildFloatOpcodeHandlers(b);
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

    fn laneWidthIntType(i: Interpretation, b: *Builder) Oom!Type {
        return try b.module.intType(@ctz(i.laneCount()) + 1);
    }

    const LaneIdx = struct {
        imm: Value,
        /// Value of `vip` after the lane index byte.
        vip: Value,

        fn gepToTarget(
            idx: LaneIdx,
            interp: Interpretation,
            wip: *WipFunction,
            b: *Builder,
            base: Value,
        ) Oom!Value {
            return try wip.gep(
                .inbounds,
                interp.laneType(),
                base,
                &.{try wip.cast(.zext, idx.imm, b.size_type, "target_idx")},
                "target_ptr",
            );
        }
    };

    fn readLaneIdx(
        i: Interpretation,
        wip: *WipFunction,
        b: *Builder,
        start_vip: Value,
    ) Oom!LaneIdx {
        return .{
            .imm = try wip.load(
                .normal,
                try i.laneWidthIntType(b),
                start_vip,
                .default,
                "lane_imm",
            ),
            .vip = try wip.gep(
                .inbounds,
                .i8,
                start_vip,
                &.{try b.sizeIntValue(1)},
                "vip_after_lane_imm",
            ),
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

    for (
        &[4]Interpretation{ .i8x16, .i16x8, .i32x4, .i64x2 },
        &[4]FDPrefixOpcode{
            .@"v128.load8_lane",
            .@"v128.load16_lane",
            .@"v128.load32_lane",
            .@"v128.load64_lane",
        },
        &[4]std.mem.Alignment{ .@"1", .@"2", .@"4", .@"8" },
    ) |interp, opcode, access_size| {
        var load = try b.opcodeHandler(.{ .fd = opcode });
        const wip = &load.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };

        const perform_load = try wip.block(1, "Load");
        const access = try load.linearMemoryAccess(b, 1, access_size, perform_load);

        const src_vec = try load.loadOperandAt(b, try interp.vectorType(b), 0, "src_vec");
        const lane = try interp.readLaneIdx(wip, b, access.vip);

        const lane_ty = interp.laneType();
        const elem = try wip.load(.normal, lane_ty, access.ptr, byte_alignment, "elem");

        const new_vec = try wip.insertElement(src_vec, elem, lane.imm, "new_vec");
        _ = try wip.store(.normal, new_vec, try load.gepOperandAt(b, 1), .default);

        const new_vsp = try load.adjustVspBy(b, -1);
        try load.jmpToNextHandler(b, .{ .vip = lane.vip, .vsp = new_vsp });
        try load.finish(b);
    }
}

fn buildMemoryStoreOpcodeHandlers(b: *Builder) Oom!void {
    {
        var store = try b.opcodeHandler(.{ .fd = .@"v128.store" });
        const wip = &store.wip;

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const perform_store = try wip.block(1, "Store");
        const access = try store.linearMemoryAccess(b, 1, .@"16", perform_store);

        _ = try wip.callIntrinsic(
            .normal,
            b.value_copy.attributes_dst_unaligned,
            .@"memcpy.inline",
            &b.value_copy.overload,
            &.{ access.ptr, try store.gepOperandAt(b, 0), try b.sizeIntValue(16), .false },
            "",
        );

        const new_vsp = try store.adjustVspBy(b, -2);
        try store.jmpToNextHandler(b, .{ .vip = access.vip, .vsp = new_vsp });
        try store.finish(b);
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
            b.value_copy.attributes_src_unaligned,
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
    var concat_mask_buf: [16]Constant = undefined;
    // On x86+sse4_1, this should compile down to `packsswb`/`packssdw`/`packuswb`/`packusdw`
    for (&[4]struct { FDPrefixOpcode, i17, i17 }{
        .{ .@"i8x16.narrow_i16x8_s", std.math.minInt(i8), std.math.maxInt(i8) },
        .{ .@"i8x16.narrow_i16x8_u", 0, std.math.maxInt(u8) },
        .{ .@"i16x8.narrow_i32x4_s", std.math.minInt(i16), std.math.maxInt(i16) },
        .{ .@"i16x8.narrow_i32x4_u", 0, std.math.maxInt(u16) },
    }) |info| {
        const opcode, const min_value, const max_value = info;
        const opcode_name = @tagName(opcode);
        const to_interp: Interpretation = std.meta.stringToEnum(
            Interpretation,
            opcode_name[0..5],
        ) orelse unreachable;
        const to_int = to_interp.laneType();
        const to_vec = try to_interp.vectorType(b);

        const from_interp: Interpretation = std.meta.stringToEnum(
            Interpretation,
            opcode_name[13..18],
        ) orelse unreachable;
        const from_int = from_interp.laneType();
        const from_vec = try from_interp.vectorType(b);

        var narrow = try b.opcodeHandler(.{ .fd = opcode });
        const wip = &narrow.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const bin_op = try narrow.binOp(b, from_vec);

        const concat_mask = concat_mask_buf[0..to_interp.laneCount()];
        for (0.., concat_mask) |i, *c| {
            c.* = try b.module.intConst(to_int, i);
        }
        const concatenated_inputs = try wip.shuffleVector(
            bin_op.c_1,
            bin_op.c_2,
            try b.module.vectorValue(to_vec, concat_mask),
            "concatenated_inputs",
        );

        const clamp_vec = try b.module.vectorType(.normal, to_interp.laneCount(), from_int);
        const clamp_min = try wip.callIntrinsic(
            .normal,
            .none,
            .smin,
            &.{clamp_vec},
            &.{
                concatenated_inputs,
                try b.module.splatValue(clamp_vec, try b.module.intConst(from_int, max_value)),
            },
            "clamp_min",
        );
        const clamp_max = try wip.callIntrinsic(
            .normal,
            .none,
            .smax,
            &.{clamp_vec},
            &.{
                clamp_min,
                try b.module.splatValue(clamp_vec, try b.module.intConst(from_int, min_value)),
            },
            "clamp_max",
        );
        const truncated = try wip.cast(.trunc, clamp_max, to_vec, "truncated");

        try bin_op.writeResult(&narrow, truncated);
        const new_vsp = try narrow.adjustVspBy(b, -1);
        try narrow.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
        try narrow.finish(b);
    }

    // On x86, should compile to pmovsx*
    for (&[3]Interpretation{ .i16x8, .i32x4, .i64x2 }) |to_interp| {
        const from_interp: Interpretation = @enumFromInt(@intFromEnum(to_interp) - 1);
        const from_lane_count = from_interp.laneCount();
        const to_lane_count = to_interp.laneCount();
        const from_vec = try from_interp.vectorType(b);
        const to_vec = try to_interp.vectorType(b);
        for (
            &[2][]const u8{ "low", "high" },
            &[2]u5{ 0, @divExact(from_lane_count, 2) },
        ) |lanes, src_offset| {
            for (&[2]u7{ 's', 'u' }, &[2]WipFunction.Instruction.Tag{ .sext, .zext }) |sign, cast| {
                var name_buf: [25]u8 = undefined;
                var extend = try b.opcodeHandler(.fromName(
                    FDPrefixOpcode,
                    std.fmt.bufPrint(
                        &name_buf,
                        "{t}.extend_{s}_{t}_{c}",
                        .{ to_interp, lanes, from_interp, sign },
                    ) catch unreachable,
                ));

                const wip = &extend.wip;
                wip.cursor = .{ .block = try wip.block(0, "Entry") };
                const un_op = try extend.unOp(b, from_vec);

                const chosen_lanes_type = try b.module.vectorType(
                    .normal,
                    to_lane_count,
                    from_interp.laneType(),
                );
                const chosen_lanes = try wip.callIntrinsic(
                    .normal,
                    .none,
                    .@"vector.extract",
                    &.{ chosen_lanes_type, from_vec },
                    &.{ un_op.c_1, try b.module.intValue(.i64, src_offset) },
                    "chosen_lanes",
                );
                const result = try wip.cast(cast, chosen_lanes, to_vec, "result");
                try un_op.writeResult(&extend, result);
                try extend.jmpToNextHandler(b, .{
                    .vip = OpcodeHandlerParam.vip.arg(wip),
                    .vsp = OpcodeHandlerParam.vsp.arg(wip),
                });
                try extend.finish(b);
            }
        }
    }

    const i32x4_vec = try Interpretation.i32x4.vectorType(b);
    const f32x4_vec = try Interpretation.f32x4.vectorType(b);

    for ([2]struct { []const u8, FDPrefixOpcode }{
        .{ "llvm.fptosi.sat", .@"i32x4.trunc_sat_f32x4_s" },
        .{ "llvm.fptoui.sat", .@"i32x4.trunc_sat_f32x4_u" },
    }) |info| {
        const intrin_name, const opcode = info;
        var trunc = try b.opcodeHandler(.{ .fd = opcode });
        const wip = &trunc.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const un_op = try trunc.unOp(b, f32x4_vec);

        const intrin_ty = try b.fnType(i32x4_vec, &.{f32x4_vec});
        const intrin = try b.module.addFunction(
            intrin_ty,
            try b.module.strtabString(intrin_name),
            .default,
        );

        try un_op.writeResult(&trunc, try wip.call(
            .normal,
            .default,
            .none,
            intrin_ty,
            intrin.toValue(&b.module),
            &.{un_op.c_1},
            "result",
        ));
        try trunc.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try trunc.finish(b);
    }

    for ([2]struct { WipFunction.Instruction.Tag, FDPrefixOpcode }{
        .{ .sitofp, .@"f32x4.convert_i32x4_s" },
        .{ .uitofp, .@"f32x4.convert_i32x4_u" },
    }) |info| {
        const cast, const opcode = info;
        var conv = try b.opcodeHandler(.{ .fd = opcode });
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

    const i32x2_zero = try b.module.splatValue(i32x2_vec, try b.module.intConst(.i32, 0));
    const i32x4_indices_0_to_3 = try b.module.vectorValue(i32x4_vec, &indices: {
        var indices: [4]Constant = undefined;
        for (&indices, 0..4) |*i, n| {
            i.* = try b.module.intConst(.i32, n);
        }
        break :indices indices;
    });
    for ([2]struct { []const u8, FDPrefixOpcode }{
        .{ "llvm.fptosi.sat", .@"i32x4.trunc_sat_f64x2_s_zero" },
        .{ "llvm.fptoui.sat", .@"i32x4.trunc_sat_f64x2_u_zero" },
    }) |info| {
        const intrin_name, const opcode = info;
        var trunc = try b.opcodeHandler(.{ .fd = opcode });
        const wip = &trunc.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const un_op = try trunc.unOp(b, f64x2_vec);
        const intrin_ty = try b.fnType(i32x2_vec, &.{f64x2_vec});
        const intrin = try b.module.addFunction(
            intrin_ty,
            try b.module.strtabString(intrin_name),
            .default,
        );
        const converted = try wip.call(
            .normal,
            .default,
            .none,
            intrin_ty,
            intrin.toValue(&b.module),
            &.{un_op.c_1},
            "converted",
        );

        try un_op.writeResult(
            &trunc,
            try wip.shuffleVector(converted, i32x2_zero, i32x4_indices_0_to_3, "result"),
        );
        try trunc.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try trunc.finish(b);
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
            i32x4_indices_0_to_3,
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

fn buildLaneAccessOpcodeHandlers(b: *Builder) Oom!void {
    const i8x16 = try Interpretation.i8x16.vectorType(b);

    // On x86+ssse3, can be compiled down to two `pshufb` instructions (and masking).
    {
        var shuffle = try b.opcodeHandler(.{ .fd = .@"i8x16.shuffle" });
        const wip = &shuffle.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const bin_op = try shuffle.binOp(b, i8x16);

        const start_vip = OpcodeHandlerParam.vip.arg(wip);
        const indices = try wip.load(.normal, i8x16, start_vip, byte_alignment, "indices");
        const vip_after_imm = try wip.gep(
            .inbounds,
            .i8,
            start_vip,
            &.{try b.sizeIntValue(16)},
            "vip_after_imm",
        );

        const concat_vecs = try wip.shuffleVector(
            bin_op.c_1,
            bin_op.c_2,
            try b.module.vectorValue(try b.module.vectorType(.normal, 32, .i32), &indices: {
                var concat_indices: [32]Constant = undefined;
                for (0..32, &concat_indices) |i, *idx| {
                    idx.* = try b.module.intConst(.i32, i);
                }
                break :indices concat_indices;
            }),
            "concat_vecs",
        );

        var result = try b.module.poisonValue(i8x16);
        for (0..16) |i| {
            const i_value = try b.sizeIntValue(@intCast(i));
            const index = try wip.extractElement(indices, i_value, "");
            const chosen = try wip.extractElement(concat_vecs, index, "");
            result = try wip.insertElement(result, chosen, i_value, "");
        }

        try bin_op.writeResult(&shuffle, result);

        const new_vsp = try shuffle.adjustVspBy(b, -1);
        try shuffle.jmpToNextHandler(b, .{ .vip = vip_after_imm, .vsp = new_vsp });
        try shuffle.finish(b);
    }

    const zero_byte = try b.module.intValue(.i8, 0);
    // On x86+ssse3, can be compiled down to `paddusb`+`pshufb`
    {
        var swizzle = try b.opcodeHandler(.{ .fd = .@"i8x16.swizzle" });
        const wip = &swizzle.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const indices_ptr = try swizzle.gepOperandAt(b, 0);
        const indices = try wip.load(.normal, i8x16, indices_ptr, byte_alignment, "indices");
        const result_ptr = try swizzle.gepOperandAt(b, 1);
        const source = try wip.load(.normal, i8x16, result_ptr, value_stack_alignment, "source");

        if (b.hasX86Feature(.ssse3)) {
            const intrin_ty = try b.fnType(i8x16, &.{ i8x16, i8x16 });
            const paddusb = try b.module.addFunction(
                intrin_ty,
                try b.module.strtabString("llvm.x86.sse2.paddus.b"),
                .default,
            );
            // Ensures OOB lane indices are set to `0x80`, so `pshufb` sets those lanes to zero.
            const clamped_indices = try wip.call(
                .normal,
                .default,
                .none,
                intrin_ty,
                paddusb.toValue(&b.module),
                &.{ indices, try b.module.splatValue(i8x16, try b.module.intConst(.i8, 0x70)) },
                "clamped_indices",
            );

            const pshufb = try b.module.addFunction(
                intrin_ty,
                try b.module.strtabString("llvm.x86.ssse3.pshuf.b.128"),
                .default,
            );

            const result = try wip.call(
                .normal,
                .default,
                .none,
                intrin_ty,
                pshufb.toValue(&b.module),
                &.{ source, clamped_indices },
                "result",
            );

            _ = try wip.store(.normal, result, result_ptr, value_stack_alignment);
        } else {
            const max_valid_index = try b.module.intValue(.i8, 15);
            for (0..16) |i| {
                const i_value = try b.sizeIntValue(@intCast(i));
                const index_unsafe = try wip.extractElement(indices, i_value, "");
                const index_clamped = try wip.callIntrinsic(
                    .normal,
                    .none,
                    .umin,
                    &.{.i8},
                    &.{ index_unsafe, max_valid_index },
                    "",
                );
                const to_store = try wip.select(
                    .normal,
                    try wip.icmp(.ule, index_unsafe, max_valid_index, ""),
                    // Can't allow OOB memory access
                    try wip.extractElement(source, index_clamped, ""),
                    zero_byte,
                    "",
                );

                const dst_ptr = if (i == 0)
                    result_ptr
                else
                    try wip.gep(.inbounds, .i8, result_ptr, &.{i_value}, "");

                _ = try wip.store(.normal, to_store, dst_ptr, .default);
            }
        }

        try swizzle.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = indices_ptr,
        });
        try swizzle.finish(b);
    }

    // On x86+avx2, compiles down to `vpbroadcast`
    for (&[4]Interpretation{ .i8x16, .i16x8, .i32x4, .f32x4 }) |interp| {
        var splat = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), "splat");
        const wip = &splat.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const lane_ty = interp.laneType();
        const un_op = try splat.unOp(b, switch (interp) {
            .i8x16, .i16x8 => .i32,
            .i32x4, .f32x4 => lane_ty,
            else => unreachable,
        });
        const elem = switch (interp) {
            .i8x16, .i16x8 => try wip.cast(.trunc, un_op.c_1, lane_ty, ""),
            .i32x4, .f32x4 => un_op.c_1,
            else => unreachable,
        };

        try un_op.writeResult(&splat, try wip.splatVector(try interp.vectorType(b), elem, "splat"));
        try splat.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try splat.finish(b);
    }

    for (&[2]Interpretation{ .i64x2, .f64x2 }) |interp| {
        var splat = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), "splat");
        const wip = &splat.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const lane_ty = interp.laneType();
        const result_ptr = try splat.gepOperandAt(b, 0);
        const elem = try wip.load(.normal, lane_ty, result_ptr, value_stack_alignment, "elem");

        const dst_ptr = try wip.gep(
            .inbounds,
            lane_ty,
            result_ptr,
            &.{try b.sizeIntValue(1)},
            "dst_ptr",
        );

        _ = try wip.store(.normal, elem, dst_ptr, .default);

        try splat.jmpToNextHandler(b, .{
            .vip = OpcodeHandlerParam.vip.arg(wip),
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try splat.finish(b);
    }

    for (&[2]Interpretation{ .i8x16, .i16x8 }) |interp| {
        for (&[2]Instruction.Tag{ .sext, .zext }, &[2]u7{ 's', 'u' }) |cast, name_suffix| {
            var suffix_buf: [14]u8 = "extract_lane_?".*;
            suffix_buf[suffix_buf.len - 1] = name_suffix;
            var extract = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                &suffix_buf,
            );
            const wip = &extract.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const result_ptr = try extract.gepOperandAt(b, 0);
            const lane = try interp.readLaneIdx(wip, b, OpcodeHandlerParam.vip.arg(wip));

            const target_ptr = try lane.gepToTarget(interp, wip, b, result_ptr);
            const target = try wip.load(.normal, interp.laneType(), target_ptr, .default, "target");

            const result = try wip.cast(cast, target, .i32, "result");
            _ = try wip.store(.normal, result, result_ptr, value_stack_alignment);
            try extract.jmpToNextHandler(b, .{
                .vip = lane.vip,
                .vsp = OpcodeHandlerParam.vsp.arg(wip),
            });
            try extract.finish(b);
        }
    }

    for (&[4]Interpretation{ .i32x4, .i64x2, .f32x4, .f64x2 }) |interp| {
        var extract = try b.opcodeHandlerFromPrefixedName(
            FDPrefixOpcode,
            @tagName(interp),
            "extract_lane",
        );
        const wip = &extract.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const result_ptr = try extract.gepOperandAt(b, 0);
        const lane = try interp.readLaneIdx(wip, b, OpcodeHandlerParam.vip.arg(wip));

        const target_ptr = try lane.gepToTarget(interp, wip, b, result_ptr);
        const target = try wip.load(.normal, interp.laneType(), target_ptr, .default, "target");

        _ = try wip.store(.normal, target, result_ptr, value_stack_alignment);
        try extract.jmpToNextHandler(b, .{
            .vip = lane.vip,
            .vsp = OpcodeHandlerParam.vsp.arg(wip),
        });
        try extract.finish(b);
    }

    for (&[6]Interpretation{ .i8x16, .i16x8, .i32x4, .i64x2, .f32x4, .f64x2 }) |interp| {
        var replace = try b.opcodeHandlerFromPrefixedName(
            FDPrefixOpcode,
            @tagName(interp),
            "replace_lane",
        );
        const wip = &replace.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const lane_ty = interp.laneType();
        const replacement_arg = try replace.loadOperandAt(
            b,
            switch (interp) {
                .i8x16, .i16x8 => .i32,
                .i32x4, .i64x2, .f32x4, .f64x2 => lane_ty,
            },
            0,
            "replacement",
        );
        const replacement = switch (interp) {
            .i8x16, .i16x8 => try wip.cast(.trunc, replacement_arg, lane_ty, "replacement.trunc"),
            .i32x4, .i64x2, .f32x4, .f64x2 => replacement_arg,
        };
        const result_ptr = try replace.gepOperandAt(b, 1);

        const lane = try interp.readLaneIdx(wip, b, OpcodeHandlerParam.vip.arg(wip));
        const target_ptr = try lane.gepToTarget(interp, wip, b, result_ptr);
        _ = try wip.store(.normal, replacement, target_ptr, .default);

        const new_vsp = try replace.adjustVspBy(b, -1);
        try replace.jmpToNextHandler(b, .{ .vip = lane.vip, .vsp = new_vsp });
        try replace.finish(b);
    }
}

fn buildFloatOpcodeHandlers(b: *Builder) Oom!void {
    for (&[2]Interpretation{ .f32x4, .f64x2 }, try FloatInfo.init(&b.module)) |interp, float_info| {
        const int_interp: Interpretation = @enumFromInt(@intFromEnum(interp) - 2);
        const float_vec = try interp.vectorType(b);
        const int_vec = try int_interp.vectorType(b);
        // const sign_bits = try b.module.splatValue(int_vec, float_info.sign_bit.toConst().?);

        for (&[6]FloatCondition{ .oeq, .une, .olt, .ogt, .ole, .oge }) |cond| {
            var cmp = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                @tagName(cond)[1..],
            );
            const wip = &cmp.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const bin_op = try cmp.binOp(b, float_vec);
            const result = try wip.fcmp(.normal, cond, bin_op.c_1, bin_op.c_2, "cmp");
            try bin_op.writeResult(&cmp, try wip.cast(.sext, result, int_vec, "mask"));
            const new_vsp = try cmp.adjustVspBy(b, -1);
            try cmp.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
            try cmp.finish(b);
        }

        // TODO: detect when LLVM emits a libc/compiler_rt call instead of inline instructions
        for (&[4]Intrinsic{ .ceil, .floor, .trunc, .roundeven }) |intrin| {
            var op = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                switch (intrin) {
                    .roundeven => "nearest",
                    else => @tagName(intrin),
                },
            );
            const wip = &op.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const un_op = try op.unOp(b, float_vec);
            try un_op.writeResult(&op, try wip.callIntrinsic(
                .normal,
                .none,
                intrin,
                &.{float_vec},
                &.{un_op.c_1},
                "result",
            ));
            try op.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(wip),
                .vsp = OpcodeHandlerParam.vsp.arg(wip),
            });
            try op.finish(b);
        }

        {
            var abs = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), "abs");
            const wip = &abs.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const un_op = try abs.unOp(b, float_vec);
            try un_op.writeResult(&abs, try wip.callIntrinsic(
                .normal,
                .none,
                .fabs,
                &.{float_vec},
                &.{un_op.c_1},
                "result",
            ));
            try abs.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(wip),
                .vsp = OpcodeHandlerParam.vsp.arg(wip),
            });
            try abs.finish(b);
        }
        {
            var neg = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), "neg");
            const wip = &neg.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const un_op = try neg.unOp(b, float_vec);
            try un_op.writeResult(&neg, try wip.un(.fneg, un_op.c_1, "neg"));
            try neg.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(wip),
                .vsp = OpcodeHandlerParam.vsp.arg(wip),
            });
            try neg.finish(b);
        }
        {
            // On x86, should compile to `sqrtps`/`sqrtpd`
            var sqrt = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                "sqrt",
            );
            const wip = &sqrt.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const un_op = try sqrt.unOp(b, float_vec);
            const result = try wip.callIntrinsic(
                .normal,
                .none,
                .sqrt,
                &.{float_vec},
                &.{un_op.c_1},
                "result",
            );
            try un_op.writeResult(&sqrt, result);
            try sqrt.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(wip),
                .vsp = OpcodeHandlerParam.vsp.arg(wip),
            });
            try sqrt.finish(b);
        }

        for (&[4]Instruction.Tag{ .fadd, .fsub, .fmul, .fdiv }) |instr| {
            var op = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                @tagName(instr)[1..],
            );
            const wip = &op.wip;
            op.wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, float_vec);
            try bin_op.writeResult(&op, try wip.bin(instr, bin_op.c_1, bin_op.c_2, ""));
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
            try op.finish(b);
        }

        const canonical_nan_floats = try b.module.splatValue(
            float_vec,
            float_info.canonical_nan.toConst().?,
        );

        for (&[2]Intrinsic{ .minimum, .maximum }) |intrin| {
            var op = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                @tagName(intrin)[0..3],
            );
            const wip = &op.wip;
            op.wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, float_vec);
            const chosen = try wip.callIntrinsic(
                .normal,
                .none,
                intrin,
                &.{float_vec},
                &.{ bin_op.c_1, bin_op.c_2 },
                "",
            );
            const is_nan = try wip.fcmp(.normal, .uno, chosen, chosen, "is_nan");
            try bin_op.writeResult(
                &op,
                try wip.select(.normal, is_nan, canonical_nan_floats, chosen, "canonicalize_nans"),
            );
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
            try op.finish(b);
        }

        for (&[2][]const u8{ "pmin", "pmax" }, &[2]FloatCondition{ .olt, .ogt }) |name, cond| {
            var op = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), name);
            const wip = &op.wip;
            op.wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, float_vec);
            const condition = try wip.fcmp(.normal, cond, bin_op.c_2, bin_op.c_1, "cmp");
            const selection = try wip.select(.normal, condition, bin_op.c_2, bin_op.c_1, "pick");
            try bin_op.writeResult(&op, selection);
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
            try op.finish(b);
        }
    }
}

fn buildIntegerOpcodeHandlers(b: *Builder) Oom!void {
    for (&[4]Interpretation{ .i8x16, .i16x8, .i32x4, .i64x2 }) |interp| {
        const lane_ty = interp.laneType();
        const vector_ty = try interp.vectorType(b);

        const integer_comparisons = [10]struct { llvm.Builder.IntegerCondition, []const u8 }{
            .{ .eq, "eq" },
            .{ .ne, "ne" },
            .{ .slt, "lt_s" },
            .{ .sgt, "gt_s" },
            .{ .sle, "le_s" },
            .{ .sge, "ge_s" },
            // Unsigned comparisons not available for i64x2
            .{ .ult, "lt_u" },
            .{ .ugt, "gt_u" },
            .{ .ule, "le_u" },
            .{ .uge, "ge_u" },
        };

        for (integer_comparisons[0..if (interp == .i64x2) 6 else 10]) |info| {
            const cond, const name = info;
            var cmp = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), name);
            const wip = &cmp.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const bin_op = try cmp.binOp(b, vector_ty);
            const result = try wip.icmp(cond, bin_op.c_1, bin_op.c_2, "cmp");
            try bin_op.writeResult(&cmp, try wip.cast(.sext, result, vector_ty, "mask"));
            const new_vsp = try cmp.adjustVspBy(b, -1);
            try cmp.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(wip),
                .vsp = new_vsp,
            });
            try cmp.finish(b);
        }

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

        {
            var abs = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), "abs");
            abs.wip.cursor = .{ .block = try abs.wip.block(0, "Entry") };
            const un_op = try abs.unOp(b, vector_ty);
            try un_op.writeResult(&abs, try abs.wip.callIntrinsic(
                .normal,
                .none,
                .abs,
                &.{vector_ty},
                &.{ un_op.c_1, .false },
                "abs",
            ));
            try abs.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(&abs.wip),
                .vsp = OpcodeHandlerParam.vsp.arg(&abs.wip),
            });
            try abs.finish(b);
        }
    }

    for (&[2]Interpretation{ .i8x16, .i16x8 }) |interp| {
        const vec = try interp.vectorType(b);
        for (&[4]Intrinsic{ .@"uadd.sat", .@"sadd.sat", .@"usub.sat", .@"ssub.sat" }) |intrin| {
            const intrin_name = @tagName(intrin);
            var name_suffix: [9]u8 = "XXX_sat_X".*;
            name_suffix[0..3].* = intrin_name[1..4].*;
            name_suffix[8] = intrin_name[0];

            var op = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                &name_suffix,
            );
            const wip = &op.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, vec);
            const args = .{ bin_op.c_1, bin_op.c_2 };
            try bin_op.writeResult(
                &op,
                try wip.callIntrinsic(.normal, .none, intrin, &.{vec}, &args, "result"),
            );
            const new_vsp = try op.adjustVspBy(b, -1);
            try op.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
            try op.finish(b);
        }
    }

    for (&[3]Interpretation{ .i8x16, .i16x8, .i32x4 }) |interp| {
        const int_vec = try interp.vectorType(b);
        for (&[4]Intrinsic{ .smin, .smax, .umin, .umax }) |intrin| {
            var suffix_buf: [5]u8 = "MMM_S".*;
            const intrin_name = @tagName(intrin);
            suffix_buf[0..3].* = intrin_name[1..4].*;
            suffix_buf[4] = intrin_name[0];

            var op = try b.opcodeHandlerFromPrefixedName(
                FDPrefixOpcode,
                @tagName(interp),
                &suffix_buf,
            );
            op.wip.cursor = .{ .block = try op.wip.block(0, "Entry") };
            const bin_op = try op.binOp(b, int_vec);
            try bin_op.writeResult(
                &op,
                try op.wip.callIntrinsic(
                    .normal,
                    .none,
                    intrin,
                    &.{int_vec},
                    &.{ bin_op.c_1, bin_op.c_2 },
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
    }

    // On x86+sse2, should compile to `pavgb`/`pavgw`
    for (&[2]FDPrefixOpcode{ .@"i8x16.avgr_u", .@"i16x8.avgr_u" }) |opcode| {
        const interp: Interpretation = std.meta.stringToEnum(
            Interpretation,
            @tagName(opcode)[0..5],
        ) orelse unreachable;
        const vec = try interp.vectorType(b);

        const overflow_int = try b.module.intType(interp.laneType().scalarBits(&b.module) + 1);
        const overflow_vec = try b.module.vectorType(.normal, interp.laneCount(), overflow_int);

        var avgr = try b.opcodeHandler(.{ .fd = opcode });
        const wip = &avgr.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const bin_op = try avgr.binOp(b, vec);
        try bin_op.writeResult(&avgr, result: {
            const sum = try wip.bin(
                .@"add nuw",
                try wip.cast(.zext, bin_op.c_1, overflow_vec, "a"),
                try wip.cast(.zext, bin_op.c_2, overflow_vec, "b"),
                "",
            );

            const numerator = try wip.bin(
                .@"add nuw",
                sum,
                try b.module.splatValue(overflow_vec, try b.module.intConst(overflow_int, 1)),
                "numerator",
            );

            const result = try wip.bin(
                .udiv,
                numerator,
                try b.module.splatValue(overflow_vec, try b.module.intConst(overflow_int, 2)),
                "avgr",
            );

            break :result try wip.cast(.trunc, result, vec, "result");
        });
        const new_vsp = try avgr.adjustVspBy(b, -1);
        try avgr.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
        try avgr.finish(b);
    }

    for (&[3]Interpretation{ .i16x8, .i32x4, .i64x2 }) |interp| {
        var mul = try b.opcodeHandlerFromPrefixedName(FDPrefixOpcode, @tagName(interp), "mul");
        const wip = &mul.wip;
        wip.cursor = .{ .block = try mul.wip.block(0, "Entry") };
        const bin_op = try mul.binOp(b, try interp.vectorType(b));
        try bin_op.writeResult(&mul, try wip.bin(.mul, bin_op.c_1, bin_op.c_2, ""));
        const new_vsp = try mul.adjustVspBy(b, -1);
        try mul.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
        try mul.finish(b);
    }

    // On x86+sse2, should compile down to `pmaddwd`
    {
        const i16x8 = try Interpretation.i16x8.vectorType(b);
        const i32x4 = try Interpretation.i32x4.vectorType(b);
        const i32x8 = try b.module.vectorType(.normal, 8, .i32);
        var dot = try b.opcodeHandler(.{ .fd = .@"i32x4.dot_i16x8_s" });
        const wip = &dot.wip;
        wip.cursor = .{ .block = try dot.wip.block(0, "Entry") };
        const bin_op = try dot.binOp(b, i16x8);
        const a_ext = try wip.cast(.sext, bin_op.c_1, i32x8, "a");
        const b_ext = try wip.cast(.sext, bin_op.c_2, i32x8, "b");
        const product = try wip.bin(.@"mul nuw", a_ext, b_ext, "product");
        const i32x8_poison = try b.module.poisonValue(i32x8);

        var indices_buf: [4]Constant = undefined;
        const even_lanes = try wip.shuffleVector(
            product,
            i32x8_poison,
            try b.module.vectorValue(i32x4, indices: {
                for (0..4, &indices_buf) |i, *idx| {
                    idx.* = try b.module.intConst(.i32, i * 2);
                }
                break :indices &indices_buf;
            }),
            "even_lanes",
        );
        const odd_lanes = try wip.shuffleVector(
            product,
            i32x8_poison,
            try b.module.vectorValue(i32x4, indices: {
                for (0..4, &indices_buf) |i, *idx| {
                    idx.* = try b.module.intConst(.i32, (i * 2) + 1);
                }
                break :indices &indices_buf;
            }),
            "odd_lanes",
        );

        try bin_op.writeResult(&dot, try wip.bin(.add, even_lanes, odd_lanes, "result"));
        const new_vsp = try dot.adjustVspBy(b, -1);
        try dot.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
        try dot.finish(b);
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

    for (&[3]Interpretation{ .i16x8, .i32x4, .i64x2 }) |to_interp| {
        const to_vec = try to_interp.vectorType(b);
        const from_interp: Interpretation = @enumFromInt(@intFromEnum(to_interp) - 1);
        const from_vec = try from_interp.vectorType(b);
        const from_lane_count = from_interp.laneCount();
        const from_half_vec = try b.module.vectorType(
            .normal,
            @divExact(from_lane_count, 2),
            from_interp.laneType(),
        );

        for (
            &[2][]const u8{ "low", "high" },
            &[2]u5{ 0, @divExact(from_lane_count, 2) },
        ) |lanes, src_offset| {
            const src_offset_value = try b.module.intValue(.i64, src_offset);
            for (&[2]Instruction.Tag{ .sext, .zext }) |cast| {
                const suffix: u7, const mul_instr: Instruction.Tag = switch (cast) {
                    .sext => .{ 's', .@"mul nsw" },
                    .zext => .{ 'u', .@"mul nuw" },
                    else => unreachable,
                };

                var name_buf: [25]u8 = undefined;
                var name = std.ArrayList(u8).initBuffer(&name_buf);
                name.appendSliceAssumeCapacity(@tagName(to_interp));
                name.appendSliceAssumeCapacity(".extmul_");
                name.appendSliceAssumeCapacity(lanes);
                name.appendAssumeCapacity('_');
                name.appendSliceAssumeCapacity(@tagName(from_interp));
                name.appendAssumeCapacity('_');
                name.appendAssumeCapacity(suffix);

                var mul = try b.opcodeHandler(.fromName(FDPrefixOpcode, name.items));
                const wip = &mul.wip;
                wip.cursor = .{ .block = try mul.wip.block(0, "Entry") };
                const bin_op = try mul.binOp(b, from_vec);

                const c_1 = try wip.callIntrinsic(
                    .normal,
                    .none,
                    .@"vector.extract",
                    &.{ from_half_vec, from_vec },
                    &.{ bin_op.c_1, src_offset_value },
                    "c1.half",
                );
                const c_2 = try wip.callIntrinsic(
                    .normal,
                    .none,
                    .@"vector.extract",
                    &.{ from_half_vec, from_vec },
                    &.{ bin_op.c_2, src_offset_value },
                    "c2.half",
                );

                const c1_ext = try wip.cast(cast, c_1, to_vec, "c1.ext");
                const c2_ext = try wip.cast(cast, c_2, to_vec, "c2.ext");

                try bin_op.writeResult(&mul, try wip.bin(mul_instr, c1_ext, c2_ext, "mul"));
                const new_vsp = try mul.adjustVspBy(b, -1);
                try mul.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
                try mul.finish(b);
            }
        }
    }

    // On x86+ssse3, can use `pmulhrsw` with overflow detection
    // On aarch64, this apparently follows the semantics of `sqrdmulh`
    // See also: https://github.com/WebAssembly/relaxed-simd/issues/40
    {
        const i16x8 = try Interpretation.i16x8.vectorType(b);
        const i32x8 = try b.module.vectorType(.normal, 8, .i32);

        var mul = try b.opcodeHandler(.{ .fd = .@"i16x8.q15mulr_sat_s" });
        const wip = &mul.wip;
        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const bin_op = try mul.binOp(b, i16x8);

        const overflow_bounds = try b.module.splatValue(
            i16x8,
            try b.module.intConst(.i16, std.math.minInt(i16)),
        );
        const saturated = try b.module.splatValue(
            i16x8,
            try b.module.intConst(.i16, std.math.maxInt(i16)),
        );

        const result: Value = saturated: {
            const product = if (b.hasX86Feature(.ssse3)) ssse3: {
                const intrin_ty = try b.fnType(i16x8, &.{ i16x8, i16x8 });
                const intrin_name = try b.module.strtabString("llvm.x86.ssse3.pmul.hr.sw.128");
                const intrin = try b.module.addFunction(intrin_ty, intrin_name, .default);
                break :ssse3 try wip.call(
                    .normal,
                    .default,
                    .none,
                    intrin_ty,
                    intrin.toValue(&b.module),
                    &.{ bin_op.c_1, bin_op.c_2 },
                    "mul",
                );
            } else portable: {
                const c1 = try wip.cast(.sext, bin_op.c_1, i32x8, "c1.ext");
                const c2 = try wip.cast(.sext, bin_op.c_2, i32x8, "c2.ext");
                const product = try wip.bin(.@"mul nuw", c1, c2, "product");
                const to_shift = try wip.bin(
                    .@"add nuw",
                    product,
                    try b.module.splatValue(i32x8, try b.module.intConst(.i32, 0x4000)),
                    "to_shift",
                );

                const shift_amt = try b.module.splatValue(i32x8, try b.module.intConst(.i32, 15));
                const shifted = try wip.bin(.lshr, to_shift, shift_amt, "shifted");
                break :portable try wip.cast(.trunc, shifted, i16x8, "result");
            };

            const overflowed = try wip.bin(
                .@"and",
                try wip.icmp(.eq, bin_op.c_1, overflow_bounds, "c1.is_min"),
                try wip.icmp(.eq, bin_op.c_2, overflow_bounds, "c2.is_min"),
                "overflowed",
            );
            break :saturated try wip.select(.normal, overflowed, saturated, product, "chosen");
        };

        try bin_op.writeResult(&mul, result);
        const new_vsp = try mul.adjustVspBy(b, -1);
        try mul.jmpToNextHandler(b, .{ .vip = OpcodeHandlerParam.vip.arg(wip), .vsp = new_vsp });
        try mul.finish(b);
    }

    for (&[2]Interpretation{ .i16x8, .i32x4 }) |to_interp| {
        const from_interp: Interpretation = @enumFromInt(@intFromEnum(to_interp) - 1);
        const from_vec = try from_interp.vectorType(b);
        const to_vec = try to_interp.vectorType(b);
        const to_lane_count = to_interp.laneCount();

        var lane_indices_buf: [8]Constant = undefined;
        const lane_indices_vec = try b.module.vectorType(.normal, to_lane_count, .i32);
        const even_lanes_indices = try b.module.vectorValue(lane_indices_vec, indices: {
            for (0.., lane_indices_buf[0..to_lane_count]) |i, *idx| {
                idx.* = try b.module.intConst(.i32, i * 2);
            }
            break :indices lane_indices_buf[0..to_lane_count];
        });
        const odd_lanes_indices = try b.module.vectorValue(lane_indices_vec, indices: {
            for (0.., lane_indices_buf[0..to_lane_count]) |i, *idx| {
                idx.* = try b.module.intConst(.i32, (i * 2) + 1);
            }
            break :indices lane_indices_buf[0..to_lane_count];
        });
        const from_vec_poison = try b.module.poisonValue(from_vec);

        for (&[2]Instruction.Tag{ .sext, .zext }) |cast| {
            const name_suffix: u7, const add: Instruction.Tag = switch (cast) {
                .sext => .{ 's', .@"add nsw" },
                .zext => .{ 'u', .@"add nuw" },
                else => unreachable,
            };

            var name_buf: [29]u8 = undefined;
            var name = std.ArrayList(u8).initBuffer(&name_buf);
            name.appendSliceAssumeCapacity(@tagName(to_interp));
            name.appendSliceAssumeCapacity(".extadd_pairwise_");
            name.appendSliceAssumeCapacity(@tagName(from_interp));
            name.appendAssumeCapacity('_');
            name.appendAssumeCapacity(name_suffix);

            var extadd = try b.opcodeHandler(.fromName(FDPrefixOpcode, name.items));
            const wip = &extadd.wip;
            wip.cursor = .{ .block = try wip.block(0, "Entry") };
            const un_op = try extadd.unOp(b, from_vec);
            const even_lanes = try wip.shuffleVector(
                un_op.c_1,
                from_vec_poison,
                even_lanes_indices,
                "even_lanes",
            );
            const odd_lanes = try wip.shuffleVector(
                un_op.c_1,
                from_vec_poison,
                odd_lanes_indices,
                "odd_lanes",
            );

            const even_lanes_ext = try wip.cast(cast, even_lanes, to_vec, "even_lanes_ext");
            const odd_lanes_ext = try wip.cast(cast, odd_lanes, to_vec, "odd_lanes_ext");
            try un_op.writeResult(&extadd, try wip.bin(add, even_lanes_ext, odd_lanes_ext, "sum"));
            try extadd.jmpToNextHandler(b, .{
                .vip = OpcodeHandlerParam.vip.arg(wip),
                .vsp = OpcodeHandlerParam.vsp.arg(wip),
            });
            try extadd.finish(b);
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
const FloatInfo = @import("FloatInfo.zig");

const Constant = llvm.Builder.Constant;
const FloatCondition = llvm.Builder.FloatCondition;
const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const WipFunction = llvm.Builder.WipFunction;
const Instruction = WipFunction.Instruction;
const Intrinsic = llvm.Builder.Intrinsic;
