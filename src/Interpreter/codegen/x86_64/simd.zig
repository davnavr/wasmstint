//! Writes definitions for all SIMD opcodes

pub fn defineAllOpcodes(as: *AsmWriter) void {
    defineCommonConstants(as);
    defineMemoryLoadOpcodes(as);
    defineMemoryStoreOpcodes(as);
    defineBitwiseOpcodes(as);
    defineBooleanOpcodes(as);
    defineConstructionOpcodes(as);
    defineConversionOpcodes(as);
    defineFloatOpcodes(as);

    defineIntegerOpcodes(as);
}

fn defineCommonConstants(as: *AsmWriter) void {
    as.write(
        \\.section .rodata.cst16, "aM", @progbits, 16
        \\.p2align 4, 0x00
        \\
    );

    as.print("\n.L{[symbol_prefix]s}i8x16_even_lanes:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([8][]const u8, @splat(".word 0x00FF")));

    as.print("\n.L{[symbol_prefix]s}i8x16_odd_lanes:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([8][]const u8, @splat(".word 0xFF00")));

    as.print("\n.L{[symbol_prefix]s}i16x8_sign_bits:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([8][]const u8, @splat(".word 0x8000")));

    as.print("\n.L{[symbol_prefix]s}i32x4_sign_bits:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([4][]const u8, @splat(".long 0x8000" ++ "0000")));

    as.print("\n.L{[symbol_prefix]s}i64x2_sign_bits:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([2][]const u8, @splat(".quad 0x8000" ++ "0000" ++ "0000" ++ "0000")));

    as.write("\n.text\n");
}

fn defineMemoryLoadOpcodes(as: *AsmWriter) void {
    {
        var load = as.defineOpcodeHandler(.{ .fd = .@"v128.load" }, .@"64");
        var access = LinearMemoryAccess.start(as, .@"0x10", .@"16");
        as.printInstrs(&.{
            "movups xmm0, xmmword ptr [r13 + r15] # load from memory",
            "movaps xmmword ptr [{[vsp]f} - 0x10], xmm0 # write loaded value",
        }, .{ .vsp = Gpr.vsp });
        access.end(&load, as);
    }
}

fn defineMemoryStoreOpcodes(as: *AsmWriter) void {
    {
        var load = as.defineOpcodeHandler(.{ .fd = .@"v128.store" }, .@"64");
        var access = LinearMemoryAccess.start(as, .@"0x20", .@"16");
        as.printInstrs(&.{
            "movaps xmm0, xmmword ptr [{[vsp]f} - 0x10] # get vector to store",
            "movups xmmword ptr [r13 + r15], xmm0 # write into linear memory",
            "lea {[vsp]f}, [{[vsp]f} - 0x20] # vsp",
        }, .{ .vsp = Gpr.vsp });
        access.end(&load, as);
    }
}

fn defineBitwiseOpcodes(as: *AsmWriter) void {
    {
        var op = as.defineOpcodeHandler(.{ .fd = .@"v128.not" }, .@"32");
        as.printInstrs(&.{
            "pcmpeqd xmm0, xmm0 # all ones",
            "pxor xmm0, xmmword ptr [{[vsp]f} - 0x10] # bitwise NOT",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # write result",
        }, .{ .vsp = Gpr.vsp });
        op.end(as);
    }
    for (&[_]FDPrefixOpcode{ .@"v128.and", .@"v128.or", .@"v128.xor" }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "p{[operation]s} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # write result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{ .vsp = Gpr.vsp, .operation = @tagName(opcode)[5..] });
        op.end(as);
    }
    {
        var op = as.defineOpcodeHandler(.{ .fd = .@"v128.andnot" }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20]",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "pandn xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # write result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{ .vsp = Gpr.vsp });
        op.end(as);
    }
    {
        var op = as.defineOpcodeHandler(.{ .fd = .@"v128.bitselect" }, .@"64");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x30] # operand A",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand B",
            "movdqa xmm2, xmmword ptr [{[vsp]f} - 0x10] # mask operand",
            "pand xmm0, xmm2",
            "pcmpeqd xmm3, xmm3 # all ones",
            "pxor xmm2, xmm3 # bitwise NOT",
            "pand xmm1, xmm2",
            "por xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x30], xmm0 # write result",
            "lea {[vsp]f}, [{[vsp]f} - 0x20] # update VSP",
        }, .{ .vsp = Gpr.vsp });
        op.end(as);
    }
}

const IntInterp = enum {
    i8x16,
    i16x8,
    i32x4,
    i64x2,

    fn suffix(interp: IntInterp) u7 {
        return switch (interp) {
            .i8x16 => 'b',
            .i16x8 => 'w',
            .i32x4 => 'd',
            .i64x2 => 'q',
        };
    }

    fn bitSize(interp: IntInterp) u7 {
        return switch (interp) {
            .i8x16 => 8,
            .i16x8 => 16,
            .i32x4 => 32,
            .i64x2 => 64,
        };
    }

    fn laneCount(interp: IntInterp) u5 {
        return @intCast(@divExact(128, interp.bitSize()));
    }

    fn fromOpcodeName(opcode: FDPrefixOpcode) IntInterp {
        return std.meta.stringToEnum(IntInterp, @tagName(opcode)[0..5]).?;
    }
};

fn defineBooleanOpcodes(as: *AsmWriter) void {
    {
        var any_true = as.defineOpcodeHandler(.{ .fd = .@"v128.any_true" }, .@"32");
        as.printInstrs(&.{
            "xor r13d, r13d",
            "mov r11, qword ptr [{[vsp]f} - 0x10] # low 64-bits",
            "or r11, qword ptr [{[vsp]f} - 0x08] # high 64-bits",
            "setnz r13b",
            "mov dword ptr [{[vsp]f} - 0x10], r13d # store result",
        }, .{ .vsp = Gpr.vsp });
        any_true.end(as);
    }

    for (&[_]FDPrefixOpcode{
        .@"i8x16.all_true",
        .@"i16x8.all_true",
        .@"i32x4.all_true",
    }) |opcode| {
        const interp = IntInterp.fromOpcodeName(opcode);
        {
            var all_true = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
            as.printInstrs(&.{
                "xor r13d, r13d",
                "xorps xmm0, xmm0",
                "pcmpeq{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]" ++
                    "# lane is set to all one's when zero (false)",
                "{[mask_instr]s} r11d, xmm0 # all zeroes if no lane was zero",
                "test r11d, r11d",
                "setz r13b",
                "mov dword ptr [{[vsp]f} - 0x10], r13d # store result",
            }, .{
                .vsp = Gpr.vsp,
                .mask_instr = switch (opcode) {
                    .@"i32x4.all_true" => "movmskps",
                    .@"i8x16.all_true", .@"i16x8.all_true" => "pmovmskb",
                    else => unreachable,
                },
                .suffix = interp.suffix(),
            });
            all_true.end(as);
        }
    }

    // PCMPEQQ and PCMPGTQ require SSE4.1
    {
        var all_true = as.defineOpcodeHandler(.{ .fd = .@"i64x2.all_true" }, .@"32");
        as.printInstrs(&.{
            "xor r11d, r11d",
            "xor r13d, r13d",
            "cmp qword ptr [{[vsp]f} - 0x10], 0 # low 64-bits",
            "setne r11b",
            "cmp qword ptr [{[vsp]f} - 0x08], 0 # high 64-bits",
            "setne r13b",
            "and r11d, r13d",
            "mov dword ptr [{[vsp]f} - 0x10], r11d # store result",
        }, .{ .vsp = Gpr.vsp });
        all_true.end(as);
    }

    {
        var bitmask = as.defineOpcodeHandler(.{ .fd = .@"i8x16.bitmask" }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "pmovmskb r11d, xmm0",
            "mov dword ptr [{[vsp]f} - 0x10], r11d",
        }, .{ .vsp = Gpr.vsp });
        bitmask.end(as);
    }
    {
        // No 16-bit pmovmsk/movmsk
        var bitmask = as.defineOpcodeHandler(.{ .fd = .@"i16x8.bitmask" }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "packsswb xmm0, xmm0 # high 64-bits contain the 8 high bytes of each 16-bit lane",
            "pmovmskb r11d, xmm0",
            "and r11w, 0xFF",
            "mov dword ptr [{[vsp]f} - 0x10], r11d",
        }, .{ .vsp = Gpr.vsp });
        bitmask.end(as);
    }
    {
        var bitmask = as.defineOpcodeHandler(.{ .fd = .@"i32x4.bitmask" }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movmskps r11d, xmm0",
            "mov dword ptr [{[vsp]f} - 0x10], r11d",
        }, .{ .vsp = Gpr.vsp });
        bitmask.end(as);
    }
    {
        var bitmask = as.defineOpcodeHandler(.{ .fd = .@"i64x2.bitmask" }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movmskpd r11d, xmm0",
            "mov dword ptr [{[vsp]f} - 0x10], r11d",
        }, .{ .vsp = Gpr.vsp });
        bitmask.end(as);
    }
}

fn defineConstructionOpcodes(as: *AsmWriter) void {
    {
        var op = as.defineOpcodeHandler(.{ .fd = .@"v128.const" }, .@"32");
        as.printInstrs(&.{
            "movdqu xmm0, xmmword ptr [{[vip]f}] # load 16-byte immediate",
            "movdqa xmmword ptr [{[vsp]f}], xmm0 # store v128",
            "lea {[vip]f}, [{[vip]f} + 0x10] # update VIP",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # update VSP",
        }, .{ .vip = Gpr.vip, .vsp = Gpr.vsp });
        op.end(as);
    }
    // splat could use vpbroadcast on AVX2
    {
        var splat = as.defineOpcodeHandler(.{ .fd = .@"i8x16.splat" }, .@"32");
        as.printInstrs(&.{
            "movd xmm0, dword ptr [{[vsp]f} - 0x10]",
            "punpcklbw xmm0, xmm0 # replicate byte value to low 2 x 8-bit lanes",
            "pshuflw xmm0, xmm0, 0 # replicate byte value across low 8 x 8-bit lanes",
            "pshufd xmm0, xmm0, 0 # fill high 8 x 8-bit lanes",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        splat.end(as);
    }
    {
        var splat = as.defineOpcodeHandler(.{ .fd = .@"i16x8.splat" }, .@"32");
        as.printInstrs(&.{
            "movd xmm0, dword ptr [{[vsp]f} - 0x10]",
            "pshuflw xmm0, xmm0, 0 # replicate word across low 4 x 16-bit lanes",
            "pshufd xmm0, xmm0, 0 # fill high 4 x 16-bit lanes",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        splat.end(as);
    }
    for ([2]FDPrefixOpcode{ .@"i32x4.splat", .@"f32x4.splat" }) |opcode| {
        var splat = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        as.printInstrs(&.{
            "movd xmm0, dword ptr [{[vsp]f} - 0x10]",
            "pshufd xmm0, xmm0, 0",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        splat.end(as);
    }
    for ([2]FDPrefixOpcode{ .@"i64x2.splat", .@"f64x2.splat" }) |opcode| {
        var splat = as.defineOpcodeHandler(.{ .fd = opcode }, .@"16");
        as.printInstrs(&.{
            "mov r13, qword ptr [{[vsp]f} - 0x10]",
            "mov qword ptr [{[vsp]f} - 0x08], r13 # store high lane",
        }, .{ .vsp = Gpr.vsp });
        splat.end(as);
    }
}

fn defineConversionOpcodes(as: *AsmWriter) void {
    for (&[_]FDPrefixOpcode{
        .@"i8x16.narrow_i16x8_s",
        .@"i8x16.narrow_i16x8_u",
        .@"i16x8.narrow_i32x4_s",
        .@"i16x8.narrow_i32x4_u",
    }) |opcode| {
        var narrow = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        const opcode_name = @tagName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # load 1st operand",
            "pack{[sign]c}s{[suffix]s} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{
            .vsp = Gpr.vsp,
            .sign = opcode_name[opcode_name.len - 1],
            .suffix = switch (interp) {
                .i8x16 => "wb",
                .i16x8 => "dw",
                else => unreachable,
            },
        });
        narrow.end(as);
    }
    for ([2]FDPrefixOpcode{
        .@"i16x8.extend_low_i8x16_s",
        .@"i16x8.extend_high_i8x16_s",
    }) |opcode| {
        var extend = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "punpck{[pos]c}bw xmm0, xmm0" ++
                " # move 8 x 8-bit lane to high 8-bits of target 8 x 16-bit lane",
            "# lower 8-bits of 8 x 16-bit lanes are ignored",
            "psraw xmm0, 8 # fill high 8-bits with sign bit of lane",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .pos = @tagName(opcode)[13] });
        extend.end(as);
    }
    for ([2]FDPrefixOpcode{
        .@"i16x8.extend_low_i8x16_u",
        .@"i16x8.extend_high_i8x16_u",
    }) |opcode| {
        var extend = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "pxor xmm1, xmm1 # zeroes to be put in high 8-bits of 8 x 16-bit lanes",
            "punpck{[pos]c}bw xmm0, xmm1" ++
                " # move high 8 x 8-bit lanes into low 8-bits of target 8 x 16-bit lanes",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .pos = @tagName(opcode)[13] });
        extend.end(as);
    }
    for ([2]FDPrefixOpcode{
        .@"i32x4.extend_low_i16x8_s",
        .@"i32x4.extend_high_i16x8_s",
    }) |opcode| {
        var extend = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "punpck{[pos]c}wd xmm0, xmm0" ++
                " # move 4 x 16-bit lane to high 16-bits of target 4 x 32-bit lanes",
            "# lower 16-bits of 4 x 32-bit lanes are ignored",
            "psrad xmm0, 16 # fill high 16-bits with sign bit of lane",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .pos = @tagName(opcode)[13] });
        extend.end(as);
    }
    for ([2]FDPrefixOpcode{
        .@"i32x4.extend_low_i16x8_u",
        .@"i32x4.extend_high_i16x8_u",
    }) |opcode| {
        var extend = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "pxor xmm1, xmm1 # zeroes to be put in high 16-bits of 4 x 32-bit lanes",
            "punpck{[pos]c}wd xmm0, xmm1" ++
                " # move high 4 x 16-bit lanes into low 16-bits of target 4 x 32-bit lanes",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .pos = @tagName(opcode)[13] });
        extend.end(as);
    }
    for ([4]FDPrefixOpcode{
        .@"i64x2.extend_low_i32x4_s",
        .@"i64x2.extend_high_i32x4_s",
        .@"i64x2.extend_low_i32x4_u",
        .@"i64x2.extend_high_i32x4_u",
    }) |opcode| {
        var extend = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const opcode_name = @tagName(opcode);
        const low_lane_offset: u4 = switch (opcode_name[13]) {
            'l' => 0,
            'h' => 8,
            else => unreachable,
        };
        const sign = opcode_name[opcode_name.len - 1];
        const reg_size: Gpr.Size = switch (sign) {
            's' => .qword,
            'u' => .dword,
            else => unreachable,
        };
        as.printInstrs(&.{
            "{[mov]s} {[r11]f}, dword ptr [{[vsp]f} - 0x10 + {[low_lane_offset]X}] # low lane",
            "{[mov]s} {[r13]f}, dword ptr [{[vsp]f} - 0x10 + {[low_lane_offset]X} + 4] # high lane",
            "mov qword ptr [{[vsp]f} - 0x10], r11 # store result low lane",
            "mov qword ptr [{[vsp]f} - 0x08], r13 # store result high lane",
        }, .{
            .mov = switch (sign) {
                's' => "movsxd",
                'u' => "mov",
                else => unreachable,
            },
            .r11 = Gpr.r11.withSize(reg_size),
            .r13 = Gpr.r13.withSize(reg_size),
            .vsp = Gpr.vsp,
            .low_lane_offset = low_lane_offset,
        });
        extend.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(.{ .fd = .@"f32x4.convert_i32x4_s" }, .@"32");
        as.printInstrs(&.{
            "cvtdq2ps xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movaps xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(.{ .fd = .@"f32x4.convert_i32x4_u" }, .@"32");
        as.writeInstrs(&.{"# Taken from LLVM output for Zig @floatFromInt"});
        as.write(
            \\.section .rodata.cst16, "aM", @progbits, 16
            \\.p2align 4, 0x00
            \\
        );
        var const_0 = as.label(&.{"i32x4_max_u16"});
        const_0.place(as);
        as.writeInstrs(&@as([4][]const u8, @splat(".long 0xFFFF")));

        var const_1 = as.label(&.{"const"});
        const_1.place(as);
        as.writeInstrs(&@as([4][]const u8, @splat(".long 0x4B00" ++ "0000")));

        var const_2 = as.label(&.{"const"});
        const_2.place(as);
        as.writeInstrs(&@as([4][]const u8, @splat(".long 0x5300" ++ "0000")));

        var const_3 = as.label(&.{"const"});
        const_3.place(as);
        as.writeInstrs(&@as([4][]const u8, @splat(".long 0x5300" ++ "0080")));

        as.write(".text\n");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "movdqa xmm1, xmmword ptr [{[const_0]f}]",
            "pand xmm1, xmm0 # get low 16-bits of operand",
            "por xmm1, xmmword ptr [{[const_1]f}]",
            "psrld xmm0, 16 # shift away low 16-bits of operand",
            "por xmm0, xmmword ptr [{[const_2]f}]",
            "subps xmm0, xmmword ptr [{[const_3]f}]",
            "addps xmm0, xmm1",
            "movaps xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{
            .vsp = Gpr.vsp,
            .const_0 = const_0,
            .const_1 = const_1,
            .const_2 = const_2,
            .const_3 = const_3,
        });
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(.{ .fd = .@"f64x2.convert_low_i32x4_s" }, .@"32");
        as.printInstrs(&.{
            "cvtdq2pd xmm0, qword ptr [{[vsp]f} - 0x10]",
            "movapd xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(.{ .fd = .@"f64x2.convert_low_i32x4_u" }, .@"32");
        as.writeInstrs(&.{"# Taken from LLVM output for Zig @floatFromInt"});

        as.write(
            \\.section .rodata.cst16, "aM", @progbits, 16
            \\.p2align 4, 0x00
            \\
        );
        var const_0 = as.label(&.{"const"});
        const_0.place(as);
        as.writeInstrs(&@as([2][]const u8, @splat(".quad 0x4330000000000000")));

        as.write(".text\n");
        as.printInstrs(&.{
            "movapd xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "xorpd xmm1, xmm1",
            "unpcklps xmm0, xmm1",
            "movapd xmm1, xmmword ptr [{[const_0]f}]",
            "orpd xmm0, xmm1",
            "subpd xmm0, xmm1",
            "movapd xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .const_0 = const_0 });
        convert.end(as);
    }
    {
        var demote = as.defineOpcodeHandler(.{ .fd = .@"f32x4.demote_f64x2_zero" }, .@"32");
        as.printInstrs(&.{
            "cvtpd2ps xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movaps xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        demote.end(as);
    }
    {
        var promote = as.defineOpcodeHandler(.{ .fd = .@"f64x2.promote_low_f32x4" }, .@"32");
        as.printInstrs(&.{
            "cvtps2pd xmm0, qword ptr [{[vsp]f} - 0x10]",
            "movapd xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        promote.end(as);
    }
}

const FloatInterp = enum {
    f32x4,
    f64x2,

    fn toInt(interp: FloatInterp) IntInterp {
        return switch (interp) {
            .f32x4 => .i32x4,
            .f64x2 => .i64x2,
        };
    }

    fn suffix(interp: FloatInterp) u7 {
        return switch (interp) {
            .f32x4 => 's',
            .f64x2 => 'd',
        };
    }

    fn fromOpcodeName(opcode: FDPrefixOpcode) FloatInterp {
        return std.meta.stringToEnum(FloatInterp, @tagName(opcode)[0..5]).?;
    }
};

fn defineFloatOpcodes(as: *AsmWriter) void {
    for (&[_]FDPrefixOpcode{
        .@"f32x4.eq",
        .@"f32x4.lt",
        .@"f32x4.le",

        .@"f64x2.eq",
        .@"f64x2.lt",
        .@"f64x2.le",
    }) |opcode| {
        var cmp = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = FloatInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movap{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "cmp{[op]s}p{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix(), .op = @tagName(opcode)[6..] });
        cmp.jmpToNextHandler(as);
        cmp.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"f32x4.ne", .@"f64x2.ne" }) |opcode| {
        var ne = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = FloatInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movap{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 0",
            "cmpneqp{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        ne.jmpToNextHandler(as);
        ne.end(as);
    }

    for (&[_]FDPrefixOpcode{
        .@"f32x4.gt",
        .@"f32x4.ge",

        .@"f64x2.gt",
        .@"f64x2.ge",
    }) |opcode| {
        var cmp = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = FloatInterp.fromOpcodeName(opcode);
        const opcode_name = @tagName(opcode);
        as.printInstrs(&.{
            "movap{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "cmpl{[op]c}p{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{
            .vsp = Gpr.vsp,
            .suffix = interp.suffix(),
            .op = opcode_name[opcode_name.len - 1],
        });
        cmp.jmpToNextHandler(as);
        cmp.end(as);
    }

    // When only SSE2 is available, LLVM calls libc functions via @PLT
    for (&[_]FDPrefixOpcode{
        .@"f32x4.ceil",
        .@"f32x4.floor",
        .@"f32x4.trunc",
        .@"f32x4.nearest",

        .@"f64x2.ceil",
        .@"f64x2.floor",
        .@"f64x2.trunc",
        .@"f64x2.nearest",
    }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = FloatInterp.fromOpcodeName(opcode);
        const rounding_mode = std.meta.stringToEnum(
            AsmWriter.RoundingControl,
            @tagName(opcode)[6..],
        ).?;
        as.printInstrs(&.{
            "roundp{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10], 0x{[rounding_mode]X}" ++
                " # TODO: Requires SSE4.1",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{
            .suffix = interp.suffix(),
            .vsp = Gpr.vsp,
            .rounding_mode = 0b1000 | @as(u8, @intFromEnum(rounding_mode)),
        });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_]FDPrefixOpcode{
        .@"f32x4.pmin",
        .@"f32x4.pmax",

        .@"f64x2.pmin",
        .@"f64x2.pmax",
    }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = FloatInterp.fromOpcodeName(opcode);
        const opcode_name = @tagName(opcode);
        as.printInstrs(&.{
            "movap{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "{[op]s}p{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{
            .vsp = Gpr.vsp,
            .suffix = interp.suffix(),
            .op = opcode_name[opcode_name.len - 3 ..][0..3],
        });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_]FDPrefixOpcode{
        .@"f32x4.add",
        .@"f32x4.sub",
        .@"f32x4.mul",
        .@"f32x4.div",

        .@"f64x2.add",
        .@"f64x2.sub",
        .@"f64x2.mul",
        .@"f64x2.div",
    }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = FloatInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movap{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "{[op]s}p{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix(), .op = @tagName(opcode)[6..] });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"f32x4.sqrt", .@"f64x2.sqrt" }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = FloatInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "sqrtp{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"f32x4.neg", .@"f64x2.neg" }) |opcode| {
        var neg = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = FloatInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movap{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "xorp{[suffix]c} xmm0, xmmword ptr [.L{[symbol_prefix]s}{[int_interp]t}_sign_bits]" ++
                " # toggle sign bit",
            "movap{[suffix]c} xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{
            .vsp = Gpr.vsp,
            .symbol_prefix = as.symbol_prefix,
            .suffix = interp.suffix(),
            .int_interp = interp.toInt(),
        });
        neg.jmpToNextHandler(as);
        neg.end(as);
    }
}

fn defineIntegerOpcodes(as: *AsmWriter) void {
    for (&[_]FDPrefixOpcode{ .@"i8x16.eq", .@"i16x8.eq", .@"i32x4.eq" }) |opcode| {
        var eq = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "pcmpeq{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        eq.jmpToNextHandler(as);
        eq.end(as);
    }

    {
        // pcmpeqq requires SSE4_1
        var eq = as.defineOpcodeHandler(.{ .fd = .@"i64x2.eq" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig == operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20]",
            "pcmpeqd xmm1, xmmword ptr [{[vsp]f} - 0x10]",
            "pshufd xmm0, xmm1, 0xB1",
            "pand xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        eq.jmpToNextHandler(as);
        eq.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"i8x16.ne", .@"i16x8.ne", .@"i32x4.ne" }) |opcode| {
        var ne = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "pcmpeq{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "pcmpeqd xmm1, xmm1 # all ones",
            "pxor xmm0, xmm1 # bitwise NOT of result",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        ne.jmpToNextHandler(as);
        ne.end(as);
    }

    {
        // pcmpeqq requires SSE4_1
        var ne = as.defineOpcodeHandler(.{ .fd = .@"i64x2.ne" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig == operator",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "pcmpeqd xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "pshufd xmm1, xmm0, 0xB1",
            "pand xmm1, xmm0",
            "pcmpeqd xmm0, xmm0 # all 1's",
            "pxor xmm0, xmm1 # bitwise NOT",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        ne.jmpToNextHandler(as);
        ne.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"i8x16.lt_s", .@"i16x8.lt_s", .@"i32x4.lt_s" }) |opcode| {
        var lt_s = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pcmpgt{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        lt_s.jmpToNextHandler(as);
        lt_s.end(as);
    }

    {
        var lt_u = as.defineOpcodeHandler(.{ .fd = .@"i8x16.lt_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig < operator",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pmaxub xmm1, xmm0",
            "pcmpeqb xmm1, xmm0",
            "pcmpeqd xmm0, xmm0 # all 1's",
            "pxor xmm0, xmm1 # bitwise NOT?",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        lt_u.jmpToNextHandler(as);
        lt_u.end(as);
    }
    {
        var lt_u = as.defineOpcodeHandler(.{ .fd = .@"i16x8.lt_u" }, .@"64");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig < operator",
            "movdqa xmm0, xmmword ptr [.L{[symbol_prefix]s}i16x8_sign_bits]",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "pxor xmm1, xmm0",
            "pxor xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pcmpgtw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        lt_u.jmpToNextHandler(as);
        lt_u.end(as);
    }
    {
        var lt_u = as.defineOpcodeHandler(.{ .fd = .@"i32x4.lt_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig < operator",
            "movdqa xmm0, xmmword ptr [.L{[symbol_prefix]s}i32x4_sign_bits]",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "pxor xmm1, xmm0",
            "pxor xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pcmpgtd xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        lt_u.jmpToNextHandler(as);
        lt_u.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"i8x16.le_s", .@"i16x8.le_s", .@"i32x4.le_s" }) |opcode| {
        var le_s = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "pcmpgt{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "pcmpeqd xmm1, xmm1 # all 1's",
            "pxor xmm0, xmm1 # bitwise NOT, <= is opposite of >",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        le_s.jmpToNextHandler(as);
        le_s.end(as);
    }

    {
        var le_u = as.defineOpcodeHandler(.{ .fd = .@"i8x16.le_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig <= operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pminub xmm0, xmm1",
            "pcmpeqb xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        le_u.jmpToNextHandler(as);
        le_u.end(as);
    }
    {
        var le_u = as.defineOpcodeHandler(.{ .fd = .@"i16x8.le_u" }, .@"64");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig <= operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "psubusw xmm1, xmmword ptr [{[vsp]f} - 0x10]",
            "pxor xmm0, xmm0",
            "pcmpeqw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        le_u.jmpToNextHandler(as);
        le_u.end(as);
    }
    {
        var le_u = as.defineOpcodeHandler(.{ .fd = .@"i32x4.le_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig <= operator",
            "movdqa xmm1, xmmword ptr [.L{[symbol_prefix]s}i32x4_sign_bits]",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pxor xmm0, xmm1",
            "pxor xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "pcmpgtd xmm1, xmm0",
            "pcmpeqd xmm0, xmm0 # all 1's",
            "pxor xmm0, xmm1 # bitwise NOT?",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        le_u.jmpToNextHandler(as);
        le_u.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"i8x16.gt_s", .@"i16x8.gt_s", .@"i32x4.gt_s" }) |opcode| {
        var gt_s = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "pcmpgt{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        gt_s.jmpToNextHandler(as);
        gt_s.end(as);
    }

    {
        var gt_u = as.defineOpcodeHandler(.{ .fd = .@"i8x16.gt_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig > operator",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pminub xmm1, xmm0",
            "pcmpeqb xmm1, xmm0",
            "pcmpeqd xmm0, xmm0 # all 1's",
            "pxor xmm0, xmm1 # bitwise NOT, > is opposite of <=",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        gt_u.jmpToNextHandler(as);
        gt_u.end(as);
    }
    {
        var gt_u = as.defineOpcodeHandler(.{ .fd = .@"i16x8.gt_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig > operator",
            "movdqa xmm0, xmmword ptr [.L{[symbol_prefix]s}i16x8_sign_bits]",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pxor xmm1, xmm0",
            "pxor xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "pcmpgtw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        gt_u.jmpToNextHandler(as);
        gt_u.end(as);
    }
    {
        var gt_u = as.defineOpcodeHandler(.{ .fd = .@"i32x4.gt_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig > operator",
            "movdqa xmm0, xmmword ptr [.L{[symbol_prefix]s}i32x4_sign_bits]",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pxor xmm1, xmm0",
            "pxor xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "pcmpgtd xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        gt_u.jmpToNextHandler(as);
        gt_u.end(as);
    }

    for (&[_]FDPrefixOpcode{ .@"i8x16.ge_s", .@"i16x8.ge_s", .@"i32x4.ge_s" }) |opcode| {
        var ge_s = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "# Basically what LLVM outputs for Zig >= operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pcmpgt{[suffix]c} xmm1, xmmword ptr [{[vsp]f} - 0x20]",
            "pcmpeqd xmm0, xmm0 # all 1's",
            "pxor xmm0, xmm1 # bitwise NOT, a >= b is opposite of b > a",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        ge_s.jmpToNextHandler(as);
        ge_s.end(as);
    }

    {
        var ge_u = as.defineOpcodeHandler(.{ .fd = .@"i8x16.ge_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig >= operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pmaxub xmm0, xmm1",
            "pcmpeqb xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        ge_u.jmpToNextHandler(as);
        ge_u.end(as);
    }
    {
        var ge_u = as.defineOpcodeHandler(.{ .fd = .@"i16x8.ge_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig >= operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "psubusw xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "pxor xmm0, xmm0",
            "pcmpeqw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        ge_u.jmpToNextHandler(as);
        ge_u.end(as);
    }
    {
        var ge_u = as.defineOpcodeHandler(.{ .fd = .@"i32x4.ge_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig >= operator",
            "movdqa xmm1, xmmword ptr [.L{[symbol_prefix]s}i32x4_sign_bits]",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "pxor xmm0, xmm1 # toggle sign bits",
            "pxor xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1, sign bits toggled",
            "pcmpgtd xmm1, xmm0",
            "pcmpeqd xmm0, xmm0",
            "pxor xmm0, xmm1",

            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        ge_u.jmpToNextHandler(as);
        ge_u.end(as);
    }

    // TODO: other integer comparisons (not i64x2, those are done)

    for (&[_]struct { FDPrefixOpcode, []const u8 }{
        .{ .@"i64x2.lt_s", "l" },
        .{ .@"i64x2.le_s", "le" },
        .{ .@"i64x2.gt_s", "g" },
        .{ .@"i64x2.ge_s", "ge" },
    }) |info| {
        // pcmpgtq requires SSE4_2
        const opcode, const condition = info;
        var cmp = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        as.printInstrs(&.{
            "# slightly smaller code size compared to using SSE instructions",
            "xor r11d, r11d",
            "mov r13, -1",
            "mov r14, qword ptr [{[vsp]f} - 0x20] # operand 0, low qword",
            "mov r15, qword ptr [{[vsp]f} - 0x10] # operand 1, low qword",
            "cmp r14, r15",
            "cmov{[condition]s} r11, r13",
            "mov qword ptr [{[vsp]f} - 0x20], r11 # low qword result",

            "xor r11d, r11d",
            "mov r14, qword ptr [{[vsp]f} - 0x18] # operand 0, high qword",
            "mov r15, qword ptr [{[vsp]f} - 0x08] # operand 1, high qword",
            "cmp r14, r15",
            "cmov{[condition]s} r11, r13",
            "mov qword ptr [{[vsp]f} - 0x18], r11 # high qword result",

            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .condition = condition });
        cmp.jmpToNextHandler(as);
        cmp.end(as);
    }

    // SSSE3 introduces PSIGNB/PSIGNW/PSIGND
    for (&[_]FDPrefixOpcode{
        .@"i8x16.neg",
        .@"i16x8.neg",
        .@"i32x4.neg",
        .@"i64x2.neg",
    }) |opcode| {
        var neg = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "pxor xmm0, xmm0 # zero",
            "psub{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix() });
        neg.jmpToNextHandler(as);
        neg.end(as);
    }

    for (&[_]FDPrefixOpcode{
        .@"i8x16.shl",
        .@"i8x16.shr_s",
        .@"i8x16.shr_u",

        .@"i16x8.shl",
        .@"i16x8.shr_s",
        .@"i16x8.shr_u",

        .@"i32x4.shl",
        .@"i32x4.shr_s",
        .@"i32x4.shr_u",

        .@"i64x2.shl",
        .@"i64x2.shr_s",
        .@"i64x2.shr_u",
    }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "mov r14d, dword ptr [{[vsp]f} - 0x10] # amt to shift",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # vector to shift",
            "and r14d, 0x{[shift_mask]X} # mod 2 of shift amt",
            "movd xmm1, r14d # shift amount in bottom 64 bits",
        }, .{ .vsp = Gpr.vsp, .shift_mask = interp.bitSize() - 1 });
        switch (opcode) {
            // x86-64 has no packed shift instruction for bytes
            .@"i8x16.shl" => as.printInstrs(&.{
                "psllw xmm0, xmm1 # shift values in even lanes",
                "movdqa xmm2, xmm0",
                "pand xmm2, xmmword ptr [.L{[symbol_prefix]s}i8x16_even_lanes] # result even lanes",
                "movdqa xmm3, xmmword ptr [.L{[symbol_prefix]s}i8x16_odd_lanes]",
                "psllw xmm3, xmm1 # mask for odd lanes", // vpsllw xmm1, xmmword ptr [i8x16_odd_lanes], xmm2
                "pand xmm0, xmm3 # result odd lanes",
                "por xmm0, xmm2",
            }, .{ .symbol_prefix = as.symbol_prefix }),
            .@"i8x16.shr_s" => as.printInstrs(&.{
                "movdqa xmm2, xmm0",
                "psraw xmm0, xmm1 # shift values in odd lanes",
                "pand xmm0, xmmword ptr [.L{[symbol_prefix]s}i8x16_odd_lanes] # result odd lanes",
                "psllw xmm2, 8 # move even lanes into odd lanes (low 8-bits to high 8-bits)",
                "psraw xmm2, xmm1 # shift values in even lanes",
                "psrlw xmm2, 8 # move even lanes back to their final position",
                "pand xmm2, xmmword ptr [.L{[symbol_prefix]s}i8x16_even_lanes] # result even lanes",
                "por xmm0, xmm2",
            }, .{ .symbol_prefix = as.symbol_prefix }),
            .@"i8x16.shr_u" => as.printInstrs(&.{
                "psrlw xmm0, xmm1 # shift values in odd lanes",
                "movdqa xmm2, xmm0",
                "pand xmm2, xmmword ptr [.L{[symbol_prefix]s}i8x16_odd_lanes] # result odd lanes",
                "movdqa xmm3, xmmword ptr [.L{[symbol_prefix]s}i8x16_even_lanes]",
                "psrlw xmm3, xmm1 # mask for even lanes",
                "pand xmm0, xmm3 # result even lanes",
                "por xmm0, xmm2",
            }, .{ .symbol_prefix = as.symbol_prefix }),

            .@"i16x8.shl" => as.writeInstrs(&.{"psllw xmm0, xmm1"}),
            .@"i16x8.shr_s" => as.writeInstrs(&.{"psraw xmm0, xmm1"}),
            .@"i16x8.shr_u" => as.writeInstrs(&.{"psrlw xmm0, xmm1"}),

            .@"i32x4.shl" => as.writeInstrs(&.{"pslld xmm0, xmm1"}),
            .@"i32x4.shr_s" => as.writeInstrs(&.{"psrad xmm0, xmm1"}),
            .@"i32x4.shr_u" => as.writeInstrs(&.{"psrld xmm0, xmm1"}),

            .@"i64x2.shl" => as.writeInstrs(&.{"psllq xmm0, xmm1"}),
            // .@"i64x2.shr_s" => as.writeInstrs(&.{"vpsraq xmm0, xmm1"}), // AVX512F?
            .@"i64x2.shr_s" => as.printInstrs(&.{
                "movdqa xmm2, xmmword ptr [.L{[symbol_prefix]s}i64x2_sign_bits]",
                "movdqa xmm3, xmm2",
                "pand xmm2, xmm0 # sign bits",
                "psrlq xmm0, xmm1 # logical shift",
                "pcmpeqq xmm2, xmm3 # all ones if sign bit is set, all zeroes otherwise",
                "movdqa xmm5, xmm2",
                "psrlq xmm2, xmm1 # logical shift of sign bits",
                "pcmpeqq xmm4, xmm4 # all ones",
                "pxor xmm2, xmm4 # bitwise NOT of sign bits to get shifted-in ones",
                "pand xmm2, xmm5 # shifted ones bits if sign bit is set, all zeroes otherwise",
                "por xmm0, xmm2",
            }, .{ .symbol_prefix = as.symbol_prefix }),
            .@"i64x2.shr_u" => as.writeInstrs(&.{"psrlq xmm0, xmm1"}),

            else => unreachable,
        }
        as.printInstrs(&.{
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_]FDPrefixOpcode{
        .@"i8x16.add",
        .@"i16x8.add",
        .@"i32x4.add",
        .@"i64x2.add",

        .@"i8x16.sub",
        .@"i16x8.sub",
        .@"i32x4.sub",
        .@"i64x2.sub",
    }) |opcode| {
        var add = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "p{[op]s}{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .op = @tagName(opcode)[6..], .suffix = interp.suffix() });
        add.jmpToNextHandler(as);
        add.end(as);
    }

    for ([_]FDPrefixOpcode{
        .@"i8x16.add_sat_s",
        .@"i8x16.sub_sat_s",

        .@"i16x8.add_sat_s",
        .@"i16x8.sub_sat_s",
    }) |opcode| {
        var op_s = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "p{[op]s}s{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .op = @tagName(opcode)[6..9], .suffix = interp.suffix() });
        op_s.jmpToNextHandler(as);
        op_s.end(as);
    }

    for ([_]FDPrefixOpcode{
        .@"i8x16.add_sat_u",
        .@"i8x16.sub_sat_u",

        .@"i16x8.add_sat_u",
        .@"i16x8.sub_sat_u",
    }) |opcode| {
        var op_s = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "p{[op]s}us{[suffix]c} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .op = @tagName(opcode)[6..9], .suffix = interp.suffix() });
        op_s.jmpToNextHandler(as);
        op_s.end(as);
    }

    {
        var mul = as.defineOpcodeHandler(.{ .fd = .@"i16x8.mul" }, .@"64");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pmullw xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        mul.jmpToNextHandler(as);
        mul.end(as);
    }
    {
        // PMULLD requires SSE4_1
        var mul = as.defineOpcodeHandler(.{ .fd = .@"i32x4.mul" }, .@"64");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig's *% operator on @Vector(4, i32)",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pshufd xmm2, xmm1, 0xF5 # only odd lanes from operand 0?",
            "pmuludq xmm1, xmm0 # product of odd lanes?",
            "pshufd xmm1, xmm1, 0xE8",
            "pshufd xmm0, xmm0, 0xF5 # only odd lanes from operand 1?",
            "pmuludq xmm0, xmm2",
            "pshufd xmm0, xmm0, 0xE8",
            "punpckldq xmm1, xmm0",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm1 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        mul.jmpToNextHandler(as);
        mul.end(as);
    }
    {
        // vpmullq requires AVX512?
        var mul = as.defineOpcodeHandler(.{ .fd = .@"i64x2.mul" }, .@"64");
        as.printInstrs(&.{
            "# smaller code size if regular instructions are used",
            "mov r11, qword ptr [{[vsp]f} - 0x20] # operand 0, low qword",
            "mov r14, qword ptr [{[vsp]f} - 0x10] # operand 1, low qword",
            "imul r11, r14 # low qword product",
            "mov r13, qword ptr [{[vsp]f} - 0x18] # operand 0, high qword",
            "mov r15, qword ptr [{[vsp]f} - 0x08] # operand 1, high qword",
            "imul r13, r15 # high qword product",
            "mov qword ptr [{[vsp]f} - 0x20], r11 # store low qword result",
            "mov qword ptr [{[vsp]f} - 0x18], r13 # store high qword result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        mul.jmpToNextHandler(as);
        mul.end(as);
    }

    for (&[_]struct { FDPrefixOpcode, []const u8 }{
        .{ .@"i8x16.min_u", "pminub" },
        .{ .@"i8x16.max_u", "pmaxub" },
        .{ .@"i16x8.min_s", "pminsw" },
        .{ .@"i16x8.max_s", "pmaxsw" },
        .{ .@"i8x16.avgr_u", "pavgb" },
        .{ .@"i16x8.avgr_u", "pavgw" },
    }) |info| {
        var min = as.defineOpcodeHandler(.{ .fd = info[0] }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "{[instr]s} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .instr = info[1] });
        min.jmpToNextHandler(as);
        min.end(as);
    }

    // pminsb (for i8x16) & pminsd (for i32x4) requires SSE4_1
    for (&[_]FDPrefixOpcode{
        .@"i8x16.min_s",
        .@"i8x16.max_s",
        .@"i32x4.min_s",
    }) |opcode| {
        var min = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        const opcode_name = @tagName(opcode);
        const is_max = std.mem.eql(u8, "max", opcode_name[opcode_name.len - 5 ..][0..3]);
        as.printInstrs(&[_][]const u8{
            "# Taken from what LLVM emits for Zig's @min/@max builtin",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "movdqa xmm2, {[cmp_mov_src]s}",
            "pcmpgt{[suffix]c} xmm2, {[cmp_reg]s} # lane set to 1's if operand 1 > operand 0",
            "pand xmm0, xmm2 # only keep lane in operand 0 if it is less than value in operand 1",
            "pandn xmm2, xmm1",
            "por xmm0, xmm2",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{
            .vsp = Gpr.vsp,
            .cmp_mov_src = if (is_max) "xmm0" else "xmm1",
            .cmp_reg = if (is_max) "xmm1" else "xmm0",
            .suffix = interp.suffix(),
        });
        min.jmpToNextHandler(as);
        min.end(as);
    }

    {
        // pminuw requires SSE4_1
        var min = as.defineOpcodeHandler(.{ .fd = .@"i16x8.min_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from what LLVM emits for Zig's @min builtin",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm1, xmm0",
            "psubusw xmm1, xmmword ptr [{[vsp]f} - 0x10]",
            "psubw xmm0, xmm1 # selects minimum value in lane based on difference",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        min.jmpToNextHandler(as);
        min.end(as);
    }
    {
        // pmaxuw requires SSE4_1
        var max = as.defineOpcodeHandler(.{ .fd = .@"i16x8.max_u" }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "psubusw xmm0, xmm1",
            "paddw xmm0, xmm1",
            "",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        max.jmpToNextHandler(as);
        max.end(as);
    }
    {
        // pmaxsd requires SSE4_1
        var max = as.defineOpcodeHandler(.{ .fd = .@"i32x4.max_s" }, .@"32");
        as.printInstrs(&.{
            "# Taken from what LLVM emits for Zig's @max builtin",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm2, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "movdqa xmm0, xmm1",
            "pcmpgtd xmm0, xmm2",
            "pand xmm1, xmm0",
            "pandn xmm0, xmm2",
            "por xmm0, xmm1",
            "",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        max.jmpToNextHandler(as);
        max.end(as);
    }
    {
        // pminud requires SSE4_1
        var min = as.defineOpcodeHandler(.{ .fd = .@"i32x4.min_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from what LLVM emits for Zig's @min builtin",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm2, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "movdqa xmm0, xmmword ptr [.L{[symbol_prefix]s}i32x4_sign_bits]",
            "movdqa xmm3, xmm1",
            "pxor xmm3, xmm0 # toggles sign bit in operand 0",
            "pxor xmm0, xmm2 # toggles sign bit in operand 1",
            "pcmpgtd xmm0, xmm3",
            "pand xmm1, xmm0",
            "pandn xmm0, xmm2",
            "por xmm0, xmm1",

            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        min.jmpToNextHandler(as);
        min.end(as);
    }
    {
        // pmaxud requires SSE4_1
        var max = as.defineOpcodeHandler(.{ .fd = .@"i32x4.max_u" }, .@"32");
        as.printInstrs(&.{
            "# Taken from what LLVM emits for Zig's @max builtin",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm2, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "movdqa xmm0, xmmword ptr [.L{[symbol_prefix]s}i32x4_sign_bits]",
            "movdqa xmm3, xmm2",
            "pxor xmm3, xmm0 # toggle sign bits in operand 1",
            "pxor xmm0, xmm1 # toggle sign bits in operand 0",
            "pcmpgtd xmm0, xmm3",
            "pand xmm1, xmm0",
            "pandn xmm0, xmm2",
            "por xmm0, xmm1",
            "",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        max.jmpToNextHandler(as);
        max.end(as);
    }

    {
        var dot = as.defineOpcodeHandler(.{ .fd = .@"i32x4.dot_i16x8_s" }, .@"32");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pmaddwd xmm0, xmmword ptr [{[vsp]f} - 0x20]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        dot.jmpToNextHandler(as);
        dot.end(as);
    }

    for (&[_]struct { FDPrefixOpcode, []const u8 }{
        .{ .@"i8x16.abs", "pminub" },
        .{ .@"i16x8.abs", "pmaxsw" },
    }) |info| {
        const opcode, const cmp_instr = info;
        // PABSB/PABSW requires SSSE3
        var abs = as.defineOpcodeHandler(.{ .fd = opcode }, .@"32");
        const interp = IntInterp.fromOpcodeName(opcode);
        as.printInstrs(&[_][]const u8{
            "# Taken from what LLVM emits for Zig's @abs builtin",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10]",
            "pxor xmm0, xmm0",
            "psub{[suffix]c} xmm0, xmm1" ++
                " # if lane value is negative, make it positive by subtracting from zero",
            "{[cmp_instr]s} xmm0, xmm1" ++
                " # if value was negative, pick the positive version, otherwise keep it",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .suffix = interp.suffix(), .cmp_instr = cmp_instr });
        abs.jmpToNextHandler(as);
        abs.end(as);
    }
    {
        // PABSD requires SSSE3
        var abs = as.defineOpcodeHandler(.{ .fd = .@"i32x4.abs" }, .@"32");
        as.printInstrs(&[_][]const u8{
            "# Taken from what LLVM emits for Zig's @abs builtin",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmm1, xmm0",
            "psrad xmm1, 31 # obtain sign bits, lane is all 1's if value was negative",
            "pxor xmm0, xmm1",
            "psubd xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        abs.jmpToNextHandler(as);
        abs.end(as);
    }
    {
        // PABSQ requires SSSE3
        var abs = as.defineOpcodeHandler(.{ .fd = .@"i64x2.abs" }, .@"32");
        as.printInstrs(&[_][]const u8{
            "# Taken from what LLVM emits for Zig's @abs builtin",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "pshufd xmm1, xmm0, 0xF5",
            "psrad xmm1, 31",
            "pxor xmm0, xmm1",
            "psubq xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        abs.jmpToNextHandler(as);
        abs.end(as);
    }

    {
        // pshufb requires SSSE3
        var popcnt = as.defineOpcodeHandler(.{ .fd = .@"i8x16.popcnt" }, .@"64");
        // Maybe this is faster: https://github.com/llvm/llvm-project/issues/79823
        as.write(
            \\.section .rodata.cst16, "aM", @progbits, 16
            \\.p2align 4, 0x00
            \\
        );
        var const_0 = as.label(&.{"const"});
        const_0.place(as);
        as.writeInstrs(&.{".skip 16, 0x55"});

        var const_1 = as.label(&.{"const"});
        const_1.place(as);
        as.writeInstrs(&.{".skip 16, 0x33"});

        var const_2 = as.label(&.{"const"});
        const_2.place(as);
        as.writeInstrs(&.{".skip 16, 0x0F"});

        as.write("\n.text\n");
        as.printInstrs(&[_][]const u8{
            "# Taken from what LLVM emits for Zig's @popcnt builtin",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "movdqa xmm0, xmm1",
            "psrlw xmm0, 1",
            "pand xmm0, xmmword ptr [{[const_0]f}]",
            "psubb xmm1, xmm0",
            "movdqa xmm0, xmmword ptr [{[const_1]f}]",
            "movdqa xmm2, xmm1",
            "pand xmm2, xmm0",
            "psrlw xmm1, 2",
            "pand xmm1, xmm0",
            "paddb xmm1, xmm2",
            "movdqa xmm0, xmm1",
            "psrlw xmm0, 4",
            "paddb xmm0, xmm1",
            "pand xmm0, xmmword ptr [{[const_2]f}]",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{
            .vsp = Gpr.vsp,
            .const_0 = const_0,
            .const_1 = const_1,
            .const_2 = const_2,
        });
        popcnt.jmpToNextHandler(as);
        popcnt.end(as);
    }

    {
        var extadd = as.defineOpcodeHandler(.{ .fd = .@"i16x8.extadd_pairwise_i8x16_s" }, .@"64");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "movdqa xmm1, xmm0",
            "psllw xmm0, 8 # low 8-bits of pair, moved to high 8-bits",
            "psraw xmm0, 8 # low 8-bits of pair",
            "psraw xmm1, 8 # high 8-bits of pair",
            "paddw xmm0, xmm1",

            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        extadd.jmpToNextHandler(as);
        extadd.end(as);
    }
    {
        var extadd = as.defineOpcodeHandler(.{ .fd = .@"i16x8.extadd_pairwise_i8x16_u" }, .@"64");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "movdqa xmm1, xmm0",
            "pand xmm0, xmmword ptr [.L{[symbol_prefix]s}i8x16_even_lanes] # low 8-bits of pair",
            "psrlw xmm1, 8 # high 8-bits of pair",
            "paddw xmm0, xmm1",

            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .symbol_prefix = as.symbol_prefix });
        extadd.jmpToNextHandler(as);
        extadd.end(as);
    }

    {
        var extmul_low = as.defineOpcodeHandler(.{ .fd = .@"i16x8.extmul_low_i8x16_s" }, .@"64");
        as.printInstrs(&.{
            "pxor xmm0, xmm0",
            "pxor xmm1, xmm1",
            "punpcklbw xmm0, xmmword ptr [{[vsp]f} - 0x20]" ++
                " # move low 8 x 8-bit lanes of operand 0 into high 8-bits of 8 x 16-bit lanes",
            "punpcklbw xmm1, xmmword ptr [{[vsp]f} - 0x10] # same but for operand 1",
            "psraw xmm0, 8 # fill high 8-bits with sign bit",
            "psraw xmm1, 8",
            "pmullw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        extmul_low.jmpToNextHandler(as);
        extmul_low.end(as);
    }
    {
        var extmul_high = as.defineOpcodeHandler(.{ .fd = .@"i16x8.extmul_high_i8x16_s" }, .@"64");
        as.printInstrs(&.{
            "pxor xmm0, xmm0",
            "pxor xmm1, xmm1",
            "punpckhbw xmm0, xmmword ptr [{[vsp]f} - 0x20]" ++
                " # move high 8 x 8-bit lanes of operand 0 into high 8-bits of 8 x 16-bit lanes",
            "punpckhbw xmm1, xmmword ptr [{[vsp]f} - 0x10] # same but for operand 1",
            "psraw xmm0, 8 # fill high 8-bits with sign bit",
            "psraw xmm1, 8",
            "pmullw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        extmul_high.jmpToNextHandler(as);
        extmul_high.end(as);
    }
    {
        var extmul_low = as.defineOpcodeHandler(.{ .fd = .@"i16x8.extmul_low_i8x16_u" }, .@"64");
        as.printInstrs(&.{
            "pxor xmm0, xmm0",
            "pxor xmm1, xmm1",
            "punpcklbw xmm0, xmmword ptr [{[vsp]f} - 0x20]" ++
                " # move low 8 x 8-bit lanes of operand 0 into high 8-bits of 8 x 16-bit lanes",
            "punpcklbw xmm1, xmmword ptr [{[vsp]f} - 0x10] # same but for operand 1",
            "psrlw xmm0, 8 # fill high 8-bits with zero",
            "psrlw xmm1, 8",
            "pmullw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        extmul_low.jmpToNextHandler(as);
        extmul_low.end(as);
    }
    {
        var extmul_high = as.defineOpcodeHandler(.{ .fd = .@"i16x8.extmul_high_i8x16_u" }, .@"64");
        as.printInstrs(&.{
            "pxor xmm0, xmm0",
            "pxor xmm1, xmm1",
            "punpckhbw xmm0, xmmword ptr [{[vsp]f} - 0x20]" ++
                " # move high 8 x 8-bit lanes of operand 0 into high 8-bits of 8 x 16-bit lanes",
            "punpckhbw xmm1, xmmword ptr [{[vsp]f} - 0x10] # same but for operand 1",
            "psrlw xmm0, 8 # fill high 8-bits with sign bit",
            "psrlw xmm1, 8",
            "pmullw xmm0, xmm1",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        extmul_high.jmpToNextHandler(as);
        extmul_high.end(as);
    }

    for (&[_]FDPrefixOpcode{
        .@"i32x4.extmul_low_i16x8_s",
        .@"i32x4.extmul_high_i16x8_s",
    }) |opcode| {
        var extmul = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        as.printInstrs(&.{
            // pmulld requires SSE4_1
            // "pxor xmm0, xmm0",
            // "pxor xmm1, xmm1",
            // "punpcklwd xmm0, xmmword ptr [{[vsp]f} - 0x20]" ++
            //     " # move low 4 x 16-bit lanes of operand 0 into high 16-bits of 4 x 32-bit lanes",
            // "punpcklwd xmm1, xmmword ptr [{[vsp]f} - 0x10] # same but for operand 1",

            "# Taken from LLVM output for Zig's *% operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "pxor xmm2, xmm2",
            "punpck{[target]c}wd xmm1, xmm2" ++
                "# move target 4 x 16-bit lanes of operand 0 to 4 x 32-bit lanes, zero extended",
            "punpck{[target]c}wd xmm0, xmm0" ++
                " # low and high 16-bits containing the 16-bit lane from operand 1",
            "pmaddwd xmm0, xmm1",

            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .target = @tagName(opcode)[13] });
        extmul.jmpToNextHandler(as);
        extmul.end(as);
    }
    {
        // pmulld requires SSE4_1
        var extmul_low = as.defineOpcodeHandler(.{ .fd = .@"i32x4.extmul_low_i16x8_u" }, .@"64");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig's *% operator",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "movdqa xmm2, xmm0",
            "pmulhuw xmm2, xmm1 # calculate high 16-bits of product?",
            "pmullw xmm0, xmm1 # calculate low 16-bits of product?",
            "punpcklwd xmm0, xmm2",

            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        extmul_low.jmpToNextHandler(as);
        extmul_low.end(as);
    }
    {
        // pmulld requires SSE4_1
        var extmul_high = as.defineOpcodeHandler(.{ .fd = .@"i32x4.extmul_high_i16x8_u" }, .@"64");
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig's *% operator",
            "pshufd xmm1, xmmword ptr [{[vsp]f} - 0x20], 0xEE # operand 0, high lanes",
            "pshufd xmm0, xmmword ptr [{[vsp]f} - 0x10], 0xEE # operand 1, high lanes",
            "movdqa xmm2, xmm0",
            "pmulhuw xmm2, xmm1 # calculate high 16-bits of product?",
            "pmullw xmm0, xmm1 # calculate low 16-bits of product?",
            "punpcklwd xmm0, xmm2",

            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp });
        extmul_high.jmpToNextHandler(as);
        extmul_high.end(as);
    }

    {
        // https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#saturating-integer-q-format-rounding-multiplication
        // pmulhrsw requires SSSE3, but requires additional overflow checks anyway
        var q15mulr_sat_s = as.defineOpcodeHandler(.{ .fd = .@"i16x8.q15mulr_sat_s" }, .@"64");

        as.write(
            \\.section .rodata.cst16, "aM", @progbits, 16
            \\.p2align 4, 0x00
            \\
        );
        var const_0 = as.label(&.{"const"});
        const_0.place(as);
        as.writeInstrs(&@as([4][]const u8, @splat(".long 0x0000" ++ "4000")));
        as.write("\n.text\n");

        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 0",
            "movdqa xmm1, xmmword ptr [{[vsp]f} - 0x10] # operand 1",
            "movdqa xmm4, xmmword ptr [{[const_0]f}]",
            "movdqa xmm2, xmm0",
            "pmullw xmm0, xmm1 # product, low bits",
            "pmulhw xmm2, xmm1 # product, high bits",
            "movdqa xmm3, xmm0",
            "# i32x4 of the products from original low 4 lanes",
            "punpcklwd xmm0, xmm2",
            "# i32x4 of the products from original high 4 lanes",
            "punpckhwd xmm3, xmm2",
            "# saturating must occur as last step",
            "paddd xmm0, xmm4",
            "paddd xmm3, xmm4",
            "psrad xmm0, 15",
            "psrad xmm3, 15",
            "packssdw xmm0, xmm3",

            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP",
        }, .{ .vsp = Gpr.vsp, .const_0 = const_0 });
        q15mulr_sat_s.jmpToNextHandler(as);
        q15mulr_sat_s.end(as);
    }

    {
        var extadd = as.defineOpcodeHandler(.{ .fd = .@"i32x4.extadd_pairwise_i16x8_s" }, .@"64");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "movdqa xmm1, xmm0",
            "pslld xmm0, 16 # low 16-bits of pair, moved to high 16-bits",
            "psrad xmm0, 16 # low 16-bits of pair",
            "psrad xmm1, 16 # high 16-bits of pair",
            "paddd xmm0, xmm1",

            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp });
        extadd.jmpToNextHandler(as);
        extadd.end(as);
    }
    {
        var extadd = as.defineOpcodeHandler(.{ .fd = .@"i32x4.extadd_pairwise_i16x8_u" }, .@"64");
        as.write(
            \\.section .rodata.cst16, "aM", @progbits, 16
            \\.p2align 4, 0x00
            \\
        );
        var low_16_bits = as.label(&.{"low_16_bits"});
        low_16_bits.place(as);
        as.writeInstrs(&@as([4][]const u8, @splat(".long 0x0000FFFF")));

        as.write(".text\n");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x10] # operand",
            "movdqa xmm1, xmm0",
            "pand xmm0, xmmword ptr [{[low_16_bits]f}] # low 16-bits of pair",
            "psrld xmm1, 16 # high 16-bits of pair",
            "paddd xmm0, xmm1",

            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .vsp = Gpr.vsp, .low_16_bits = low_16_bits });
        extadd.jmpToNextHandler(as);
        extadd.end(as);
    }

    // .@"i32x4.dot_i16x8_s"
    // phaddsw (horizontal add, saturating) requires SSSE3
}

const std = @import("std");
const AsmWriter = @import("AsmWriter.zig");
const SystemVParam = AsmWriter.SystemVParam;
const FDPrefixOpcode = @import("opcodes").FDPrefixOpcode;
const Gpr = AsmWriter.Gpr;
const LinearMemoryAccess = @import("LinearMemoryAccess.zig");
