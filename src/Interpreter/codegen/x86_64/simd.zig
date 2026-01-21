//! Writes definitions for all SIMD opcodes

pub fn defineAllOpcodes(as: *AsmWriter) void {
    defineMemoryLoadOpcodes(as);
    defineMemoryStoreOpcodes(as);
    defineBitwiseOpcodes(as);
    defineBooleanOpcodes(as);
    defineConstOpcodes(as);
    defineConversionOpcodes(as);

    defineIntegerOpcodes(as);
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

fn defineConstOpcodes(as: *AsmWriter) void {
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

fn defineIntegerOpcodes(as: *AsmWriter) void {
    as.write(
        \\.section .rodata.cst16, "aM", @progbits, 16
        \\.p2align 4, 0x00
        \\
    );

    as.print("\n.L{[symbol_prefix]s}i8x16_even_lanes:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([8][]const u8, @splat(".word 0x00FF")));

    as.print("\n.L{[symbol_prefix]s}i8x16_odd_lanes:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([8][]const u8, @splat(".word 0xFF00")));

    as.print("\n.L{[symbol_prefix]s}i64x2_sign_bits:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([2][]const u8, @splat(".quad 0x8000" ++ "0000" ++ "0000" ++ "0000")));

    as.write("\n.text\n");

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

    // PMULLD requires SSE4_1
    {
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
}

const std = @import("std");
const AsmWriter = @import("AsmWriter.zig");
const SystemVParam = AsmWriter.SystemVParam;
const FDPrefixOpcode = @import("opcodes").FDPrefixOpcode;
const Gpr = AsmWriter.Gpr;
const LinearMemoryAccess = @import("LinearMemoryAccess.zig");
