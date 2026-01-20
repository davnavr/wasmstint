//! Writes definitions for all SIMD opcodes

pub fn defineAllOpcodes(as: *AsmWriter) void {
    defineMemoryLoadOpcodes(as);
    defineBitwiseOpcodes(as);
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

fn defineBitwiseOpcodes(as: *AsmWriter) void {
    {
        var op = as.defineOpcodeHandler(.{ .fd = .@"v128.not" }, .@"64");
        as.printInstrs(&.{
            "pcmpeqd xmm0, xmm0 # all ones",
            "pxor xmm0, xmmword ptr [{[vsp]f} - 0x10] # bitwise NOT",
            "movdqa xmmword ptr [{[vsp]f} - 0x10], xmm0 # write result",
        }, .{ .vsp = Gpr.vsp });
        op.end(as);
    }
    for (&[_]FDPrefixOpcode{ .@"v128.and", .@"v128.or", .@"v128.xor" }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        as.printInstrs(&.{
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # operand 1",
            "p{[operation]s} xmm0, xmmword ptr [{[vsp]f} - 0x10]",
            "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # write result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
        }, .{ .vsp = Gpr.vsp, .operation = @tagName(opcode)[5..] });
        op.end(as);
    }
}

const IntInterp = enum {
    i8x16,
    i16x8,
    i32x4,
    i64x2,

    fn bitSize(interp: IntInterp) u7 {
        return switch (interp) {
            .i8x16 => 8,
            .i16x8 => 16,
            .i32x4 => 32,
            .i64x2 => 64,
        };
    }
};

pub fn defineIntegerOpcodes(as: *AsmWriter) void {
    as.write(
        \\.section .rodata.cst16, "aM", @progbits, 16
        \\.p2align 4, 0x00
        \\
    );

    as.print("\n.L{[symbol_prefix]s}i8x16_even_lanes:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([8][]const u8, @splat(".word 0x00FF")));

    as.print("\n.L{[symbol_prefix]s}i8x16_odd_lanes:\n", .{ .symbol_prefix = as.symbol_prefix });
    as.writeInstrs(&@as([8][]const u8, @splat(".word 0xFF00")));

    as.print("\n.L{[symbol_prefix]s}i64x2_max:\n", .{ .symbol_prefix = as.symbol_prefix });
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
        const interp = std.meta.stringToEnum(IntInterp, @tagName(opcode)[0..5]).?;
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
                "movdqa xmm2, xmmword ptr [.L{[symbol_prefix]s}i64x2_max]",
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
}

const std = @import("std");
const AsmWriter = @import("AsmWriter.zig");
const SystemVParam = AsmWriter.SystemVParam;
const FDPrefixOpcode = @import("opcodes").FDPrefixOpcode;
const Gpr = AsmWriter.Gpr;
const LinearMemoryAccess = @import("LinearMemoryAccess.zig");
