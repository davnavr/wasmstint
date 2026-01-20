//! Writes definitions for all SIMD opcodes

pub fn defineAllOpcodes(as: *AsmWriter) void {
    defineIntegerOpcodes(as);
}

const IntInterp = enum {
    i8x16,

    fn bitSize(interp: IntInterp) u7 {
        return switch (interp) {
            .i8x16 => 8,
        };
    }

    fn shiftMask(interp: IntInterp) u63 {
        return interp.bitSize() - 1;
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

    as.write("\n.text\n");

    for (&[_]FDPrefixOpcode{
        .@"i8x16.shl",
        .@"i8x16.shr_s",
        .@"i8x16.shr_u",
    }) |opcode| {
        var op = as.defineOpcodeHandler(.{ .fd = opcode }, .@"64");
        const interp = std.meta.stringToEnum(IntInterp, @tagName(opcode)[0..5]).?;
        as.printInstrs(&.{
            "mov r14d, dword ptr [{[vsp]f} - 0x10] # amt to shift",
            "movdqa xmm0, xmmword ptr [{[vsp]f} - 0x20] # vector to shift",
            "and r14d, 0x{[shift_mask]X} # mod 2 of shift amt",
            "movd xmm1, r14d # shift amount in bottom 64 bits",
        }, .{ .vsp = Gpr.vsp, .shift_mask = interp.shiftMask() });
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
                "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            }, .{ .symbol_prefix = as.symbol_prefix, .vsp = Gpr.vsp }),
            .@"i8x16.shr_s" => as.printInstrs(&.{
                "movdqa xmm2, xmm0",
                "psraw xmm0, xmm1 # shift values in odd lanes",
                "pand xmm0, xmmword ptr [.L{[symbol_prefix]s}i8x16_odd_lanes] # result odd lanes",
                "psllw xmm2, 8 # move even lanes into odd lanes (low 8-bits to high 8-bits)",
                "psraw xmm2, xmm1 # shift values in even lanes",
                "psrlw xmm2, 8 # move even lanes back to their final position",
                "pand xmm2, xmmword ptr [.L{[symbol_prefix]s}i8x16_even_lanes] # result even lanes",
                "por xmm0, xmm2",
                "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            }, .{ .symbol_prefix = as.symbol_prefix, .vsp = Gpr.vsp }),
            .@"i8x16.shr_u" => as.printInstrs(&.{
                "psrlw xmm0, xmm1 # shift values in odd lanes",
                "movdqa xmm2, xmm0",
                "pand xmm2, xmmword ptr [.L{[symbol_prefix]s}i8x16_odd_lanes] # result odd lanes",
                "movdqa xmm3, xmmword ptr [.L{[symbol_prefix]s}i8x16_even_lanes]",
                "psrlw xmm3, xmm1 # mask for even lanes",
                "pand xmm0, xmm3 # result even lanes",
                "por xmm0, xmm2",
                "movdqa xmmword ptr [{[vsp]f} - 0x20], xmm0 # store result",
            }, .{ .symbol_prefix = as.symbol_prefix, .vsp = Gpr.vsp }),
            else => unreachable,
        }
        as.printInstrs(&.{"lea {[vsp]f}, [{[vsp]f} - 0x10] # adjust VSP"}, .{ .vsp = Gpr.vsp });
        op.jmpToNextHandler(as);
        op.end(as);
    }
}

const std = @import("std");
const AsmWriter = @import("AsmWriter.zig");
const SystemVParam = AsmWriter.SystemVParam;
const FDPrefixOpcode = @import("opcodes").FDPrefixOpcode;
const Gpr = AsmWriter.Gpr;
