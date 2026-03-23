align_skip: SkipUlebIdx,
offset_decode: DecodeUlebIdx,
oob: AsmWriter.Label,
size: std.mem.Alignment,

const LinearMemoryAccess = @This();

/// Pointer to memory base is stored in `r15`, while offset into to memory is stored in `r13d`.
pub fn start(
    as: *AsmWriter,
    /// Offset from value stack pointer to `i32` memory offset.
    offset: u16,
    size: std.mem.Alignment,
) LinearMemoryAccess {
    std.debug.assert(offset % 16 == 0);
    const oob = as.label(&.{"oob"});
    const align_skip = SkipUlebIdx.fastPath(as, .r13, "align");
    const offset_decode = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "offset");
    as.printInstrs(&.{
        "mov r14, qword ptr [{[mems]f}] # Pointer to MemInst",
        "mov r15, qword ptr [r14] # Base pointer",
        "add r13d, dword ptr [{[vsp]f} - 0x{[offset]X}] # offset",
        "jc {[oob]f} # target address overflowed",
        "lea r11, [r13 + {[access_size]d}]",
        "cmp r11, qword ptr [r14 + {[size_field_off]d}]",
        "ja {[oob]f} # exceeded memory bounds",
        "# Actually perform the access",
    }, .{
        .mems = Gpr.mems,
        .vsp = Gpr.vsp,
        .size_field_off = 8,
        .access_size = size.toByteUnits(),
        .oob = oob,
        .offset = offset,
    });
    return .{
        .oob = oob,
        .align_skip = align_skip,
        .offset_decode = offset_decode,
        .size = size,
    };
}

/// At this point `rsp` must refer to the saved `rbp` (it must be equal to `rbp`).
pub fn end(access: *LinearMemoryAccess, op: *AsmWriter.OpcodeHandler, as: *AsmWriter) void {
    op.jmpToNextHandler(as);
    access.align_skip.writeSlowPath(as);
    access.offset_decode.writeSlowPath(as);

    as.write(".p2align 4\n");
    access.oob.place(as);
    as.printInstrs(&.{
        "lea {[param_0]f}, [{[vip]f} - 1] #0 VIP",
        "#1 VSP in rsi",
        "mov {[param_2]f}, {[eip]f} #2 EIP",
        "mov {[param_3]f}, {[stp]f} #3 STP",
        "mov {[param_4]f}, 0 #4 memory index",
        "#5 interp in r9",
        "mov {[param_6]f}, r13d #6 address",
        "mov {[param_7]f}, {[size]d} #7 size",
        "mov {[param_8]f}, r14 #8 *MemInst",
    }, .{
        .param_0 = SystemVParam{ .index = 0 },
        .vip = Gpr.vip,
        .param_2 = SystemVParam{ .index = 2 },
        .eip = Gpr.eip,
        .param_3 = SystemVParam{ .index = 3 },
        .stp = Gpr.stp,
        .param_4 = SystemVParam{ .index = 4 },
        .param_6 = SystemVParam{ .index = 6, .size = .dword },
        .size = @intFromEnum(access.size),
        .param_7 = SystemVParam{ .index = 7, .size = .dword },
        .param_8 = SystemVParam{ .index = 8 },
    });
    as.popSystemVSavedRegisters();
    as.printInstrs(&.{
        "# rsp already refers to saved rbp",
        "pop rbp",
        ".cfi_def_cfa rsp, 8",
        "jmp {[prefix]s}trapMemoryAccessOutOfBounds",
        "ud2",
    }, .{ .prefix = as.options.symbol_prefix });
    access.* = undefined;
    op.end(as);
}

const std = @import("std");
const AsmWriter = @import("AsmWriter.zig");
const Gpr = AsmWriter.Gpr;
const SystemVParam = AsmWriter.SystemVParam;
const SkipUlebIdx = @import("SkipUlebIdx.zig");
const DecodeUlebIdx = @import("DecodeUlebIdx.zig");
