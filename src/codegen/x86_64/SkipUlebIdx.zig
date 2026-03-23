skip_type_idx: AsmWriter.Label,
finished: AsmWriter.Label,
byte: Gpr,

const SkipUlebIdx = @This();

pub fn writeDecodeByte(skip: *const SkipUlebIdx, as: *AsmWriter, first_comment: []const u8) void {
    as.printInstrs(&.{
        "movzx {[byte]f}, byte ptr [{[vip]f}] # {[first_comment]s}",
        "inc {[vip]f} # vip",
        "test {[byte_lo]f}, 0x80 # check for longer index",
    }, .{
        .byte = skip.byte,
        .byte_lo = skip.byte.withSize(.byte),
        .first_comment = first_comment,
        .vip = Gpr.vip,
    });
}

pub fn fastPath(as: *AsmWriter, clobber: Gpr, name: []const u8) SkipUlebIdx {
    var skip = SkipUlebIdx{
        .skip_type_idx = as.label(&.{ "skip_idx_", name }),
        .finished = as.label(&.{ "after_idx_", name }),
        .byte = clobber,
    };

    skip.writeDecodeByte(as, "first byte of index");
    as.printInstrs(&.{"jnz {f}"}, .{skip.skip_type_idx});
    skip.finished.place(as);
    return skip;
}

pub fn writeSlowPath(skip: *SkipUlebIdx, as: *AsmWriter) void {
    as.write(".p2align 4\n");
    skip.skip_type_idx.place(as);
    skip.writeDecodeByte(as, "next byte of index");
    as.printInstrs(&.{
        "jz {[finished]f}",
        "jmp {[loop]f}",
        "ud2",
    }, .{ .finished = skip.finished, .loop = skip.skip_type_idx });
    skip.* = undefined;
}

const AsmWriter = @import("AsmWriter.zig");
const Gpr = AsmWriter.Gpr;
