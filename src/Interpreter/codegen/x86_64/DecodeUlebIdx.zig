done: AsmWriter.Label,
slow_path: AsmWriter.Label,
result: Gpr,
byte: Gpr,
accumulator: Gpr,

const DecodeUlebIdx = @This();

pub fn fastPath(
    as: *AsmWriter,
    result: Gpr,
    clobbers: [2]Gpr,
    name: []const u8,
) DecodeUlebIdx {
    var decode = DecodeUlebIdx{
        .done = as.label(&.{ "index_", name, "_done" }),
        .slow_path = as.label(&.{ "index_", name, "_slow" }),
        .result = result,
        .byte = clobbers[0],
        .accumulator = clobbers[1],
    };
    as.printInstrs(&.{
        "movzx {[result]f}, byte ptr [{[vip]f}] # first byte",
        "inc {[vip]f}",
        "test {[result_l]f}, 0x80 # check for longer index",
        "jnz {[slow_path]f}",
    }, .{
        .result = result,
        .result_l = result.withSize(.byte),
        .vip = Gpr.vip,
        .slow_path = decode.slow_path,
    });
    decode.done.place(as);
    return decode;
}

pub fn writeSlowPath(decode: *DecodeUlebIdx, as: *AsmWriter) void {
    as.write(".p2align 4\n");
    decode.slow_path.place(as);
    as.printInstrs(&.{"and {[result]f}, 0x7F # keep lower 7 bits"}, .{
        .result = decode.result,
    });
    // A loop would probably work better here, but clobbering another register is annoying
    for (1..4) |i| {
        as.printInstrs(&.{
            "movzx {[byte]f}, byte ptr [{[vip]f}] # length is {[len]d} bytes",
            "inc {[vip]f}",
            "mov {[acc]f}, {[byte]f}",
            "and {[acc]f}, 0x7F",
            "shl {[acc]f}, {[shift_by]d}",
            "or {[result]f}, {[acc]f}",
            "test {[byte_l]f}, 0x80 # check for continuation",
            "jz {[done]f}",
        }, .{
            .len = i + 1,
            .result = decode.result,
            .byte = decode.byte,
            .byte_l = decode.byte.withSize(.byte),
            .acc = decode.accumulator,
            .shift_by = i * 7,
            .vip = Gpr.vip,
            .done = decode.done,
        });
    }

    // Assume max length (5 bytes) ULEB128
    as.printInstrs(&.{
        "movzx {[byte]f}, byte ptr [{[vip]f}] # length is maximum of 5 bytes",
        "inc {[vip]f}",
        "mov {[acc]f}, {[byte]f} ",
        // "and {[acc]f}, 0x7F", // final byte, no need to mask
        "shl {[acc]f}, 28",
        "or {[result]f}, {[acc]f}",
        "jmp {[done]f}",
        "ud2",
    }, .{
        .result = decode.result,
        .byte = decode.byte,
        .acc = decode.accumulator,
        .vip = Gpr.vip,
        .done = decode.done,
    });
}

const AsmWriter = @import("AsmWriter.zig");
const Gpr = AsmWriter.Gpr;
