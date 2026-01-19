//! Writes definitions for all SIMD opcodes

pub fn defineAllOpcodes(as: *AsmWriter) void {
    _ = as;
}

const AsmWriter = @import("AsmWriter.zig");
const SystemVParam = AsmWriter.SystemVParam;
const Gpr = AsmWriter.Gpr;
