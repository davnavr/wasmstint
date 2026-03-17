pub const OpcodeHandlerParam = enum(u4) {
    locals,
    vsp,
    module,
    /// Preserved across WASM function calls.
    fuel,
    /// Derived from `module`.
    memories,
    /// Preserved across WASM function calls.
    ctx,
    vip,
    stp,
    eip,
    /// Preserved across WASM function calls.
    disp,

    pub fn arg(param: OpcodeHandlerParam, wip: *llvm.Builder.WipFunction) llvm.Builder.Value {
        return wip.arg(@intFromEnum(param));
    }
};

const llvm = @import("std").zig.llvm;
