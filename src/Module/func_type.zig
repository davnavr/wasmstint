const std = @import("std");
const IndexedArena = @import("../IndexedArena.zig");
const ValType = @import("val_type.zig").ValType;

pub const FuncType = extern struct {
    types: [*]const ValType,
    param_count: u16,
    result_count: u16,

    inline fn paramAndResultTypes(sig: *const FuncType) []const ValType {
        return sig.types[0 .. @as(u32, sig.param_count) + sig.result_count];
    }

    pub inline fn parameters(sig: *const FuncType) []const ValType {
        return sig.paramAndResultTypes()[0..sig.param_count];
    }

    pub inline fn results(sig: *const FuncType) []const ValType {
        return sig.paramAndResultTypes()[sig.param_count..];
    }
};
