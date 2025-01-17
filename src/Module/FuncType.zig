const std = @import("std");
const IndexedArena = @import("../IndexedArena.zig");
const ValType = @import("val_type.zig").ValType;

types: IndexedArena.Idx(ValType),
param_count: u16,
result_count: u16,

const FuncType = @This();

comptime {
    // Adjust alignment to be 4 if `@sizeOf(ValType)` becomes `@sizeOf(usize)`.
    std.debug.assert(@alignOf(ValType) <= 4);
}

fn paramAndResultTypes(func_type: FuncType) IndexedArena.Slice(ValType) {
    return .{
        .idx = func_type.types,
        .len = @as(u32, func_type.param_count) + func_type.result_count,
    };
}
