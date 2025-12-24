//! Tracks which functions were referenced in global and element segment initializer expressions.
//!
//! TODO: Use to create hashmap to replace `FuncAddr.Wasm.Block` array in module instances.

set: std.bit_set.DynamicBitSetUnmanaged,

const FuncRefs = @This();

pub fn init(allocator: std.mem.Allocator, func_import_count: u16) std.mem.Allocator.Error!FuncRefs {
    return .{
        .set = try .initEmpty(allocator, func_import_count),
    };
}

/// Indicates that a given function index can be referenced.
///
/// According to the [validation rules], references to functions can only be allowed if they are
/// function imports, or are referred to outside of functions defined in the module.
///
/// [validation rules]: https://webassembly.github.io/extended-const/core/valid/conventions.html#context
pub fn insert(refs: *FuncRefs, idx: FuncIdx) void {
    refs.set.set(@intFromEnum(idx));
}

const std = @import("std");
const FuncIdx = @import("../Module.zig").FuncIdx;
