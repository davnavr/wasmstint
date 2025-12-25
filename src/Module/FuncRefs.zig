//! Tracks which functions were referenced in global and element segment initializer expressions.

pub const Lookup = std.ArrayHashMapUnmanaged(FuncIdx, void, Context, false);

// Could exclude import functions from this set to save space, but current approach is simple
lookup: Lookup,
arena: *std.heap.ArenaAllocator,

const FuncRefs = @This();

pub const dummy = FuncRefs{
    .lookup = .empty,
    .arena = undefined,
};

pub fn init(
    arena: *std.heap.ArenaAllocator,
    import_count: @typeInfo(FuncIdx).@"enum".tag_type,
) Allocator.Error!FuncRefs {
    var lookup = Lookup.empty;
    try lookup.ensureUnusedCapacityContext(arena.allocator(), import_count, Context{});
    errdefer comptime unreachable;
    for (0..import_count) |i| {
        lookup.putAssumeCapacityNoClobberContext(@enumFromInt(i), {}, Context{});
    }
    std.debug.assert(lookup.count() == import_count);
    return .{
        .arena = arena,
        .lookup = lookup,
    };
}

pub fn ensureUnusedCapacity(refs: *FuncRefs, additional: usize) Allocator.Error!void {
    try refs.lookup.ensureUnusedCapacityContext(refs.arena.allocator(), additional, Context{});
}

const Context = struct {
    pub fn hash(_: Context, idx: FuncIdx) u32 {
        return std.hash.int(@as(u32, @intFromEnum(idx)));
    }

    pub fn eql(_: Context, a: FuncIdx, b: FuncIdx, _: usize) bool {
        return a == b;
    }
};

/// Indicates that a given function index can be referenced.
///
/// According to the [validation rules], references to functions can only be allowed if they are
/// function imports, or are referred to outside of functions defined in the module.
///
/// [validation rules]: https://webassembly.github.io/extended-const/core/valid/conventions.html#context
pub fn insert(refs: *FuncRefs, idx: FuncIdx) Allocator.Error!void {
    try refs.lookup.putContext(refs.arena.allocator(), idx, {}, Context{});
}

pub fn finish(refs: *FuncRefs, allocator: Allocator) Allocator.Error!Lookup {
    // Ideally, this would always discard excess capacity, but `MultiArrayList.clone()` doesn't
    const cloned = try refs.lookup.cloneContext(allocator, Context{});
    errdefer comptime unreachable;
    refs.lookup.clearRetainingCapacity();
    refs.* = undefined;
    return cloned;
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const FuncIdx = @import("../Module.zig").FuncIdx;
