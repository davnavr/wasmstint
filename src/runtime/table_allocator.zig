//! Uses an `Allocator` to allocate tables.

const Error = ModuleAllocating.LimitsError || Allocator.Error;

pub fn allocate(
    table_type: *TableType,
    allocator: Allocator,
    /// The initial size of the allocation, in elements.
    ///
    /// If this value is less than `table_type.limits.min`, then `error.LimitsMismatch` is
    /// returned.
    initial_capacity: usize,
) Error!TableInst {
    std.debug.assert(table_type.limits.min <= table_type.limits.max);
    if (table_type.limits.min < initial_capacity) {
        return error.LimitsMismatch;
    }

    // Cast always succeeds since `limits.max` is always a `u32`.
    const actual_capacity: u32 = @intCast(@min(initial_capacity, table_type.limits.max));
    const stride = TableStride.ofType(table_type.elem_type);
    const stride_bytes = stride.toBytes();
    const allocation = try allocator.rawAlloc(
        std.math.mul(u32, stride_bytes, actual_capacity) catch return error.OutOfMemory,
        .fromByteUnits(stride_bytes),
        @returnAddress(),
    );
    @memset(allocation, 0);

    return TableInst{
        .base = TableInst.Base{ .ptr = @ptrCast(allocation) },
        .len = table_type.limits.min,
        .capacity = actual_capacity,
        .limit = @intCast(table_type.limits.max),
    };
}

pub fn allocateForModule(
    request: *ModuleAllocating,
    allocator: Allocator,
    initial_capacity: usize,
) Error!void {
    const table_inst = try allocate(request.nextTableType().?, allocator, initial_capacity);
    request.nextTable().* = table_inst;
}

// pub fn free(table: *TableInst, allocator: Allocator) void {}

const std = @import("std");
const Allocator = std.mem.Allocator;
const TableType = @import("../Module.zig").TableType;
const ModuleAllocating = @import("ModuleAllocating.zig");
const TableInst = @import("table.zig").TableInst;
const TableStride = @import("table.zig").TableStride;
