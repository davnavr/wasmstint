//! Uses an `Allocator` to allocate tables.

const Error = ModuleAllocating.LimitsError || Allocator.Error;

pub fn allocate(
    table_type: *const TableType,
    allocator: Allocator,
    /// The initial size of the allocation, in elements.
    ///
    /// If this value is less than `table_type.limits.min`, then `error.LimitsMismatch` is
    /// returned.
    initial_capacity: usize,
) Error!TableInst {
    std.debug.assert(table_type.limits.min <= table_type.limits.max);
    std.debug.assert(table_type.limits.max <= std.math.maxInt(u32));
    if (initial_capacity < table_type.limits.min) {
        return error.LimitsMismatch;
    }

    // Cast always succeeds since `limits.max` is always a `u32`.
    const actual_capacity: u32 = @intCast(@min(initial_capacity, table_type.limits.max));
    const allocation = try allocator.alloc(?*anyopaque, actual_capacity);
    @memset(allocation[0..actual_capacity], null);

    return TableInst{
        .base = TableInst.Base{ .ptr = allocation.ptr },
        .len = @intCast(table_type.limits.min),
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

pub fn grow(
    request: *const Interpreter.InterruptionCause.TableGrow,
    allocator: Allocator,
) void {
    const table = request.table.table;
    const old_capacity = table.capacity;
    std.debug.assert(request.new_len <= table.limit);
    std.debug.assert(old_capacity < request.new_len);
    std.debug.assert(request.old_len <= table.len);

    if (request.new_len <= table.len) {
        std.debug.assert(request.new_len <= old_capacity);
        return; // resize already occurred
    }

    const new_capacity: u32 = @min(
        @max(
            request.new_len,
            // Try multiplying by 1.5
            old_capacity +| (old_capacity / 2),
        ),
        table.limit,
    );

    const old_allocation: []?*anyopaque = table.base.ptr[0..old_capacity];

    const elem = request.elem.ptr;
    const resized_in_place = allocator.resize(old_allocation, new_capacity);

    // Fill new elements with the provided initialization value
    if (resized_in_place) {
        table.capacity = new_capacity;
        table.fillWithinCapacity(elem, table.len, request.new_len);
    } else {
        // Fill the unused parts so the allocator actually copies useful stuff
        table.fillWithinCapacity(elem, table.len, old_capacity);

        const new_allocation: []?*anyopaque =
            allocator.remap(old_allocation, new_capacity) orelse return;

        table.base = .{ .ptr = new_allocation.ptr };
        table.capacity = new_capacity;
        table.fillWithinCapacity(elem, old_capacity, request.new_len);
    }

    request.elem.* = .{ .i32 = @bitCast(request.old_len) };
}

// pub fn free(table: *TableInst, allocator: Allocator) void {}

const std = @import("std");
const Allocator = std.mem.Allocator;
const TableType = @import("../Module.zig").TableType;
const ModuleAllocating = @import("ModuleAllocating.zig");
const TableInst = @import("table.zig").TableInst;
const Interpreter = @import("../Interpreter.zig");
