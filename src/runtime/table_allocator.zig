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
    const stride = TableStride.ofType(table_type.elem_type);
    const stride_bytes = stride.toBytes();
    const allocation_size = std.math.mul(u32, stride_bytes, actual_capacity) catch
        return error.OutOfMemory;
    const allocation = allocator.rawAlloc(
        allocation_size,
        .fromByteUnits(stride_bytes),
        @returnAddress(),
    ) orelse return error.OutOfMemory;
    @memset(allocation[0..allocation_size], 0);

    return TableInst{
        .base = TableInst.Base{ .ptr = @ptrCast(@alignCast(allocation)) },
        .stride = stride,
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
    const stride_bytes = table.stride.toBytes();
    std.debug.assert(request.new_len <= table.limit);
    std.debug.assert(old_capacity < request.new_len);
    std.debug.assert(request.old_len <= table.len);

    if (request.new_len <= table.len) {
        std.debug.assert(request.new_len <= old_capacity);
        return; // resize already occurred
    }

    const new_capacity: u32 = @max(
        request.new_len,
        // Try multiplying by 1.5
        old_capacity +| (old_capacity / 2),
    );
    const new_capacity_bytes = std.math.mul(usize, new_capacity, stride_bytes) catch return;

    const old_allocation: []align(TableInst.buffer_align) u8 =
        table.base.ptr[0 .. old_capacity * stride_bytes];

    const elem_bytes = std.mem.asBytes(request.elem)[0..stride_bytes];
    const resized_in_place = allocator.rawResize(
        old_allocation,
        .fromByteUnits(stride_bytes),
        new_capacity_bytes,
        @returnAddress(),
    );

    // Fill new elements with the provided initialization value
    if (resized_in_place) {
        table.capacity = new_capacity;
        table.fillWithinCapacity(elem_bytes, table.len, request.new_len);
    } else {
        // Fill the unused parts so the allocator actually copies useful stuff
        table.fillWithinCapacity(elem_bytes, table.len, old_capacity);

        const new_allocation: [*]align(TableInst.buffer_align) u8 = @alignCast(
            allocator.rawRemap(
                old_allocation,
                .fromByteUnits(stride_bytes),
                new_capacity_bytes,
                @returnAddress(),
            ) orelse return,
        );

        table.base = .{ .ptr = new_allocation };
        table.capacity = new_capacity;
        table.fillWithinCapacity(elem_bytes, old_capacity, request.new_len);
    }

    request.elem.* = .{ .i32 = @bitCast(request.old_len) };
}

// pub fn free(table: *TableInst, allocator: Allocator) void {}

const std = @import("std");
const Allocator = std.mem.Allocator;
const TableType = @import("../Module.zig").TableType;
const ModuleAllocating = @import("ModuleAllocating.zig");
const TableInst = @import("table.zig").TableInst;
const TableStride = @import("table.zig").TableStride;
const Interpreter = @import("../Interpreter.zig");
