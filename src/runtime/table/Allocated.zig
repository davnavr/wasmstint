//! A `TableInst` implementation backed by an `Allocator`.

allocator: Allocator,
table: TableInst,

const Allocated = @This();

/// Asserts that `size <= capacity`.
pub fn allocate(
    allocator: Allocator,
    /// The value all elements are initially set to.
    init_elem: ?*anyopaque,
    len: u32,
    capacity: u32,
    /// The maximum number of elements the table can ever have.
    maximum: u32,
) Oom!Allocated {
    std.debug.assert(len <= capacity);
    std.debug.assert(capacity <= maximum);

    const elements = try allocator.alloc(?*anyopaque, capacity);
    @memset(elements[0..len], init_elem);

    return Allocated{
        .allocator = allocator,
        .table = TableInst{
            .base = .{ .ptr = elements.ptr },
            .len = len,
            .capacity = capacity,
            .limit = maximum,
            .vtable = &vtable,
        },
    };
}

/// Allocates a new `MemInst` corresponding to the given `MemType`.
///
/// The initial size is the minimum specified in the `MemType`.
///
/// Asserts that `initial_capacity` and `maximum_size` are not less than the minimum specified
/// in the `MemType`.
pub fn allocateFromType(
    allocator: Allocator,
    table_type: *const TableType,
    init_elem: ?*anyopaque,
    initial_capacity: u32,
    /// Allows a smaller limit than the one specified in the `table_type`.
    maximum: u32,
) Oom!Allocated {
    std.debug.assert(table_type.limits.min <= initial_capacity);
    std.debug.assert(table_type.limits.min <= maximum);
    // TODO: If non-nullable reference support is added, need to check `init_elem != null`

    return allocate(
        allocator,
        init_elem,
        @intCast(table_type.limits.min),
        initial_capacity,
        if (maximum <= table_type.limits.max) maximum else @intCast(table_type.limits.max),
    );
}

const vtable = TableInst.VTable{
    .grow = grow,
    .free = free,
};

/// After a successful resize, `table.len == new_len`, and the elements in the newly
/// allocated range are set to `init_elem`.
fn grow(inst: *TableInst, init_elem: ?*anyopaque, new_len: u32) Oom!void {
    std.debug.assert(inst.len < new_len);
    std.debug.assert(inst.capacity < new_len);
    std.debug.assert(inst.len <= inst.limit);

    const table: *Allocated = @fieldParentPtr("table", inst);
    const old_elems: []?*anyopaque = inst.elements();
    const new_capacity: u32 = if (table.allocator.resize(old_elems, new_len))
        new_len
    else realloc: {
        // Resize in place failed, try new allocation
        const new_elems = try table.allocator.alloc(
            ?*anyopaque,
            // Growth factor of 1.5
            @max(new_len, inst.capacity +| (inst.capacity / 2)),
        );

        @memcpy(new_elems[0..inst.len], old_elems);
        @memset(new_elems[inst.len..new_len], init_elem);

        inst.base.ptr = new_elems.ptr;

        break :realloc @intCast(new_elems.len);
    };

    @memset(inst.base.ptr[inst.len..new_len], init_elem);
    inst.len = new_len;
    inst.capacity = new_capacity;
}

fn free(inst: *TableInst) void {
    const table: *Allocated = @fieldParentPtr("table", inst);
    table.allocator.free(inst.base.ptr[0..inst.capacity]);
    table.* = undefined;
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const TableType = @import("../../Module.zig").TableType;
const Oom = Allocator.Error;
const TableInst = @import("../table.zig").TableInst;
