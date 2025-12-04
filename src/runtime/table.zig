pub const TableInst = extern struct {
    base: Base,
    /// The current size, in elements.
    len: u32,
    /// Indicates the amount that the tables's size, in elements, can grow without reallocating.
    ///
    /// Elements in the range `base[len..capacity]` are `undefined`.
    capacity: u32,
    /// The maximum size, in elements.
    limit: u32,
    vtable: *const VTable,

    pub const Base = packed union {
        func_ref: [*]FuncAddr.Nullable,
        extern_ref: [*]ExternAddr,
        ptr: [*]?*anyopaque,

        comptime {
            std.debug.assert(@sizeOf(Base) == @sizeOf(*anyopaque));
        }
    };

    pub const OobError = error{TableAccessOutOfBounds};

    fn checkInvariants(table: *const TableInst) void {
        std.debug.assert(table.len <= table.capacity);
        std.debug.assert(table.len <= table.limit);
    }

    pub const VTable = struct {
        /// Implements the logic for performing a resize when there is no more capacity remaining.
        ///
        /// After a successful resize, `table.len == new_len`, and the elements in the newly
        /// allocated range are set to `init_elem`.
        grow: *const fn (
            table: *TableInst,
            init_elem: ?*anyopaque,
            /// Must be `> table.len`, `> table.capacity` and `<= table.limit`.
            new_len: u32,
        ) Oom!void,
        free: *const fn (*TableInst) void,
    };

    pub fn grow(table: *TableInst, init_elem: ?*anyopaque, new_len: u32) Oom!void {
        table.checkInvariants();
        if (table.limit < new_len) {
            return Oom.OutOfMemory;
        } else if (new_len <= table.len) {
            return;
        }

        const old_len = table.len;
        if (new_len <= table.capacity) {
            @memset(table.base.ptr[table.len..new_len], init_elem);
            table.len = new_len;
        } else {
            try table.vtable.grow(table, init_elem, new_len);
        }
        table.checkInvariants();
        std.debug.assert(table.len == new_len);
        if (builtin.mode == .Debug) {
            const expected = @intFromPtr(init_elem);
            for (table.elements()[old_len..new_len], old_len..) |*e, i| {
                const actual = @intFromPtr(e.*);
                if (actual != expected) {
                    std.debug.panic(
                        "expected element {X:0>8} at index {d} (0x{X}), got {X:0>8}",
                        .{ expected, i, @intFromPtr(e), actual },
                    );
                }
            }
        }
    }

    pub fn free(table: *TableInst) void {
        table.checkInvariants();
        table.vtable.free(table);
        table.* = undefined;
    }

    pub const Allocated = @import("table/Allocated.zig");

    /// Creates a `TableInst` from a static buffer.
    pub fn fromStaticBuffer(
        buffer: []?*anyopaque,
        init_elem: ?*anyopaque,
        /// The initial size of the table.
        size: usize,
    ) TableInst {
        std.debug.assert(size <= buffer.len);
        @memset(buffer[0..size], init_elem);
        return TableInst{
            .base = buffer.ptr,
            .len = size,
            .capacity = buffer.len,
            .limit = buffer.len,
            .vtable = &VTable{
                .grow = noGrow,
                .free = emptyFree,
            },
        };
    }

    pub fn noGrow(_: *TableInst, new_len: usize) Oom!void {
        _ = new_len;
        return error.OutOfMemory;
    }

    fn emptyFree(table: *TableInst) void {
        std.debug.assert(table.len == 0);
        std.debug.assert(table.capacity == 0);
    }

    pub fn limits(table: *const TableInst) Module.Limits {
        table.checkInvariants();
        return .{ .min = table.len, .max = table.limit };
    }

    /// Implements the [`table.init`] instruction, which is also used in module instantiation.
    ///
    /// [`table.init`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-init
    pub fn init(
        table: Module.TableIdx,
        module: ModuleInst,
        src: Module.ElemIdx,
        len: ?u32,
        src_idx: u32,
        dst_idx: u32,
    ) OobError!void {
        const module_inst = module.header();
        const table_addr = module_inst.tableAddr(table);
        const table_inst = table_addr.table;
        const src_elems = module_inst.elemSegment(src);
        const actual_len = len orelse src_elems.len;

        table_inst.checkInvariants();

        const src_end_idx = std.math.add(usize, src_idx, actual_len) catch
            return error.TableAccessOutOfBounds;

        if (src_end_idx > src_elems.len) {
            return error.TableAccessOutOfBounds;
        }
        const dst_end_idx = std.math.add(usize, dst_idx, actual_len) catch
            return error.TableAccessOutOfBounds;

        if (dst_end_idx > table_inst.len) {
            return error.TableAccessOutOfBounds;
        }

        std.debug.assert(src_elems.elementType() == table_addr.elem_type);

        if (actual_len == 0) return;

        switch (table_addr.elem_type) {
            .funcref => {
                const dst_elems: []FuncAddr.Nullable = table_inst.base
                    .func_ref[0..table_inst.len][dst_idx..dst_end_idx];

                switch (src_elems.tag) {
                    .func_indices => {
                        const src_indices = src_elems.contents.func_indices[src_idx..src_end_idx];
                        for (src_indices, dst_elems) |i, *dst| {
                            dst.* = @as(FuncAddr.Nullable, @bitCast(module_inst.funcAddr(i)));
                        }
                    },
                    .func_expressions => {
                        const src_exprs = src_elems.contents.expressions[src_idx..src_end_idx];
                        for (src_exprs, dst_elems) |*src_expr, *dst| {
                            dst.* = switch (src_expr.tag) {
                                .@"ref.null" => FuncAddr.Nullable.null,
                                .@"ref.func" => @bitCast(
                                    module_inst.funcAddr(src_expr.inner.@"ref.func".get()),
                                ),
                                .@"global.get" => get: {
                                    const global = module_inst.globalAddr(
                                        src_expr.inner.@"global.get".get(),
                                    );

                                    std.debug.assert(global.global_type.val_type == .funcref);

                                    break :get @as(
                                        *const FuncAddr.Nullable,
                                        @ptrCast(@alignCast(global.value)),
                                    ).*;
                                },
                            };
                        }
                    },
                    .extern_expressions => unreachable,
                }
            },
            .externref => {
                const dst_elems: []ExternAddr = table_inst.base
                    .extern_ref[0..table_inst.len][dst_idx..dst_end_idx];

                const src_exprs = src_elems.contents.expressions[src_idx..src_end_idx];
                for (src_exprs, dst_elems) |*src_expr, *dst| {
                    dst.* = switch (src_expr.tag) {
                        .@"ref.null" => ExternAddr.null,
                        .@"global.get" => get: {
                            const global = module_inst.globalAddr(
                                src_expr.inner.@"global.get".get(),
                            );

                            std.debug.assert(global.global_type.val_type == .externref);

                            break :get @as(
                                *const ExternAddr,
                                @ptrCast(@alignCast(global.value)),
                            ).*;
                        },
                        .@"ref.func" => unreachable,
                    };
                }
            },
            else => unreachable,
        }
    }

    pub fn elements(table: *const TableInst) []?*anyopaque {
        table.checkInvariants();
        return table.base.ptr[0..table.len];
    }

    pub fn elementAt(table: *const TableInst, idx: usize) OobError!*?*anyopaque {
        return if (table.len <= idx)
            error.TableAccessOutOfBounds
        else
            &table.elements()[idx];
    }

    /// Implements the [`table.copy`] instruction.
    ///
    /// (Currently does not) Asserts that the `src` and `dst` tables have the same element types.
    ///
    /// [`table.copy`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-copy
    pub fn copy(
        dst: *const TableInst,
        src: *const TableInst,
        len: u32,
        src_idx: u32,
        dst_idx: u32,
    ) OobError!void {
        dst.checkInvariants();
        src.checkInvariants();
        // TODO: Assert that table types are compatible

        const src_end_idx = std.math.add(usize, src_idx, len) catch
            return error.TableAccessOutOfBounds;

        if (src_end_idx > src.len)
            return error.TableAccessOutOfBounds;

        const dst_end_idx = std.math.add(usize, dst_idx, len) catch
            return error.TableAccessOutOfBounds;

        if (dst_end_idx > dst.len)
            return error.TableAccessOutOfBounds;

        const src_slice: []const ?*anyopaque = src.elements()[src_idx..src_end_idx];
        @memmove(dst.elements()[dst_idx..dst_end_idx], src_slice);
    }

    /// Asserts that `idx` and `end_idx` refer to a valid range within the table's allocated
    /// capacity.
    pub fn fillWithinCapacity(
        table: *const TableInst,
        elem: ?*anyopaque,
        idx: u32,
        end_idx: u32,
    ) void {
        table.checkInvariants();
        std.debug.assert(idx <= end_idx);
        std.debug.assert(end_idx <= table.capacity);
        std.debug.assert(end_idx <= table.limit);

        @memset(table.base.ptr[idx..end_idx], elem);
    }

    /// Returns an error if the range of elements to fill is out of bounds.
    pub fn fill(table: *const TableInst, len: u32, elem: ?*anyopaque, idx: u32) OobError!void {
        table.checkInvariants();

        const end_idx = std.math.add(u32, idx, len) catch
            return error.TableAccessOutOfBounds;

        if (end_idx > table.len) {
            return error.TableAccessOutOfBounds;
        }

        return table.fillWithinCapacity(elem, idx, end_idx);
    }
};

const std = @import("std");
const builtin = @import("builtin");
const Oom = std.mem.Allocator.Error;
const FuncAddr = @import("value.zig").FuncAddr;
const ExternAddr = @import("value.zig").ExternAddr;
const Module = @import("../Module.zig");
const ModuleInst = @import("module_inst.zig").ModuleInst;
