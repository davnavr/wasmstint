pub const TableInst = extern struct {
    base: Base,
    /// The current size, in elements.
    len: u32,
    /// Indicates the amount that the tables's size, in elements, can grow without reallocating.
    capacity: u32,
    /// The maximum size, in elements.
    limit: u32,

    pub const Base = packed union {
        func_ref: [*]FuncAddr.Nullable,
        extern_ref: [*]ExternAddr,
        ptr: [*]?*anyopaque,

        comptime {
            std.debug.assert(@sizeOf(Base) == @sizeOf(*anyopaque));
        }
    };

    pub const OobError = error{TableAccessOutOfBounds};

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
        std.debug.assert(table.len <= table.capacity);
        std.debug.assert(table.capacity <= table.limit);
        std.debug.assert(idx <= end_idx);
        std.debug.assert(end_idx <= table.capacity);

        @memset(table.base.ptr[idx..end_idx], elem);
    }

    /// Returns an error if the range of elements to fill is out of bounds.
    pub fn fill(table: *const TableInst, len: u32, elem: ?*anyopaque, idx: u32) OobError!void {
        const end_idx = std.math.add(u32, idx, len) catch
            return error.TableAccessOutOfBounds;

        if (end_idx > table.len)
            return error.TableAccessOutOfBounds;

        return table.fillWithinCapacity(elem, idx, end_idx);
    }
};

const std = @import("std");
const FuncAddr = @import("value.zig").FuncAddr;
const ExternAddr = @import("value.zig").ExternAddr;
const Module = @import("../Module.zig");
const ModuleInst = @import("module_inst.zig").ModuleInst;
