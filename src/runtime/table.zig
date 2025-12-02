pub const TableStride = enum(u32) {
    ptr = @sizeOf(*anyopaque),
    fat = @sizeOf([2]*anyopaque),

    pub fn ofType(elem_type: Module.ValType) TableStride {
        return switch (elem_type) {
            .funcref => .fat,
            .externref => .ptr,
            else => unreachable,
        };
    }

    pub inline fn toBytes(stride: TableStride) u32 {
        return @intFromEnum(stride);
    }

    comptime {
        std.debug.assert(ofType(.funcref).toBytes() == @sizeOf(FuncAddr.Nullable));
        std.debug.assert(ofType(.externref).toBytes() == @sizeOf(ExternAddr));
    }
};

pub const TableInst = extern struct {
    base: Base,
    stride: TableStride,
    /// The current size, in elements.
    len: u32,
    /// Indicates the amount that the tables's size, in elements, can grow without reallocating.
    capacity: u32,
    /// The maximum size, in elements.
    limit: u32,

    pub const buffer_align = @max(@alignOf(FuncAddr.Nullable), @alignOf(ExternAddr));

    comptime {
        std.debug.assert(buffer_align == @alignOf(*anyopaque));
    }

    pub const Base = packed union {
        func_ref: [*]FuncAddr.Nullable,
        extern_ref: [*]ExternAddr,
        ptr: [*]align(buffer_align) u8,

        comptime {
            std.debug.assert(@sizeOf(Base) == @sizeOf([*]const u8));
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

        if (src_end_idx > src_elems.len)
            return error.TableAccessOutOfBounds;

        const dst_end_idx = std.math.add(usize, dst_idx, actual_len) catch
            return error.TableAccessOutOfBounds;

        if (dst_end_idx > table_inst.len)
            return error.TableAccessOutOfBounds;

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

    pub fn bytes(table: *const TableInst) []align(buffer_align) u8 {
        return table.base.ptr[0..(@as(usize, table.len) * table.stride.toBytes())];
    }

    pub fn elementSlice(
        table: *const TableInst,
        idx: usize,
    ) OobError![]align(@alignOf(*anyopaque)) u8 {
        if (table.len <= idx) return error.TableAccessOutOfBounds;
        const stride = table.stride.toBytes();
        const base_addr = idx * stride;
        return @alignCast(table.bytes()[base_addr .. base_addr + stride]);
    }

    /// Implements the [`table.copy`] instruction.
    ///
    /// Asserts that the `src` and `dst` tables have the same element types.
    ///
    /// [`table.copy`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-copy
    pub fn copy(
        dst: *const TableInst,
        src: *const TableInst,
        len: u32,
        src_idx: u32,
        dst_idx: u32,
    ) OobError!void {
        std.debug.assert(dst.stride == src.stride);
        const src_end_idx = std.math.add(usize, src_idx, len) catch
            return error.TableAccessOutOfBounds;

        if (src_end_idx > src.len)
            return error.TableAccessOutOfBounds;

        const dst_end_idx = std.math.add(usize, dst_idx, len) catch
            return error.TableAccessOutOfBounds;

        if (dst_end_idx > dst.len)
            return error.TableAccessOutOfBounds;

        if (len == 0) return;

        const stride = src.stride.toBytes();
        const src_slice: []align(@sizeOf(usize)) const u8 =
            @alignCast(src.bytes()[src_idx * stride .. src_end_idx * stride]);
        std.debug.assert(src_slice.len % stride == 0);

        const dst_slice: []align(@sizeOf(usize)) u8 =
            @alignCast(dst.bytes()[dst_idx * stride .. dst_end_idx * stride]);
        std.debug.assert(dst_slice.len % stride == 0);

        // This is duplicate code from the `memory.copy` helper
        if (@intFromPtr(src) == @intFromPtr(dst) and (dst_idx < src_end_idx or src_idx < dst_end_idx)) {
            @memmove(dst_slice, src_slice);
        } else {
            @memcpy(dst_slice, src_slice);
        }
    }

    pub fn fillWithinCapacity(
        table: *const TableInst,
        elem: []align(@alignOf(*anyopaque)) const u8,
        idx: u32,
        end_idx: u32,
    ) void {
        std.debug.assert(table.len <= table.capacity);
        std.debug.assert(table.capacity <= table.limit);

        const stride = table.stride.toBytes();
        std.debug.assert(elem.len == stride);
        std.debug.assert(idx <= end_idx);
        std.debug.assert(end_idx <= table.capacity);

        const FatPtr = [2]*anyopaque;
        const fat_size = @sizeOf(FatPtr);
        comptime {
            std.debug.assert(TableStride.fat.toBytes() == fat_size);
        }

        var src_fat_buf: FatPtr align(fat_size) = undefined;
        switch (table.stride) {
            .ptr => @memset(&src_fat_buf, @as(*const *anyopaque, @ptrCast(elem)).*),
            .fat => @memcpy(&src_fat_buf, @as(*const FatPtr, @ptrCast(elem))),
        }

        // Rely on auto-vectorization to fill the table.
        const dst_bytes = table.base.ptr[@as(usize, idx) * stride .. @as(usize, end_idx) * stride];
        const dst_fat_bytes = dst_bytes[0 .. (dst_bytes.len / fat_size) * fat_size];
        @memset(
            @as(
                []align(buffer_align) FatPtr,
                @ptrCast(@alignCast(dst_fat_bytes)),
            ),
            src_fat_buf,
        );

        switch (table.stride) {
            .fat => {},
            .ptr => if (dst_bytes.len % fat_size != 0) {
                @as(
                    **anyopaque,
                    @ptrCast(@alignCast(dst_bytes[dst_bytes.len - stride ..])),
                ).* = src_fat_buf[0];
            },
        }
    }

    pub fn fill(
        table: *const TableInst,
        len: u32,
        elem: []align(@alignOf(*anyopaque)) const u8,
        idx: u32,
    ) OobError!void {
        const end_idx = std.math.add(u32, idx, len) catch
            return error.TableAccessOutOfBounds;

        if (end_idx > table.len)
            return error.TableAccessOutOfBounds;

        if (len == 0) return;

        return table.fillWithinCapacity(elem, idx, end_idx);
    }
};

const std = @import("std");
const FuncAddr = @import("value.zig").FuncAddr;
const ExternAddr = @import("value.zig").ExternAddr;
const Module = @import("../Module.zig");
const ModuleInst = @import("module_inst.zig").ModuleInst;
