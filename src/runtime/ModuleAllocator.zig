const ModuleAllocator = @This();

ctx: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    allocate: *const fn (
        ctx: *anyopaque,
        request: *Request,
    ) Allocator.Error!void,
    free: *const fn (ctx: *anyopaque, info: Free) void,
};

pub const Request = struct {
    table_types: []const Module.TableType,
    tables: [*]TableInst,
    mem_types: []const Module.MemType,
    mems: [*]MemInst,

    pub fn init(
        table_types: []const Module.TableType,
        tables: []TableInst,
        mem_types: []const Module.MemType,
        mems: []MemInst,
    ) Request {
        std.debug.assert(table_types.len <= tables.len);
        std.debug.assert(mem_types.len <= mems.len);
        return .{
            .table_types = table_types,
            .tables = tables.ptr,
            .mem_types = mem_types,
            .mems = mems.ptr,
        };
    }

    pub fn nextTableType(req: *const Request) ?*const Module.TableType {
        return if (req.table_types.len > 0) &req.table_types[0] else null;
    }

    pub fn nextMemType(req: *const Request) ?*const Module.MemType {
        return if (req.mem_types.len > 0) &req.mem_types[0] else null;
    }

    pub fn isDone(req: *const Request) bool {
        return req.table_types.len == 0 and req.mem_types.len == 0;
    }

    pub fn allocateMemory(req: *Request, buffer: []align(MemInst.buffer_align) u8) Allocator.Error!bool {
        if (req.mem_types.len == 0)
            return false;

        // This requirement could be relaxed, but there is no benefit.
        std.debug.assert(buffer.len % MemInst.page_size == 0);

        const expected_type = &req.mem_types[0];

        if (buffer.len < expected_type.limits.min * MemInst.page_size)
            return error.OutOfMemory;

        errdefer comptime unreachable;

        req.mem_types = req.mem_types[1..];
        req.mems[0] = MemInst{
            .base = buffer.ptr,
            .size = expected_type.limits.min * MemInst.page_size,
            .capacity = buffer.len,
            .limit = expected_type.limits.max * MemInst.page_size,
        };
        req.mems += 1;
        return true;
    }

    // TODO: Helper methods to init a table, but how to ensure length of allocation (memory/table data area) is correct?
    pub fn allocateTable(req: *Request, buffer: []align(TableInst.buffer_align) u8) Allocator.Error!bool {
        if (req.table_types.len == 0)
            return false;

        const expected_type = &req.table_types[0];
        const stride = TableStride.ofType(expected_type.elem_type);

        const len = std.math.cast(
            u32,
            @divExact(buffer.len, stride.toBytes()),
        ) orelse return error.OutOfMemory;

        if (len < expected_type.limits.min)
            return error.OutOfMemory;

        const max = std.math.cast(u32, expected_type.limits.max) orelse
            return error.OutOfMemory;

        errdefer comptime unreachable;

        req.table_types = req.table_types[1..];
        req.tables[0] = TableInst{
            .base = .{ .ptr = buffer.ptr },
            .stride = stride,
            .len = len,
            .capacity = len,
            .limit = max,
        };
        req.tables += 1;
        return true;
    }
};

pub inline fn allocate(self: ModuleAllocator, request: *Request) Allocator.Error!void {
    return self.vtable.allocate(self.ctx, request);
}

pub const Free = struct {
    mems: []const *MemInst,
    tables: []const *TableInst,
};

pub inline fn free(self: ModuleAllocator, info: Free) void {
    return self.vtable.free(self.ctx, info);
}

pub const PageAllocator = struct {
    pub const vtable = VTable{
        .allocate = PageAllocator.allocate,
        .free = PageAllocator.free,
    };

    fn allocate(ctx: *anyopaque, request: *Request) Allocator.Error!void {
        _ = ctx;

        // TODO: Reserve pages, create a helper module page_allocator.zig
        while (request.nextMemType()) |mem_type| {
            const buf = try std.heap.page_allocator.alignedAlloc(
                u8,
                .fromByteUnits(MemInst.buffer_align),
                mem_type.limits.min * MemInst.page_size,
            );

            @memset(buf, 0);
            _ = request.allocateMemory(buf) catch unreachable;
        }

        while (request.nextTableType()) |table_type| {
            const buf = try std.heap.page_allocator.alignedAlloc(
                u8,
                .fromByteUnits(TableInst.buffer_align),
                std.math.mul(
                    usize,
                    table_type.limits.min,
                    TableStride.ofType(table_type.elem_type).toBytes(),
                ) catch return error.OutOfMemory,
            );

            @memset(buf, 0);
            _ = request.allocateTable(buf) catch unreachable;
        }
    }

    fn free(ctx: *anyopaque, info: Free) void {
        _ = ctx;

        for (info.mems) |mem| {
            std.heap.page_allocator.free(mem.base[0..mem.capacity]);
        }

        for (info.tables) |table| {
            std.heap.page_allocator.free(
                table.base.ptr[0 .. table.capacity * table.stride.toBytes()],
            );
        }
    }
};

fn noFree(ctx: *anyopaque, info: Free) void {
    _ = ctx;
    for (info.mems) |mem| mem.* = undefined;
    for (info.tables) |table| table.* = undefined;
}

pub const page_allocator = ModuleAllocator{
    .ctx = undefined,
    .vtable = &PageAllocator.vtable,
};

pub const WithinArena = struct {
    arena: *std.heap.ArenaAllocator,
    mem_limit: MemLimit = .allocate_minimum,

    pub const MemLimit = union(enum) {
        /// Only ever allocate the minimum number of pages.
        allocate_minimum,
        /// Always allocate the given number of bytes, rounded down to the nearest multiple of
        /// the page size, limited by the linear memory's maximum limit.
        ///
        /// Allocation fails if this limit is less than a linear memory's minimum limit.
        up_to_amount: usize,
    };

    const vtable = VTable{
        .allocate = WithinArena.allocate,
        .free = noFree,
    };

    fn allocate(ctx: *anyopaque, request: *Request) Allocator.Error!void {
        const self: *WithinArena = @ptrCast(@alignCast(ctx));
        const into_arena = self.arena.allocator();

        // TODO: Duplicate code, maybe make a common wraper over an `std.mem.Allocator`?
        while (request.nextMemType()) |mem_type| {
            const minimum_len = mem_type.limits.min * MemInst.page_size;

            const buf = try into_arena.alignedAlloc(
                u8,
                .fromByteUnits(MemInst.buffer_align),
                request: switch (self.mem_limit) {
                    .allocate_minimum => minimum_len,
                    .up_to_amount => |limit| {
                        const actual_limit = (limit / MemInst.page_size) * MemInst.page_size;
                        if (actual_limit < minimum_len) return error.OutOfMemory;
                        break :request @min(actual_limit, mem_type.limits.max * MemInst.page_size);
                    },
                },
            );

            @memset(buf, 0);

            _ = request.allocateMemory(buf) catch unreachable;
        }

        while (request.nextTableType()) |table_type| {
            const buf = try into_arena.alignedAlloc(
                u8,
                .fromByteUnits(TableInst.buffer_align),
                std.math.mul(
                    usize,
                    table_type.limits.min,
                    TableStride.ofType(table_type.elem_type).toBytes(),
                ) catch return error.OutOfMemory,
            );

            @memset(buf, 0);

            _ = request.allocateTable(buf) catch unreachable;
        }
    }

    pub fn allocator(self: *WithinArena) ModuleAllocator {
        return .{
            .ctx = self,
            .vtable = &vtable,
        };
    }
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const TableStride = @import("table.zig").TableStride;
const TableInst = @import("table.zig").TableInst;
const MemInst = @import("memory.zig").MemInst;
const Module = @import("../Module.zig");
