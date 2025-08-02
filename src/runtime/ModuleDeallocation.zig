//! Used to assist with the deallocation of a `ModuleInst`.
//!
//! TODO: How do callers deal with imported things?

const ModuleDeallocation = @This();

inst: ModuleInst,
mems: []const *MemInst,
tables: []const *TableInst,

// TODO: Iterator like functions to retrieve next MemInst/TableInst to free

pub fn finish(dealloc: *ModuleDeallocation, gpa: std.mem.Allocator) void {
    const buffer_len = dealloc.inst.inner.buffer_len;
    const buffer: []align(std.atomic.cache_line) u8 =
        @as([*]align(std.atomic.cache_line) u8, @ptrCast(dealloc.inst.inner))[0..buffer_len];

    gpa.free(buffer);
    dealloc.* = undefined;
}

const std = @import("std");
const ModuleInst = @import("module_inst.zig").ModuleInst;
const MemInst = @import("memory.zig").MemInst;
const TableInst = @import("table.zig").TableInst;
