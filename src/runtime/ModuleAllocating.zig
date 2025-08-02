//! A `ModuleInst` that has not yet been fully, *allocated*.

const ModuleAllocating = @This();

/// A partially allocated `ModuleInst`.
///
/// Accessing this field may result in undefined behavior.
requiring_allocation: ModuleInst,
mem_idx: @typeInfo(Module.MemIdx).@"enum".tag_type,
table_idx: @typeInfo(Module.TableIdx).@"enum".tag_type,

pub const BeginError = ImportProvider.Error || Allocator.Error;

/// Begins the process of module allocation.
pub fn begin(
    module: Module,
    import_provider: ImportProvider,
    gpa: Allocator,
    import_failure: ?*ImportProvider.FailedRequest,
) BeginError!ModuleAllocating {
    var arena = std.heap.FixedBufferAllocator.init(
        try gpa.alignedAlloc(
            u8,
            .fromByteUnits(std.atomic.cache_line),
            module.inner.runtime_shape.size.bytes,
        ),
    );
    errdefer gpa.free(arena.buffer);

    const header = &(arena.allocator().alignedAlloc(
        ModuleInst.Header,
        .fromByteUnits(std.atomic.cache_line),
        1,
    ) catch unreachable)[0];
    std.debug.assert(@intFromPtr(header) == @intFromPtr(arena.buffer.ptr));

    const func_imports = arena.allocator().alloc(
        value.FuncAddr,
        module.inner.raw.func_import_count,
    ) catch unreachable;
    for (
        func_imports,
        module.funcImportNames(),
        module.funcImportTypes(),
    ) |*import, name, func_type| {
        import.* = try import_provider.resolveTyped(
            name.module_name(module),
            name.desc_name(module),
            .func,
            func_type,
            import_failure,
        );
    }

    const tables =
        arena.allocator().alloc(*TableInst, module.inner.raw.table_count) catch unreachable;
    for (
        tables[0..module.inner.raw.table_import_count],
        module.tableImportNames(),
        module.tableImportTypes(),
    ) |*import, name, *table_type| {
        import.* = (try import_provider.resolveTyped(
            name.module_name(module),
            name.desc_name(module),
            .table,
            table_type,
            import_failure,
        )).table;
    }

    const table_definitions = arena.allocator().alloc(
        TableInst,
        module.inner.raw.table_count - module.inner.raw.table_import_count,
    ) catch unreachable;
    @memset(table_definitions, undefined);

    const mems = arena.allocator().alloc(*MemInst, module.inner.raw.mem_count) catch
        unreachable;
    for (
        mems[0..module.inner.raw.mem_import_count],
        module.memImportNames(),
        module.memImportTypes(),
    ) |*import, name, *mem_type| {
        import.* = try import_provider.resolveTyped(
            name.module_name(module),
            name.desc_name(module),
            .mem,
            mem_type,
            import_failure,
        );
    }

    const mem_definitions = arena.allocator().alloc(
        MemInst,
        module.inner.raw.mem_count - module.inner.raw.mem_import_count,
    ) catch unreachable;
    @memset(mem_definitions, undefined);

    const globals = arena.allocator().alloc(*anyopaque, module.inner.raw.global_count) catch
        unreachable;
    for (
        globals[0..module.inner.raw.global_import_count],
        module.globalImportNames(),
        module.globalImportTypes(),
    ) |*import, name, *global_type| {
        import.* = (try import_provider.resolveTyped(
            name.module_name(module),
            name.desc_name(module),
            .global,
            global_type,
            import_failure,
        )).value;
    }

    for (
        globals[module.inner.raw.global_import_count..],
        module.globalTypes()[module.inner.raw.global_import_count..],
    ) |*value_ptr, *global_type| {
        value_ptr.* = switch (global_type.val_type) {
            .v128 => unreachable,
            inline else => |val_type| value: {
                const Pointee = value.GlobalAddr.Pointee(val_type);
                const is_primitive = switch (@typeInfo(Pointee)) {
                    .int, .float => true,
                    else => false,
                };

                const global_value = arena.allocator().create(Pointee) catch unreachable;

                // Instantiation is responsible for initializing defined globals
                global_value.* = if (!is_primitive and @hasDecl(Pointee, "null"))
                    .null
                else
                    std.mem.zeroes(Pointee);

                break :value @as(*anyopaque, @ptrCast(value));
            },
        };
    }

    const datas_drop_mask = arena.allocator().alloc(
        u32,
        std.math.divCeil(u32, module.inner.raw.datas_count, 32) catch unreachable,
    ) catch unreachable;
    @memset(datas_drop_mask, std.math.maxInt(u32));

    const elems_drop_mask_len = std.math.divCeil(u32, module.inner.raw.elems_count, 32) catch
        unreachable;
    const elems_drop_mask = arena.allocator().dupe(
        u32,
        module.inner.raw.non_declarative_elems_mask[0..elems_drop_mask_len],
    ) catch unreachable;

    errdefer comptime unreachable;

    for (
        tables[module.inner.raw.table_import_count..],
        table_definitions,
    ) |*table_addr, *table_inst| {
        table_addr.* = table_inst;
    }

    for (
        mems[module.inner.raw.mem_import_count..],
        mem_definitions,
    ) |*mem_addr, *mem_inst| {
        mem_addr.* = mem_inst;
    }

    header.* = ModuleInst.Header{
        .buffer_len = arena.buffer.len,
        .module = module,
        .func_imports = func_imports.ptr,
        .mems = mems.ptr,
        .tables = tables.ptr,
        .globals = globals.ptr,
        .datas_drop_mask = datas_drop_mask.ptr,
        .elems_drop_mask = elems_drop_mask.ptr,
    };

    return ModuleAllocating{
        .requiring_allocation = ModuleInst{ .inner = header },
        .mem_idx = module.inner.raw.mem_import_count,
        .table_idx = module.inner.raw.table_import_count,
    };
}

const LimitsError = error{LimitsMismatch};

pub fn nextMemoryType(request: *const ModuleAllocating) ?*const Module.MemType {
    const types = request.requiring_allocation.header().module.memTypes();
    if (request.mem_idx < types.len) {
        const mem_type = &types[request.mem_idx];
        std.debug.assert(mem_type.limits.min <= mem_type.limits.max);
        return mem_type;
    } else return null;
}

pub fn nextTable(request: *ModuleAllocating) *TableInst {
    const table_inst = request.requiring_allocation.header().tableInsts()[request.table_idx];
    request.table_idx += 1;
    return table_inst;
}

/// Asserts that another table still needs allocation.
pub fn noTable(request: *ModuleAllocating) LimitsError!void {
    const table_type = request.nextTableType().?;
    if (table_type.limits.min > 0) {
        return error.LimitsMismatch;
    }

    const table = request.nextTable();
    const stride = TableStride.ofType(table_type.elem_type);
    table.* = TableInst{
        .base = @intFromPtr(stride.toBytes()),
        .stride = stride,
        .len = 0,
        .capacity = 0,
        .limit = table_type.limits.max,
    };

    return table;
}

pub fn nextTableType(request: *ModuleAllocating) ?*Module.TableType {
    const types = request.requiring_allocation.header().module.tableTypes();
    if (request.table_idx < types.len) {
        const table_type = &types[request.table_idx];
        std.debug.assert(table_type.limits.min <= table_type.limits.max);
        return table_type;
    } else return null;
}

pub fn nextMemory(request: *ModuleAllocating) *MemInst {
    const mem_inst = request.requiring_allocation.header().memInsts()[request.mem_idx];
    request.mem_idx += 1;
    return mem_inst;
}

/// Asserts that another memory still needs allocation.
pub fn noMemory(request: *ModuleAllocating) LimitsError!void {
    const mem_type = request.nextMemoryType().?;
    if (mem_type.limits.min > 0) {
        return error.LimitsMismatch;
    }

    const mem = request.nextMemory();
    mem.* = MemInst{
        .base = @intFromPtr(MemInst.buffer_align),
        .size = 0,
        .capacity = 0,
        .limit = mem_type.limits.max * MemInst.page_size,
    };

    return mem;
}

// TODO: need to note that mems and tables must still contain zeroes until module instantiation is done

pub fn finish(request: *ModuleAllocating) LimitsError!ModuleAlloc {
    while (request.nextMemoryType() != null) {
        request.noMemory();
    }

    while (request.nextTableType() != null) {
        request.noTable();
    }

    defer request.* = undefined;
    return .{ .requiring_instantiation = request.requiring_allocation };
}

pub fn deinit(request: *ModuleAllocating) ModuleDeallocation {
    const inst = request.requiring_allocation;
    defer request.* = undefined;
    return .{
        .inst = inst,
        .mems = inst.header().definedMemInsts()[0..request.mem_idx],
        .tables = inst.header().definedTableInsts()[0..request.table_idx],
    };
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const reservation_allocator = @import("../reservation_allocator.zig");
const Module = @import("../Module.zig");
const ImportProvider = @import("ImportProvider.zig");
const ModuleInst = @import("module_inst.zig").ModuleInst;
const ModuleAlloc = @import("ModuleAlloc.zig");
const ModuleDeallocation = @import("ModuleDeallocation.zig");
const value = @import("value.zig");
const MemInst = @import("memory.zig").MemInst;
const TableInst = @import("table.zig").TableInst;
const TableStride = @import("table.zig").TableStride;
