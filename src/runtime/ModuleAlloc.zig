//! A `ModuleInst` that has been *allocated*, but not *instantiated*.

const ModuleAlloc = @This();

/// Accessing the module instance before instantiation has occurred violates
/// the semantics of WebAssembly, even if the module does *not* contain
/// a *start* function.
///
/// This is because active element segments, active data segments, and global variable
/// initialization expressions have not yet been run.
requiring_instantiation: ModuleInst,
/// `true` if module instantiation is complete and the `start` function, if it exists, has
/// already been run.
instantiated: bool,

pub const AllocationError = ImportProvider.Error || Allocator.Error;

/// The pointers to individual `TableInst`s and `MemInst`s must outlive the `ModuleInst`.
pub const Definitions = struct {
    tables: []const *TableInst = &.{},
    memories: []const *MemInst = &.{},
    // More fields may be added in the future
    //tags: []const Tag = &.{},

    pub fn deinit(definitions: *Definitions) void {
        for (definitions.tables) |table| {
            table.free();
        }
        for (definitions.memories) |mem| {
            mem.free();
        }
        definitions.* = undefined;
    }
};

/// On successful allocation, the ownership of each value in the `AllocatedDefinitions` is passed to
/// the `ModuleInst`.
///
/// On error, the `AllocatedDefinitions` are not deinitialized.
///
/// Asserts that the types and number of `AllocatedDefinitions` exactly match those listed in the
/// `Module`.
pub fn allocateWithDefinitions(
    module: Module,
    /// Used to allocate the `ModuleInst` itself.
    allocator: Allocator,
    import_provider: ImportProvider,
    /// Optional pointer where diagnostics are written on `ImportProvider.Error`.
    import_failure: ?*ImportProvider.FailedRequest,
    definitions: Definitions,
) AllocationError!ModuleAlloc {
    const defined_table_types = module.tableDefinedTypes();
    const defined_mem_types = module.memDefinedTypes();
    std.debug.assert(definitions.tables.len == defined_table_types.len);
    std.debug.assert(definitions.memories.len == defined_mem_types.len);

    var arena = std.heap.FixedBufferAllocator.init(
        try allocator.alignedAlloc(
            u8,
            .fromByteUnits(std.atomic.cache_line),
            module.inner.runtime_shape.size.bytes,
        ),
    );
    errdefer allocator.free(arena.buffer);

    const header: *align(std.atomic.cache_line) ModuleInst.Header =
        &(arena.allocator().alignedAlloc(
            ModuleInst.Header,
            .fromByteUnits(std.atomic.cache_line),
            1,
        ) catch unreachable)[0];
    std.debug.assert(@intFromPtr(header) == @intFromPtr(arena.buffer.ptr));
    const module_inst = ModuleInst{ .inner = header };
    // Order important to ensure consistent alignment, avoiding panic on OOM
    const func_blocks = arena.allocator().alignedAlloc(
        value.FuncAddr.Wasm.Block,
        .fromByteUnits(@sizeOf(value.FuncAddr.Wasm.Block)),
        ModuleInst.Header.funcBlockCount(module),
    ) catch unreachable;
    const func_imports = arena.allocator().alloc(
        value.FuncAddr,
        module.inner.raw.func_import_count,
    ) catch unreachable;
    const tables =
        arena.allocator().alloc(*TableInst, module.inner.raw.table_count) catch unreachable;
    const mems = arena.allocator().alloc(*MemInst, module.inner.raw.mem_count) catch
        unreachable;
    const globals = arena.allocator().alloc(*anyopaque, module.inner.raw.global_count) catch
        unreachable;
    const datas_drop_mask = arena.allocator().alloc(
        u32,
        std.math.divCeil(u32, module.inner.raw.datas_count, 32) catch unreachable,
    ) catch unreachable;
    const elems_drop_mask = arena.allocator().dupe(
        u32,
        module.inner.raw.non_declarative_elems_mask[0 .. std.math.divCeil(
            u32,
            module.inner.raw.elems_count,
            32,
        ) catch unreachable],
    ) catch unreachable;

    // Initialize imports ASAP so any errors happen before any more code can run.
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

    for (
        tables[0..module.inner.raw.table_import_count],
        module.tableImportNames(),
        module.tableImportTypes(),
    ) |*import, name, *table_type| {
        import.* = try import_provider.resolveTyped(
            name.module_name(module),
            name.desc_name(module),
            .table,
            table_type,
            import_failure,
        );
    }

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

    errdefer comptime unreachable;

    for (func_blocks, 0..) |*block, i| {
        block.* = value.FuncAddr.Wasm.Block{
            .module = module_inst,
            .starting_idx = module.inner.raw.func_import_count +
                (@as(u32, @intCast(i)) * value.FuncAddr.Wasm.Block.funcs_per_block),
        };
    }

    // Initialize definitions
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

                break :value @as(*anyopaque, @ptrCast(global_value));
            },
        };
    }

    for (
        tables[module.inner.raw.table_import_count..],
        defined_table_types,
        definitions.tables,
    ) |*table_addr, *table_type, table_inst| {
        std.debug.assert(table_inst.len == table_type.limits.min);
        // TODO: table_type.matches(table_inst.tableType())
        std.debug.assert(table_inst.limits().matches(&table_type.limits));
        table_addr.* = table_inst;
    }

    for (
        mems[module.inner.raw.mem_import_count..],
        defined_mem_types,
        definitions.memories,
    ) |*mem_addr, *mem_type, mem_inst| {
        std.debug.assert(mem_inst.size == mem_type.limits.min * MemInst.page_size);
        std.debug.assert(mem_inst.memType().matches(mem_type));
        mem_addr.* = mem_inst;
    }

    @memset(datas_drop_mask, std.math.maxInt(u32));

    header.* = ModuleInst.Header{
        .buffer_len = arena.buffer.len,
        .module = module,
        .func_imports = func_imports.ptr,
        .func_blocks = func_blocks.ptr,
        .mems = mems.ptr,
        .tables = tables.ptr,
        .globals = globals.ptr,
        .datas_drop_mask = datas_drop_mask.ptr,
        .elems_drop_mask = elems_drop_mask.ptr,
    };

    return ModuleAlloc{
        .requiring_instantiation = module_inst,
        .instantiated = false,
    };
}

/// Asserts the `ModuleInst` is instantiated and returns it.
///
/// This deinitializes the `ModuleAlloc`.
pub fn assumeInstantiated(alloc: *ModuleAlloc) ModuleInst {
    std.debug.assert(alloc.instantiated);
    defer alloc.* = undefined;
    return alloc.requiring_instantiation;
}

/// Deinitializes the underlying `ModuleInst`, usually because initialization needs to be canceled.
pub fn deinit(module: *ModuleAlloc, allocator: Allocator) void {
    module.requiring_instantiation.deinit(allocator);
    module.* = undefined;
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const Module = @import("../Module.zig");
const ModuleInst = @import("module_inst.zig").ModuleInst;
const value = @import("value.zig");
const MemInst = @import("memory.zig").MemInst;
const TableInst = @import("table.zig").TableInst;
const ImportProvider = @import("ImportProvider.zig");
