//! WASM runtime structure.

pub const ModuleAllocator = @import("runtime/ModuleAllocator.zig");
pub const TableStride = @import("runtime/table.zig").TableStride;
pub const TableInst = @import("runtime/table.zig").TableInst;
pub const MemInst = @import("runtime/memory.zig").MemInst;
pub const TableAddr = @import("runtime/value.zig").TableAddr;
pub const FuncAddr = @import("runtime/value.zig").FuncAddr;
pub const GlobalAddr = @import("runtime/value.zig").GlobalAddr;
pub const ExternAddr = @import("runtime/value.zig").ExternAddr;
pub const ExternVal = @import("runtime/value.zig").ExternVal;
pub const ImportProvider = @import("runtime/ImportProvider.zig");
pub const ModuleInst = @import("runtime/module_inst.zig").ModuleInst;

/// A `ModuleInst` that has been *allocated*, but not *instantiated*.
pub const ModuleAlloc = struct {
    /// Accessing the module instance before instantiation has occurred violates
    /// the semantics of WebAssembly, even if the module does *not* contain
    /// a *start* function.
    requiring_instantiation: ModuleInst,

    // alternative instantiation mechanism could have Interpreter.instantiateModule
    // take a *ModuleInst parameter, with each stack frame return writing the
    // module instead of the bool flag, but this requires chasing down the
    // current ModuleInst pointer.

    instantiated: bool = false,

    pub const Error = ImportProvider.Error || Allocator.Error;

    pub fn allocate(
        module: Module,
        import_provider: ImportProvider,
        gpa: Allocator,
        store: ModuleAllocator,
        // scratch: Allocator, // could be used to avoid arena_array reallocation
        import_failure: ?*ImportProvider.FailedRequest,
    ) Error!ModuleAlloc {
        var arena_array = IndexedArena.init(gpa);
        defer arena_array.deinit();

        var header = try arena_array.create(ModuleInst.Header);
        std.debug.assert(header == ModuleInst.Header.index);

        const func_imports = try arena_array.alloc(FuncAddr, module.inner.raw.func_import_count);
        for (
            func_imports.items(&arena_array),
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

        const tables = try arena_array.alloc(*TableInst, module.inner.raw.table_count);
        for (
            tables.items(&arena_array)[0..module.inner.raw.table_import_count],
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

        const table_definitions = try arena_array.alloc(
            TableInst,
            module.inner.raw.table_count - module.inner.raw.table_import_count,
        );

        const mems = try arena_array.alloc(*MemInst, module.inner.raw.mem_count);
        for (
            mems.items(&arena_array)[0..module.inner.raw.mem_import_count],
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

        const mem_definitions = try arena_array.alloc(
            MemInst,
            module.inner.raw.mem_count - module.inner.raw.mem_import_count,
        );

        {
            var request = ModuleAllocator.Request.init(
                module.tableTypes()[module.inner.raw.table_import_count..],
                table_definitions.items(&arena_array),
                module.memTypes()[module.inner.raw.mem_import_count..],
                mem_definitions.items(&arena_array),
            );

            try store.allocate(&request);

            if (!request.isDone()) return error.OutOfMemory;
        }

        const GlobalFixup = packed union {
            ptr: *anyopaque,
            idx: IndexedArena.Idx(IndexedArena.Word),
        };

        const globals = try arena_array.alloc(GlobalFixup, module.inner.raw.global_count);
        for (
            globals.items(&arena_array)[0..module.inner.raw.global_import_count],
            module.globalImportNames(),
            module.globalImportTypes(),
        ) |*import, name, *global_type| {
            import.* = GlobalFixup{
                .ptr = (try import_provider.resolveTyped(
                    name.module_name(module),
                    name.desc_name(module),
                    .global,
                    global_type,
                    import_failure,
                )).value,
            };
        }

        for (
            module.inner.raw.global_import_count..,
            module.globalTypes()[module.inner.raw.global_import_count..],
        ) |i, *global_type| {
            const size: u5 = switch (global_type.val_type) {
                .i32, .f32 => 4,
                .i64, .f64 => 8,
                .v128 => 16,
                .funcref => @sizeOf(FuncAddr.Nullable),
                .externref => @sizeOf(ExternAddr),
            };

            const raw_space_idx = try arena_array.rawAlloc(size, switch (global_type.val_type) {
                .i32, .f32 => 4,
                .i64, .f64 => @alignOf(u64),
                .v128 => 16, // 8 if no SIMD
                .funcref, .externref => @alignOf(*anyopaque),
            });

            const space_idx = IndexedArena.Idx(IndexedArena.Word).fromInt(raw_space_idx);

            // Instantiation is responsible for initializing defined globals
            @memset(
                @as(
                    [*]align(IndexedArena.min_alignment) u8,
                    @ptrCast(space_idx.getPtr(&arena_array)),
                )[0..size],
                undefined,
            );

            globals.setAt(
                i,
                &arena_array,
                GlobalFixup{ .idx = space_idx },
            );
        }

        const datas_drop_mask = try arena_array.alloc(
            u32,
            std.math.divCeil(
                u32,
                module.inner.raw.datas_count,
                32,
            ) catch unreachable,
        );
        @memset(datas_drop_mask.items(&arena_array), std.math.maxInt(u32));

        const elems_drop_mask_len = std.math.divCeil(
            u32,
            module.inner.raw.elems_count,
            32,
        ) catch unreachable;
        const elems_drop_mask = try arena_array.dupe(
            u32,
            module.inner.raw.non_declarative_elems_mask[0..elems_drop_mask_len],
        );

        errdefer comptime unreachable;

        for (
            tables.items(&arena_array)[module.inner.raw.table_import_count..],
            table_definitions.items(&arena_array),
        ) |*table_addr, *table_inst| {
            table_addr.* = table_inst;
        }

        for (
            mems.items(&arena_array)[module.inner.raw.mem_import_count..],
            mem_definitions.items(&arena_array),
        ) |*mem_addr, *mem_inst| {
            mem_addr.* = mem_inst;
        }

        for (globals.items(&arena_array)[module.inner.raw.global_import_count..]) |*global| {
            const value_ptr: *IndexedArena.Word = global.idx.getPtr(&arena_array);
            global.* = GlobalFixup{ .ptr = @ptrCast(value_ptr) };
        }

        arena_array.data.expandToCapacity();

        const module_data = arena_array.data.toOwnedSlice() catch unreachable;

        header.getPtr(module_data).* = ModuleInst.Header{
            .data_len = module_data.len,
            .module = module,
            .func_import_count = module.inner.raw.func_import_count,
            .func_imports = func_imports.items(module_data).ptr,
            .mems = mems.items(module_data).ptr,
            .tables = tables.items(module_data).ptr,
            .globals = @ptrCast(globals.items(module_data).ptr),
            .datas_drop_mask = datas_drop_mask.items(module_data).ptr,
            .elems_drop_mask = elems_drop_mask.items(module_data).ptr,
        };

        return ModuleAlloc{
            .requiring_instantiation = ModuleInst{
                .data = module_data.ptr,
            },
        };
    }

    pub fn expectInstantiated(alloc: ModuleAlloc) ModuleInst {
        std.debug.assert(alloc.instantiated);
        return alloc.requiring_instantiation;
    }
};

const std = @import("std");
const Writer = std.Io.Writer;
const IndexedArena = @import("IndexedArena.zig");
const Allocator = std.mem.Allocator;
const Module = @import("Module.zig");
