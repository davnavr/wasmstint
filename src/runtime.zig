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

    /// Allocates, but does not instantiate, a WebAssembly module.
    pub fn allocate(
        module: Module,
        import_provider: ImportProvider,
        gpa: Allocator,
        store: ModuleAllocator,
        import_failure: ?*ImportProvider.FailedRequest,
    ) Error!ModuleAlloc {
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
            FuncAddr,
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

        {
            var request = ModuleAllocator.Request.init(
                module.tableTypes()[module.inner.raw.table_import_count..],
                table_definitions,
                module.memTypes()[module.inner.raw.mem_import_count..],
                mem_definitions,
            );

            try store.allocate(&request);

            if (!request.isDone()) return error.OutOfMemory;
        }

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
                    const Pointee = GlobalAddr.Pointee(val_type);
                    const is_primitive = switch (@typeInfo(Pointee)) {
                        .int, .float => true,
                        else => false,
                    };

                    const value = arena.allocator().create(Pointee) catch unreachable;

                    // Instantiation is responsible for initializing defined globals
                    value.* = if (!is_primitive and @hasDecl(Pointee, "null"))
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

        return ModuleAlloc{
            .requiring_instantiation = ModuleInst{ .inner = header },
        };
    }

    pub fn expectInstantiated(alloc: ModuleAlloc) ModuleInst {
        std.debug.assert(alloc.instantiated);
        return alloc.requiring_instantiation;
    }
};

const std = @import("std");
const Writer = std.Io.Writer;
const reservation_allocator = @import("reservation_allocator.zig");
const Allocator = std.mem.Allocator;
const Module = @import("Module.zig");
