const std = @import("std");
const Allocator = std.mem.Allocator;
const IndexedArena = @import("IndexedArena.zig");
const Module = @import("Module.zig");

inline fn tableElementStride(elem_type: Module.ValType) u32 {
    return switch (elem_type) {
        .funcref => @sizeOf(FuncAddr.Nullable),
        .externref => @sizeOf(ExternAddr),
        else => unreachable,
    };
}

pub const ModuleAllocator = struct {
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
            const stride = tableElementStride(expected_type.elem_type);

            const len = std.math.cast(u32, @divExact(buffer.len, stride)) orelse
                return error.OutOfMemory;

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
                _ = request.allocateMemory(
                    try std.heap.page_allocator.alignedAlloc(
                        u8,
                        MemInst.buffer_align,
                        mem_type.limits.min * MemInst.page_size,
                    ),
                ) catch unreachable;
            }

            while (request.nextTableType()) |table_type| {
                _ = request.allocateTable(
                    try std.heap.page_allocator.alignedAlloc(
                        u8,
                        TableInst.buffer_align,
                        std.math.mul(
                            usize,
                            table_type.limits.min,
                            tableElementStride(table_type.elem_type),
                        ) catch return error.OutOfMemory,
                    ),
                ) catch unreachable;
            }
        }

        fn free(ctx: *anyopaque, info: Free) void {
            _ = ctx;

            for (info.mems) |mem| {
                std.heap.page_allocator.free(mem.base[0..mem.capacity]);
            }

            for (info.tables) |table| {
                std.heap.page_allocator.free(table.base.ptr[0 .. table.capacity * table.stride]);
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
                    MemInst.buffer_align,
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
                    TableInst.buffer_align,
                    std.math.mul(
                        usize,
                        table_type.limits.min,
                        tableElementStride(table_type.elem_type),
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
};

pub const ImportProvider = struct {
    /// Used to indicate the type of value the module is expecting.
    pub const Desc = union(std.meta.FieldEnum(Module.Export.Desc)) {
        func: *const Module.FuncType,
        table: *const Module.TableType,
        mem: *const Module.MemType,
        global: *const Module.GlobalType,
    };

    ctx: *anyopaque,
    resolve: *const fn (
        ctx: *anyopaque,
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        desc: Desc,
    ) ?ExternVal,

    pub const Error = error{
        /// The host did not provide an import with the given name or one with the expected type.
        ImportFailure,
    };

    pub const FailedRequest = struct {
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        desc: Desc,
    };

    fn resolveTyped(
        provider: *const ImportProvider,
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        comptime desc_tag: std.meta.FieldEnum(Module.Export.Desc),
        desc: std.meta.FieldType(Desc, desc_tag),
        failed: ?*FailedRequest,
    ) Error!@FieldType(ExternVal, @tagName(desc_tag)) {
        const import_desc = @unionInit(
            Desc,
            std.meta.fieldInfo(Desc, desc_tag).name,
            desc,
        );

        failed_request: {
            const provided = provider.resolve(
                provider.ctx,
                module,
                name,
                import_desc,
            ) orelse break :failed_request;

            switch (desc_tag) {
                .func => if (provided == .func) {
                    if (!provided.func.signature().matches(desc)) break :failed_request;
                    return provided.func;
                },
                .table => if (provided == .table) {
                    if (provided.table.tableType().matches(desc)) break :failed_request;
                    return provided.table.table;
                },
                .mem => if (provided == .mem) {
                    if (provided.mem.memType().matches(desc)) break :failed_request;
                    return provided.mem;
                },
                .global => if (provided == .global) {
                    if (provided.global.global_type.matches(desc)) break :failed_request;
                    return provided.global;
                },
            }
        }

        if (failed) |failed_ptr| failed_ptr.* = FailedRequest{
            .module = module,
            .name = name,
            .desc = import_desc,
        };

        return Error.ImportFailure;
    }
};

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
        module: *const Module,
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

        const func_imports = try arena_array.alloc(FuncAddr, module.inner.func_import_count);
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

        const tables = try arena_array.alloc(*TableInst, module.inner.table_count);
        for (
            tables.items(&arena_array)[0..module.inner.table_import_count],
            module.tableImportNames(),
            module.tableImportTypes(),
        ) |*import, name, *table_type| {
            const val = import_provider.resolve(
                import_provider.ctx,
                name.module_name(module),
                name.desc_name(module),
                .{ .table = table_type },
            ) orelse return error.ImportFailure;

            switch (val) {
                .table => |table| {
                    if (table.tableType().matches(table_type)) return error.ImportFailure;
                    import.* = table.table;
                },
                else => return error.ImportFailure,
            }
        }

        const table_definitions = try arena_array.alloc(
            TableInst,
            module.inner.table_count - module.inner.table_import_count,
        );

        const mems = try arena_array.alloc(*MemInst, module.inner.mem_count);
        for (
            mems.items(&arena_array)[0..module.inner.mem_import_count],
            module.memImportNames(),
            module.memImportTypes(),
        ) |*import, name, *mem_type| {
            const val = import_provider.resolve(
                import_provider.ctx,
                name.module_name(module),
                name.desc_name(module),
                .{ .mem = mem_type },
            ) orelse return error.ImportFailure;

            switch (val) {
                .mem => |mem| {
                    if (mem.memType().matches(mem_type)) return error.ImportFailure;
                    import.* = mem;
                },
                else => return error.ImportFailure,
            }
        }

        const mem_definitions = try arena_array.alloc(
            MemInst,
            module.inner.mem_count - module.inner.mem_import_count,
        );

        {
            var request = ModuleAllocator.Request{
                .tables = table_definitions.items(&arena_array).ptr,
                .table_types = module.tableTypes()[module.inner.table_import_count..],
                .mems = mem_definitions.items(&arena_array).ptr,
                .mem_types = module.memTypes()[module.inner.mem_import_count..],
            };

            try store.allocate(&request);

            if (!request.isDone()) return error.OutOfMemory;
        }

        const GlobalFixup = packed union {
            ptr: *anyopaque,
            idx: IndexedArena.Idx(IndexedArena.Word),
        };

        const globals = try arena_array.alloc(GlobalFixup, module.inner.global_count);
        for (
            globals.items(&arena_array)[0..module.inner.global_import_count],
            module.globalImportNames(),
            module.globalImportTypes(),
        ) |*import, name, *global_type| {
            const val = import_provider.resolve(
                import_provider.ctx,
                name.module_name(module),
                name.desc_name(module),
                .{ .global = global_type },
            ) orelse return error.ImportFailure;

            switch (val) {
                .global => |global| {
                    if (global.global_type.matches(global_type)) return error.ImportFailure;
                    import.* = GlobalFixup{ .ptr = global.value };
                },
                else => return error.ImportFailure,
            }
        }

        for (
            module.inner.global_import_count..,
            module.globalTypes()[module.inner.global_import_count..],
        ) |i, *global_type| {
            const size: u5 = switch (global_type.val_type) {
                .i32, .f32 => 4,
                .i64, .f64 => 8,
                .v128 => 16,
                .funcref => @sizeOf(FuncAddr.Nullable),
                .externref => @sizeOf(ExternAddr),
            };

            const space_idx = try arena_array.rawAlloc(size, switch (global_type.val_type) {
                .i32, .f32 => 4,
                .i64, .f64 => @alignOf(u64),
                .v128 => 16, // 8 if no SIMD
                .funcref, .externref => @alignOf(*anyopaque),
            });

            globals.setAt(
                i,
                &arena_array,
                GlobalFixup{ .idx = IndexedArena.Idx(IndexedArena.Word).fromInt(space_idx) },
            );
        }

        const passive_datas_mask_len = std.math.divCeil(
            u32,
            module.inner.datas_count,
            32,
        ) catch unreachable;

        const passive_datas_mask = try arena_array.dupe(
            u32,
            module.inner.passive_datas_mask[0..passive_datas_mask_len],
        );

        errdefer comptime unreachable;

        for (
            tables.items(&arena_array)[module.inner.table_import_count..],
            table_definitions.items(&arena_array),
        ) |*table_addr, *table_inst| {
            table_addr.* = table_inst;
        }

        for (
            mems.items(&arena_array)[module.inner.mem_import_count..],
            mem_definitions.items(&arena_array),
        ) |*mem_addr, *mem_inst| {
            mem_addr.* = mem_inst;
        }

        for (globals.items(&arena_array)[module.inner.global_import_count..]) |*global| {
            const value_ptr: *IndexedArena.Word = global.idx.getPtr(&arena_array);
            global.* = GlobalFixup{ .ptr = @ptrCast(value_ptr) };
        }

        arena_array.data.expandToCapacity();

        const module_data = arena_array.data.toOwnedSlice() catch unreachable;

        header.getPtr(module_data).* = ModuleInst.Header{
            .data_len = module_data.len,
            .module = module,
            .func_import_count = module.inner.func_import_count,
            .func_imports = func_imports.items(module_data).ptr,
            .mems = mems.items(module_data).ptr,
            .tables = tables.items(module_data).ptr,
            .globals = @ptrCast(globals.items(module_data).ptr),
            .data_segment_mask = passive_datas_mask.items(module_data).ptr,
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

/// "The runtime representation of a *module*."
///
/// To obtain a `ModuleInst`, a `Module` must first be passed to `ModuleAlloc.allocate`, which is
/// then passed to `Interpreter.instantiateModule`.
pub const ModuleInst = extern struct {
    /// Internal API.
    pub const Header = struct {
        data_len: usize,
        module: *const Module,
        // /// Used to detect multi-threaded usage of a module instance.
        // ///
        // /// Currently, the WASM specification focuses only on single-threaded usage, with
        // /// *shared* memories currently being the sole exception.
        // acquired_flag: std.atomic.Value(bool) = .{ .raw = false },
        func_import_count: u32,
        func_imports: [*]const FuncAddr,
        mems: [*]const *MemInst, // TODO: Could use comptime config to have specialized [1]MemInst (same for TableInst)
        tables: [*]const *TableInst,
        globals: [*]const *anyopaque,
        /// Indicates which data segments have not been dropped.
        ///
        /// After instantiation, only passive data segments have not been dropped.
        ///
        /// To zero-out the length of dropped data segments, AND its length with the corresponding bit.
        data_segment_mask: [*]u32,

        const index = IndexedArena.Idx(Header).fromInt(0);

        pub fn moduleInst(inst: *const Header) ModuleInst {
            const module = ModuleInst{ .data = @constCast(@ptrCast(@alignCast(inst))) };
            std.debug.assert(@intFromPtr(inst) == @intFromPtr(module.header()));
            return module;
        }

        pub fn funcAddr(inst: *const Header, idx: Module.FuncIdx) FuncAddr {
            const i: usize = @intFromEnum(idx);
            std.debug.assert(i < inst.module.inner.func_count);
            return if (i < inst.func_import_count)
                inst.func_imports[i]
            else
                FuncAddr.init(.{
                    .wasm = .{
                        .module = inst.moduleInst(),
                        .idx = idx,
                    },
                });
        }

        inline fn tableInsts(inst: *const Header) []const *TableInst {
            return inst.tables[0..inst.module.inner.table_count];
        }

        inline fn definedTableInsts(inst: *const Header) []const *TableInst {
            return inst.tableInsts()[inst.module.inner.table_import_count..];
        }

        pub fn tableAddr(inst: *const Header, idx: Module.TableIdx) TableAddr {
            const i: usize = @intFromEnum(idx);
            return TableAddr{
                .elem_type = inst.module.tableTypes()[i].elem_type,
                .table = inst.tableInsts()[i],
            };
        }

        inline fn memInsts(inst: *const Header) []const *MemInst {
            return inst.mems[0..inst.module.inner.mem_count];
        }

        inline fn definedMemInsts(inst: *const Header) []const *MemInst {
            return inst.memInsts()[inst.module.inner.mem_import_count..];
        }

        /// Internal API.
        ///
        /// TODO: Add a note here about how some `wasm32-wasip1` applications don't export memory.
        pub fn memAddr(inst: *const Header, idx: Module.MemIdx) *MemInst {
            return inst.memInsts()[@intFromEnum(idx)];
        }

        pub inline fn globalValues(inst: *const Header) []const *anyopaque {
            return inst.globals[0..inst.module.inner.global_count];
        }

        pub inline fn definedGlobalValues(inst: *const Header) []const *anyopaque {
            return inst.globalValues()[inst.module.inner.global_import_count..];
        }

        pub fn globalAddr(inst: *const Header, idx: Module.GlobalIdx) GlobalAddr {
            const i: usize = @intFromEnum(idx);
            return GlobalAddr{
                .global_type = inst.module.globalTypes()[i],
                .value = inst.globalValues()[i],
            };
        }

        pub const DataDropFlag = struct {
            word: *u32,
            bit: u5,

            pub inline fn get(flag: DataDropFlag) u1 {
                return @truncate(flag.word.* >> flag.bit);
            }

            pub inline fn drop(flag: DataDropFlag) void {
                flag.word.* &= (~(@as(u32, 1) << flag.bit));
            }
        };

        pub fn dataSegmentDropFlag(inst: *const Header, idx: Module.DataIdx) DataDropFlag {
            const i = @intFromEnum(idx);
            return DataDropFlag{
                .word = &inst.data_segment_mask[i / 32],
                .bit = @intCast(i % 32),
            };
        }

        pub fn dataSegment(inst: *const Header, idx: Module.DataIdx) []const u8 {
            var data = inst.module.dataSegmentContents(idx);
            const drop_flag: usize = inst.dataSegmentDropFlag(idx).get();

            // This has the effect of making the length zero when the data segment is "dropped"
            const len_move = @bitSizeOf(usize) - 1;
            const len_mask: usize = @bitCast(@as(isize, @bitCast(drop_flag << len_move)) >> len_move);
            std.debug.assert(@popCount(len_mask) == 0 or @popCount(len_mask) == @bitSizeOf(usize));
            data.len &= len_mask;
            return data;
        }
    };

    data: [*]align(IndexedArena.max_alignment) IndexedArena.Word,

    /// Internal API used to obtain the functions, tables, memories, globals, etc.
    /// that are defined or imported by the module.
    pub fn header(inst: ModuleInst) *const Header {
        const header_ptr: *Header = @ptrCast(inst.data);
        std.debug.assert(
            @intFromPtr(Header.index.getPtr(inst.data[0..header_ptr.data_len])) == @intFromPtr(header_ptr),
        );
        return header_ptr;
    }

    pub const FindExportError = error{
        /// A function, table, memory, or global with the given name could not be found.
        ExportNotFound,
    };

    pub fn findExport(inst: ModuleInst, name: []const u8) FindExportError!ExternVal {
        const instance = inst.header();

        for (instance.module.exports()) |*exp| {
            if (!std.mem.eql(u8, name, exp.name(instance.module).bytes)) continue;

            return switch (exp.desc_tag) {
                .func => .{ .func = instance.funcAddr(exp.desc.func) },
                .table => .{ .table = instance.tableAddr(exp.desc.table) },
                .mem => .{ .mem = instance.memAddr(exp.desc.mem) },
                .global => .{ .global = instance.globalAddr(exp.desc.global) },
            };
        }

        return error.ExportNotFound;
    }

    /// Callers must ensure that there are no dangling references to this module's functions,
    /// memories, globals, and tables.
    ///
    /// Additionally, callers are responsible for freeing any imported functions, memories, globals
    /// used by this module.
    pub fn deinit(inst: ModuleInst, gpa: Allocator, store: ModuleAllocator) void {
        const instance = inst.header();
        store.free(ModuleAllocator.Free{
            .mems = instance.definedMemInsts(),
            .tables = instance.definedTableInsts(),
        });

        gpa.free(inst.data[0..instance.data_len]);
        inst.data = undefined;
    }
};

pub const MemInst = extern struct {
    base: [*]align(buffer_align) u8,
    // shared: bool,
    /// The current size, in bytes.
    size: usize,
    /// Indicates the amount that the memory's size, in bytes, can grow without reallocating.
    capacity: usize,
    /// The maximum size, in bytes.
    limit: usize,

    /// The amount memory buffers should be aligned by.
    ///
    /// Currently, this is enough to store aligned `v128` values.
    pub const buffer_align = 16;

    /// The size of a WebAssembly page, in bytes.
    pub const page_size = 65536;

    comptime {
        if (@import("builtin").cpu.arch.endian() != .little)
            @compileError("wasmstint is currently not supported on big-endian systems");
    }

    /// Returns a memory type matching the current memory instance.
    ///
    /// This does not use any original minimum limit as part of the memory type. For more information, see
    /// <https://webassembly.github.io/spec/core/appendix/properties.html#store-validity>.
    fn memType(inst: *const MemInst) Module.MemType {
        return .{
            .limits = .{
                .min = inst.size / page_size,
                .max = inst.limit / page_size,
            },
        };
    }

    pub inline fn bytes(inst: *const MemInst) []u8 {
        return inst.base[0..inst.size];
    }

    pub const OobError = error{MemoryAccessOutOfBounds};

    /// Implements the [`memory.init`] instruction, which is also used in module instantiation.
    ///
    /// Asserts that `src.len` can fit into a `u32`, which is always the case for WASM data segments.
    ///
    /// [`memory.init`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-init
    pub fn init(
        inst: *const MemInst,
        src: []const u8,
        len: u32,
        src_idx: u32,
        dst_idx: u32,
    ) OobError!void {
        std.debug.assert(src.len <= std.math.maxInt(u32));

        // std.debug.print(
        //     "memory.init: memory len={}, segment len={}, len={}, src_idx={}, dst_idx={}\n",
        //     .{ inst.size, src.len, len, src_idx, dst_idx },
        // );

        const src_end_idx = std.math.add(usize, src_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (src_end_idx > src.len)
            return error.MemoryAccessOutOfBounds;

        const dst_end_idx = std.math.add(usize, dst_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (dst_end_idx > inst.size)
            return error.MemoryAccessOutOfBounds;

        @memcpy(inst.bytes()[dst_idx..dst_end_idx], src[src_idx..src_end_idx]);
    }

    /// Implements the [`memory.copy`] instruction.
    ///
    /// [`memory.copy`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-copy
    pub fn copy(
        dst: *const MemInst,
        src: *const MemInst,
        len: u32,
        src_idx: u32,
        dst_idx: u32,
    ) OobError!void {
        // std.debug.print(
        //     "memory.copy: src len={}, dst len={}, len={}, src_idx={}, dst_idx={}\n",
        //     .{ src.size, dst.size, len, src_idx, dst_idx },
        // );

        const src_end_idx = std.math.add(usize, src_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (src_end_idx > src.size)
            return error.MemoryAccessOutOfBounds;

        const dst_end_idx = std.math.add(usize, dst_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (dst_end_idx > dst.size)
            return error.MemoryAccessOutOfBounds;

        if (len == 0) return;

        const src_slice: []const u8 = src.bytes()[src_idx..src_end_idx];
        // std.debug.dumpHex(src_slice);
        const dst_slice = dst.bytes()[dst_idx..dst_end_idx];
        // std.debug.dumpHex(dst_slice);
        if (@intFromPtr(src) == @intFromPtr(dst) and (dst_idx < src_end_idx or src_idx < dst_end_idx)) {
            if (src_idx < dst_idx) {
                std.mem.copyBackwards(u8, dst_slice, src_slice);
            } else if (dst_idx < src_idx) {
                std.mem.copyForwards(u8, dst_slice, src_slice);
            } else {
                unreachable;
            }
        } else {
            @memcpy(dst_slice, src_slice);
        }

        // std.debug.dumpHex(dst_slice);
    }

    /// Implements the [`memory.fill`] instruction.
    ///
    /// [`memory.fill`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-fill
    pub fn fill(
        inst: *const MemInst,
        num: u32,
        val: u8,
        start_idx: u32,
    ) OobError!void {
        const end_idx = std.math.add(usize, num, start_idx) catch
            return error.MemoryAccessOutOfBounds;

        if (end_idx > inst.size)
            return error.MemoryAccessOutOfBounds;

        @memset(inst.bytes()[start_idx..end_idx], val);
    }
};

pub const TableInst = extern struct {
    base: Base,
    stride: u32,
    /// The current size, in elements.
    len: u32,
    /// Indicates the amount that the tables's size, in elements, can grow without reallocating.
    capacity: u32,
    /// The maximum size, in elements.
    limit: u32,

    pub const buffer_align = @max(@alignOf(FuncAddr.Nullable), @alignOf(ExternAddr));

    pub const Base = packed union {
        func_ref: [*]FuncAddr.Nullable,
        extern_ref: [*]ExternAddr,
        ptr: [*]align(buffer_align) u8,

        comptime {
            std.debug.assert(@sizeOf(Base) == @sizeOf([*]const u8));
        }
    };
};

pub const TableAddr = extern struct {
    elem_type: Module.ValType,
    table: *TableInst,

    fn tableType(addr: *const TableAddr) Module.TableType {
        return .{
            .elem_type = addr.elem_type,
            .limits = .{ .min = addr.table.len, .max = addr.table.limit },
        };
    }
};

pub const GlobalAddr = extern struct {
    global_type: Module.GlobalType, // *const GlobalType if it becomes too big
    value: *anyopaque, // TODO: Have it be a pointer to struct containing both value and its size? Need to allow global.get/set to know the operand size

    pub fn Pointee(comptime val_type: Module.ValType) type {
        return switch (val_type) {
            .i32 => i32,
            .f32 => f32,
            .i64 => i64,
            .f64 => f64,
            .funcref => FuncAddr.Nullable,
            .externref => ExternAddr,
            .v128 => unreachable,
        };
    }
};

pub const FuncAddr = extern struct {
    /// If the lowest bit is `0`, then this is a `ModuleInst`.
    module_or_host: *anyopaque,
    func: packed union {
        wasm: Module.FuncIdx,
        host_data: ?*anyopaque,
    },

    /// A *host function*, uniquely identified by its address.
    ///
    /// Embedders of *wasmstint* are intended to store the data of a host function in some structure containing a
    /// `HostFunc`, passing the pointer to the `HostFunc` to *wasmstint*.
    pub const Host = extern struct {
        signature: Module.FuncType,
    };

    pub const Expanded = union(enum) {
        host: struct {
            func: *Host,
            data: ?*anyopaque,
        },
        wasm: Wasm,

        pub const Wasm = struct {
            module: ModuleInst,
            idx: Module.FuncIdx,

            pub inline fn code(wasm: *const Wasm) *Module.Code {
                return wasm.idx.code(wasm.module.header().module).?;
            }
        };

        pub fn signature(inst: *const Expanded) *const Module.FuncType {
            return switch (inst.*) {
                .host => |*host| &host.func.signature,
                .wasm => |*wasm| wasm.module.header().module.funcTypes()[@intFromEnum(wasm.idx)],
            };
        }
    };

    pub fn init(inst: Expanded) FuncAddr {
        return FuncAddr{
            .module_or_host = switch (inst) {
                .wasm => |*wasm| @ptrCast(wasm.module.data),
                .host => |*host| @ptrFromInt(@intFromPtr(host.func) | 1),
            },
            .func = switch (inst) {
                .wasm => |*wasm| .{ .wasm = wasm.idx },
                .host => |*host| .{ .host_data = host.data },
            },
        };
    }

    pub fn expanded(inst: FuncAddr) Expanded {
        const module_or_host = @intFromPtr(inst.module_or_host);
        return if (module_or_host & 1 == 0) Expanded{
            .wasm = .{
                .module = ModuleInst{ .data = @ptrFromInt(module_or_host) },
                .idx = inst.func.wasm,
            },
        } else .{
            .host = .{
                .func = @ptrFromInt(module_or_host & ~@as(usize, 1)),
                .data = inst.func.host_data,
            },
        };
    }

    comptime {
        std.debug.assert(@sizeOf(FuncAddr) == @sizeOf([2]*anyopaque));
        std.debug.assert(std.meta.alignment(@FieldType(ModuleInst, "data")) >= 2);
        std.debug.assert(@alignOf(Host) >= 2);
    }

    pub fn signature(inst: *const FuncAddr) *const Module.FuncType {
        return inst.expanded().signature();
    }

    pub const Nullable = extern struct {
        module_or_host: ?*anyopaque,
        func: @FieldType(FuncAddr, "func"),

        pub const @"null" = std.mem.zeroes(Nullable);

        pub fn funcInst(inst: Nullable) ?FuncAddr {
            return if (inst.module_or_host) |module_or_host|
                .{ .module_or_host = module_or_host, .func = inst.func }
            else
                null;
        }

        comptime {
            std.debug.assert(@bitSizeOf(FuncAddr) == @bitSizeOf(Nullable));
            std.debug.assert(Nullable.null.funcInst() == null);
        }
    };
};

pub const ExternVal = union(enum) {
    func: FuncAddr,
    mem: *MemInst,
    table: TableAddr,
    global: GlobalAddr,

    // @sizeOf(ExternVal) ~= @sizeOf([3]usize), but this is fine as it is not expected to be stored in slices
};

pub const ExternAddr = packed union {
    ptr: ?*anyopaque,
    nat: Nat,

    pub const @"null" = ExternAddr{ .ptr = null };

    pub const Nat = enum(usize) {
        null = 0,
        _,

        pub const Size = std.meta.Int(.unsigned, @bitSizeOf(usize) - 1);

        pub fn fromInt(n: Size) Nat {
            return @enumFromInt(@as(usize, n) + 1);
        }

        pub fn toInt(nat: Nat) ?Size {
            return if (nat == .null) null else @intCast(@as(usize, @intFromEnum(nat)) - 1);
        }
    };

    comptime {
        std.debug.assert(@sizeOf(ExternAddr) == @sizeOf(?*anyopaque));
    }
};
