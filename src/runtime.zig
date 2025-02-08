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
        mems: []*MemInst,
        tables: []*TableInst,
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

        const vtable = VTable{
            .allocate = WithinArena.allocate,
            .free = noFree,
        };

        fn allocate(ctx: *anyopaque, request: *Request) Allocator.Error!void {
            const into_arena = @as(*std.heap.ArenaAllocator, @ptrCast(@alignCast(ctx))).allocator();

            // TODO: Duplicate code, maybe make a common wraper over an `std.mem.Allocator`?
            while (request.nextMemType()) |mem_type| {
                const buf = try into_arena.alignedAlloc(
                    u8,
                    MemInst.buffer_align,
                    mem_type.limits.min * MemInst.page_size,
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
                .ctx = self.arena,
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

pub const ModuleInst = struct {
    module: *const Module,
    // /// Used to detect multi-threaded usage of a module instance.
    // ///
    // /// Currently, the WASM specification focuses only on single-threaded usage, with
    // /// *shared* memories currently being the sole exception.
    // acquired_flag: std.atomic.Value(bool) = .{ .raw = false },
    instantiated: bool = false,
    func_import_count: u32,
    func_imports: [*]FuncAddr,
    mems: [*]*MemInst, // Could use comptime config to have specialized [1]MemInst
    tables: [*]*TableInst,
    globals: [*]*anyopaque,
    data: IndexedArena.Data,

    pub const AllocateError = ImportProvider.Error || Allocator.Error;

    pub fn allocate(
        module: *const Module,
        import_provider: ImportProvider,
        gpa: Allocator,
        store: ModuleAllocator,
        // scratch: Allocator,
        import_failure: ?*ImportProvider.FailedRequest,
    ) AllocateError!ModuleInst {
        var arena_array = IndexedArena.init(gpa);
        defer arena_array.deinit();

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

        return .{
            .module = module,
            .func_import_count = module.inner.func_import_count,
            .func_imports = func_imports.items(&arena_array).ptr,
            .mems = mems.items(&arena_array).ptr,
            .tables = tables.items(&arena_array).ptr,
            .globals = @ptrCast(globals.items(&arena_array).ptr),
            .data = arena_array.data.toOwnedSlice() catch unreachable,
        };
    }

    /// Internal API.
    pub fn funcAddr(inst: *ModuleInst, idx: Module.FuncIdx) FuncAddr {
        const i: usize = @intFromEnum(idx);
        std.debug.assert(i < inst.module.inner.func_count);
        return if (i < inst.func_import_count)
            inst.func_imports[i]
        else
            FuncAddr.init(.{ .wasm = .{ .module = inst, .idx = idx } });
    }

    /// Internal API.
    pub fn tableAddr(inst: *const ModuleInst, idx: Module.TableIdx) TableAddr {
        const i: usize = @intFromEnum(idx);
        return TableAddr{
            .elem_type = inst.module.tableTypes()[i].elem_type,
            .table = inst.tables[i],
        };
    }

    /// Internal API.
    ///
    /// TODO: Add a note here about how some `wasm32-wasip1` applications don't export memory.
    pub fn memAddr(inst: *const ModuleInst, idx: Module.MemIdx) *MemInst {
        const i: usize = @intFromEnum(idx);
        std.debug.assert(i < inst.module.inner.mem_count);
        return inst.mems[i];
    }

    /// Internal API.
    pub fn globalAddr(inst: *const ModuleInst, idx: Module.GlobalIdx) GlobalAddr {
        const i: usize = @intFromEnum(idx);
        return GlobalAddr{
            .global_type = inst.module.globalTypes()[i],
            .value = inst.globals[i],
        };
    }

    pub const FindExportError = error{ ModuleNotInstantiated, ExportNotFound };

    pub fn findExport(inst: *ModuleInst, name: []const u8) FindExportError!ExternVal {
        if (!inst.instantiated) return error.ModuleNotInstantiated;

        for (inst.module.exports()) |*exp| {
            if (!std.mem.eql(u8, name, exp.name(inst.module).bytes)) continue;

            return switch (exp.desc_tag) {
                .func => .{ .func = inst.funcAddr(exp.desc.func) },
                .table => .{ .table = inst.tableAddr(exp.desc.table) },
                .mem => .{ .mem = inst.memAddr(exp.desc.mem) },
                .global => .{ .global = inst.globalAddr(exp.desc.global) },
            };
        }

        return error.ExportNotFound;
    }

    /// Callers must ensure that there are no dangling references to this module's functions, memories, globals, and
    /// tables.
    ///
    /// Additionally, callers are responsible for appropriately freeing any imported functions, memories, globals used
    /// by this module.
    pub fn deinit(inst: *ModuleInst, gpa: Allocator, store: ModuleAllocator) void {
        store.free(ModuleAllocator.Free{
            .mems = inst.mems[inst.module.inner.mem_import_count..inst.module.inner.mem_count],
            .tables = inst.tables[inst.module.inner.table_import_count..inst.module.inner.table_count],
        });

        gpa.free(inst.data);
        inst.* = undefined;
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
    /// If the lowest bit is `0`, then this is a `*const ModuleInst`.
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
            module: *ModuleInst,
            idx: Module.FuncIdx,

            pub inline fn code(wasm: *const Wasm) *Module.Code {
                return wasm.idx.code(wasm.module.module).?;
            }
        };

        pub fn signature(inst: *const Expanded) *const Module.FuncType {
            return switch (inst.*) {
                .host => |*host| &host.func.signature,
                .wasm => |*wasm| wasm.module.module.funcTypes()[@intFromEnum(wasm.idx)],
            };
        }
    };

    pub fn init(inst: Expanded) FuncAddr {
        return FuncAddr{
            .module_or_host = switch (inst) {
                .wasm => |*wasm| @constCast(@as(*const anyopaque, @ptrCast(wasm.module))),
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
                .module = @ptrFromInt(module_or_host),
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
        std.debug.assert(@alignOf(ModuleInst) >= 2);
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
            return @intFromEnum(@as(usize, n) + 1); // TODO: Prevent overflow?? or is it not possible
        }

        pub fn toInt(nat: Nat) ?Size {
            return if (nat == .null) null else @intCast(@as(usize, @intFromEnum(nat)) - 1);
        }
    };

    comptime {
        std.debug.assert(@sizeOf(ExternAddr) == @sizeOf(?*anyopaque));
    }
};
