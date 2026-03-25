pub const WasmModule = struct {
    inner: wasmstint.Module,

    pub fn init(wasm: []const u8, scratch: *ArenaAllocator) !WasmModule {
        var reader = wasm;

        var diag_buf: [256]u8 = undefined;
        var diag_writer = std.Io.Writer.fixed(&diag_buf);
        const diag = wasmstint.Module.ParseDiagnostics.init(&diag_writer);
        errdefer {
            if (diag_writer.buffered().len > 0) {
                std.log.err("{s}", .{diag_writer.buffered()});
            }
        }

        const module = try wasmstint.Module.parse(testing.allocator, &reader, scratch, .{
            .random_seed = std.testing.random_seed,
            .diagnostics = diag,
        });
        errdefer module.deinitLeakCodeEntries(testing.allocator);
        try testing.expect(try module.finishCodeValidation(testing.allocator, scratch, diag));

        return .{ .inner = module };
    }

    pub fn deinit(module: WasmModule) void {
        for (module.inner.inner.code[0..module.inner.inner.code_count]) |*code| {
            code.deinit(testing.allocator);
        }
        module.inner.deinitLeakCodeEntries(testing.allocator);
    }

    pub const ModuleDefinitions = struct {
        tables: []runtime.TableInst.Allocated,
        memories: []runtime.MemInst.Allocated,

        /// Does not free the underlying tables & memories, only the slices.
        pub fn deinit(defs: *ModuleDefinitions) void {
            testing.allocator.free(defs.tables);
            testing.allocator.free(defs.memories);
            defs.* = undefined;
        }
    };

    pub fn allocate(
        module: WasmModule,
        /// Initialized after this function returns successfully.
        defined: *ModuleDefinitions,
        scratch: *ArenaAllocator,
        import_provider: runtime.ImportProvider,
    ) !runtime.ModuleAlloc {
        _ = scratch.reset(.retain_capacity);
        const table_types = module.inner.tableDefinedTypes();
        const mem_types = module.inner.memDefinedTypes();

        const table_ptrs = try scratch.allocator().alloc(*runtime.TableInst, table_types.len);
        const mem_ptrs = try scratch.allocator().alloc(*runtime.MemInst, mem_types.len);

        var tables = try std.ArrayList(runtime.TableInst.Allocated)
            .initCapacity(testing.allocator, table_types.len);
        errdefer {
            for (tables.items) |*t| {
                t.table.free();
            }
        }

        for (0.., table_ptrs, table_types) |i, *t, *ty| {
            tables.appendAssumeCapacity(try runtime.TableInst.Allocated.allocateFromType(
                testing.allocator,
                ty,
                null,
                @intCast(ty.limits.min),
                @intCast(ty.limits.max),
            ));
            t.* = &tables.items[i].table;
        }

        var memories = try std.ArrayList(runtime.MemInst.Allocated)
            .initCapacity(testing.allocator, mem_types.len);
        errdefer {
            for (memories.items) |*m| {
                m.memory.free();
            }
        }

        for (0.., mem_ptrs, mem_types) |i, *m, *ty| {
            memories.appendAssumeCapacity(try runtime.MemInst.Allocated.allocateFromType(
                testing.allocator,
                ty,
                ty.limits.min * runtime.MemInst.page_size,
                ty.limits.max * runtime.MemInst.page_size,
            ));
            m.* = &memories.items[i].memory;
        }

        defined.* = .{ .memories = memories.items, .tables = tables.items };

        var import_failure: runtime.ImportProvider.FailedRequest = undefined;
        return runtime.ModuleAlloc.allocateWithDefinitions(
            module.inner,
            testing.allocator,
            import_provider,
            &import_failure,
            // TODO: Definitions.deinit()
            runtime.ModuleAlloc.Definitions{ .tables = table_ptrs, .memories = mem_ptrs },
        ) catch |e| {
            if (e == error.ImportFailure) {
                std.log.err("{f}", .{import_failure});
            }

            return e;
        };
    }
};

const std = @import("std");
const testing = std.testing;
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const runtime = wasmstint.runtime;
