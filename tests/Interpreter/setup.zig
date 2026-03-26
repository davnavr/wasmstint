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

    pub fn allocateWithDefinitions(
        module: WasmModule,
        import_provider: runtime.ImportProvider,
        definitions: runtime.ModuleAlloc.Definitions,
    ) !runtime.ModuleAlloc {
        var import_failure: runtime.ImportProvider.FailedRequest = undefined;
        return runtime.ModuleAlloc.allocateWithDefinitions(
            module.inner,
            testing.allocator,
            import_provider,
            &import_failure,
            definitions,
        ) catch |e| {
            if (e == error.ImportFailure) {
                std.log.err("{f}", .{import_failure});
            }

            return e;
        };
    }

    pub fn allocate(
        module: WasmModule,
        scratch: *ArenaAllocator,
        import_provider: runtime.ImportProvider,
    ) !runtime.ModuleAlloc {
        _ = scratch.reset(.retain_capacity);
        const table_types = module.inner.tableDefinedTypes();
        const mem_types = module.inner.memDefinedTypes();

        const table_arena = try scratch.allocator()
            .alloc(runtime.TableInst.Allocated, table_types.len);
        var table_ptrs = try std.ArrayList(*runtime.TableInst)
            .initCapacity(scratch.allocator(), table_types.len);
        errdefer {
            for (table_ptrs.items) |table| {
                table.free();
            }
        }

        const memory_arena = try scratch.allocator()
            .alloc(runtime.MemInst.Allocated, mem_types.len);
        var mem_ptrs = try std.ArrayList(*runtime.MemInst)
            .initCapacity(scratch.allocator(), mem_types.len);
        errdefer {
            for (mem_ptrs.items) |memory| {
                memory.free();
            }
        }

        for (table_arena, table_types) |*table, *ty| {
            table.* = try runtime.TableInst.Allocated.allocateFromType(
                testing.allocator,
                ty,
                null,
                @intCast(ty.limits.min),
                @intCast(ty.limits.max),
            );
            table_ptrs.appendAssumeCapacity(&table.table);
        }

        for (memory_arena, mem_types) |*memory, *ty| {
            memory.* = try runtime.MemInst.Allocated.allocateFromType(
                testing.allocator,
                ty,
                ty.limits.min * runtime.MemInst.page_size,
                ty.limits.max * runtime.MemInst.page_size,
            );
            mem_ptrs.appendAssumeCapacity(&memory.memory);
        }

        return try module.allocateWithDefinitions(
            import_provider,
            // No need to call `Definitions.deinit()`, earlier `errdefer`s do cleanup.
            runtime.ModuleAlloc.Definitions{
                .tables = table_ptrs.items,
                .memories = mem_ptrs.items,
            },
        );
    }
};

const std = @import("std");
const testing = std.testing;
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const runtime = wasmstint.runtime;
