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
        errdefer module.deinit(testing.allocator, testing.allocator);
        try testing.expect(try module.finishCodeValidation(testing.allocator, scratch, diag));

        return .{ .inner = module };
    }

    pub fn deinit(module: WasmModule) void {
        module.inner.deinit(testing.allocator, testing.allocator);
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

        var definitions = runtime.ModuleAlloc.Definitions.Builder{
            .tables = try .initCapacity(scratch.allocator(), table_types.len),
            .memories = try .initCapacity(scratch.allocator(), mem_types.len),
        };
        errdefer definitions.definitions().deinit();

        const table_arena = try scratch.allocator()
            .alloc(runtime.TableInst.Allocated, table_types.len);
        for (table_arena, table_types) |*table, *ty| {
            table.* = try runtime.TableInst.Allocated.allocateFromType(
                testing.allocator,
                ty,
                null,
                @intCast(ty.limits.min),
                @intCast(ty.limits.max),
            );
            definitions.tables.appendAssumeCapacity(&table.table);
        }

        const memory_arena = try scratch.allocator()
            .alloc(runtime.MemInst.Allocated, mem_types.len);
        for (memory_arena, mem_types) |*memory, *ty| {
            memory.* = try runtime.MemInst.Allocated.allocateFromType(
                testing.allocator,
                ty,
                ty.limits.min * runtime.MemInst.page_size,
                ty.limits.max * runtime.MemInst.page_size,
            );
            definitions.memories.appendAssumeCapacity(&memory.memory);
        }

        return try module.allocateWithDefinitions(import_provider, definitions.definitions());
    }
};

const std = @import("std");
const testing = std.testing;
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const runtime = wasmstint.runtime;
