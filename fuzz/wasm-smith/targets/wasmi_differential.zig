const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const harness = @import("harness");
const wasmstint = @import("wasmstint");

const Imports = struct {
    const ProvidedImport = harness.wasmi_differential.ProvidedImport;

    arena: ArenaAllocator,
    exec: harness.wasmi_differential.Execution,
    oom: ?error{OutOfMemory} = null,
    // host_funcs: []const ?,
    remaining: []const ProvidedImport,

    fn init(
        gpa: std.mem.Allocator,
        exec: harness.wasmi_differential.Execution,
    ) error{OutOfMemory}!Imports {
        var arena = ArenaAllocator.init(gpa);
        errdefer arena.deinit();

        return .{
            .exec = exec,
            .remaining = exec.inner.provided_imports.items.toSlice(),
            .arena = arena,
        };
    }

    fn resolveInner(
        imports: *Imports,
        module: []const u8,
        name: []const u8,
    ) error{ OutOfMemory, ImportFailure }!wasmstint.runtime.ExternVal {
        const expected: *const ProvidedImport = if (imports.remaining.len > 0) provided: {
            imports.remaining = imports.remaining[1..];
            break :provided &imports.remaining[0];
        } else return error.ImportFailure;

        if (!std.mem.eql(u8, module, expected.module.contents(imports.exec)) or
            !std.mem.eql(u8, name, expected.name.contents(imports.exec)))
        {
            return error.ImportFailure;
        }

        return switch (expected.kind.tagForSwitch()) {
            // .func
            .global => |global| .{
                .global = wasmstint.runtime.GlobalAddr{
                    .global_type = .{
                        .mut = if (global.mutable) .@"var" else .@"const",
                        .val_type = global.value.valType(),
                    },
                    .value = value: switch (global.value.tagForSwitch()) {
                        .i32 => |i| {
                            const dst = try imports.arena.allocator().create(i32);
                            dst.* = i;
                            break :value @ptrCast(dst);
                        },
                        .i64 => |i| {
                            const dst = try imports.arena.allocator().create(i64);
                            dst.* = i;
                            break :value @ptrCast(dst);
                        },
                        .f32 => |i| {
                            const dst = try imports.arena.allocator().create(u32);
                            dst.* = i;
                            break :value @ptrCast(dst);
                        },
                        .f64 => |i| {
                            const dst = try imports.arena.allocator().create(u64);
                            dst.* = i;
                            break :value @ptrCast(dst);
                        },
                    },
                },
            },
        };
    }

    fn resolve(
        ctx: *anyopaque,
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        desc: wasmstint.runtime.ImportProvider.Desc,
    ) ?wasmstint.runtime.ExternVal {
        _ = desc;
        var imports: *Imports = @ptrCast(@alignCast(ctx));

        // TODO: Could collect expected.module, name, and type to use when mismatch is detected
        return imports.resolveInner(module.bytes, name.bytes) catch |e| {
            switch (e) {
                error.OutOfMemory => |oom| imports.oom = oom,
                else => imports.remaining.len = 0,
            }

            return null;
        };
    }

    fn provider(imports: *Imports) wasmstint.runtime.ImportProvider {
        return .{
            .ctx = imports,
            .resolve = resolve,
        };
    }

    fn deinit(imports: Imports) void {
        std.debug.assert(imports.oom == null);
        imports.arena.deinit();
    }
};

pub fn target(input_bytes: []const u8) !harness.Result {
    var gen = harness.Generator.init(input_bytes);
    const wasmi_exec = try harness.wasmi_differential.Execution.runTestCase(&gen);
    defer wasmi_exec.deinit();

    var main_pages = try wasmstint.PageBufferAllocator.init(64 * (1024 * 1024));
    defer main_pages.deinit();

    var scratch_pages = try wasmstint.PageBufferAllocator.init(4 * (1024 * 1024));
    var scratch = ArenaAllocator.init(scratch_pages.allocator());
    defer scratch_pages.deinit();

    std.debug.print("parsing module...\n", .{});

    var rng = std.Random.Xoshiro256{ .s = @bitCast(try gen.byteArray(32)) };
    var wasm_parse = wasmi_exec.wasmBinaryModule();
    var module = try wasmstint.Module.parse(
        main_pages.allocator(),
        &wasm_parse,
        &scratch,
        rng.random(),
        .{ .realloc_contents = true },
    );

    defer module.deinit(main_pages.allocator());

    std.debug.print("constructing import values...\n", .{});

    var imports = try Imports.init(main_pages.allocator(), wasmi_exec);
    defer imports.deinit();

    std.debug.print("allocating module...\n", .{});

    var import_failure: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_alloc = wasmstint.runtime.ModuleAlloc.allocate(
        &module,
        imports.provider(),
        main_pages.allocator(),
        wasmstint.runtime.ModuleAllocator.page_allocator,
        &import_failure,
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        // TODO: Check imports.oom
    };

    defer module_alloc.requiring_instantiation.deinit(
        main_pages.allocator(),
        wasmstint.runtime.ModuleAllocator.page_allocator,
    );

    var code_arena = ArenaAllocator.init(main_pages.allocator());
    defer code_arena.deinit();
}

comptime {
    harness.defineFuzzTarget(target);
}
