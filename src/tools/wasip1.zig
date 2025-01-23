const std = @import("std");
const wasmstint = @import("wasmstint");
const GlobalAllocator = @import("GlobalAllocator");

const WasiImports = struct {
    const init = wasmstint.runtime.ImportProvider{
        .ctx = undefined,
        .resolve = resolve_imports,
    };

    const signatures = struct {};

    const lookup: std.StaticStringMap(*wasmstint.runtime.FuncAddr.Host) = map: {
        const fields = @typeInfo(signatures).@"struct".decls;
        var entries: [fields.len]struct { []const u8, wasmstint.runtime.FuncAddr.Host } = undefined;
        for (&entries, fields) |*entry, *f| {
            entry.* = .{ f.name, &@field(signatures, f.name) };
        }

        break :map std.StaticStringMap(*wasmstint.runtime.FuncAddr.Host).initComptime(entries);
    };

    fn resolve_imports(
        ctx: *anyopaque,
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        desc: wasmstint.runtime.ImportProvider.Desc,
    ) ?wasmstint.runtime.ExternVal {
        _ = ctx;
        _ = desc;

        if (!std.mem.eql(u8, "wasi_snapshot_preview1", module.bytes))
            return null;

        return .{
            .func = wasmstint.runtime.FuncAddr.init(.{
                .host = .{
                    .data = undefined,
                    .func = lookup.get(name.bytes) orelse return null,
                },
            }),
        };
    }
};

pub fn main() !u8 {
    var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    var gpa = GlobalAllocator.init();
    defer gpa.deinit();

    var rng = std.Random.Xoshiro256{ .s = undefined };
    std.crypto.random.bytes(std.mem.asBytes(&rng.s));

    // TODO: Reuse CLI arg parser from run_wast.zig, moved to separate module/file.
    const wasm_file = opened: {
        var args_iter = try std.process.argsWithAllocator(scratch.allocator());
        defer _ = scratch.reset(.retain_capacity);
        _ = args_iter.next(); // EXE name

        const cwd = std.fs.cwd();
        const path = args_iter.next() orelse {
            std.debug.print("Usage: wasmstint-wasip1 app.wasm\n", .{});
            return error.InvalidCommandLineArgument;
        };

        break :opened try cwd.openFileZ(path, .{});
    };
    defer wasm_file.close();

    const wasm_buffer: []const u8 = try wasm_file.readToEndAlloc(std.heap.page_allocator, std.math.maxInt(usize) / 8);
    defer std.heap.page_allocator.free(wasm_buffer);

    const call_stack_size = @as(usize, 1) << 21; // 2 MiB
    var interpreter = try wasmstint.Interpreter.init(std.heap.page_allocator, call_stack_size);
    defer interpreter.deinit(std.heap.page_allocator);

    var wasm_buffer_pos = wasm_buffer;
    var module = wasmstint.Module.parse(
        gpa.allocator(),
        &wasm_buffer_pos,
        &scratch,
        rng.random(),
        .{ .keep_custom_sections = true },
    ) catch |e| {
        if (e != error.OutOfMemory) {
            std.debug.print("error: {!} at {X}\n", .{
                e,
                @intFromPtr(wasm_buffer_pos.ptr) - @intFromPtr(wasm_buffer.ptr),
            });
        }
        return e;
    };
    defer module.deinit(gpa.allocator());

    var module_inst = try wasmstint.runtime.ModuleInst.allocate(
        &module,
        WasiImports.init,
        gpa.allocator(),
        wasmstint.runtime.ModuleAllocator.page_allocator,
    );
    defer module_inst.deinit(gpa.allocator(), wasmstint.runtime.ModuleAllocator.page_allocator);

    return 0;
}
