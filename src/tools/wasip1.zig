const std = @import("std");
const wasmstint = @import("wasmstint");
const GlobalAllocator = @import("GlobalAllocator");

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

    var wasm_buffer: []const u8 = try wasm_file.readToEndAlloc(std.heap.page_allocator, std.math.maxInt(usize) / 8);
    defer std.heap.page_allocator.free(wasm_buffer);

    const call_stack_size = @as(usize, 1) << 21; // 2 MiB
    var interpreter = try wasmstint.Interpreter.init(std.heap.page_allocator, call_stack_size);
    defer interpreter.deinit(std.heap.page_allocator);

    var module = wasmstint.Module.parse(
        gpa.allocator(),
        &wasm_buffer,
        scratch.allocator(),
        rng.random(),
        .{ .keep_custom_sections = true },
    ) catch |e| {
        if (e != error.OutOfMemory) {
            std.debug.print("error: {!} at {*}", .{ e, wasm_buffer.ptr });
        }
        return e;
    };
    defer module.deinit(gpa.allocator());

    // const module_inst = try wasmstint.runtime.ModuleInst.allocate(module);
    return 0;
}
