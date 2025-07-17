//! Implements the specification test [host module].
//!
//! [host module]: https://github.com/WebAssembly/spec/blob/main/interpreter/README.md#spectest-host-module

const Imports = @This();

lookup_buffer: [2048]u8 align(16),
lookup: std.StringHashMapUnmanaged(wasmstint.runtime.ExternVal),
memory: wasmstint.runtime.MemInst,
table: wasmstint.runtime.TableInst,
/// Imports provided by registered modules.
registered: Registered,
registered_context: RegisteredContext,

const Registered = std.HashMapUnmanaged(
    Name,
    wasmstint.runtime.ExternVal,
    RegisteredContext,
    std.hash_map.default_max_load_percentage,
);

const RegisteredContext = struct {
    seed: u32,

    pub fn hash(ctx: RegisteredContext, key: Name) u64 {
        var hasher = std.hash.Wyhash.init(ctx.seed);
        hasher.update(key.module());
        hasher.update("\xFF");
        hasher.update(key.name());
        return hasher.final();
    }

    pub fn eql(_: RegisteredContext, a: Name, b: Name) bool {
        return std.mem.eql(u8, a.module(), b.module()) and
            std.mem.eql(u8, a.name(), b.name());
    }
};

pub const Name = struct {
    module_ptr: [*]const u8,
    module_len: u32,
    name_len: u32,
    name_ptr: [*]const u8,

    pub fn init(module_bytes: []const u8, name_bytes: []const u8) Name {
        return .{
            .module_ptr = module_bytes.ptr,
            .module_len = @intCast(module_bytes.len),
            .name_ptr = name_bytes.ptr,
            .name_len = @intCast(name_bytes.len),
        };
    }

    fn module(self: *const Name) []const u8 {
        return self.module_ptr[0..self.module_len];
    }

    fn name(self: *const Name) []const u8 {
        return self.name_ptr[0..self.name_len];
    }
};

pub const PrintFunction = enum(u8) {
    print = 0,
    print_i32,
    print_i64,
    print_f32,
    print_f64,
    print_i32_f32,
    print_f64_f64,

    const param_types = [_]wasmstint.Module.ValType{
        .i32,
        .f32,
        .i64,
        .f64,
        .f64,
    };

    pub fn signature(func: PrintFunction) wasmstint.Module.FuncType {
        return switch (func) {
            .print => .empty,
            .print_i32 => .{
                .types = param_types[0..1].ptr,
                .param_count = 1,
                .result_count = 0,
            },
            .print_i64 => .{
                .types = param_types[2..3].ptr,
                .param_count = 1,
                .result_count = 0,
            },
            .print_f32 => .{
                .types = param_types[1..2].ptr,
                .param_count = 1,
                .result_count = 0,
            },
            .print_f64 => .{
                .types = param_types[3..4].ptr,
                .param_count = 1,
                .result_count = 0,
            },
            .print_i32_f32 => .{
                .types = param_types[0..2].ptr,
                .param_count = 2,
                .result_count = 0,
            },
            .print_f64_f64 => .{
                .types = param_types[3..5].ptr,
                .param_count = 2,
                .result_count = 0,
            },
        };
    }

    pub const all = std.enums.values(PrintFunction);

    pub const functions: [all.len]wasmstint.runtime.FuncAddr.Host = functions: {
        var result: [all.len]wasmstint.runtime.FuncAddr.Host = undefined;
        for (all) |func| {
            result[@intFromEnum(func)] = .{ .signature = func.signature() };
        }
        break :functions result;
    };

    pub fn hostFunc(func: PrintFunction) *const wasmstint.runtime.FuncAddr.Host {
        return &functions[@intFromEnum(func)];
    }

    pub fn addr(func: PrintFunction) wasmstint.runtime.FuncAddr {
        return wasmstint.runtime.FuncAddr.init(.{
            .host = .{
                .func = @constCast(func.hostFunc()),
                .data = null,
            },
        });
    }
};

const globals = struct {
    // Spectests expect these exact values
    const @"i32" = wasmstint.runtime.GlobalAddr{
        .global_type = .{ .mut = .@"const", .val_type = .i32 },
        .value = @constCast(@ptrCast(&@as(i32, 666))),
    };

    const @"i64" = wasmstint.runtime.GlobalAddr{
        .global_type = .{ .mut = .@"const", .val_type = .i64 },
        .value = @constCast(@ptrCast(&@as(i64, 666))),
    };

    const @"f32" = wasmstint.runtime.GlobalAddr{
        .global_type = .{ .mut = .@"const", .val_type = .f32 },
        .value = @constCast(@ptrCast(&@as(f32, 666.6))),
    };

    const @"f64" = wasmstint.runtime.GlobalAddr{
        .global_type = .{ .mut = .@"const", .val_type = .f64 },
        .value = @constCast(@ptrCast(&@as(f64, 666.6))),
    };

    const names = [4][]const u8{ "i32", "i64", "f32", "f64" };
};

pub fn init(
    imports: *Imports,
    rng: std.Random,
    store_allocator: wasmstint.runtime.ModuleAllocator,
) void {
    imports.* = Imports{
        .lookup_buffer = undefined,
        .lookup = std.StringHashMapUnmanaged(wasmstint.runtime.ExternVal).empty,
        .memory = undefined,
        .table = undefined,
        .registered = .empty,
        .registered_context = .{ .seed = rng.int(u32) },
    };

    var allocation_request = wasmstint.runtime.ModuleAllocator.Request.init(
        &[1]wasmstint.Module.TableType{
            .{
                .elem_type = .funcref,
                .limits = .{ .min = 10, .max = 20 },
            },
        },
        (&imports.table)[0..1],
        &[1]wasmstint.Module.MemType{.{ .limits = .{ .min = 1, .max = 2 } }},
        (&imports.memory)[0..1],
    );

    store_allocator.allocate(&allocation_request) catch @panic("oom");

    var lookup_buffer = std.heap.FixedBufferAllocator.init(&imports.lookup_buffer);
    imports.lookup.ensureTotalCapacity(
        lookup_buffer.allocator(),
        comptime (PrintFunction.all.len + globals.names.len + 2),
    ) catch unreachable;

    for (PrintFunction.all) |func| {
        imports.lookup.putAssumeCapacityNoClobber(
            @tagName(func),
            .{ .func = func.addr() },
        );
    }

    inline for (globals.names) |name| {
        imports.lookup.putAssumeCapacityNoClobber(
            "global_" ++ name,
            .{ .global = @field(globals, name) },
        );
    }

    imports.lookup.putAssumeCapacityNoClobber("memory", .{ .mem = &imports.memory });
    imports.lookup.putAssumeCapacityNoClobber(
        "table",
        .{ .table = .{ .elem_type = .funcref, .table = &imports.table } },
    );
}

pub fn provider(host: *Imports) wasmstint.runtime.ImportProvider {
    return .{
        .ctx = host,
        .resolve = resolve,
    };
}

fn resolve(
    ctx: *anyopaque,
    module: std.unicode.Utf8View,
    name: std.unicode.Utf8View,
    desc: wasmstint.runtime.ImportProvider.Desc,
) ?wasmstint.runtime.ExternVal {
    const host: *const Imports = @ptrCast(@alignCast(ctx));
    _ = desc;

    return if (std.mem.eql(u8, "spectest", module.bytes))
        host.lookup.get(name.bytes)
    else
        host.registered.getContext(
            Name.init(module.bytes, name.bytes),
            host.registered_context,
        );
}

const std = @import("std");
const wasmstint = @import("wasmstint");
