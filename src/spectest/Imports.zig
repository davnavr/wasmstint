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
        hasher.update(key.module().bytes());
        hasher.update("\xFF");
        hasher.update(key.name().bytes());
        return hasher.final();
    }

    pub fn eql(_: RegisteredContext, a: Name, b: Name) bool {
        return std.mem.eql(u8, a.module().bytes(), b.module().bytes()) and
            std.mem.eql(u8, a.name().bytes(), b.name().bytes());
    }
};

pub const Name = struct {
    module_ptr: [*]const u8,
    name_ptr: [*]const u8,
    module_len: u16,
    name_len: u16,

    pub fn init(module_name: wasmstint.Module.Name, value_name: wasmstint.Module.Name) Name {
        return .{
            .module_ptr = module_name.ptr,
            .module_len = module_name.len,
            .name_ptr = value_name.ptr,
            .name_len = value_name.len,
        };
    }

    fn module(self: *const Name) wasmstint.Module.Name {
        return .{ .ptr = self.module_ptr, .len = self.module_len };
    }

    fn name(self: *const Name) wasmstint.Module.Name {
        return .{ .ptr = self.name_ptr, .len = self.name_len };
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
        .value = @ptrCast(@constCast(&@as(i32, 666))),
    };

    const @"i64" = wasmstint.runtime.GlobalAddr{
        .global_type = .{ .mut = .@"const", .val_type = .i64 },
        .value = @ptrCast(@constCast(&@as(i64, 666))),
    };

    const @"f32" = wasmstint.runtime.GlobalAddr{
        .global_type = .{ .mut = .@"const", .val_type = .f32 },
        .value = @ptrCast(@constCast(&@as(f32, 666.6))),
    };

    const @"f64" = wasmstint.runtime.GlobalAddr{
        .global_type = .{ .mut = .@"const", .val_type = .f64 },
        .value = @ptrCast(@constCast(&@as(f64, 666.6))),
    };

    const names = [4][]const u8{ "i32", "i64", "f32", "f64" };
};

pub fn init(
    imports: *Imports,
    rng: std.Random,
    arena: *std.heap.ArenaAllocator,
) void {
    imports.* = Imports{
        .lookup_buffer = undefined,
        .lookup = std.StringHashMapUnmanaged(wasmstint.runtime.ExternVal).empty,
        .memory = undefined,
        .table = undefined,
        .registered = .empty,
        .registered_context = .{ .seed = rng.int(u32) },
    };

    const table_type = wasmstint.Module.TableType{
        .elem_type = .funcref,
        .limits = .{ .min = 10, .max = 20 },
    };

    imports.table = wasmstint.runtime.table_allocator.allocate(
        &table_type,
        arena.allocator(),
        rng.intRangeAtMost(u32, table_type.limits.min, table_type.limits.max),
    ) catch @panic("oom");

    const mem_type = wasmstint.Module.MemType{
        .limits = .{ .min = 1, .max = 2 },
    };

    imports.memory = wasmstint.runtime.paged_memory.map(
        &mem_type,
        rng.intRangeAtMost(usize, mem_type.limits.min, mem_type.limits.max) *
            wasmstint.runtime.MemInst.page_size,
        mem_type.limits.max * wasmstint.runtime.MemInst.page_size,
    ) catch @panic("oom");

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
    module: wasmstint.Module.Name,
    name: wasmstint.Module.Name,
    desc: wasmstint.runtime.ImportProvider.Desc,
) ?wasmstint.runtime.ExternVal {
    const host: *const Imports = @ptrCast(@alignCast(ctx));
    _ = desc;

    return if (std.mem.eql(u8, "spectest", module.bytes()))
        host.lookup.get(name.bytes())
    else
        host.registered.getContext(Name.init(module, name), host.registered_context);
}

const std = @import("std");
const wasmstint = @import("wasmstint");
