pub const SetupError = union(enum) {
    memory_access_out_of_bounds: Trap.MemoryAccessOutOfBounds,
    table_access_out_of_bounds: Trap.TableAccessOutOfBounds,
};

/// Performs the steps of module instantiation up to but excluding the invocation of the *start*
/// function.
pub fn setupModule(
    module: *runtime.ModuleAlloc,
    err: *SetupError,
) error{ModuleInstantiationTrapped}!void {
    const module_inst = module.requiring_instantiation.header();
    const wasm = module_inst.module;
    const global_types = wasm.globalTypes()[wasm.inner.raw.global_import_count..];
    for (
        wasm.inner.raw.global_exprs[0..global_types.len],
        module_inst.definedGlobalValues(),
        global_types,
    ) |*init_expr, global_value, *global_type| {
        errdefer comptime unreachable;
        switch (init_expr.*) {
            .i32_or_f32 => |n32| {
                std.debug.assert(global_type.val_type == .i32 or global_type.val_type == .f32);
                @as(*u32, @ptrCast(@alignCast(global_value))).* = n32;
            },
            .i64_or_f64 => |n64| {
                std.debug.assert(global_type.val_type == .i64 or global_type.val_type == .f64);
                @as(*u64, @ptrCast(@alignCast(global_value))).* = n64;
            },
            .@"ref.null" => |ref_type| {
                std.debug.assert(ref_type == global_type.val_type);
                switch (ref_type) {
                    .funcref => {
                        @as(*runtime.FuncAddr.Nullable, @ptrCast(@alignCast(global_value))).* = .null;
                    },
                    .externref => {
                        @as(*runtime.ExternAddr, @ptrCast(@alignCast(global_value))).* = .null;
                    },
                    else => unreachable,
                }
            },
            .@"ref.func" => |func_idx| {
                @as(*runtime.FuncAddr.Nullable, @ptrCast(@alignCast(global_value))).* =
                    @bitCast(@as(runtime.FuncAddr, module_inst.funcAddr(func_idx)));
            },
            .@"global.get" => |src_global| {
                const src_addr = module_inst.globalAddr(src_global);
                std.debug.assert(src_addr.global_type.val_type == global_type.val_type);

                const src: *const anyopaque = module_inst.globalAddr(src_global).value;
                switch (global_type.val_type) {
                    .i32, .f32 => {
                        @as(*u32, @ptrCast(@alignCast(global_value))).* =
                            @as(*const u32, @ptrCast(@alignCast(src))).*;
                    },
                    .i64, .f64 => {
                        @as(*u64, @ptrCast(@alignCast(global_value))).* =
                            @as(*const u64, @ptrCast(@alignCast(src))).*;
                    },
                    .funcref => {
                        @as(*runtime.FuncAddr.Nullable, @ptrCast(@alignCast(global_value))).* =
                            @as(*const runtime.FuncAddr.Nullable, @ptrCast(@alignCast(src))).*;
                    },
                    .externref => {
                        @as(*runtime.ExternAddr, @ptrCast(@alignCast(global_value))).* =
                            @as(*const runtime.ExternAddr, @ptrCast(@alignCast(src))).*;
                    },
                    .v128 => unreachable,
                }
            },
        }
    }

    for (wasm.inner.raw.active_elems[0..wasm.inner.raw.active_elems_count]) |*active_elem| {
        const offset: u32 = offset: switch (active_elem.header.offset_tag) {
            .@"i32.const" => active_elem.offset.@"i32.const",
            .@"global.get" => {
                const global = module_inst.globalAddr(active_elem.offset.@"global.get");
                std.debug.assert(global.global_type.val_type == .i32);
                break :offset @as(*const u32, @ptrCast(@alignCast(global.value))).*;
            },
        };

        runtime.TableInst.init(
            active_elem.header.table,
            module.requiring_instantiation,
            active_elem.header.elements,
            null,
            0,
            offset,
        ) catch |e| switch (e) {
            error.TableAccessOutOfBounds => {
                err.* = .{
                    .table_access_out_of_bounds = .{
                        .table = active_elem.header.table,
                        .cause = .@"table.init",
                    },
                };
                return error.ModuleInstantiationTrapped;
            },
        };

        module_inst.elemSegmentDropFlag(active_elem.header.elements).drop();
    }

    for (wasm.inner.raw.active_datas[0..wasm.inner.raw.active_datas_count]) |*active_data| {
        const mem = module_inst.memAddr(active_data.header.memory);

        const offset: u32 = switch (active_data.header.offset_tag) {
            .@"i32.const" => active_data.offset.@"i32.const",
            .@"global.get" => get: {
                const global = module_inst.globalAddr(active_data.offset.@"global.get");
                std.debug.assert(global.global_type.val_type == .i32);
                break :get @as(*const u32, @ptrCast(@alignCast(global.value))).*;
            },
        };

        const src: []const u8 = module_inst.dataSegment(active_data.data);
        mem.init(src, @intCast(src.len), 0, offset) catch |e| switch (e) {
            error.MemoryAccessOutOfBounds => {
                err.* = .{
                    .memory_access_out_of_bounds = .init(
                        active_data.header.memory,
                        .@"memory.init",
                        {},
                    ),
                };
                return error.ModuleInstantiationTrapped;
            },
        };

        module_inst.dataSegmentDropFlag(active_data.data).drop();
    }
}

const std = @import("std");
const Trap = @import("Trap.zig");
const runtime = @import("../runtime.zig");
