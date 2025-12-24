pub const SetupError = union(enum) {
    memory_access_out_of_bounds: Trap.MemoryAccessOutOfBounds,
    table_access_out_of_bounds: Trap.TableAccessOutOfBounds,
};

/// Performs the steps of module instantiation up to but excluding the invocation of the *start*
/// function.
pub fn setupModule(
    module: *runtime.ModuleAlloc,
    err: *SetupError,
    const_expr_buf: []align(@sizeOf(Value)) Value,
) error{ModuleInstantiationTrapped}!void {
    const module_inst = module.requiring_instantiation.header();
    const wasm = module_inst.module;

    std.debug.assert(const_expr_buf.len <= wasm.inner.raw.init_max_stack);

    // TODO: Fuel check against `wasm.init_fuel`, error.InsufficientFuel

    const global_types = wasm.globalTypes()[wasm.inner.raw.global_import_count..];
    for (
        wasm.inner.raw.global_exprs[0..global_types.len],
        module_inst.definedGlobalValues(),
        global_types,
    ) |*init_expr, global_value, *global_type| {
        errdefer comptime unreachable;
        switch (global_type.val_type) {
            inline .i32, .i64, .f32, .f64, .funcref, .externref, .v128 => |val_type| {
                const tag: Value.Tag = @field(Value.Tag, @tagName(val_type));
                const dst: *(tag.Type()) = @ptrCast(@alignCast(global_value));
                dst.* = const_eval.calculate(
                    init_expr.bytes(wasm),
                    module.requiring_instantiation,
                    tag,
                    const_expr_buf,
                );
            },
        }
    }

    for (wasm.inner.raw.active_elems[0..wasm.inner.raw.active_elems_count]) |*active_elem| {
        const offset: u32 = @bitCast(@as(
            i32,
            const_eval.calculate(
                active_elem.offsetBytes(wasm),
                module.requiring_instantiation,
                .i32,
                const_expr_buf,
            ),
        ));

        runtime.TableInst.init(
            active_elem.table,
            module.requiring_instantiation,
            active_elem.elements,
            null,
            0,
            offset,
            const_expr_buf,
        ) catch |e| switch (e) {
            error.TableAccessOutOfBounds => {
                err.* = .{
                    .table_access_out_of_bounds = .{
                        .table = active_elem.table,
                        .cause = .@"table.init",
                    },
                };
                return error.ModuleInstantiationTrapped;
            },
        };

        module_inst.elemSegmentDropFlag(active_elem.elements).drop();
    }

    for (wasm.inner.raw.active_datas[0..wasm.inner.raw.active_datas_count]) |*active_data| {
        const mem = module_inst.memAddr(active_data.memory);

        const offset: u32 = @bitCast(@as(
            i32,
            const_eval.calculate(
                active_data.offsetBytes(wasm),
                module.requiring_instantiation,
                .i32,
                const_expr_buf,
            ),
        ));

        const src: []const u8 = module_inst.dataSegment(active_data.data);
        mem.init(src, @intCast(src.len), 0, offset) catch |e| switch (e) {
            error.MemoryAccessOutOfBounds => {
                err.* = .{
                    .memory_access_out_of_bounds = .init(active_data.memory, .@"memory.init", {}),
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
const Value = @import("value.zig").Value;
const const_eval = @import("const_eval.zig");
