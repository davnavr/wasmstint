//! Helpers for loading and storing into the fields of structs.

pub fn fieldType(ty: structs.FieldType, b: *const Builder) Type {
    return switch (ty) {
        .i8 => .i8,
        .i16 => .i16,
        .i32 => .i32,
        .i64 => .i64,
        .isize => b.size_type,
        .ptr => .ptr,
    };
}

pub fn typeOfField(field: anytype, b: *const Builder) Type {
    return fieldType(field.typeOf(), b);
}

/// Obtains a `ptr` to a field.
pub fn gepField(
    field: anytype,
    wip: *WipFunction,
    b: *const Builder,
    struct_type: Type,
    base: Value,
) Oom!Value {
    std.debug.assert(
        struct_type.structFields(&b.module).len >= @typeInfo(@TypeOf(field)).@"enum".fields.len,
    );
    return try wip.gepStruct(struct_type, base, @intFromEnum(field), @tagName(field));
}

fn loadName(field: anytype) []const u8 {
    return switch (field) {
        inline else => |t| "load" ++ @tagName(t),
    };
}

fn loadWithGepFixedBase(
    comptime F: type,
    comptime gep: fn (field: F, wip: *WipFunction, b: *const Builder) Oom!Value,
) (fn (field: F, wip: *WipFunction, b: *const Builder) Oom!Value) {
    return struct {
        pub fn load(field: F, wip: *WipFunction, b: *const Builder) Oom!Value {
            const ty = typeOfField(field, b);
            return try wip.load(.normal, ty, try gep(field, wip, b), .default, loadName(field));
        }
    }.load;
}

pub const module_inst = struct {
    /// Obtains a `ptr` to a field within the `ModuleInst`.
    pub fn gep(field: field_enums.ModuleInst, wip: *WipFunction, b: *const Builder) Oom!Value {
        return try gepField(field, wip, b, b.module_inst, OpcodeHandlerParam.module.arg(wip));
    }

    pub const load = loadWithGepFixedBase(field_enums.ModuleInst, gep);
};

pub const module = struct {
    pub fn gep(field: field_enums.Module, wip: *WipFunction, b: *const Builder) Oom!Value {
        return try gepField(field, wip, b, b.module_info, try module_inst.load(.module, wip, b));
    }

    pub const load = loadWithGepFixedBase(field_enums.Module, gep);
};

pub fn loadField(
    field: anytype,
    wip: *WipFunction,
    b: *const Builder,
    struct_type: Type,
    base: Value,
) Oom!Value {
    const ty = typeOfField(field, b);
    const ptr = try gepField(field, wip, b, struct_type, base);
    return try wip.load(.normal, ty, ptr, .default, loadName(field));
}

fn BasicAccessors(comptime F: type, comptime struct_type_field: []const u8) type {
    return struct {
        /// Obtains a `ptr` to a field derived from a `ptr` to the `struct`.
        pub fn gep(field: F, wip: *WipFunction, b: *const Builder, base: Value) Oom!Value {
            return try gepField(field, wip, b, @field(b, struct_type_field), base);
        }

        pub fn load(field: F, wip: *WipFunction, b: *const Builder, base: Value) Oom!Value {
            return try loadField(field, wip, b, @field(b, struct_type_field), base);
        }
    };
}

pub const mem_inst = BasicAccessors(field_enums.MemInst, "mem_inst");
pub const table_inst = BasicAccessors(field_enums.TableInst, "table_inst");
pub const side_table_entry = BasicAccessors(field_enums.SideTableEntry, "side_table_entry");

const std = @import("std");
const Oom = std.mem.Allocator.Error;

const structs = @import("structs");
const field_enums = structs.fields;

const Builder = @import("Builder.zig");
const OpcodeHandlerParam = @import("opcode_handler_param.zig").OpcodeHandlerParam;

const llvm = std.zig.llvm;
const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const WipFunction = llvm.Builder.WipFunction;
