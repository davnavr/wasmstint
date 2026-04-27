pub const FieldType = enum {
    i8,
    i16,
    i32,
    i64,
    isize,
    ptr,

    pub fn assertMatchesType(comptime expected: FieldType, comptime Actual: type) void {
        switch (expected) {
            .i16, .i8, .i32, .i64 => {
                const Expected = switch (expected) {
                    .i8 => i8,
                    .i16 => i16,
                    .i32 => i32,
                    .i64 => i64,
                    else => unreachable,
                };

                const expected_bits = @typeInfo(Expected).int.bits;

                ok: {
                    switch (@typeInfo(Actual)) {
                        .int => |i| if (i.bits == expected_bits) break :ok,
                        inline .@"union", .@"struct" => |u| {
                            if (u.layout == .@"packed" and @bitSizeOf(Actual) == expected_bits) {
                                break :ok;
                            }
                        },
                        .@"enum" => |e| if (@typeInfo(e.tag_type).int.bits == expected_bits) {
                            break :ok;
                        },
                        else => {},
                    }

                    @compileError(
                        "expected " ++ @typeName(Expected) ++ ", but got " ++ @typeName(Actual),
                    );
                }
            },
            .isize => if (!(Actual == usize or Actual == isize)) {
                @compileError("expected isize or usize, got " ++ @typeName(Actual));
            },
            .ptr => {
                const ptr: std.builtin.Type.Pointer = ptr: switch (@typeInfo(Actual)) {
                    .pointer => |p| p,
                    .@"struct" => |s| {
                        if (s.fields.len != 1) {
                            @compileError(@typeName(Actual) ++ " must have a single field");
                        }

                        const Nested = s.fields[0].type;
                        switch (@typeInfo(Nested)) {
                            .pointer => |p| break :ptr p,
                            else => @compileError(@typeName(Nested) ++ " is not a pointer type"),
                        }
                    },
                    .@"union" => |u| {
                        if (u.fields.len == 0) {
                            @compileError(@typeName(Actual) ++ " is an empty union");
                        }

                        for (u.fields) |f| {
                            if (@typeInfo(f.type) != .pointer) {
                                @compileError("field " ++ f.name ++ " in " ++ @typeName(Actual) ++
                                    " is not a pointer");
                            }

                            switch (@typeInfo(f.type).pointer.size) {
                                .one, .many => {},
                                else => |bad_size| @compileError(
                                    "bad pointer size " ++ @tagName(bad_size) ++ " for field " ++
                                        f.name ++ " in " ++ @typeName(Actual),
                                ),
                            }
                        }

                        return;
                    },
                    else => @compileError(@typeName(Actual) ++ " is not a pointer type"),
                };

                switch (ptr.size) {
                    .one, .many => {},
                    else => |bad_size| @compileError(
                        "bad pointer size " ++ @tagName(bad_size) ++ " in " ++ @typeName(Actual),
                    ),
                }
            },
        }
    }
};

pub const fields = struct {
    pub const ModuleInst = enum {
        buffer_len,
        module,
        func_imports,
        func_blocks,
        mems,
        tables,
        globals,
        datas_drop_mask,
        elems_drop_mask,

        pub fn typeOf(field: ModuleInst) FieldType {
            return switch (field) {
                .buffer_len => .isize,
                .module,
                .func_imports,
                .func_blocks,
                .mems,
                .tables,
                .globals,
                .datas_drop_mask,
                .elems_drop_mask,
                => .ptr,
            };
        }
    };

    pub const Module = enum {
        types,
        global_types,
        datas_ptrs,
        datas_lens,

        pub fn typeOf(field: Module) FieldType {
            return switch (field) {
                .types, .global_types, .datas_ptrs, .datas_lens => .ptr,
            };
        }
    };

    pub const MemInst = enum {
        base,
        size,
        capacity,
        limit,
        vtable,

        pub fn typeOf(field: MemInst) FieldType {
            return switch (field) {
                .base, .vtable => .ptr,
                .size, .capacity, .limit => .isize,
            };
        }
    };

    pub const TableInst = enum {
        base,
        elem_type,
        len,
        capacity,
        limit,

        pub fn typeOf(field: TableInst) FieldType {
            return switch (field) {
                .base => .ptr,
                .elem_type => .i8,
                .len, .capacity, .limit => .i32,
            };
        }
    };

    pub const SideTableEntry = enum {
        delta_ip,
        delta_stp,
        copy_count,
        pop_count,

        pub fn typeOf(field: SideTableEntry) FieldType {
            return switch (field) {
                .delta_ip => .i32,
                .delta_stp => .i16,
                .copy_count, .pop_count => .i8,
            };
        }
    };
};

const std = @import("std");
