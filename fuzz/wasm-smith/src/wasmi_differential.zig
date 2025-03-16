const std = @import("std");
const harness = @import("harness.zig");
const wasmstint = @import("wasmstint");

pub const TrapCode = wasmstint.Interpreter.Trap.Code;
pub const ValType = wasmstint.Module.ValType;

fn FfiTagged(comptime T: type) type {
    return struct {
        const Tag = @FieldType(T, "tag");
        const Payload = @FieldType(T, "payload");

        comptime {
            std.debug.assert(@typeInfo(T).@"struct".layout == .@"extern");
            std.debug.assert(@typeInfo(Tag).@"enum".is_exhaustive);
            std.debug.assert(@typeInfo(Payload).@"union".tag_type == null);
            std.debug.assert(@typeInfo(Payload).@"union".layout == .@"extern");
        }

        const payload_fields = @typeInfo(Payload).@"union".fields;

        const Union = @Type(.{
            .@"union" = std.builtin.Type.Union{
                .layout = .auto,
                .decls = &.{},
                .tag_type = Tag,
                .fields = fields: {
                    var fields: [payload_fields]std.builtin.Type.UnionField = undefined;
                    for (&fields, payload_fields) |*dst, *src| {
                        dst = std.builtin.Type.UnionField{
                            .name = src.name,
                            .alignment = 0,
                            .type = *const src.type,
                        };
                    }
                    break :fields fields;
                },
            },
        });

        fn tagForSwitch(s: *const T) Union {
            return switch (s.tag) {
                inline else => |tag| @unionInit(
                    Union,
                    @tagName(tag),
                    &@field(s.payload, @tagName(tag)),
                ),
            };
        }
    };
}

pub const ExternRef = enum(u32) {
    null = 0,
    _,
};

pub const String = enum(u32) {
    _,

    extern fn wasmstint_fuzz_differential_wasmi_string_contents(
        exec: *const Execution,
        str: String,
    ) callconv(.c) harness.FfiSlice(.@"const", u8);

    pub fn contents(str: String, exec: *const Execution) []const u8 {
        return wasmstint_fuzz_differential_wasmi_string_contents(exec, str)
            .toSlice();
    }
};

pub const HostFunc = enum(u32) {
    _,
};

pub const ArgumentVal = extern struct {
    tag: enum(u32) {
        i32 = 0,
        i64 = 1,
        f32 = 2,
        f64 = 3,
        null_func_ref = 4,
        func_ref = 5,
        host_func_ref = 6,
        extern_ref = 7,
    },
    payload: extern union {
        i32: i32,
        i64: i64,
        f32: u32,
        f64: u64,
        null_func_ref: void,
        func_ref: String,
        host_func_ref: HostFunc,
        extern_ref: ExternRef,
    },

    pub const tagForSwitch = FfiTagged(ArgumentVal).tagForSwitch;

    pub fn valType(arg: *const ArgumentVal) ValType {
        return switch (arg.tag) {
            .i32 => .i32,
            .i64 => .i64,
            .f32 => .f32,
            .f64 => .f64,
            .null_func_ref, .func_ref, .host_func_ref => .funcref,
            .extern_ref => .externref,
        };
    }

    pub const List = enum(u32) {
        _,
    };
};

pub const ResultVal = extern struct {
    tag: enum(u32) {
        i32 = 0,
        i64 = 1,
        f32 = 2,
        f64 = 3,
        null_func_ref = 4,
        func_ref = 5,
        extern_ref = 7,
    },
    payload: extern union {
        i32: i32,
        i64: i64,
        f32: u32,
        f64: u64,
        null_func_ref: void,
        func_ref: void,
        extern_ref: ExternRef,
    },

    pub const tagForSwitch = FfiTagged(ResultVal).tagForSwitch;

    pub const List = enum(u32) {
        _,
    };
};

pub const ProvidedImport = extern struct {
    module: String,
    name: String,
    kind: Kind,

    pub const Table = extern struct {
        length: u32,
        minimum: u32,
        maximum: u32,
        expected_type: ValType,
    };

    pub const Mem = extern struct {
        size: u32,
        minimum: u32,
        maximum: u32,
    };

    pub const Global = extern struct {
        value: ArgumentVal,
        mutable: bool,
    };

    pub const Kind = extern struct {
        tag: enum(u32) {
            func = 0,
            table = 1,
            mem = 2,
            global = 3,
        },
        payload: extern union {
            func: HostFunc,
            table: Table,
            mem: Mem,
            global: Global,
        },

        pub const tagForSwitch = FfiTagged(Kind).tagForSwitch;
    };
};

pub const Action = extern struct {
    tag: enum(u32) {
        invoke = 0,
        check_memory_contents = 1,
        compare_global_value = 3,
    },
    payload: extern union {
        invoke: Invoke,
        check_memory_contents: CheckMemoryContents,
    },

    pub const Invoke = enum(u32) {
        _,

        pub const Inner = extern struct {
            name: String,
            arguments: ArgumentVal.List,
            results: Result,
        };

        pub const Result = extern struct {
            tag: enum(u32) {
                values = 0,
                trap = 1,
            },
            payload: extern union {
                values: ResultVal.List,
                trap: TrapCode,
            },

            pub const tagForSwitch = FfiTagged(Result).tagForSwitch;
        };
    };

    pub const CheckMemoryContents = enum(u32) {
        _,

        pub const Inner = extern struct {
            hash: u64,
            length: usize,
            memory: String,
        };
    };
};

pub const Execution = struct {
    const Inner = extern struct {
        wasm: harness.FfiVec(u8),
        provided_imports: harness.FfiVec(ProvidedImport),
        instantiation: InstantiationResult,
        // @"opaque": opaque{},
    };

    pub const InstantiationResult = extern struct {
        tag: enum(u32) {
            trapped = 0,
            instantiated = 1,
        },
        payload: extern union {
            trapped: TrapCode,
            instantiated: harness.FfiVec(Action),
        },

        pub const tagForSwitch = FfiTagged(InstantiationResult).tagForSwitch;
    };

    inner: *const Inner,

    extern fn wasmstint_fuzz_differential_wasmi_execute(
        input: *harness.FfiSlice(.@"const", u8),
    ) callconv(.c) ?*const Inner;

    extern fn wasmstint_fuzz_differential_wasmi_deinit(exec: *const Inner) callconv(.c) void;

    pub fn runTestCase(gen: *harness.Generator) harness.Generator.Error!Execution {
        return if (wasmstint_fuzz_differential_wasmi_execute(&gen.src)) |inner|
            .{ .inner = inner }
        else
            error.OutOfDataBytes;
    }

    pub fn wasmBinaryModule(exec: *const Execution) []const u8 {
        return exec.inner.wasm.items.toSlice();
    }

    pub fn deinit(exec: *const Execution) void {
        wasmstint_fuzz_differential_wasmi_deinit(exec.inner);
    }
};
