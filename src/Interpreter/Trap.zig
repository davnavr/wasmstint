code: Code,
information: Information,

const Trap = @This();

/// Describes the kind of trap that occurred.
///
/// Hosts can specify their own codes in the negative range.
pub const Code = enum(i32) {
    unreachable_code_reached = 0,
    /// The function did not contain valid WebAssembly.
    ///
    /// See <https://webassembly.github.io/spec/core/appendix/implementation.html#validation>
    /// for more information.
    lazy_validation_failure = 1,
    integer_division_by_zero = 2,
    integer_overflow = 3,
    invalid_conversion_to_integer = 4,
    memory_access_out_of_bounds = 5,
    table_access_out_of_bounds = 6,
    indirect_call_to_null = 7,
    indirect_call_signature_mismatch = 8,
    _,

    pub fn initHost(code: u31) Code {
        return @enumFromInt(-@as(i31, code) - 1);
    }

    pub fn host(code: Code) ?u31 {
        return if (code < 0) @intCast(-(@intFromEnum(code) + 1)) else null;
    }
};

pub const MemoryAccessOutOfBounds = struct {
    memory: Module.MemIdx,
    cause: Cause,
    info: Info,

    pub const Info = union {
        @"memory.init": void,
        @"memory.copy": void,
        @"memory.fill": void,
        access: Access,

        pub const Access = packed struct {
            address: std.meta.Int(.unsigned, @typeInfo(usize).int.bits),
            size: std.mem.Alignment,
            maximum: usize,
        };
    };

    pub const Cause = std.meta.FieldEnum(Info);

    pub fn init(
        mem: Module.MemIdx,
        comptime cause: Cause,
        info: @FieldType(Info, @tagName(cause)),
    ) MemoryAccessOutOfBounds {
        return .{
            .memory = mem,
            .cause = cause,
            .info = @unionInit(Info, @tagName(cause), info),
        };
    }
};

pub const TableAccessOutOfBounds = struct {
    table: Module.TableIdx,
    cause: Cause,

    pub const Cause = union(enum) {
        @"table.init",
        call_indirect,
        return_call_indirect,
        @"table.copy",
        @"table.fill",
        @"table.get": Access,
        @"table.set": Access,

        pub const Access = struct {
            index: u32,
            maximum: u32,
        };
    };

    pub fn init(table: Module.TableIdx, cause: Cause) TableAccessOutOfBounds {
        return .{ .table = table, .cause = cause };
    }
};

pub const IndirectCallToNull = struct { index: u32 };

pub const IndirectCallSignatureMismatch = struct {
    expected: *const Module.FuncType,
    actual: *const Module.FuncType,
};

pub const Information = union {
    indirect_call_to_null: IndirectCallToNull,
    indirect_call_signature_mismatch: IndirectCallSignatureMismatch,
    lazy_validation_failure: struct {
        function: Module.FuncIdx,
    },
    memory_access_out_of_bounds: MemoryAccessOutOfBounds,
    table_access_out_of_bounds: TableAccessOutOfBounds,
};

fn InformationType(comptime code: Code) type {
    return if (@hasField(Information, @tagName(code)))
        @FieldType(Information, @tagName(code))
    else
        void;
}

pub fn init(
    comptime code: Code,
    information: InformationType(code),
) Trap {
    return Trap{
        .code = code,
        .information = if (@hasField(Information, @tagName(code)))
            @unionInit(Information, @tagName(code), information)
        else
            undefined,
    };
}

pub fn initHostCode(code: u31) Trap {
    return .{
        .code = @enumFromInt(-@as(i32, code) - 1),
        .information = undefined,
    };
}

pub fn toHostCode(trap: *const Trap) ?u31 {
    const code: i32 = @intFromEnum(trap.code);
    return if (code < 0) @intCast(-(code + 1)) else null;
}

const std = @import("std");
const Module = @import("../Module.zig");
