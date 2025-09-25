const std = @import("std");
const ValType = @import("val_type.zig").ValType;

pub const FuncType = extern struct {
    types: [*]const ValType,
    param_count: u16,
    result_count: u16,

    pub const empty = FuncType{
        .types = &[0]ValType{},
        .param_count = 0,
        .result_count = 0,
    };

    inline fn paramAndResultTypes(sig: *const FuncType) []const ValType {
        return sig.types[0 .. @as(u32, sig.param_count) + sig.result_count];
    }

    pub inline fn parameters(sig: *const FuncType) []const ValType {
        return sig.paramAndResultTypes()[0..sig.param_count];
    }

    pub inline fn results(sig: *const FuncType) []const ValType {
        return sig.paramAndResultTypes()[sig.param_count..];
    }

    pub fn matches(a: *const FuncType, b: *const FuncType) bool {
        return @intFromPtr(a) == @intFromPtr(b) or
            (a.param_count == b.param_count and
                a.result_count == b.result_count and
                std.mem.eql(ValType, a.paramAndResultTypes(), b.paramAndResultTypes()));
    }

    pub fn format(func_type: FuncType, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (0..func_type.param_count, func_type.parameters()) |i, param| {
            if (i > 0) {
                try writer.writeByte(' ');
            }

            try writer.print("(param {t})", .{param});
        }

        if (func_type.param_count > 0 and func_type.result_count > 0) {
            try writer.writeByte(' ');
        }

        for (0..func_type.result_count, func_type.results()) |i, result| {
            if (i > 0) {
                try writer.writeByte(' ');
            }

            try writer.print("(result {t})", .{result});
        }
    }
};
