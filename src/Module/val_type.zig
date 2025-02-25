const std = @import("std");

pub const ValType = enum(u8) { // packed union
    // primitive: enum,
    // thing: *align(@max(@alignOf(Thing), 4)) const Thing,
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0x7D,
    f64 = 0x7C,
    v128 = 0x7B,
    funcref = 0x70,
    externref = 0x6F,

    pub inline fn eql(a: ValType, b: ValType) bool {
        return a == b;
    }

    pub inline fn isRefType(val_type: ValType) bool {
        return switch (val_type) {
            .funcref, .externref => true,
            else => false,
        };
    }

    pub fn format(
        val_type: ValType,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll(@tagName(val_type));
    }

    // comptime {
    //     std.debug.assert(@sizeOf(ValType) == @sizeOf(usize));
    //     std.debug.assert(@sizeOf(ValType) == @sizeOf(*const anytype));
    // }
};
