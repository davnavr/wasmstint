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

    pub fn parse(reader: Reader, diag: Reader.Diagnostics) Reader.Error!ValType {
        // Code has to change if ValType becomes a pointer to support typed function references/GC proposal.
        comptime std.debug.assert(@typeInfo(ValType).@"enum".tag_type == u8);

        return reader.readByteTag(ValType, diag, "valtype");
    }

    // comptime {
    //     std.debug.assert(@sizeOf(ValType) == @sizeOf(usize));
    //     std.debug.assert(@sizeOf(ValType) == @sizeOf(*const anytype));
    // }
};

const std = @import("std");
const Reader = @import("Reader.zig");
