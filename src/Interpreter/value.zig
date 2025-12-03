/// For simplicity, the `Interpreter` operates on fixed-sized `Value`s. This keeps branches fast
/// and ensures O(1) access of parameter/local variables.
pub const Value = extern union {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    ptr: ?*anyopaque,
    externref: runtime.ExternAddr,
    funcref: runtime.FuncAddr.Nullable,
    i64x2: @Vector(2, i64),

    pub const Tag = enum {
        i32,
        f32,
        i64,
        f64,
        externref,
        funcref,

        pub fn Type(comptime tag: Tag) type {
            return @FieldType(Value, @tagName(tag));
        }
    };

    comptime {
        std.debug.assert(@sizeOf(Value) == 16);
    }

    pub const Tagged = TaggedValue;

    pub fn tagged(value: *const Value, ty: Module.ValType) Tagged {
        return switch (ty) {
            .v128 => unreachable, // Not implemented
            .externref => .{ .externref = value.externref },
            inline else => |tag| @unionInit(Tagged, @tagName(tag), @field(value, @tagName(tag))),
        };
    }

    pub fn formatBytes(value: *const Value, writer: *Writer) Writer.Error!void {
        const bytes: *align(@alignOf(Value)) const [@sizeOf(Value)]u8 = std.mem.asBytes(value);
        var tuple: std.meta.Tuple(&(.{u8} ** bytes.len)) = undefined;
        inline for (bytes, 0..) |src, i| tuple[i] = src;
        try writer.print(
            ("{X:0>2}" ** 4) ++ ((" " ++ ("{X:0>2}" ** 4)) ** (@divExact(bytes.len, 4) - 1)),
            tuple,
        );
    }

    pub fn bytesFormatter(value: *const Value) std.fmt.Alt(*const Value, formatBytes) {
        return .{ .data = value };
    }
};

pub const TaggedValue = union(enum) {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    externref: runtime.ExternAddr,
    funcref: runtime.FuncAddr.Nullable,

    comptime {
        std.debug.assert(@sizeOf(TaggedValue) == switch (@sizeOf(*anyopaque)) {
            // 32 if v128 support is added
            8 => 16,
            else => unreachable,
        });
    }

    pub fn valueType(tagged: *const TaggedValue) Module.ValType {
        return switch (@as(std.meta.Tag(TaggedValue), tagged.*)) {
            inline else => |tag| @field(Module.ValType, @tagName(tag)),
        };
    }

    pub fn untagged(tagged: *const TaggedValue) Value {
        return switch (@as(std.meta.Tag(TaggedValue), tagged.*)) {
            .externref => .{ .externref = tagged.externref },
            inline else => |tag| @unionInit(
                Value,
                @tagName(tag),
                @field(tagged, @tagName(tag)),
            ),
        };
    }

    /// Constructs a `TaggedValue` based on the compile-time type of `value`.
    pub fn initInferred(value: anytype) TaggedValue {
        const T = @TypeOf(value);

        if (@typeInfo(T) == .pointer) {
            @compileError("pointer type " ++ @typeName(T) ++ " is not supported");
        }

        return switch (T) {
            i32, u32 => .{ .i32 = @bitCast(value) },
            i64, u64 => .{ .i64 = @bitCast(value) },
            f32 => .{ .f32 = value },
            f64 => .{ .f64 = value },
            runtime.ExternAddr => .{ .externref = value },
            runtime.FuncAddr.Nullable => .{ .funcref = value },
            runtime.FuncAddr => .{ .funcref = @bitCast(value) },
            else => switch (@typeInfo(T)) {
                .int => @compileError("unsupported integer value type " ++ @typeName(T)),
                .float => @compileError("unsupported float value type " ++ @typeName(T)),
                else => @compileError("unrecognized value type" ++ @typeName(T)),
            },
        };
    }

    pub const Formatter = struct {
        value: *const TaggedValue,
        options: Options,

        pub const Options = packed struct(u3) {
            int: packed struct(u2) {
                signed: bool = true,
                unsigned: bool = false,
            } = .{},
            float: packed struct(u1) {
                /// Append a WASM style comment indicating the float's bits, in hexadecimal.
                hex: bool = true,
            } = .{},
        };

        pub fn format(self: Formatter, writer: *Writer) Writer.Error!void {
            const value = self.value;
            switch (value.*) {
                inline .i32, .i64 => |i, tag| {
                    const Unsigned = std.meta.Int(.unsigned, @typeInfo(@TypeOf(i)).int.bits);

                    try writer.writeAll("(" ++ @tagName(tag));
                    try writer.print(".const 0x{X}", .{i});
                    if (self.options.int.signed or self.options.int.unsigned) {
                        try writer.writeAll(" (; ");

                        if (self.options.int.signed) {
                            try writer.print("signed={d}", .{i});
                        }

                        if (self.options.int.signed and self.options.int.unsigned) {
                            try writer.writeAll(", ");
                        }

                        if (self.options.int.unsigned) {
                            try writer.print("unsigned={d}", .{@as(Unsigned, @bitCast(i))});
                        }

                        try writer.writeAll(" ;))");
                    }
                },
                inline .f32, .f64 => |z, tag| {
                    try writer.writeAll("(" ++ @tagName(tag));
                    try writer.print(".const {}", .{z});
                    if (self.options.float.hex) {
                        try writer.print(
                            " (; 0x{X} ;)",
                            .{
                                @as(
                                    std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(z))),
                                    @bitCast(z),
                                ),
                            },
                        );
                    }
                    try writer.writeByte(')');
                },
                inline .funcref, .externref => |*ref| try ref.format(writer),
            }
        }
    };

    pub fn formatter(value: *const TaggedValue, options: Formatter.Options) Formatter {
        return Formatter{ .value = value, .options = options };
    }

    pub fn format(value: *const TaggedValue, writer: *Writer) Writer.Error!void {
        try value.formatter(.{}).format(writer);
    }

    pub fn formatSlice(values: []const TaggedValue, writer: *Writer) Writer.Error!void {
        for (0.., values) |i, val| {
            if (i > 0) {
                try writer.writeByte(' ');
            }

            try val.format(writer);
        }
    }

    pub fn sliceFormatter(values: []const TaggedValue) std.fmt.Alt(
        []const TaggedValue,
        formatSlice,
    ) {
        return std.fmt.Alt([]const TaggedValue, formatSlice){ .data = values };
    }
};

const std = @import("std");
const Writer = std.Io.Writer;
const Module = @import("../Module.zig");
const runtime = @import("../runtime.zig");
