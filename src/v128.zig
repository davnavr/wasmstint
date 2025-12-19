/// Implements 128-bit SIMD operations introduced in the
/// [fixed-width SIMD proposal](https://github.com/WebAssembly/simd).
pub const V128 = extern union {
    i8x16: @Vector(16, i8),
    u8x16: @Vector(16, u8),
    i16x8: @Vector(8, i16),
    u16x8: @Vector(8, u16),
    i32x4: @Vector(4, i32),
    u32x4: @Vector(4, u32),
    f32x4: @Vector(4, f32),
    i64x2: @Vector(2, i64),
    u64x2: @Vector(2, u64),
    f64x2: @Vector(2, f64),

    comptime {
        std.debug.assert(@sizeOf(V128) == 16);

        if (builtin.cpu.arch == .x86_64) {
            std.debug.assert(@alignOf(V128) == 16);
        }

        if (builtin.cpu.arch.endian() != .little) {
            @compileError("128-bit SIMD needs implementation on big-endian platforms");
        }
    }

    pub const LaneIdxSize = enum(u4) {
        @"2" = 1,
        @"4" = 2,
        @"8" = 3,
        @"16" = 4,
        @"32" = 5,
    };

    pub fn LaneIdx(comptime size: LaneIdxSize) type {
        return std.meta.Int(.unsigned, @intFromEnum(size));
    }

    pub const Interpretation = enum {
        i8,
        u8,
        i16,
        u16,
        i32,
        u32,
        f32,
        i64,
        u64,
        f64,

        pub fn laneCount(i: Interpretation) u5 {
            return switch (i) {
                .i8, .u8 => 16,
                .i16, .u16 => 8,
                .i32, .u32, .f32 => 4,
                .i64, .u64, .f64 => 2,
            };
        }

        pub fn fromLaneType(comptime T: type) Interpretation {
            return @field(
                Interpretation,
                std.fmt.comptimePrint(
                    "{c}{}",
                    .{
                        switch (@typeInfo(T)) {
                            .int => |int| switch (int.signedness) {
                                .unsigned => 'u',
                                .signed => 'i',
                            },
                            .float => 'f',
                            else => @compileError("invalid lane type " ++ @typeName(T)),
                        },
                        @bitSizeOf(T),
                    },
                ),
            );
        }

        pub fn signed(i: Interpretation) Interpretation {
            return switch (i) {
                .u8 => .i8,
                .u16 => .i16,
                .u32 => .i32,
                .u64 => .i64,
                else => i,
            };
        }

        pub fn fieldName(i: Interpretation) []const u8 {
            return switch (i.signed()) {
                .u8, .u16, .u32, .u64 => unreachable,
                inline else => |int| std.fmt.comptimePrint("{t}x{}", .{ int, int.laneCount() }),
            };
        }
    };

    pub fn init(
        comptime interpretation: Interpretation,
        lanes: @FieldType(V128, interpretation.fieldName()),
    ) V128 {
        return @unionInit(V128, interpretation.fieldName(), lanes);
    }

    const Formatter = struct {
        vector: V128,
        interpretation: Interpretation,

        pub fn format(ctx: Formatter, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeAll("(v128.const ");
            switch (ctx.interpretation) {
                inline else => |interp| {
                    try writer.writeAll(comptime interp.signed().fieldName());
                    const interp_name = comptime interp.fieldName();
                    const LaneType = @typeInfo(@FieldType(V128, interp_name)).vector.child;
                    const lanes: [interp.laneCount()]LaneType = @field(ctx.vector, interp_name);
                    for (lanes) |v| {
                        switch (interp) {
                            .u8 => try writer.print(" 0x{X:0>2}", .{v}),
                            else => {
                                const Hex = std.meta.Int(.unsigned, @bitSizeOf(LaneType));
                                try writer.print(
                                    " {[value]} (;0x{[hex]X:0>[width]};)",
                                    .{
                                        .value = v,
                                        .hex = @as(Hex, @bitCast(v)),
                                        .width = @sizeOf(Hex) * 2,
                                    },
                                );
                            },
                        }
                    }
                },
            }
            try writer.writeAll(")");
        }
    };

    pub fn formatter(vector: V128, interpretation: Interpretation) Formatter {
        return Formatter{
            .vector = vector,
            .interpretation = interpretation,
        };
    }

    pub fn format(vector: V128, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try (vector.formatter(.u8)).format(writer);
    }
};

const std = @import("std");
const builtin = @import("builtin");
