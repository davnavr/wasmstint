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

    pub const LaneWidth = enum(u2) {
        x8 = 0,
        x16,
        x32,
        x64,

        pub fn toBytes(width: LaneWidth) u4 {
            return @shlExact(@as(u4, 1), @intFromEnum(width));
        }

        pub fn toBits(width: LaneWidth) u7 {
            return @as(u7, width.toBytes()) * 8;
        }

        /// The number of lanes in a `V128`.
        pub fn count(width: LaneWidth) u5 {
            return @divExact(@as(u5, 16), width.toBytes());
        }

        pub fn integerInterpretation(
            width: LaneWidth,
            comptime signedness: std.builtin.Signedness,
        ) Interpretation {
            const signedness_char = comptime switch (signedness) {
                .unsigned => 'u',
                .signed => 'i',
            };

            switch (width) {
                inline else => |chosen| {
                    const chosen_name = @tagName(chosen);
                    var name: [chosen_name.len]u8 = undefined;
                    @memcpy(&name, chosen_name);
                    name[0] = signedness_char;
                    return @field(Interpretation, &name);
                },
            }
        }
    };

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

        pub fn laneWidth(i: Interpretation) LaneWidth {
            return switch (i) {
                .i8, .u8 => .x8,
                .i16, .u16 => .x16,
                .i32, .u32, .f32 => .x32,
                .i64, .u64, .f64 => .x64,
            };
        }

        pub fn laneCount(i: Interpretation) u5 {
            return i.laneWidth().count();
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
            return switch (i) {
                inline else => |int| std.fmt.comptimePrint("{t}x{}", .{ int, int.laneCount() }),
            };
        }

        // TODO: Rename to VectorType?
        pub fn Type(comptime interpretation: Interpretation) type {
            return @FieldType(V128, interpretation.fieldName());
        }
    };

    pub fn init(comptime interpretation: Interpretation, lanes: interpretation.Type()) V128 {
        return @unionInit(V128, interpretation.fieldName(), lanes);
    }

    pub fn interpret(v: V128, comptime interpretation: Interpretation) (interpretation.Type()) {
        return @field(v, interpretation.fieldName());
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

    /// Bitwise NOT.
    ///
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#bitwise-logic
    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-inot
    pub fn not(v: V128) V128 {
        return V128{ .u8x16 = ~v.u8x16 };
    }

    /// Bitwise AND.
    ///
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#bitwise-logic
    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-iand
    pub fn @"and"(c_1: V128, c_2: V128) V128 {
        return V128{ .u8x16 = c_1.u8x16 & c_2.u8x16 };
    }

    /// Bitwise AND of `c_1` with bitwise NOT of `c_2`.
    ///
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#bitwise-and-not
    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-iandnot
    pub fn andnot(c_1: V128, c_2: V128) V128 {
        return V128{ .u8x16 = c_1.u8x16 & (~c_2.u8x16) };
    }

    /// Bitwise OR.
    ///
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#bitwise-logic
    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-ior
    pub fn @"or"(c_1: V128, c_2: V128) V128 {
        return V128{ .u8x16 = c_1.u8x16 | c_2.u8x16 };
    }

    /// Bitwise OR.
    ///
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#bitwise-logic
    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-ixor
    pub fn xor(c_1: V128, c_2: V128) V128 {
        return V128{ .u8x16 = c_1.u8x16 ^ c_2.u8x16 };
    }

    /// For every bit in `mask`, selects the corresponding bit from `a` when `0`, or `b` when `0`.
    ///
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#bitwise-select
    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-ibitselect
    pub fn bitselect(a: V128, b: V128, mask: V128) V128 {
        return V128.@"or"(V128.@"and"(a, mask), V128.@"and"(b, mask.not()));
    }

    /// Returns `true` if any bit in `v` is `1`.
    ///
    /// Implements the `v128.any_true` instruction.
    ///
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#any-bit-true
    /// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vvtestop
    pub fn anyTrue(v: V128) bool {
        return @as(u128, @bitCast(v)) != 0;
    }

    /// Returns `true` if all lanes in `v` are non-zero.
    ///
    /// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vtestop
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#all-lanes-true
    pub fn allTrue(v: V128, comptime lane_width: LaneWidth) bool {
        const interpretation = comptime lane_width.integerInterpretation(.unsigned);
        return @reduce(.And, v.interpret(interpretation) != @as(interpretation.Type(), @splat(0)));
    }

    /// Retrieves the high bits of each lane in `v`.
    ///
    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-ivbitmask
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#bitmask-extraction
    pub fn bitmask(v: V128, comptime lane_width: LaneWidth) @Vector(lane_width.count(), u1) {
        const interpretation = comptime lane_width.integerInterpretation(.signed);
        return @bitCast(v.interpret(interpretation) < @as(interpretation.Type(), @splat(0)));
    }

    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-iq15mulrsat
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#saturating-integer-q-format-rounding-multiplication
    pub fn @"i16x8.q15mulr_sat_s"(i_1: V128, i_2: V128) V128 {
        const a: @Vector(8, i32) = i_1.i16x8;
        const b: @Vector(8, i32) = i_2.i16x8;
        const result: @Vector(8, i32) =
            ((a * b) + comptime @as(@Vector(8, i32), @splat(0x4000))) >>
            comptime @as(@Vector(8, i32), @splat(15));

        const minimums: @Vector(8, i16) = comptime @splat(std.math.minInt(i16));
        const maximums: @Vector(8, i16) = comptime @splat(std.math.maxInt(i16));
        return V128{ .i16x8 = @intCast(@min(maximums, @max(minimums, result))) };
    }

    /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-ivdot
    /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-dot-product
    pub fn @"i32x4.dot_i16x8_s"(i_1: V128, i_2: V128) V128 {
        const a: @Vector(8, i32) = i_1.i16x8;
        const b: @Vector(8, i32) = i_2.i16x8;
        const product = a *% b;
        var result: @Vector(4, i32) = undefined;
        inline for (0..4) |i| {
            result[i] = product[i * 2] +% product[(i * 2) + 1];
        }

        return V128{ .i32x4 = result };
    }
};

const std = @import("std");
const builtin = @import("builtin");
