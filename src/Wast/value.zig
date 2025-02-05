//! Parsing of values in the WebAssembly [grammar].
//!
//! These are intended to parse the contents of a `Lexer.Token`, and assume that the contents of the
//! token are already in the correct format.
//!
//! [grammar]: https://webassembly.github.io/spec/core/text/values.html

const std = @import("std");
const floating_point = @import("../float.zig");

fn hexDigitValue(digit: u8) u4 {
    return switch (digit) {
        '0'...'9' => @as(u4, @intCast(digit - '0')),
        'a'...'f' => @as(u4, @intCast(digit - 'a' + 10)),
        'A'...'F' => @as(u4, @intCast(digit - 'A' + 10)),
        else => unreachable,
    };
}

pub fn unsignedInteger(comptime T: type, token: []const u8) error{Overflow}!T {
    comptime {
        std.debug.assert(@typeInfo(T).int.signedness == .unsigned);
    }

    std.debug.assert(token.len > 0);
    std.debug.assert(token[0] != '_');
    std.debug.assert(token[token.len - 1] != '_');

    const Decoded = std.math.ByteAlignedInt(T);
    var decoded: Decoded = 0;
    if (std.mem.startsWith(u8, token, "0x")) {
        std.debug.assert(token[2] != '_');
        for (token[2..]) |c| if (c != '_') {
            decoded = try std.math.shlExact(Decoded, decoded, 4) | hexDigitValue(c);
        };
    } else {
        std.debug.assert(token[0] != '_');
        for (token) |c| switch (c) {
            '0'...'9' => {
                decoded = try std.math.add(
                    Decoded,
                    try std.math.mul(Decoded, decoded, 10),
                    c - '0',
                );
            },
            '_' => {},
            else => if (@import("builtin").mode == .Debug)
                std.debug.panic("invalid unsigned integer {s}", .{token})
            else
                unreachable,
        };
    }

    return std.math.cast(T, decoded) orelse error.Overflow;
}

pub fn signedInteger(comptime T: type, token: []const u8) error{Overflow}!T {
    comptime {
        std.debug.assert(@typeInfo(T).int.signedness == .signed);
    }

    std.debug.assert(token.len > 0);
    std.debug.assert(token[0] != '_');
    std.debug.assert(token[token.len - 1] != '_');

    const digits: []const u8 = switch (token[0]) {
        '+', '-' => token[1..],
        '0'...'9', 'a'...'f', 'A'...'F' => token,
        else => unreachable,
    };

    const magnitude = @as(
        std.meta.Int(.signed, @typeInfo(T).int.bits + 1),
        try unsignedInteger(std.meta.Int(.unsigned, @typeInfo(T).int.bits), digits),
    );

    const value = switch (token[0]) {
        '-' => -magnitude,
        else => magnitude,
    };

    return std.math.cast(T, value) orelse return error.Overflow;
}

pub fn uninterpretedInteger(comptime T: type, token: []const u8) error{Overflow}!T {
    const bit_width = @typeInfo(T).int.bits;
    const signed_value = try signedInteger(std.meta.Int(.signed, bit_width + 1), token);

    const Unsigned = std.meta.Int(.unsigned, bit_width);
    const Signed = std.meta.Int(.signed, bit_width);

    return if (signed_value >= 0)
        @bitCast(std.math.cast(Unsigned, signed_value) orelse return error.Overflow)
    else
        @bitCast(std.math.cast(Signed, signed_value) orelse return error.Overflow);
}

pub fn float(comptime F: type, token: []const u8) error{InvalidNanPayload}!floating_point.Bits(F) {
    comptime switch (F) {
        f32, f64 => {},
        else => @compileError("unsupported float type: " ++ @typeName(F)),
    };

    std.debug.assert(token.len > 0);

    if (token.len >= 3 and std.mem.indexOfScalar(u8, token[0..@min(token.len, 4)], 'n') != null) {
        const f: struct { digits: []const u8, sign: u1 } = switch (token[0]) {
            '+' => .{
                .digits = token[1..],
                .sign = 0,
            },
            '-' => .{
                .digits = token[1..],
                .sign = 1,
            },
            else => .{
                .digits = token,
                .sign = 0,
            },
        };

        std.debug.assert(f.digits.len >= 3);

        if (std.mem.eql(u8, "inf", f.digits)) {
            return floating_point.inf(F, f.sign);
        } else if (std.mem.eql(u8, "nan", f.digits[0..3])) {
            if (f.digits.len == 3) {
                return floating_point.canonicalNan(F, f.sign);
            } else {
                std.debug.assert(f.digits[3] == ':');
                const payload_digits = f.digits[4..];
                const payload = unsignedInteger(floating_point.Mantissa(F), payload_digits) catch |e| switch (e) {
                    error.Overflow => return error.InvalidNanPayload,
                };

                if (payload == 0) return error.InvalidNanPayload; // infinity

                return floating_point.infOrNan(F, f.sign, payload);
            }
        } else {
            unreachable;
        }
    }

    // Zig' floating point parser works with the same syntax used in WASM.
    const f: F = std.fmt.parseFloat(F, token) catch |e| switch (e) {
        error.InvalidCharacter => unreachable,
    };

    return @bitCast(f);
}

pub const StringEscape = union(enum) {
    literal: []const u8,
    escaped: Sequence,

    pub const Sequence = std.BoundedArray(u8, 4);

    pub fn bytes(esc: *const StringEscape) []const u8 {
        const result: []const u8 = switch (esc.*) {
            .literal => |lit| lit,
            .escaped => |*b| b.slice(),
        };

        std.debug.assert(result.len > 0);
        return result;
    }

    pub const Iterator = struct {
        remaining: []const u8,
        /// At the end of iteration, this is set to `false` if a hexadecimal escape sequence is encountered at any point.
        guaranteed_valid_utf8: bool,

        pub fn next(iter: *Iterator) ?StringEscape {
            const literal_start = std.mem.indexOfScalar(u8, iter.remaining, '\\') orelse {
                if (iter.remaining.len > 0) {
                    const full = iter.remaining;
                    iter.remaining = iter.remaining[iter.remaining.len..];
                    return .{ .literal = full };
                } else {
                    return null;
                }
            };

            if (literal_start > 0) {
                const b = iter.remaining[0..literal_start];
                iter.remaining = iter.remaining[literal_start..];
                return .{ .literal = b };
            }

            var seq = Sequence{};
            switch (iter.remaining[1]) {
                't' => {
                    iter.remaining = iter.remaining[2..];
                    seq.append('\t') catch unreachable;
                },
                'n' => {
                    iter.remaining = iter.remaining[2..];
                    seq.append('\n') catch unreachable;
                },
                'r' => {
                    iter.remaining = iter.remaining[2..];
                    seq.append('\r') catch unreachable;
                },
                '\"', '\'', '\\' => |c| {
                    iter.remaining = iter.remaining[2..];
                    seq.append(c) catch unreachable;
                },
                // Hexadecimal escape.
                '0'...'9', 'a'...'f', 'A'...'F' => |upper_digit| {
                    iter.guaranteed_valid_utf8 = false;

                    const b = (@as(u8, hexDigitValue(upper_digit)) << 4) | hexDigitValue(iter.remaining[2]);
                    iter.remaining = iter.remaining[3..];
                    seq.append(b) catch unreachable;
                },
                // Unicode escape.
                'u' => {
                    iter.remaining = iter.remaining[3..];
                    const closing_bracket = std.mem.indexOfScalar(u8, iter.remaining, '}') orelse unreachable;
                    const digits = iter.remaining[0..closing_bracket];

                    const code_point = code_point: {
                        var char: u21 = 0;
                        for (digits) |d| if (d != '_') {
                            char = (char << 4) | hexDigitValue(d);
                        };

                        break :code_point char;
                    };

                    const buf_len = std.unicode.utf8CodepointSequenceLength(code_point) catch unreachable;
                    const buf = seq.addManyAsSlice(buf_len) catch unreachable;
                    const written = std.unicode.utf8Encode(code_point, buf) catch unreachable;
                    std.debug.assert(written == buf_len);

                    iter.remaining = iter.remaining[closing_bracket + 1 ..];
                },
                else => unreachable,
            }

            return .{ .escaped = seq };
        }

        pub fn allocPrint(iter: Iterator, allocator: std.mem.Allocator) error{OutOfMemory}!std.ArrayListUnmanaged(u8) {
            var iterator = iter;

            var buf = std.ArrayListUnmanaged(u8).empty;
            errdefer buf.deinit(allocator);

            while (iterator.next()) |escape| {
                const append = escape.bytes();
                if (iterator.remaining.len == 0) {
                    // Last escape sequence.
                    try buf.ensureTotalCapacityPrecise(
                        allocator,
                        std.math.add(
                            usize,
                            buf.items.len,
                            append.len,
                        ) catch return error.OutOfMemory,
                    );

                    buf.appendSliceAssumeCapacity(append);
                } else {
                    try buf.appendSlice(allocator, append);
                }
            }

            return buf;
        }
    };
};

/// Iterates over the contents of a string, translating escape sequences.
///
/// When parsing string literal tokens, as an optimization callers can check if
/// any escape sequences are even present.
pub fn string(contents: []const u8) StringEscape.Iterator {
    if (contents.len > 0) {
        std.debug.assert(contents[0] != '\"');
        std.debug.assert(contents[contents.len - 1] != '\"');
    }

    return StringEscape.Iterator{
        .remaining = contents,
        .guaranteed_valid_utf8 = true,
    };
}

test unsignedInteger {
    try std.testing.expectEqual(32, unsignedInteger(u32, "32"));
    try std.testing.expectEqual(0, unsignedInteger(u64, "000"));
    try std.testing.expectEqual(1000, unsignedInteger(u64, "1000"));
    try std.testing.expectEqual(32, unsignedInteger(u32, "0x20"));
    try std.testing.expectEqual(0xABBA, unsignedInteger(u64, "0xABBA"));
    try std.testing.expectEqual(0, unsignedInteger(u64, "0x0___0"));
    try std.testing.expectEqual(123_456, unsignedInteger(u64, "123_456"));
    try std.testing.expectEqual(std.math.maxInt(u32), unsignedInteger(u32, "0xFFFF_FFFF"));
    try std.testing.expectError(error.Overflow, unsignedInteger(u32, "0x1_FFFF_FFFF"));
}

test signedInteger {
    try std.testing.expectEqual(32, signedInteger(i32, "32"));
    try std.testing.expectEqual(-5, signedInteger(i32, "-5"));
    try std.testing.expectEqual(123, signedInteger(i32, "+123"));
    try std.testing.expectEqual(0xABBA, signedInteger(i64, "0xABBA"));
    try std.testing.expectEqual(std.math.maxInt(i32), signedInteger(i32, "2_147_483_647"));
    try std.testing.expectEqual(std.math.minInt(i32), signedInteger(i32, "-2_147_483_648"));
    try std.testing.expectEqual(std.math.minInt(i32), signedInteger(i32, "-0x8000_0000"));
    try std.testing.expectError(error.Overflow, signedInteger(i32, "-0xFFFF_FFFF"));
    try std.testing.expectError(error.Overflow, signedInteger(i32, "-0x8000_0001"));
}

test float {
    try std.testing.expectEqual(0x4049_0FDB, float(f32, "3.14159265"));
    try std.testing.expectEqual(0xBF99_999A, float(f32, "-1.2"));
    try std.testing.expectEqual(0, float(f32, "+0.00"));
    try std.testing.expectEqual(0x8000_0000, float(f32, "-0"));

    try std.testing.expectEqual(0x4F2B_BABB, float(f32, "0xABBA_BABA"));
    try std.testing.expectEqual(0x4491_A228, float(f32, "0x1234.45P-2"));

    try std.testing.expectEqual(0x7F80_0000, float(f32, "inf"));
    try std.testing.expectEqual(0xFF80_0000, float(f32, "-inf"));
    try std.testing.expectEqual(0x7FC0_0000, float(f32, "nan"));
    try std.testing.expectEqual(0xFFC0_0000, float(f32, "-nan"));
    try std.testing.expectEqual(0x7F80_CAFE, float(f32, "nan:0xCAFE"));
}

test string {
    const test_case = struct {
        fn run(input: [:0]const u8, expected: [:0]const u8) !void {
            var buf = try string(input).allocPrint(std.testing.allocator);
            defer buf.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings(expected, buf.items);
        }
    };

    try test_case.run("hello", "hello");
    try test_case.run(
        \\w\6Frld
    , "world");
    try test_case.run(
        \\\u{1F600}
    , "\u{1F600}");
    try test_case.run(
        \\one\u{20}line\ntwo\20line
    , "one line\ntwo line");
}
