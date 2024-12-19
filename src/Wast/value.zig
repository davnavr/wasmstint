//! Parsing of values in the WebAssembly [grammar].
//!
//! These are intended to parse the contents of a `Lexer.Token`.
//!
//! [grammar]: https://webassembly.github.io/spec/core/text/values.html

const std = @import("std");

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
    std.debug.assert(token[token.len - 1] != '_');

    // Round number of bits up to a multiple of 8.
    const Decoded = std.meta.Int(.unsigned, ((@typeInfo(T).int.bits + 7) / 8) * 8);
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
            else => unreachable,
        };
    }

    return std.math.cast(T, decoded) orelse error.Overflow;
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

        pub const AllocPrint = union(enum) {
            allocated: std.ArrayListUnmanaged(u8),
            original: []const u8,

            pub fn deinit(print: *AllocPrint, allocator: std.mem.Allocator) void {
                switch (print.*) {
                    .original => {},
                    .allocated => |*buf| buf.deinit(allocator),
                }

                print.* = undefined;
            }

            pub fn bytes(print: *const AllocPrint) []const u8 {
                return switch (print.*) {
                    .original => |s| s,
                    .allocated => |*buf| buf.items,
                };
            }
        };

        pub fn allocPrint(iter: Iterator, allocator: std.mem.Allocator) error{OutOfMemory}!AllocPrint {
            var iterator = iter;

            const first = iterator.next() orelse return .{ .original = iterator.remaining };
            const second = iterator.next();

            if (first == .literal and second == null) {
                return .{ .original = first.literal };
            }

            var buf = try std.ArrayListUnmanaged(u8).initCapacity(
                allocator,
                std.math.add(
                    usize,
                    first.bytes().len,
                    if (second != null) second.?.bytes().len else 0,
                ) catch return error.OutOfMemory,
            );
            errdefer buf.deinit(allocator);

            buf.appendSliceAssumeCapacity(first.bytes());

            if (second) |second_escape|
                buf.appendSliceAssumeCapacity(second_escape.bytes());

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

            return .{ .allocated = buf };
        }
    };
};

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

test string {
    const test_case = struct {
        fn run(input: [:0]const u8, expected: [:0]const u8) !void {
            var print = try string(input).allocPrint(std.testing.allocator);
            defer print.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings(expected, print.bytes());
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
