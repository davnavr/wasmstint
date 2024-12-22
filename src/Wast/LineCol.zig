//! Represents a line and column number.

const std = @import("std");
const Offset = @import("Lexer.zig").Offset;

/// 1-based line number.
line: u32,
/// 1-based column number.
col: u32,

const LineCol = @This();

pub fn format(loc: LineCol, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    try writer.print("{}:{}", .{ loc.line, loc.col });
}

pub const FromOffset = struct {
    prev_line: ?struct {
        /// Offset to the byte after the end of the newline sequence.
        offset: usize,
        line: u32,
    },
    src: []const u8,

    pub fn locate(lookup: *FromOffset, target: usize) error{Overflow}!LineCol {
        var loc = LineCol{ .line = 1, .col = 1 };
        var offset: usize = 0;

        if (lookup.prev_line) |prev_line| {
            if (target >= prev_line.offset) {
                offset = prev_line.offset;
                loc.line = prev_line.line;
            }
        }

        // This probably handles `\r\n` sequences correctly, but that has not been tested.
        while (std.mem.indexOfScalarPos(u8, lookup.src, offset, '\n')) |next_line| {
            if (next_line <= target) {
                offset = next_line + 1;
                loc.line += 1;
                lookup.prev_line = .{ .offset = offset, .line = loc.line };
            } else {
                break;
            }
        }

        loc.col = std.math.cast(u32, target - offset + 1) orelse return error.Overflow;
        return loc;
    }

    pub fn init(src: []const u8) FromOffset {
        return .{ .prev_line = null, .src = src };
    }

    test locate {
        var find = FromOffset.init(
            \\(module
            \\  (func (result i32)
            \\    i32.const 2)
            \\
            \\  (global i32 (i32.const 5))
            \\)
            \\
        );

        const tests = [_]struct { expected: LineCol, input: usize }{
            .{ .expected = .{ .line = 1, .col = 1 }, .input = 0 },
            .{ .expected = .{ .line = 2, .col = 4 }, .input = 11 },
            .{ .expected = .{ .line = 2, .col = 17 }, .input = 24 },
            .{ .expected = .{ .line = 3, .col = 15 }, .input = 43 },

            // Caching of previous locations shouldn't cause incorrect results.
            .{ .expected = .{ .line = 2, .col = 17 }, .input = 24 },
            .{ .expected = .{ .line = 1, .col = 2 }, .input = 1 },
            .{ .expected = .{ .line = 1, .col = 4 }, .input = 3 },
        };

        for (tests) |t| {
            const actual = result: {
                errdefer std.debug.print("expected {}\n", .{t.expected});
                break :result try find.locate(t.input);
            };

            if (!std.meta.eql(t.expected, actual)) {
                std.debug.print(
                    "expected {any}, got {any} for offset {} ('{c}')\n",
                    .{ t.expected, actual, t.input, find.src[t.input] },
                );

                return error.TestUnexpectedResult;
            }
        }
    }
};

test {
    _ = FromOffset;
}
