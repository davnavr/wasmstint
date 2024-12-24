//! Breaks a stream of UTF-8 *characters* (code points) into a sequence of `Token`s according
//! to the [WebAssembly lexical format].
//!
//! [WebAssembly lexical format]: https://webassembly.github.io/spec/core/text/lexical.html#tokens

const std = @import("std");
const opcodes = @import("../opcodes.zig");

utf8: std.unicode.Utf8Iterator,

const Lexer = @This();

/// Byte offsets into UTF-8 source code.
pub const Offset = struct {
    start: usize,
    end: usize,
};

pub const Token = struct {
    /// Refers to the first byte and the byte after the last byte of the token.
    offset: Offset,
    /// Indicates what kind of token was parsed.
    ///
    /// - `reserved`: Used for malformed and nonsensical syntax.
    /// - `id`: Used for symbolic [*identifiers*] in place of numeric WebAssembly indices.
    ///   - The `start` index points to the starting `$` character.
    /// - `string`, `string_raw`: Used for string literals known to be guaranteed valid UTF-8 or
    ///     containing a hexadecimal escape respectively.
    ///   - The `start` and `end` indices refer to the opening and closing quotation marks (`"`) respectively.
    /// - `unexpected_eof`: Used for block comments or string literals missing a closing `;)` or quotation mark (`"`).
    ///
    /// [*identifiers*]: https://webassembly.github.io/spec/core/text/values.html#text-id
    tag: Tag,

    const keywords_list = [_][:0]const u8{
        // Based on this grammar:
        // https://github.com/WebAssembly/spec/blob/d52e42df1314521c6e4cd7331593f2901e1d7b43/interpreter/README.md#s-expression-syntax
        "i32",
        "i64",
        "f32",
        "f64",
        "v128",
        "func",
        "extern",
        "funcref",
        "externref",
        "result",
        "type",
        "mut",

        // These are treated as `keyword_unknown`.
        // "offset=",
        // "align=",
        // `nan:0x`, // keyword only when sign is omitted

        "export",
        "import",
        "param",
        "local",
        "global",
        "table",
        "elem",
        "declare",
        "offset",
        "item",
        "memory",
        "data",
        "start",
        "module",

        "register",
        "binary",
        "quote",
        "invoke",
        "get",

        "assert_return",
        "assert_trap",
        "assert_exhaustion",
        "assert_malformed",
        "assert_invalid",
        "assert_unlinkable",
        "inf",
        "nan",
        "nan:canonical",
        "nan:arithmetic",

        // 'meta' commands are not supported
        // "script",
        // "input",
        // "output",

        // Keywords corresponding to opcodes are concatenated next.
    } ++ byte_opcode: {
        const byte_opcode_cases = @typeInfo(opcodes.ByteOpcode).@"enum".fields;
        var names: [byte_opcode_cases.len - 1][:0]const u8 = undefined;
        var names_idx = 0;
        for (byte_opcode_cases) |case| {
            if (case.value == @intFromEnum(opcodes.ByteOpcode.@"0xFC")) continue;
            names[names_idx] = case.name;
            names_idx += 1;
        }
        std.debug.assert(names_idx == names.len);
        break :byte_opcode names;
    };

    const non_keyword_tags = [_][:0]const u8{
        "reserved",
        "open_paren",
        "close_paren",
        "id",
        "string",
        "string_raw",
        "float",
        "integer",
        "unexpected_eof",
        "keyword_unknown",
    };

    pub const Tag: type = @Type(std.builtin.Type{ .@"enum" = .{
        .is_exhaustive = true,
        .tag_type = u16,
        .decls = &[0]std.builtin.Type.Declaration{},
        .fields = cases: {
            var cases: [keywords_list.len + non_keyword_tags.len]std.builtin.Type.EnumField = undefined;
            var cases_idx = 0;
            for (non_keyword_tags) |tag| {
                cases[cases_idx] = .{ .name = tag, .value = cases_idx };
                cases_idx += 1;
            }
            for (keywords_list) |keyword| {
                cases[cases_idx] = .{ .name = "keyword_" ++ keyword, .value = cases_idx };
                cases_idx += 1;
            }
            break :cases &cases;
        },
    } });

    const keyword_lookup = std.static_string_map.StaticStringMap(Tag).initComptime(kvs: {
        var entries: [keywords_list.len]struct { []const u8, Tag } = undefined;
        for (&entries, keywords_list) |*entry, keyword|
            entry.* = .{ keyword, @field(Tag, "keyword_" ++ keyword) };
        break :kvs entries;
    });

    pub fn contents(token: *const Token, src: []const u8) []const u8 {
        return src[token.offset.start..][0..token.offset.end];
    }
};

pub fn initUtf8(utf8: std.unicode.Utf8Iterator) Lexer {
    return Lexer{ .utf8 = utf8 };
}

pub fn init(s: []const u8) error{InvalidUtf8}!Lexer {
    return Lexer.initUtf8((try std.unicode.Utf8View.init(s)).iterator());
}

fn isIdChar(c: u8) bool {
    return switch (c) {
        '0'...'9',
        'A'...'Z',
        'a'...'z',
        '!',
        '#'...'\'',
        '*',
        '+',
        '-',
        '.',
        '/',
        ':',
        '<'...'@',
        '\\',
        '^',
        '_',
        '`',
        '|',
        '~',
        => true,
        else => false,
    };
}

fn remainingInputStartsWith(lexer: *const Lexer, match: []const u8) bool {
    return match.len <= lexer.utf8.bytes.len and
        lexer.utf8.i <= lexer.utf8.bytes.len - match.len and
        std.mem.eql(u8, match, lexer.utf8.bytes[lexer.utf8.i..][0..match.len]);
}

/// Reads the next token, skipping any sequences of [*white space*] including comments.
///
/// If there are no more tokens remaining, returns `null`.
///
/// [*white space*]: https://webassembly.github.io/spec/core/text/lexical.html#white-space
pub fn next(lexer: *Lexer) ?Token {
    const State = enum {
        start,
        open_paren,
        semicolon,
        string,
        id_or_keyword,
        sign,
        digits,
        hexadecimal_number,
        line_comment,
        block_comment,
        reserved,
        end,
    };

    var token: Token = undefined;
    state: switch (State.start) {
        .start => {
            if (lexer.utf8.i == lexer.utf8.bytes.len) {
                @branchHint(.unlikely);
                return null;
            }

            token.offset.start = lexer.utf8.i;
            switch (lexer.utf8.bytes[lexer.utf8.i]) {
                // Either a block comment start or an opening parenthesis.
                '(' => {
                    lexer.utf8.i += 1;
                    continue :state .open_paren;
                },
                ')' => {
                    lexer.utf8.i += 1;
                    token.tag = .close_paren;
                    break :state;
                },
                ';' => {
                    lexer.utf8.i += 1;
                    continue :state .semicolon;
                },
                '$' => {
                    token.tag = .id;
                    lexer.utf8.i += 1;
                    continue :state .id_or_keyword;
                },
                'a'...'z' => {
                    token.tag = .keyword_unknown;
                    lexer.utf8.i += 1;
                    continue :state .id_or_keyword;
                },
                // Whitespace
                ' ', '\t', '\n', '\r' => if (lexer.utf8.i < lexer.utf8.bytes.len) {
                    lexer.utf8.i += 1;
                    continue :state .start;
                } else return null,
                '\"' => {
                    token.tag = .string;
                    lexer.utf8.i += 1;
                    continue :state .string;
                },
                '0'...'9' => {
                    lexer.utf8.i += 1;
                    continue :state .digits;
                },
                '+', '-' => {
                    lexer.utf8.i += 1;
                    continue :state .sign;
                },
                // Non-ASCII characters are not allowed outside of string literals or comments.
                else => |b| {
                    lexer.utf8.i += std.unicode.utf8ByteSequenceLength(b) catch unreachable;
                    continue :state .reserved;
                },
            }

            comptime unreachable;
        },
        .open_paren => if (lexer.remainingInputStartsWith(";")) {
            lexer.utf8.i += 1;
            continue :state .block_comment;
        } else {
            token.tag = .open_paren;
        },
        .semicolon => if (lexer.remainingInputStartsWith(";")) {
            lexer.utf8.i += 1;
            continue :state .line_comment;
        } else {
            continue :state .reserved;
        },
        .line_comment => {
            while (lexer.utf8.nextCodepoint()) |c| switch (c) {
                '\n', '\r' => continue :state .start,
                else => {},
            };

            return null;
        },
        .block_comment => {
            // Overflow can't occur, as it would imply an input size that exceeds the address space size.
            var nesting_level: usize = 1;

            while (nesting_level > 0 and lexer.utf8.i < lexer.utf8.bytes.len) {
                switch (lexer.utf8.bytes[lexer.utf8.i]) {
                    ';' => {
                        lexer.utf8.i += 1;

                        // Check for close parenthesis of comment.
                        if (lexer.remainingInputStartsWith(")")) {
                            lexer.utf8.i += 1;
                            nesting_level -= 1;
                        }
                    },
                    '(' => {
                        lexer.utf8.i += 1;

                        // Check for start of a nested comment.
                        if (lexer.remainingInputStartsWith(";")) {
                            lexer.utf8.i += 1;
                            nesting_level += 1;
                        }
                    },
                    else => |b| lexer.utf8.i += std.unicode.utf8ByteSequenceLength(b) catch unreachable,
                }
            }

            if (nesting_level > 0) {
                token.tag = .unexpected_eof;
            } else {
                continue :state .start;
            }
        },
        .id_or_keyword => {
            std.debug.assert(token.tag == .id or token.tag == .keyword_unknown);

            while (lexer.utf8.i < lexer.utf8.bytes.len) {
                if (isIdChar(lexer.utf8.bytes[lexer.utf8.i]))
                    lexer.utf8.i += 1
                else
                    break;
            }

            continue :state .end;
        },
        .string => while (lexer.utf8.nextCodepoint()) |c| {
            switch (c) {
                '\\' => {
                    const esc_c = lexer.utf8.nextCodepoint() orelse {
                        token.tag = .unexpected_eof;
                        continue :state .end;
                    };

                    switch (esc_c) {
                        't', 'n', 'r', '\"', '\'', '\\' => {},
                        'u' => {
                            if (lexer.utf8.nextCodepoint() != '{')
                                continue :state .reserved;

                            const digits_start = lexer.utf8.i;
                            const digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                                switch (lexer.utf8.bytes[lexer.utf8.i]) {
                                    '0'...'9', 'a'...'f', 'A'...'F', '_' => lexer.utf8.i += 1,
                                    '}' => {
                                        lexer.utf8.i += 1;
                                        break lexer.utf8.i;
                                    },
                                    else => |b| {
                                        lexer.utf8.i += std.unicode.utf8ByteSequenceLength(b) catch unreachable;
                                        continue :state .reserved;
                                    },
                                }
                            } else continue :state .reserved; // Missing closing bracket.

                            // Check for leading or trailing underscores.
                            const digits = lexer.utf8.bytes[digits_start..digits_end];
                            if (digits.len == 0 or (digits[0] == '_' or digits[digits.len - 1] == '_'))
                                continue :state .reserved;

                            const code_point = std.fmt.parseUnsigned(u21, digits, 16) catch |e| switch (e) {
                                error.InvalidCharacter => unreachable,
                                error.Overflow => continue :state .reserved,
                            };

                            if ((0xD800 <= code_point and code_point < 0xE000) or 0x110000 <= code_point)
                                continue :state .reserved;
                        },
                        // Hexadecimal escape sequence.
                        '0'...'9', 'a'...'f', 'A'...'F' => {
                            const second_digit = lexer.utf8.nextCodepoint() orelse continue :state .reserved;
                            switch (second_digit) {
                                '0'...'9', 'a'...'f', 'A'...'F' => token.tag = .string_raw,
                                else => continue :state .reserved,
                            }
                        },
                        // Invalid escape sequence
                        else => continue :state .reserved,
                    }
                },
                '\"' => switch (token.tag) {
                    .string, .string_raw => continue :state .end,
                    else => unreachable,
                },
                else => {},
            }
        } else {
            token.tag = .unexpected_eof;
        },
        .digits => if (lexer.remainingInputStartsWith("x")) {
            lexer.utf8.i += 1;
            continue :state .hexadecimal_number;
        } else {
            // Handles both integers and floats.

            // Parse the integer component `d`.
            const int_digits = digits: {
                const int_digits_start = lexer.utf8.i;
                const int_digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                    switch (lexer.utf8.bytes[lexer.utf8.i]) {
                        '0'...'9', '_' => lexer.utf8.i += 1,
                        else => break lexer.utf8.i,
                    }
                } else lexer.utf8.i;

                break :digits lexer.utf8.bytes[int_digits_start..int_digits_end];
            };

            // Leading digit already parsed, ensuring no leading underscore.
            if (int_digits.len > 0 and int_digits[int_digits.len - 1] == '_')
                continue :state .reserved;

            token.tag = .integer;

            // Parse the fraction component `q`.
            if (lexer.utf8.i < lexer.utf8.bytes.len and lexer.utf8.bytes[lexer.utf8.i] == '.') {
                token.tag = .float;
                lexer.utf8.i += 1;

                const frac_digits_start = lexer.utf8.i;
                const frac_digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                    switch (lexer.utf8.bytes[lexer.utf8.i]) {
                        '0'...'9', '_' => lexer.utf8.i += 1,
                        else => break lexer.utf8.i,
                    }
                } else lexer.utf8.i;

                // Fraction can be empty.
                const frac_digits = lexer.utf8.bytes[frac_digits_start..frac_digits_end];
                if (frac_digits.len > 0 and (frac_digits[0] == '_' or frac_digits[frac_digits.len - 1] == '_'))
                    continue :state .reserved;
            }

            // Parse the exponent component `e`.
            if (lexer.utf8.i < lexer.utf8.bytes.len and
                (lexer.utf8.bytes[lexer.utf8.i] == 'e' or lexer.utf8.bytes[lexer.utf8.i] == 'E'))
            {
                token.tag = .float;
                lexer.utf8.i += 1;

                // Sign is optional here.
                if (lexer.utf8.i < lexer.utf8.bytes.len and
                    (lexer.utf8.bytes[lexer.utf8.i] == '+' or lexer.utf8.bytes[lexer.utf8.i] == '-'))
                    lexer.utf8.i += 1;

                // Parse the exponent value, which is in base-10.
                const exp_digits_start = lexer.utf8.i;
                const exp_digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                    switch (lexer.utf8.bytes[lexer.utf8.i]) {
                        '0'...'9', '_' => lexer.utf8.i += 1,
                        else => break lexer.utf8.i,
                    }
                } else lexer.utf8.i;

                const exp_digits = lexer.utf8.bytes[exp_digits_start..exp_digits_end];
                if (exp_digits.len == 0 or (exp_digits[0] == '_' or exp_digits[exp_digits.len - 1] == '_'))
                    continue :state .reserved;
            }

            continue :state .end;
        },
        .hexadecimal_number => {
            // Handles both integers and floats.

            // Parse the integer component `p`.
            const int_digits = digits: {
                const int_digits_start = lexer.utf8.i;
                const int_digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                    switch (lexer.utf8.bytes[lexer.utf8.i]) {
                        '0'...'9', 'a'...'f', 'A'...'F', '_' => lexer.utf8.i += 1,
                        else => break lexer.utf8.i,
                    }
                } else lexer.utf8.i;

                break :digits lexer.utf8.bytes[int_digits_start..int_digits_end];
            };

            // Leading digit already parsed, ensuring no leading underscore.
            if (int_digits.len > 0 and int_digits[int_digits.len - 1] == '_')
                continue :state .reserved;

            token.tag = .integer;

            // Parse the fraction component `q`.
            if (lexer.utf8.i < lexer.utf8.bytes.len and lexer.utf8.bytes[lexer.utf8.i] == '.') {
                token.tag = .float;
                lexer.utf8.i += 1;

                const frac_digits_start = lexer.utf8.i;
                const frac_digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                    switch (lexer.utf8.bytes[lexer.utf8.i]) {
                        '0'...'9', 'a'...'f', 'A'...'F', '_' => lexer.utf8.i += 1,
                        else => break lexer.utf8.i,
                    }
                } else lexer.utf8.i;

                // Fraction can be empty.
                const frac_digits = lexer.utf8.bytes[frac_digits_start..frac_digits_end];
                if (frac_digits.len > 0 and (frac_digits[0] == '_' or frac_digits[frac_digits.len - 1] == '_'))
                    continue :state .reserved;
            }

            // Parse the exponent component `e`.
            if (lexer.utf8.i < lexer.utf8.bytes.len and
                (lexer.utf8.bytes[lexer.utf8.i] == 'p' or lexer.utf8.bytes[lexer.utf8.i] == 'P'))
            {
                token.tag = .float;
                lexer.utf8.i += 1;

                // Sign is optional here.
                if (lexer.utf8.i < lexer.utf8.bytes.len and
                    (lexer.utf8.bytes[lexer.utf8.i] == '+' or lexer.utf8.bytes[lexer.utf8.i] == '-'))
                    lexer.utf8.i += 1;

                // Parse the exponent value, which is in base-10.
                const exp_digits_start = lexer.utf8.i;
                const exp_digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                    switch (lexer.utf8.bytes[lexer.utf8.i]) {
                        '0'...'9', '_' => lexer.utf8.i += 1,
                        else => break lexer.utf8.i,
                    }
                } else lexer.utf8.i;

                const exp_digits = lexer.utf8.bytes[exp_digits_start..exp_digits_end];
                if (exp_digits.len == 0 or (exp_digits[0] == '_' or exp_digits[exp_digits.len - 1] == '_'))
                    continue :state .reserved;
            }

            continue :state .end;
        },
        .sign => if (lexer.remainingInputStartsWith("inf")) {
            token.tag = .float;
            lexer.utf8.i += 3;
            continue :state .end;
        } else if (lexer.remainingInputStartsWith("nan")) {
            token.tag = .float;
            lexer.utf8.i += 3;

            if (lexer.remainingInputStartsWith(":0x")) {
                lexer.utf8.i += 3;
                const payload_digits_start = lexer.utf8.i;
                const payload_digits_end = while (lexer.utf8.i < lexer.utf8.bytes.len) {
                    switch (lexer.utf8.bytes[lexer.utf8.i]) {
                        '0'...'9', 'a'...'f', 'A'...'F', '_' => lexer.utf8.i += 1,
                        else => break lexer.utf8.i,
                    }
                } else lexer.utf8.i;

                const payload_digits = lexer.utf8.bytes[payload_digits_start..payload_digits_end];
                if (payload_digits.len == 0 or (payload_digits[0] == '_' or payload_digits[payload_digits.len - 1] == '_'))
                    continue :state .reserved;
            }

            continue :state .end;
        } else {
            // Parse a leading zero to allow hexadecimal processing to occur
            if (lexer.remainingInputStartsWith("0")) {
                lexer.utf8.i += 1;
            }

            continue :state .digits;
        },
        .reserved => {
            token.tag = .reserved;
            while (lexer.utf8.i < lexer.utf8.bytes.len) {
                switch (lexer.utf8.bytes[lexer.utf8.i]) {
                    '(', ')', ' ', '\t', '\n', '\r' => break :state,
                    ';' => if (lexer.utf8.i + 1 < lexer.utf8.bytes.len and lexer.utf8.bytes[lexer.utf8.i + 1] == ';') {
                        break :state;
                    } else {
                        lexer.utf8.i += 1;
                    },
                    else => |b| lexer.utf8.i += std.unicode.utf8ByteSequenceLength(b) catch unreachable,
                }
            }
        },
        .end => {
            std.debug.assert(token.tag != .reserved);
            if (lexer.utf8.i < lexer.utf8.bytes.len) {
                switch (lexer.utf8.bytes[lexer.utf8.i]) {
                    '(', ')', ' ', '\t', '\n', '\r' => break :state,
                    ';' => if (lexer.utf8.i + 1 < lexer.utf8.bytes.len and lexer.utf8.bytes[lexer.utf8.i + 1] == ';')
                        break :state
                    else {
                        lexer.utf8.i += 1;
                        continue :state .reserved;
                    },
                    else => |b| {
                        lexer.utf8.i += std.unicode.utf8ByteSequenceLength(b) catch unreachable;
                        continue :state .reserved;
                    },
                }

                comptime unreachable;
            }
        },
    }

    token.offset.end = lexer.utf8.i;
    std.debug.assert(token.offset.start < token.offset.end);
    std.debug.assert(token.offset.start <= lexer.utf8.bytes.len);
    std.debug.assert(token.offset.end <= lexer.utf8.bytes.len);

    if (token.tag == .keyword_unknown) {
        std.debug.assert(token.offset.end > token.offset.start);
        if (Token.keyword_lookup.get(lexer.utf8.bytes[token.offset.start..token.offset.end])) |keyword|
            token.tag = keyword;
    }

    return token;
}

fn lexerSuccessfulTest(input: [:0]const u8, expected: []const ?Token) !void {
    var lexer = try Lexer.init(input);
    for (expected, 0..) |tok, i| {
        const actual = lexer.next();
        std.testing.expectEqual(tok, actual) catch |e| {
            std.debug.print(
                "mismatch for token {}: expected {?}, got {?}\n",
                .{ i, tok, actual },
            );
            return e;
        };
    }
}

test "all token types" {
    try lexerSuccessfulTest(
        "()$hello \"world\" 0xABCD\t3.14\r\n42 (; hello ;) keyword   +nan:0x3 -0x80",
        &[_]?Token{
            .{ .offset = .{ .start = 0, .end = 1 }, .tag = Token.Tag.open_paren },
            .{ .offset = .{ .start = 1, .end = 2 }, .tag = .close_paren },
            .{ .offset = .{ .start = 2, .end = 8 }, .tag = .id },
            .{ .offset = .{ .start = 9, .end = 16 }, .tag = .string },
            .{ .offset = .{ .start = 17, .end = 23 }, .tag = .integer },
            .{ .offset = .{ .start = 24, .end = 28 }, .tag = .float },
            .{ .offset = .{ .start = 30, .end = 32 }, .tag = .integer },
            .{ .offset = .{ .start = 45, .end = 52 }, .tag = .keyword_unknown },
            .{ .offset = .{ .start = 55, .end = 63 }, .tag = .float },
            .{ .offset = .{ .start = 64, .end = 69 }, .tag = .integer },
            null,
        },
    );
}

test "keywords" {
    try lexerSuccessfulTest(
        "module i32.const",
        &[_]?Token{
            .{ .offset = .{ .start = 0, .end = 6 }, .tag = .keyword_module },
            .{ .offset = .{ .start = 7, .end = 16 }, .tag = .@"keyword_i32.const" },
            null,
        },
    );
}
