const Reader = @This();

bytes: *[]const u8,

pub const Error = error{
    /// An error occurred while parsing the WebAssembly module.
    MalformedWasm,
};

pub const LimitError = error{
    /// See <https://webassembly.github.io/spec/core/appendix/implementation.html>.
    WasmImplementationLimit,
};

pub const ValidationError = error{
    /// A validation error occurred after parsing the WebAssembly module.
    InvalidWasm,
};

pub const Diagnostics = struct {
    output: ?*std.Io.Writer,

    pub const none = Diagnostics{ .output = null };

    pub fn init(output: *std.Io.Writer) Diagnostics {
        return .{ .output = output };
    }

    pub const Kind = enum {
        parse,
        validation,

        pub fn Error(comptime kind: Kind) type {
            return switch (kind) {
                .parse => Reader.Error,
                .validation => ValidationError,
            };
        }

        pub fn value(comptime kind: Kind) kind.Error() {
            return switch (kind) {
                .parse => Reader.Error.MalformedWasm,
                .validation => ValidationError.InvalidWasm,
            };
        }
    };

    pub fn writeAll(diag: Diagnostics, comptime kind: Kind, message: []const u8) kind.Error() {
        @branchHint(.cold);
        if (diag.output) |output| output.writeAll(message) catch {};
        return kind.value();
    }

    pub fn print(
        diag: Diagnostics,
        comptime kind: Kind,
        comptime fmt: []const u8,
        args: anytype,
    ) kind.Error() {
        @branchHint(.cold);
        if (diag.output) |output| output.print(fmt, args) catch {};
        return kind.value();
    }
};

pub fn init(bytes: *[]const u8) Reader {
    return .{ .bytes = bytes };
}

pub fn isEmpty(reader: Reader) bool {
    return reader.bytes.len == 0;
}

pub fn expectEnd(reader: Reader, diag: Diagnostics, desc: []const u8) Error!void {
    if (!reader.isEmpty()) {
        return diag.print(
            .parse,
            "{} bytes were remaining: {s}",
            .{ reader.bytes.len, desc },
        );
    }
}

pub fn readAssumeLength(reader: Reader, len: usize) []const u8 {
    const skipped = reader.bytes.*[0..len];
    reader.bytes.* = reader.bytes.*[len..];
    return skipped;
}

pub fn read(reader: Reader, len: usize, diag: Diagnostics, desc: []const u8) Error![]const u8 {
    if (reader.bytes.len < len) {
        return diag.print(
            .parse,
            "expected {} bytes for {s}, but {} bytes were remaining",
            .{ len, desc, reader.bytes.len },
        );
    }

    return reader.readAssumeLength(len);
}

pub fn readArray(
    reader: Reader,
    comptime len: usize,
    diag: Diagnostics,
    desc: []const u8,
) Error!*const [len]u8 {
    const s = try reader.read(len, diag, desc);
    return s[0..len];
}

pub fn readByte(reader: Reader, diag: Diagnostics, desc: []const u8) Error!u8 {
    return (try reader.readArray(1, diag, desc))[0];
}

pub fn readByteTag(
    reader: Reader,
    comptime Tag: type,
    diag: Diagnostics,
    desc: []const u8,
) Error!Tag {
    comptime {
        std.debug.assert(@bitSizeOf(@typeInfo(Tag).@"enum".tag_type) <= 8);
    }

    const byte = try reader.readByte(diag, desc);
    return std.meta.intToEnum(Tag, byte) catch |e| switch (e) {
        std.meta.IntToEnumError.InvalidEnumTag => diag.print(
            .parse,
            "invalid {s}: 0x{X:0>2}",
            .{ desc, byte },
        ),
    };
}

pub fn readUleb128(reader: Reader, comptime T: type, diag: Diagnostics, desc: []const u8) Error!T {
    const max_byte_len = comptime std.math.divCeil(u16, @typeInfo(T).int.bits, 7) catch unreachable;
    const Value = std.meta.Int(
        .unsigned,
        7 * max_byte_len,
    );

    const suffix = " LEB128 encoded " ++ @typeName(T) ++ ": {s}";

    var value: Value = 0;
    for (0..max_byte_len) |i| {
        if (reader.isEmpty()) {
            return diag.print(.parse, "unexpected end of" ++ suffix, .{desc});
        }

        const byte = reader.readAssumeLength(1)[0];

        value |= @shlExact(
            @as(Value, byte & 0x7F),
            @as(std.math.Log2Int(Value), @intCast(i * 7)),
        );

        if (byte & 0x80 == 0) break;
    } else return diag.print(.parse, "integer representation too long for" ++ suffix, .{desc});

    return std.math.cast(T, value) orelse
        diag.print(.parse, "integer too large for" ++ suffix, .{desc});
}

pub fn readUleb128Casted(
    reader: Reader,
    comptime T: type,
    comptime U: type,
    diag: Diagnostics,
    desc: []const u8,
) (Error || LimitError)!U {
    comptime std.debug.assert(@bitSizeOf(U) < @bitSizeOf(T));
    return std.math.cast(U, try reader.readUleb128(T, diag, desc)) orelse
        LimitError.WasmImplementationLimit;
}

pub fn readUleb128Enum(
    reader: Reader,
    comptime T: type,
    comptime E: type,
    diag: Diagnostics,
    desc: []const u8,
) Error!E {
    const value = try reader.readUleb128(T, diag, desc);
    return std.meta.intToEnum(E, value) catch |e| switch (e) {
        std.meta.IntToEnumError.InvalidEnumTag => diag.print(
            .parse,
            "invalid {s}: {}",
            .{ desc, value },
        ),
    };
}

pub fn readIleb128(reader: Reader, comptime T: type, diag: Diagnostics, desc: []const u8) Error!T {
    const max_byte_len = comptime std.math.divCeil(u16, @typeInfo(T).int.bits, 7) catch unreachable;
    const Value = std.meta.Int(
        .signed,
        7 * max_byte_len,
    );

    const suffix = " LEB128 encoded " ++ @typeName(T) ++ ": {s}";

    var value: Value = 0;
    for (0..max_byte_len) |i| {
        if (reader.isEmpty()) {
            return diag.print(.parse, "unexpected end of" ++ suffix, .{desc});
        }

        const byte = reader.readAssumeLength(1)[0];

        const shift: std.math.Log2Int(Value) = @intCast(i * 7);
        value |= @shlExact(@as(Value, byte & 0x7F), shift);

        if (byte & 0x80 == 0) {
            if (i < max_byte_len - 1 and (byte & 0x40) != 0) {
                // Sign extension is needed, fills the rest of the bits with ones
                value |= std.math.shl(Value, -1, shift);
            }

            break;
        }
    } else return diag.print(.parse, "integer representation too long for" ++ suffix, .{desc});

    return std.math.cast(T, value) orelse
        return diag.print(.parse, "integer too large for" ++ suffix, .{desc});
}

pub fn readByteVec(reader: Reader, diag: Diagnostics, desc: []const u8) Error![]const u8 {
    const len = try reader.readUleb128(u32, diag, "bytes length");
    return reader.read(len, diag, desc);
}

pub fn readName(reader: Reader, diag: Diagnostics) Error!std.unicode.Utf8View {
    const contents = try reader.readByteVec(diag, "name");
    return if (std.unicode.utf8ValidateSlice(contents))
        .{ .bytes = contents }
    else
        diag.writeAll(.parse, "malformed UTF-8 encoding");
}

pub fn readIdx(
    reader: Reader,
    comptime I: type,
    len: usize,
    diag: Diagnostics,
    oob_desc: []const u8,
) !I {
    const idx = try reader.readUleb128(u32, diag, @typeName(I));
    return if (idx < len)
        @enumFromInt(
            std.math.cast(@typeInfo(I).@"enum".tag_type, idx) orelse
                return error.WasmImplementationLimit,
        )
    else
        diag.print(.validation, "invalid index {}: {s}", .{ idx, oob_desc });
}

const std = @import("std");
const ValType = @import("val_type.zig").ValType;
