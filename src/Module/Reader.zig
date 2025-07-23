const Reader = @This();

bytes: *[]const u8,

pub const NoEofError = error{EndOfStream};

pub const Error = error{
    /// An error occurred while parsing the WebAssembly module.
    MalformedWasm,
} || NoEofError;

pub const LimitError = error{
    /// See <https://webassembly.github.io/spec/core/appendix/implementation.html>.
    WasmImplementationLimit,
};

pub const ParseError = error{
    /// The input did not start with the WebAssembly preamble.
    NotWasm,
    InvalidWasm,
} || Reader.Error || LimitError || std.mem.Allocator.Error;

pub fn init(bytes: *[]const u8) Reader {
    return .{ .bytes = bytes };
}

pub fn isEmpty(reader: Reader) bool {
    return reader.bytes.len == 0;
}

pub fn expectEndOfStream(reader: Reader) Error!void {
    if (!reader.isEmpty()) return error.MalformedWasm;
}

pub fn readAssumeLength(reader: Reader, len: usize) []const u8 {
    const skipped = reader.bytes.*[0..len];
    reader.bytes.* = reader.bytes.*[len..];
    return skipped;
}

pub fn read(reader: Reader, len: usize) NoEofError![]const u8 {
    if (reader.bytes.len < len) return error.EndOfStream;
    return reader.readAssumeLength(len);
}

pub fn readArray(reader: Reader, comptime len: usize) NoEofError!*const [len]u8 {
    const s = try reader.read(len);
    return s[0..len];
}

pub fn readByte(reader: Reader) NoEofError!u8 {
    if (reader.isEmpty()) return error.EndOfStream;
    return (try reader.readArray(1))[0];
}

pub fn readByteTag(reader: Reader, comptime Tag: type) Error!Tag {
    comptime {
        std.debug.assert(@bitSizeOf(@typeInfo(Tag).@"enum".tag_type) <= 8);
    }

    return std.meta.intToEnum(Tag, try reader.readByte()) catch |e| switch (e) {
        std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
    };
}

pub fn readUleb128(reader: Reader, comptime T: type) Error!T {
    return std.leb.readUleb128(T, reader) catch |e| switch (e) {
        error.Overflow => Reader.Error.MalformedWasm,
        NoEofError.EndOfStream => |eof| eof,
    };
}

pub fn readUleb128Casted(reader: Reader, comptime T: type, comptime U: type) (Error || LimitError)!U {
    comptime std.debug.assert(@bitSizeOf(U) < @bitSizeOf(T));
    return std.math.cast(U, try reader.readUleb128(T)) orelse LimitError.WasmImplementationLimit;
}

pub fn readUleb128Enum(reader: Reader, comptime T: type, comptime E: type) Error!E {
    return std.meta.intToEnum(E, try reader.readUleb128(T)) catch |e| switch (e) {
        std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
    };
}

pub fn readIleb128(reader: Reader, comptime T: type) Error!T {
    return std.leb.readIleb128(T, reader) catch |e| switch (e) {
        error.Overflow => Reader.Error.MalformedWasm,
        NoEofError.EndOfStream => |eof| eof,
    };
}

pub fn readByteVec(reader: Reader) Error![]const u8 {
    const len = try reader.readUleb128(u32);
    return reader.read(len);
}

pub fn readName(reader: Reader) Error!std.unicode.Utf8View {
    const contents = try reader.readByteVec();
    return if (std.unicode.utf8ValidateSlice(contents))
        .{ .bytes = contents }
    else
        error.MalformedWasm;
}

pub fn readIdx(reader: Reader, comptime I: type, bounds: anytype) !I {
    const idx = try reader.readUleb128(u32);
    const len = switch (@typeInfo(@TypeOf(bounds))) {
        .@"struct" => bounds.len,
        .int => bounds,
        else => @compileError(@typeName(@TypeOf(bounds)) ++ " cannot be used as index bounds"),
    };

    return if (idx < len)
        @enumFromInt(std.math.cast(@typeInfo(I).@"enum".tag_type, idx) orelse return error.WasmImplementationLimit)
    else
        error.InvalidWasm;
}

const std = @import("std");
const ValType = @import("val_type.zig").ValType;
