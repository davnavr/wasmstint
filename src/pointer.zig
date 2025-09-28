//! Type-safe abstractions for reading from 32-bit `MemInst`s.

// caution: big endian code is untested
const native_endian = builtin.cpu.arch.endian();

fn ConstBytes(comptime T: type) type {
    return *align(1) const [@sizeOf(T)]u8;
}

const StructField = struct {
    name: []const u8,
    offset: comptime_int,
    type: type,

    fn Array(comptime T: type) type {
        return [@typeInfo(T).@"struct".fields.len]StructField;
    }
};

fn structFields(comptime T: type) StructField.Array(T) {
    var all_fields: StructField.Array(T) = undefined;
    for (@typeInfo(T).@"struct".fields, &all_fields) |src, *f| {
        f.* = .{
            .name = src.name,
            .offset = @offsetOf(T, src.name),
            .type = src.type,
        };
    }

    return all_fields;
}

pub fn readFromBytes(
    comptime T: type,
    bytes: ConstBytes(T),
) T {
    if (@sizeOf(T) * 8 != @bitSizeOf(T)) {
        @compileError("bit size of " ++ @typeName(T) ++ " must be multiple of a byte");
    }

    return switch (@typeInfo(T)) {
        .int => std.mem.readInt(T, bytes, .little),
        .@"enum" => |enumeration| if (enumeration.is_exhaustive)
            @compileError("unsupported exhaustive enum " ++ @typeName(T))
        else
            @enumFromInt(readFromBytes(enumeration.tag_type, bytes)),
        .@"struct" => |structure| switch (structure.layout) {
            .@"packed" => @bitCast(readFromBytes(structure.backing_integer.?, bytes)),
            .@"extern" => result: {
                var result: T = undefined;
                inline for (structFields(T)) |f| {
                    const field_bytes = bytes[f.offset..][0..@sizeOf(f.type)];
                    @field(result, f.name) = readFromBytes(f.type, field_bytes);
                }
                break :result result;
            },
            .auto => @compileError(
                "struct " ++ @typeName(T) ++ " needs packed or extern layout",
            ),
        },
        else => |bad| @compileError("unsupported " ++ @tagName(bad) ++ " " ++ @typeName(T)),
    };
}

test readFromBytes {
    try std.testing.expectEqual(0xABCD, readFromBytes(u16, "\xCD\xAB"));

    const PackedStruct = packed struct(u32) { value: u32 };

    try std.testing.expectEqual(
        PackedStruct{ .value = 0x12345678 },
        readFromBytes(PackedStruct, "\x78\x56\x34\x12"),
    );
}

fn Bytes(comptime T: type) type {
    return *align(1) [@sizeOf(T)]u8;
}

pub fn writeFromBytes(
    comptime T: type,
    bytes: Bytes(T),
    value: T,
) void {
    if (@sizeOf(T) * 8 != @bitSizeOf(T)) {
        @compileError("bit size of " ++ @typeName(T) ++ " must be multiple of a byte");
    }

    switch (@typeInfo(T)) {
        .int => std.mem.writeInt(T, bytes, value, .little),
        .@"enum" => |enumeration| if (enumeration.is_exhaustive)
            @compileError("unsupported exhaustive enum " ++ @typeName(T))
        else
            writeFromBytes(enumeration.tag_type, bytes, @intFromEnum(value)),
        .@"struct" => |structure| switch (structure.layout) {
            .@"packed" => writeFromBytes(structure.backing_integer.?, bytes, @bitCast(value)),
            .@"extern" => {
                inline for (structFields(T)) |f| {
                    const field_bytes = bytes[f.offset..][0..@sizeOf(f.type)];
                    writeFromBytes(f.type, field_bytes, @field(value, f.name));
                }
            },
            .auto => @compileError(
                "struct " ++ @typeName(T) ++ " needs packed or extern layout",
            ),
        },
        else => |bad| @compileError("unsupported " ++ @tagName(bad) ++ " " ++ @typeName(T)),
    }
}

pub const OobError = MemInst.OobError;

pub fn accessSlice(mem: *const MemInst, addr: usize, size: usize) OobError![]u8 {
    if (addr >= mem.size) {
        return error.MemoryAccessOutOfBounds;
    }

    const remainder = mem.bytes()[addr..];
    if (size >= remainder.len) {
        return error.MemoryAccessOutOfBounds;
    }

    return remainder[0..size];
}

pub fn accessArray(mem: *const MemInst, addr: usize, comptime size: usize) OobError!*[size]u8 {
    return (try accessSlice(mem, addr, size))[0..size];
}

// Could parameterize to support 64-bit pointers.

pub fn Pointer(comptime T: type) type {
    return packed struct(u32) {
        addr: u32,

        const Self = @This();

        pub const Pointee = T;
        pub const Const = ConstPointer(T);

        pub fn constCast(ptr: Self) Const {
            return .{ .addr = ptr.addr };
        }

        pub fn read(ptr: Self, mem: *const MemInst) OobError!T {
            return ptr.constCast().read(mem);
        }

        pub fn bytes(ptr: Self, mem: *const MemInst) OobError!Bytes(T) {
            return accessArray(mem, ptr.addr, @sizeOf(T));
        }

        pub fn format(ptr: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print(@typeName(T) ++ "@{X:0>8}", .{ptr.addr});
        }
    };
}

pub fn ConstPointer(comptime T: type) type {
    return packed struct(u32) {
        addr: u32,

        const Self = @This();

        pub const Pointee = T;

        pub fn constCast(ptr: Self) Pointer(T) {
            return .{ .addr = ptr.addr };
        }

        pub fn read(ptr: Self, mem: *const MemInst) OobError!T {
            return readFromBytes(T, try accessArray(mem, ptr.addr, @sizeOf(T)));
        }

        pub fn format(ptr: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            return ptr.constCast().format(writer);
        }
    };
}

pub fn Slice(comptime T: type) type {
    return struct {
        items: []align(1) [@sizeOf(T)]u8,

        const Self = @This();

        pub fn init(mem: *const MemInst, ptr: Pointer(T), len: usize) OobError!Self {
            return .{ .items = @ptrCast(try accessSlice(mem, ptr.addr, len * @sizeOf(T))) };
        }
    };
}

pub fn ConstSlice(comptime T: type) type {
    return struct {
        items: []align(1) const [@sizeOf(T)]u8,

        const Self = @This();

        pub fn init(mem: *const MemInst, ptr: ConstPointer(T), len: usize) OobError!Self {
            return .{ .items = (try Slice(T).init(mem, ptr.constCast(), len)).items };
        }

        pub fn read(slice: Self, idx: usize) T {
            return readFromBytes(T, &slice.items[idx]);
        }
    };
}

const std = @import("std");
const builtin = @import("builtin");
const MemInst = @import("runtime/memory.zig").MemInst;
