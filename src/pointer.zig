//! Type-safe abstractions for reading from 32-bit `MemInst`s.

// caution: big endian code is untested
const native_endian = builtin.cpu.arch.endian();

const Constness = enum { @"const", mut };

fn Bytes(comptime constness: Constness, comptime T: type) type {
    const size = @sizeOf(T);
    return switch (constness) {
        .mut => *align(1) [size]u8,
        .@"const" => *align(1) const [size]u8,
    };
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

const TaggedUnion = struct {
    Type: type,
    Payload: type,
    Tag: type,

    fn tagBytes(
        comptime u: TaggedUnion,
        comptime constness: Constness,
        bytes: Bytes(constness, u.Type),
    ) Bytes(constness, u.Tag) {
        const tag_offset = @offsetOf(u.Type, "tag");
        return bytes[tag_offset..(tag_offset + @sizeOf(u.Tag))];
    }

    fn payloadBytes(
        comptime u: TaggedUnion,
        comptime constness: Constness,
        bytes: Bytes(constness, u.Type),
    ) Bytes(constness, u.Payload) {
        const payload_offset = @offsetOf(u.Type, "payload");
        return bytes[payload_offset..(payload_offset + @sizeOf(u.Payload))];
    }

    fn ChosenPayload(comptime u: TaggedUnion, comptime tag: u.Tag) type {
        return @FieldType(u.Payload, @tagName(tag));
    }

    fn chosenPayloadBytes(
        comptime u: TaggedUnion,
        comptime tag: u.Tag,
        comptime constness: Constness,
        payload_bytes: Bytes(constness, u.Payload),
    ) Bytes(constness, u.ChosenPayload(tag)) {
        return payload_bytes[0..@sizeOf(u.ChosenPayload(tag))];
    }

    fn matches(comptime T: type) ?TaggedUnion {
        if (!@hasField(T, "payload") or @typeInfo(T.Payload) != .@"union") {
            return null;
        }

        const Tag = @FieldType(T, "tag");
        switch (@typeInfo(Tag)) {
            .@"enum" => {},
            else => |bad| @compileError(
                @typeName(T) ++ ".Tag is a " ++ @tagName(bad) ++ ", not an enum",
            ),
        }

        return TaggedUnion{ .Type = T, .Payload = T.Payload, .Tag = Tag };
    }
};

pub fn readFromBytes(
    comptime T: type,
    bytes: Bytes(.@"const", T),
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
                if (TaggedUnion.matches(T)) |tagged_union| {
                    const tag = readFromBytes(
                        tagged_union.Tag,
                        tagged_union.tagBytes(.@"const", bytes),
                    );

                    const payload_bytes = tagged_union.payloadBytes(.@"const", bytes);
                    switch (tag) {
                        inline else => |actual_tag| {
                            break :result T{
                                .tag = tag,
                                .payload = @unionInit(
                                    T.Payload,
                                    @tagName(actual_tag),
                                    readFromBytes(
                                        tagged_union.ChosenPayload(actual_tag),
                                        tagged_union.chosenPayloadBytes(
                                            tag,
                                            .@"const",
                                            payload_bytes,
                                        ),
                                    ),
                                ),
                            };
                        },
                    }
                } else {
                    var result: T = undefined;
                    inline for (structFields(T)) |f| {
                        const field_bytes = bytes[f.offset..][0..@sizeOf(f.type)];
                        @field(result, f.name) = readFromBytes(f.type, field_bytes);
                    }
                    break :result result;
                }
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

pub fn writeToBytes(
    comptime T: type,
    bytes: Bytes(.mut, T),
    value: T,
) void {
    if (@sizeOf(T) * 8 != @bitSizeOf(T)) {
        @compileError("bit size of " ++ @typeName(T) ++ " must be multiple of a byte");
    }

    switch (@typeInfo(T)) {
        .int => std.mem.writeInt(T, bytes, value, .little),
        .@"enum" => |enumeration| writeToBytes(enumeration.tag_type, bytes, @intFromEnum(value)),
        .@"struct" => |structure| switch (structure.layout) {
            .@"packed" => writeToBytes(structure.backing_integer.?, bytes, @bitCast(value)),
            .@"extern" => if (TaggedUnion.matches(T)) |tagged_union| {
                writeToBytes(
                    tagged_union.Tag,
                    tagged_union.tagBytes(.mut, bytes),
                    value.tag,
                );

                const payload_bytes = tagged_union.payloadBytes(.mut, bytes);
                switch (value.tag) {
                    inline else => |actual_tag| {
                        writeToBytes(
                            tagged_union.ChosenPayload(actual_tag),
                            tagged_union.chosenPayloadBytes(actual_tag, .mut, payload_bytes),
                            @field(value.payload, @tagName(actual_tag)),
                        );
                    },
                }
            } else {
                inline for (structFields(T)) |f| {
                    const field_bytes = bytes[f.offset..][0..@sizeOf(f.type)];
                    writeToBytes(f.type, field_bytes, @field(value, f.name));
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

fn typeName(comptime T: type) [:0]const u8 {
    return if (@typeInfo(T) != .@"struct" or
        !std.mem.startsWith(u8, @typeName(T), "pointer") or
        @typeInfo(T).@"struct".layout != .@"packed" or
        !@hasDecl(T, "Pointee") or !@hasDecl(T, "read") or !@hasDecl(T, "constCast"))
        @typeName(T)
    else
        "*" ++ (if (@hasDecl(T, "write")) "" else "const ") ++ typeName(T.Pointee);
}

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

        pub fn write(ptr: Self, mem: *const MemInst, value: T) OobError!void {
            return writeToBytes(T, try accessArray(mem, ptr.addr, @sizeOf(T)), value);
        }

        pub fn format(ptr: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print(typeName(T) ++ "@{X:0>8}", .{ptr.addr});
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

        pub fn bytes(slice: Self) []u8 {
            return @ptrCast(slice.items);
        }

        pub fn constCast(slice: Self) ConstSlice(T) {
            return .{ .items = slice.items };
        }

        pub fn write(slice: Self, idx: usize, value: T) void {
            writeToBytes(T, &slice.items[idx], value);
        }
    };
}

pub fn ConstSlice(comptime T: type) type {
    return struct {
        items: []align(1) const [@sizeOf(T)]u8,

        const Self = @This();

        pub fn init(mem: *const MemInst, ptr: ConstPointer(T), len: usize) OobError!Self {
            return (try Slice(T).init(mem, ptr.constCast(), len)).constCast();
        }

        pub fn bytes(slice: Self) []const u8 {
            return @ptrCast(slice.items);
        }

        pub fn read(slice: Self, idx: usize) T {
            return readFromBytes(T, &slice.items[idx]);
        }
    };
}

const std = @import("std");
const builtin = @import("builtin");
const MemInst = @import("runtime/memory.zig").MemInst;
