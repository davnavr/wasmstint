const std = @import("std");
const Allocator = std.mem.Allocator;

const Module = @This();

header: *const Header align(@alignOf(usize)),

fn FieldOffset(comptime Pointee: type) type {
    return enum(u16) {
        zero = 0,
        _,

        const Self = @This();

        fn byteOffset(offset: Self) u18 {
            return @intFromEnum(offset) << 4;
        }

        fn slice(offset: Self, header: *const Header, len: usize) []const Pointee {
            // TODO
            // const base = @as(*align(@alignOf(usize)) const u8, header) + @sizeOf(Header); // @alignCast // : *align(some_align) const u8
            _ = offset;
            _ = header;
            _ = len;
            unreachable;
        }
    };
}

const Header = struct {
    wasm: []const u8,
    num_globals_imported: u16,
    num_globals_defined: u16,
    //globals: FieldOffset(Global),
};

const wasm_preamble = "\x00asm\x01\x00\x00\x00";

pub const NoEofError = error{EndOfStream};
pub const ReaderError = error{
    /// An error occurred while parsing the WebAssembly module.
    MalformedWasm,
} || NoEofError;

const Reader = struct {
    bytes: *[]const u8,

    const Error = ReaderError;

    fn isEmpty(reader: Reader) bool {
        return reader.bytes.len == 0;
    }

    fn readAssumeLength(reader: Reader, len: usize) []const u8 {
        const skipped = reader.bytes.*[0..len];
        reader.bytes.* = reader.bytes.*[len..];
        return skipped;
    }

    fn read(reader: Reader, len: usize) NoEofError![]const u8 {
        if (reader.bytes.len < len) return error.EndOfStream;
        return reader.readAssumeLength(len);
    }

    fn readArray(reader: Reader, comptime len: usize) NoEofError![len]u8 {
        return (try reader.read(len))[0..len];
    }

    fn readByte(reader: Reader) NoEofError!u8 {
        if (reader.isEmpty()) return error.EndOfStream;
        return (try reader.readArray(1))[0];
    }

    fn readByteTag(reader: Reader, comptime Tag: type) Error!Tag {
        comptime {
            std.debug.assert(@bitSizeOf(@typeInfo(Tag).@"enum".tag_type) <= 8);
        }

        return std.meta.intToEnum(Tag, try reader.readByte()) catch |e| switch (e) {
            std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
        };
    }

    fn readUleb128(reader: Reader, comptime T: type) Error!T {
        return std.leb.readUleb128(T, reader) catch |e| switch (e) {
            error.Overflow => ReaderError.MalformedWasm,
            NoEofError.EndOfStream => |eof| eof,
        };
    }

    fn readByteVec(reader: Reader) Error![]const u8 {
        const len = try reader.readUleb128(u32);
        return reader.read(len);
    }

    fn readName(reader: Reader) Error!std.unicode.Utf8View {
        const contents = try reader.readByteVec();
        return if (std.unicode.utf8ValidateSlice(contents)) contents else error.MalformedWasm;
    }
};

pub const ParseError = error{
    /// The input did not start with the WebAssembly preamble.
    NotWasm,
    InvalidWasm,
} || ReaderError || Allocator.Error;

pub fn parse(
    allocator: Allocator,
    wasm: *[]const u8,
    scratch: Allocator,
) ParseError!Module {
    if (!std.mem.startsWith(u8, wasm.*, wasm_preamble))
        return ParseError.NotWasm;

    const wasm_reader = Reader{ .bytes = wasm };
    _ = wasm_reader.readArray(wasm_preamble.len);

    const SectionId = enum(u8) {
        type = 1,
        import = 2,
        func = 3,
        table = 4,
        mem = 5,
        global = 6,
        @"export" = 7,
        start = 8,
        elem = 9,
        data_count = 12,
        code = 10,
        data = 11,
    };

    const SectionOrder: type = order: {
        var fields: [@typeInfo(SectionId).@"enum".fields.len + 1]std.builtin.Type.EnumField = undefined;
        for (@typeInfo(SectionId).@"enum".fields, 0..) |f, i| {
            fields[i] = .{ .name = f.name, .value = i };
        }
        fields[fields.len - 1] = .{ .name = "custom", .value = fields.len - 1 };

        break :order @Type(.{
            .@"enum" = std.builtin.Type.Enum{
                .tag_type = std.math.IntFittingRange(0, fields.len),
                .is_exhaustive = true,
                .decls = &[0]std.builtin.Type.Declaration{},
                .fields = &fields,
            },
        });
    };

    const KnownSections: type = @Type(.{
        .@"struct" = std.builtin.Type.Struct{
            .layout = .auto,
            .decls = &[0]std.builtin.Type.Declaration{},
            .is_tuple = false,
            .fields = fields: {
                var fields: [@typeInfo(SectionId).@"enum".fields.len]std.builtin.Type.StructField = undefined;
                for (@typeInfo(SectionId).@"enum".fields, 0..) |f, i| {
                    fields[i] = std.builtin.Type.StructField{
                        .name = f.name,
                        .type = []const u8,
                        .default_value = &@as([0]u8{}, []const u8),
                        .is_comptime = false,
                        .alignment = 0,
                    };
                }
                break :fields fields;
            },
        },
    });

    var section_order = SectionOrder.type;
    var known_sections = KnownSections{};

    while (@as(?u8, wasm_reader.readByte() catch null)) |id_byte| {
        const id = std.meta.intToEnum(SectionId, id_byte) catch |e| switch (e) {
            std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
        };

        const section_contents = try wasm_reader.readByteVec();

        switch (id) {
            .custom => {
                const section_name = try wasm_reader.readName();
                _ = section_name;
                // Capture any custom sections (e.g. "name") here.
            },
            inline else => |known_id| {
                const id_order = @field(SectionOrder, @tagName(known_id));
                if (@intFromEnum(section_order) >= @intFromEnum(id_order)) {
                    return error.MalformedWasm;
                }

                section_order = id_order;
                @field(known_sections, @tagName(known_id)) = section_contents;
            },
        }
    }

    std.debug.assert(wasm_reader.isEmpty());
    wasm_reader = undefined;

    _ = allocator;
    _ = scratch;
    undefined;
}
