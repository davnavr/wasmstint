//! Iterates over commands to execute within a WebAssembly specification test JSON script file.
//!
//! See https://github.com/WebAssembly/wabt/blob/main/docs/wast2json.md

const Parser = @This();

source_filename: []const u8,
command_count: usize,
scanner: json.Scanner,
diagnostics: json.Diagnostics,
state: State,
command_lookup: std.StringHashMapUnmanaged(Command.Type.LookupKey),
value_lookup: std.StringHashMapUnmanaged(Command.ValueLookupKey),
lane_type_lookup: std.StringHashMapUnmanaged(Command.LaneType),

const State = enum { more, finished };

//// Leftover from previous attempt that tried streaming without knowing nextAlloc was unusable.
// fn handleBufferUnderrun(parser: *Parser, reader: *Reader) error{ReadFailed}!void {
//     reader.tossBuffered();
//     reader.fillMore() catch |e| switch (e) {
//         error.ReadFailed => |failed| return failed,
//         error.EndOfStream => {
//             parser.scanner.endInput();
//             return;
//         },
//     };
//     parser.scanner.feedInput(reader.buffered());
// }

pub const Error = Oom || error{MalformedJson};

fn nextToken(parser: *Parser, arena: *ArenaAllocator) Error!json.Token {
    return parser.scanner.nextAlloc(arena.allocator(), .alloc_if_needed) catch |e| switch (e) {
        Oom.OutOfMemory => |oom| return oom,
        error.ValueTooLong => return Oom.OutOfMemory,
        error.SyntaxError, error.UnexpectedEndOfInput => return error.MalformedJson,
    };
}

fn expectNextToken(
    parser: *Parser,
    expected: @typeInfo(json.Token).@"union".tag_type.?,
) Error!void {
    var empty_buf: [0]u8 = .{};
    var empty_buffer = std.heap.FixedBufferAllocator.init(&empty_buf);
    var arena = ArenaAllocator.init(empty_buffer.allocator());

    const token = parser.nextToken(&arena) catch return error.MalformedJson;
    if (token != expected) {
        return error.MalformedJson; // wrong token type
    }
}

fn expectNextTokenString(parser: *Parser, arena: *ArenaAllocator) Error![]const u8 {
    return switch (try parser.nextToken(arena)) {
        .string, .allocated_string => |s| s,
        else => error.MalformedJson, // expected string
    };
}

fn expectNextTokenNameString(parser: *Parser, arena: *ArenaAllocator) Error!Name {
    const name = try expectNextTokenString(parser, arena);
    return if (name.len <= std.math.maxInt(u16))
        .init(name)
    else
        error.MalformedJson; // name string too long
}

fn expectNextTokenStringEql(
    parser: *Parser,
    scratch: *ArenaAllocator,
    expected: []const u8,
) Error!void {
    return switch (try parser.nextToken(scratch)) {
        .string, .allocated_string => |s| if (!std.mem.eql(u8, s, expected)) {
            return error.MalformedJson; // string does not match
        },
        else => error.MalformedJson, // expected string
    };
}

fn initEnumStringLookup(
    arena: *ArenaAllocator,
    comptime T: type,
) Oom!std.StringHashMapUnmanaged(T) {
    var map = std.StringHashMapUnmanaged(T).empty;

    const cases = comptime std.enums.values(T);
    try map.ensureTotalCapacity(arena.allocator(), comptime @intCast(cases.len));
    errdefer comptime unreachable;

    for (cases) |c| {
        map.putAssumeCapacityNoClobber(@tagName(c), c);
    }

    return map;
}

pub fn init(
    parser: *Parser,
    arena: *ArenaAllocator,
    input: std.unicode.Utf8View,
    scratch: *ArenaAllocator,
) Error!void {
    // Need pointer to `diagnostics` to be stable.
    parser.* = .{
        .source_filename = "error occurred before 'source_filename' could be parsed",
        .command_count = 0,
        .scanner = json.Scanner.initCompleteInput(arena.allocator(), input.bytes),
        .command_lookup = try initEnumStringLookup(arena, Command.Type.LookupKey),
        .value_lookup = try initEnumStringLookup(arena, Command.ValueLookupKey),
        .lane_type_lookup = try initEnumStringLookup(arena, Command.LaneType),
        .diagnostics = .{},
        .state = .more,
    };
    parser.scanner.enableDiagnostics(&parser.diagnostics);
    errdefer parser.state = .finished;

    // JSON technically is unordered, but spectest-interp reads fields in order too
    // This also allows streaming instead of reading the whole file at once
    try parser.expectNextToken(.object_begin);
    try parser.expectNextTokenStringEql(scratch, "source_filename");
    parser.source_filename =
        try parser.expectNextTokenString(arena); // source_filename must be a string.

    try parser.expectNextTokenStringEql(scratch, "commands");
    try parser.expectNextToken(.array_begin);
}

pub const Command = struct {
    line: usize,
    type: Type,

    pub const Type = union(enum) {
        module: Module,
        action: Action,
        assert_return: AssertReturn,
        assert_exhaustion: AssertWithMessage,
        assert_trap: AssertWithMessage,
        assert_invalid: AssertWithModule,
        assert_malformed: AssertWithModule,
        assert_uninstantiable: AssertWithModule,
        assert_unlinkable: AssertWithModule,
        register: Register,

        const LookupKey = @typeInfo(Type).@"union".tag_type.?;
    };

    fn skipExpectedArray(parser: *Parser, scratch: *ArenaAllocator) Error!void {
        // Not documented
        try parser.expectNextTokenStringEql(scratch, "expected");
        parser.scanner.skipValue() catch |e| switch (e) {
            Oom.OutOfMemory => |oom| return oom,
            error.SyntaxError, error.UnexpectedEndOfInput => return error.MalformedJson,
        };
    }

    fn parseInner(
        parser: *Parser,
        arena: *ArenaAllocator,
        command_type: Type.LookupKey,
        scratch: *ArenaAllocator,
    ) Error!Type {
        return switch (command_type) {
            .action => action: {
                const action = try Action.parseInner(parser, arena, scratch);
                try skipExpectedArray(parser, scratch);
                break :action .{ .action = action };
            },
            inline else => |tag| @unionInit(
                Type,
                @tagName(tag),
                try @FieldType(Type, @tagName(tag)).parseInner(parser, arena, scratch),
            ),
        };
    }

    pub const Module = struct {
        name: ?Name,
        /// Path to the module, relative to the JSON file.
        filename: [:0]const u8,

        fn parseInner(
            parser: *Parser,
            arena: *ArenaAllocator,
            scratch: *ArenaAllocator,
        ) Error!Module {
            const filename_or_name = try parser.expectNextTokenString(scratch);
            const name = if (std.mem.eql(u8, "name", filename_or_name)) name: {
                _ = scratch.reset(.retain_capacity);
                const module_name = try parser.expectNextTokenNameString(arena);
                try parser.expectNextTokenStringEql(scratch, "filename");
                break :name module_name;
            } else if (std.mem.eql(u8, "filename", filename_or_name))
                null
            else
                return error.MalformedJson; // expected name or filename

            _ = scratch.reset(.retain_capacity);
            const module_filename = try parser.expectNextTokenString(scratch);
            return .{
                .name = name,
                .filename = try arena.allocator().dupeZ(u8, module_filename),
            };
        }
    };

    pub const Const = union(enum) {
        i32: u32,
        i64: u64,
        f32: u32,
        f64: u64,
        funcref, // ?u32
        externref: ?u31,
        v128: V128,

        pub const Vec = []const Const;
    };

    const ValueLookupKey = @typeInfo(Const).@"union".tag_type.?;

    const LaneType = enum {
        i8,
        i16,
        i32,
        f32,
        i64,
        f64,

        fn size(ty: LaneType) u4 {
            return switch (ty) {
                .i8 => 1,
                .i16 => 2,
                .i32, .f32 => 4,
                .i64, .f64 => 8,
            };
        }
    };

    fn parseValueVec(
        parser: *Parser,
        arena: *ArenaAllocator,
        comptime T: type,
        temporary: *ArenaAllocator,
    ) Error![]const T {
        try parser.expectNextToken(.array_begin);
        var list = try std.ArrayList(T).initCapacity(temporary.allocator(), 1);
        var scratch = ArenaAllocator.init(temporary.allocator());
        defer _ = temporary.reset(.retain_capacity);

        while (true) {
            switch (try parser.nextToken(&scratch)) {
                .array_end => break,
                .object_end => unreachable,
                .object_begin => {},
                else => return error.MalformedJson, // value must be an object
            }
            _ = scratch.reset(.retain_capacity);

            try parser.expectNextTokenStringEql(&scratch, "type");
            _ = scratch.reset(.retain_capacity);
            const type_string = try parser.expectNextTokenString(&scratch);
            const type_tag = parser.value_lookup.get(type_string) orelse
                return error.MalformedJson; // bad value type
            _ = scratch.reset(.retain_capacity);

            const value: T = if (type_tag == .v128) v128: {
                try parser.expectNextTokenStringEql(&scratch, "lane_type");
                _ = scratch.reset(.retain_capacity);

                const lane_type_string = try parser.expectNextTokenString(&scratch);
                const lane_type_tag = parser.lane_type_lookup.get(lane_type_string) orelse
                    return error.MalformedJson; // bad lane type

                switch (lane_type_tag) {
                    inline else => |tag| {
                        try parser.expectNextTokenStringEql(&scratch, "value");
                        _ = scratch.reset(.retain_capacity);

                        const lane_type = comptime @field(LaneType, @tagName(tag));
                        const lane_count = comptime @divExact(@as(u5, 16), lane_type.size());
                        const lane_size = comptime 8 * @as(u16, lane_type.size());
                        const LaneInt = std.meta.Int(.signed, lane_size);

                        try parser.expectNextToken(.array_begin);
                        var lanes: [lane_count]LaneInt = undefined;
                        for (&lanes) |*lane_value| {
                            const value_string = try parser.expectNextTokenString(&scratch);
                            _ = scratch.reset(.retain_capacity);
                            lane_value.* = @bitCast(
                                std.fmt.parseInt(
                                    std.meta.Int(.unsigned, lane_size),
                                    value_string,
                                    10,
                                ) catch return error.MalformedJson, // bad lane value
                            );
                        }
                        try parser.expectNextToken(.array_end);

                        const interp = comptime V128.Interpretation.fromLaneType(LaneInt);
                        break :v128 if (T == Const)
                            T{ .v128 = V128.init(interp, lanes) }
                        else
                            @unionInit(T, interp.fieldName(), lanes);
                    },
                }
            } else value: {
                try parser.expectNextTokenStringEql(&scratch, "value");
                _ = scratch.reset(.retain_capacity);

                const value_string = try parser.expectNextTokenString(&scratch);
                switch (type_tag) {
                    .i32 => break :value T{
                        .i32 = std.fmt.parseInt(u32, value_string, 10) catch
                            return error.MalformedJson, // bad i32
                    },
                    .f32 => {
                        if (T == Expected) {
                            if (Expected.Nan.fromString(value_string)) |nan| {
                                break :value .{ .f32_nan = nan };
                            }
                        }

                        break :value .{
                            .f32 = std.fmt.parseInt(u32, value_string, 10) catch
                                return error.MalformedJson, // bad f32
                        };
                    },
                    .i64 => break :value T{
                        .i64 = std.fmt.parseInt(u64, value_string, 10) catch
                            return error.MalformedJson, // bad i64
                    },
                    .f64 => {
                        if (T == Expected) {
                            if (Expected.Nan.fromString(value_string)) |nan| {
                                break :value .{ .f64_nan = nan };
                            }
                        }

                        break :value .{
                            .f64 = std.fmt.parseInt(u64, value_string, 10) catch
                                return error.MalformedJson, // bad f64
                        };
                    },
                    .externref => break :value T{
                        .externref = if (std.mem.eql(u8, "null", value_string))
                            null
                        else
                            std.fmt.parseInt(u31, value_string, 10) catch
                                return error.MalformedJson, // bad externref number
                    },
                    .funcref => if (std.mem.eql(u8, "null", value_string))
                        break :value T.funcref
                    else
                        return error.MalformedJson, // only null funcref is allowed
                    .v128 => unreachable,
                }
            };

            try parser.expectNextToken(.object_end);
            try list.append(temporary.allocator(), value);
        }

        return arena.allocator().dupe(T, list.items);
    }

    pub const Action = struct {
        /// Which module to perform the action on, or `null` for the most recent module.
        module: ?Name,
        type: Action.Type,
        field: Name,

        pub const Type = union(enum) {
            invoke: struct { args: Const.Vec },
            get,
        };

        fn parseInner(
            parser: *Parser,
            arena: *ArenaAllocator,
            scratch: *ArenaAllocator,
        ) Error!Action {
            try parser.expectNextTokenStringEql(scratch, "action");
            _ = scratch.reset(.retain_capacity);

            try parser.expectNextToken(.object_begin);

            try parser.expectNextTokenStringEql(scratch, "type");
            _ = scratch.reset(.retain_capacity);

            const type_string = try parser.expectNextTokenString(scratch);
            _ = scratch.reset(.retain_capacity);

            const type_tag: @typeInfo(Action.Type).@"union".tag_type.? =
                if (std.mem.eql(u8, type_string, "invoke"))
                    .invoke
                else if (std.mem.eql(u8, type_string, "get"))
                    .get
                else
                    return error.MalformedJson;

            const module_or_field = try parser.expectNextTokenString(scratch);
            const module = if (std.mem.eql(u8, module_or_field, "module")) module: {
                _ = scratch.reset(.retain_capacity);
                const module_name = try parser.expectNextTokenNameString(arena);
                try parser.expectNextTokenStringEql(scratch, "field");
                break :module module_name;
            } else if (std.mem.eql(u8, module_or_field, "field"))
                null
            else
                return error.MalformedJson; // expected module or field

            _ = scratch.reset(.retain_capacity);
            const field = try parser.expectNextTokenNameString(arena);

            const kind: Action.Type = switch (type_tag) {
                .get => .get,
                .invoke => invoke: {
                    try parser.expectNextTokenStringEql(scratch, "args");
                    break :invoke .{
                        .invoke = .{
                            .args = try parseValueVec(parser, arena, Const, scratch),
                        },
                    };
                },
            };

            try parser.expectNextToken(.object_end);

            return .{ .module = module, .type = kind, .field = field };
        }
    };

    pub const Expected = union(enum) {
        i32: u32,
        i64: u64,
        f32: u32,
        f64: u64,
        f32_nan: Nan,
        f64_nan: Nan,
        funcref, // ?u32
        externref: ?u31,
        i8x16: @Vector(16, i8),
        i16x8: @Vector(8, i16),
        i32x4: @Vector(4, i32),
        f32x4: @Vector(4, f32),
        i64x2: @Vector(2, i64),
        f64x2: @Vector(2, f64),

        pub const Vec = []const Expected;

        pub const Nan = enum {
            canonical,
            arithmetic,

            fn fromString(s: []const u8) ?Nan {
                return if (std.mem.eql(u8, s, "nan:canonical"))
                    .canonical
                else if (std.mem.eql(u8, s, "nan:arithmetic"))
                    .arithmetic
                else
                    null;
            }
        };
    };

    pub const AssertReturn = struct {
        action: Action,
        expected: Expected.Vec,

        fn parseInner(
            parser: *Parser,
            arena: *ArenaAllocator,
            scratch: *ArenaAllocator,
        ) Error!AssertReturn {
            const action = try Action.parseInner(parser, arena, scratch);
            _ = scratch.reset(.retain_capacity);

            try parser.expectNextTokenStringEql(scratch, "expected");
            const expected = try parseValueVec(parser, arena, Expected, scratch);

            return .{ .action = action, .expected = expected };
        }
    };

    pub const AssertWithMessage = struct {
        action: Action,
        /// The error message to expect.
        text: Name,

        fn parseInner(
            parser: *Parser,
            arena: *ArenaAllocator,
            scratch: *ArenaAllocator,
        ) Error!AssertWithMessage {
            const action = try Action.parseInner(parser, arena, scratch);
            _ = scratch.reset(.retain_capacity);

            try parser.expectNextTokenStringEql(scratch, "text");
            const text = try parser.expectNextTokenNameString(arena);

            try skipExpectedArray(parser, scratch);

            return .{ .action = action, .text = text };
        }
    };

    pub const ModuleType = enum {
        binary,
        text,

        fn parseInner(parser: *Parser, scratch: *ArenaAllocator) Error!ModuleType {
            try parser.expectNextTokenStringEql(scratch, "module_type");
            const type_string = try parser.expectNextTokenString(scratch);
            return if (std.mem.eql(u8, "binary", type_string))
                .binary
            else if (std.mem.eql(u8, "text", type_string))
                .text
            else
                error.MalformedJson; // bad module type
        }
    };

    pub const AssertWithModule = struct {
        /// Path to the module, relative to the JSON file.
        filename: [:0]const u8,
        /// The error message to expect.
        text: Name,
        module_type: ModuleType,

        fn parseInner(
            parser: *Parser,
            arena: *ArenaAllocator,
            scratch: *ArenaAllocator,
        ) Error!AssertWithModule {
            try parser.expectNextTokenStringEql(scratch, "filename");
            _ = scratch.reset(.retain_capacity);
            const filename = try arena.allocator().dupeZ(
                u8,
                try parser.expectNextTokenString(scratch),
            );
            _ = scratch.reset(.retain_capacity);

            try parser.expectNextTokenStringEql(scratch, "text");
            _ = scratch.reset(.retain_capacity);
            const text = try parser.expectNextTokenNameString(arena);

            const module_type = try ModuleType.parseInner(parser, scratch);

            return .{ .filename = filename, .text = text, .module_type = module_type };
        }
    };

    pub const Register = struct {
        /// Which module to register, or `null` to use the most recent module.
        name: ?Name,
        /// The module name used when importing the module's exports.
        as: Name,

        fn parseInner(
            parser: *Parser,
            arena: *ArenaAllocator,
            scratch: *ArenaAllocator,
        ) Error!Register {
            const name_or_as = try parser.expectNextTokenString(scratch);
            const name = if (std.mem.eql(u8, "name", name_or_as)) name: {
                _ = scratch.reset(.retain_capacity);
                const module_name = try parser.expectNextTokenNameString(arena);
                try parser.expectNextTokenStringEql(scratch, "as");
                break :name module_name;
            } else if (std.mem.eql(u8, "as", name_or_as))
                null
            else
                return error.MalformedJson; // expected name or as

            _ = scratch.reset(.retain_capacity);

            const as = try parser.expectNextTokenNameString(arena);

            return .{ .name = name, .as = as };
        }
    };
};

pub fn next(parser: *Parser, arena: *ArenaAllocator, scratch: *ArenaAllocator) Error!?Command {
    var coz_begin = coz.begin("wasmstint.spectest.Parser.next");
    defer coz_begin.end();

    switch (parser.state) {
        .more => {},
        .finished => return null,
    }

    errdefer |e| switch (@as(Error, e)) {
        error.MalformedJson => parser.state = .finished,
        error.OutOfMemory => {},
    };

    switch (try parser.nextToken(scratch)) {
        .array_end => {
            parser.state = .finished;
            try parser.expectNextToken(.object_end); // expect last closing brace of document
            try parser.expectNextToken(.end_of_document); // expect end of document
            return null;
        },
        .object_begin => {},
        .object_end => unreachable,
        else => return error.MalformedJson,
    }

    try parser.expectNextTokenStringEql(scratch, "type");

    const type_string = try parser.expectNextTokenString(scratch);
    const command_type = parser.command_lookup.get(type_string) orelse
        return error.MalformedJson; // unrecognized command
    _ = scratch.reset(.retain_capacity);

    try parser.expectNextTokenStringEql(scratch, "line");
    _ = scratch.reset(.retain_capacity);

    const line_string = switch (try parser.nextToken(scratch)) {
        .number, .allocated_number => |s| s,
        else => return error.MalformedJson,
    };
    const line = std.fmt.parseInt(usize, line_string, 0) catch return error.MalformedJson;
    _ = scratch.reset(.retain_capacity);

    const @"type" = try Command.parseInner(parser, arena, command_type, scratch);
    try parser.expectNextToken(.object_end);

    parser.command_count += 1;
    return .{ .line = line, .type = @"type" };
}

const std = @import("std");
const Oom = std.mem.Allocator.Error;
const ArenaAllocator = std.heap.ArenaAllocator;
const json = std.json;
const wasmstint = @import("wasmstint");
const Name = wasmstint.Module.Name;
const V128 = wasmstint.V128;
const coz = @import("coz");
