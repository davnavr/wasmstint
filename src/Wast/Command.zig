const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../IndexedArena.zig");

const sexpr = @import("sexpr.zig");
const Error = sexpr.Error;

const Wast = @import("../Wast.zig");
const Ident = @import("Ident.zig");
const Name = @import("Name.zig");

const Caches = @import("Caches.zig");
const ParseResult = sexpr.Parser.Result;

keyword: sexpr.TokenId,
inner: Inner,

pub const Inner = union {
    module: IndexedArena.Idx(Wast.Module),
    register: IndexedArena.Idx(Register),
    action: IndexedArena.Idx(Action),
    assert_return: IndexedArena.Idx(AssertReturn),
    assert_trap: IndexedArena.Idx(AssertTrap), // TODO: Need assert_trap to also accept <module>
    // assert_exhaustion: AssertExhaustion,
    // assert_malformed: AssertMalformed, // TODO: Since this probably only uses quote/binary module, no need to have separate error list field
    assert_invalid: IndexedArena.Idx(AssertInvalid),
    // assert_unlinkable: AssertUnlinkable,
};

pub fn parseConstOrResult(
    parser: *sexpr.Parser,
    comptime T: type,
    tree: *const sexpr.Tree,
    arena: *IndexedArena,
    errors: *Error.List,
) error{ OutOfMemory, EndOfStream }!ParseResult(T) {
    const Value: type = T.Value;

    const list: sexpr.List.Id = switch (try parser.parseList()) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    var list_parser = sexpr.Parser.init(list.contents(tree).values(tree));

    const keyword: sexpr.TokenId = switch (list_parser.parseAtomInList(.keyword_unknown, list)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    const parsed: struct { sexpr.TokenId, Value } = value: switch (keyword.tag(tree)) {
        .@"keyword_i32.const" => switch (list_parser.parseUninterpretedIntegerInList(i32, list, tree)) {
            .ok => |ok| .{ ok.token, Value{ .i32 = ok.value } },
            .err => |err| return .{ .err = err },
        },
        .@"keyword_f32.const" => switch (list_parser.parseFloatInList(f32, list, tree)) {
            .ok => |ok| .{ ok.token, Value{ .f32 = ok.value } },
            .err => |err| return .{ .err = err },
        },
        .@"keyword_i64.const" => switch (list_parser.parseUninterpretedIntegerInList(i64, list, tree)) {
            .ok => |ok| {
                const val = try arena.create(i64);
                val.set(arena, ok.value);
                break :value .{ ok.token, Value{ .i64 = val } };
            },
            .err => |err| return .{ .err = err },
        },
        .@"keyword_f64.const" => switch (list_parser.parseFloatInList(f64, list, tree)) {
            .ok => |ok| {
                const val = try arena.create(u64);
                val.set(arena, ok.value);
                break :value .{ ok.token, Value{ .f64 = val } };
            },
            .err => |err| return .{ .err = err },
        },
        .keyword_unknown => return .{
            .err = Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value),
        },
        else => return .{
            .err = Error.initExpectedToken(sexpr.Value.initAtom(keyword), .keyword_unknown, .at_value),
        },
    };

    try list_parser.expectEmpty(errors);
    return .{
        .ok = T{
            .keyword = keyword,
            .value_token = parsed.@"0",
            .value = parsed.@"1",
        },
    };
}

pub fn parseConstOrResultList(
    contents: *sexpr.Parser,
    comptime T: type,
    tree: *const sexpr.Tree,
    arena: *IndexedArena,
    errors: *Error.List,
) error{OutOfMemory}!IndexedArena.Slice(T) {
    var values = try IndexedArena.BoundedArrayList(T).initCapacity(arena, contents.remaining.len);
    for (0..values.capacity) |_| {
        const val_result = parseConstOrResult(contents, T, tree, arena, errors) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.EndOfStream => unreachable,
        };

        switch (val_result) {
            .ok => |val| values.appendAssumeCapacity(arena, val),
            .err => |err| try errors.append(err),
        }
    }

    std.debug.assert(contents.isEmpty());
    return values.items;
}

pub const Const = struct {
    keyword: sexpr.TokenId,
    value_token: sexpr.TokenId,
    value: Value,

    pub const Value = union {
        /// `keyword.tag == .@"keyword_i32.const"`
        i32: i32,
        f32: u32,
        i64: IndexedArena.Idx(i64),
        f64: IndexedArena.Idx(u64),
        // v128: IndexedArena.Idx([u8; 16]),
        // ref_null: enum { func, extern },
        ref_extern: u32,
    };

    comptime {
        std.debug.assert(@alignOf(Const) == @alignOf(u32));
        std.debug.assert(@sizeOf(Const) == switch (@import("builtin").mode) {
            .Debug, .ReleaseSafe => 16,
            .ReleaseFast, .ReleaseSmall => 12,
        });
    }
};

pub const Result = struct {
    keyword: sexpr.TokenId,
    value_token: sexpr.TokenId,
    value: Value,

    pub const Value = union {
        i32: i32,
        f32: u32,
        i64: IndexedArena.Idx(i64),
        f64: IndexedArena.Idx(u64),
        // v128: *const [u8; 16],
        /// `keyword.tag == .@"keyword_f32.const" and value_token.tag == .@"keyword_nan:canonical"`
        f32_nan: NanPattern,
        f64_nan: NanPattern,
        // ref_null: enum { func, extern },
        ref_extern: ?u32,
        ref_func: void,
    };

    pub const NanPattern = enum { canonical, arithmetic };
};

pub const Register = struct {
    /// The `module` name string used to access values from the registered module.
    name: Name,
    /// Identifies which module to register for imports.
    ///
    /// If `.none`, then the latest initialized module is used.
    id: Ident,
};

pub const Action = struct {
    /// Identifies which module contains the function or global export to invoke or get.
    ///
    /// If `.none`, then the latest initialized module is used.
    module: Ident,
    /// The name of the function or global export to invoke or get.
    name: Name,
    /// The `invoke` or `get` keyword.
    keyword: sexpr.TokenId,
    target: Target,

    pub const Target = union {
        get: void,
        invoke: struct { arguments: IndexedArena.Slice(Const) },
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        action_keyword: sexpr.TokenId,
        parent_list: sexpr.List.Id,
        errors: *Error.List,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(IndexedArena.Idx(Action)) {
        const action = try arena.create(Action);

        const module = switch (try Ident.parse(contents, tree, caches.allocator, &caches.ids)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        _ = scratch.reset(.retain_capacity);
        const name = switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent_list, scratch)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const parsed_target: Target = switch (action_keyword.tag(tree)) {
            .keyword_invoke => .{
                .invoke = .{
                    .arguments = try parseConstOrResultList(contents, Const, tree, arena, errors),
                },
            },
            .keyword_get => Target{ .get = {} },
            else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(action_keyword), .at_value) },
        };

        try contents.expectEmpty(errors);

        action.set(
            arena,
            Action{
                .module = module,
                .name = name,
                .keyword = action_keyword,
                .target = parsed_target,
            },
        );

        return .{ .ok = action };
    }

    pub fn parse(
        parser: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arenas: *IndexedArena,
        caches: *Caches,
        parent: sexpr.List.Id,
        errors: *Error.List,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(IndexedArena.Idx(Action)) {
        const action_list: sexpr.List.Id = switch (parser.parseListInList(parent)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        var contents = sexpr.Parser.init(action_list.contents(tree).values(tree));
        const action_keyword: sexpr.TokenId = switch (contents.parseAtomInList(.keyword_unknown, action_list)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        return parseContents(
            &contents,
            tree,
            arenas,
            caches,
            action_keyword,
            action_list,
            errors,
            scratch,
        );
    }
};

pub const AssertReturn = struct {
    action: IndexedArena.Idx(Action),
    results: IndexedArena.Slice(Result),
};

pub const Failure = struct {
    const String = @import("String.zig");

    msg: String,

    pub fn parseInList(
        parser: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        list: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(Failure) {
        const atom: sexpr.TokenId = switch (parser.parseAtomInList(.string, list)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        switch (atom.tag(tree)) {
            .string => {
                const contents = atom.contents(tree);
                const msg = contents[1 .. contents.len - 1];
                // Strings without escape sequences are always valid UTF-8.
                std.debug.assert(std.unicode.utf8ValidateSlice(msg));
                return .{ .ok = .{ .msg = try String.initSlice(msg) } };
            },
            .string_raw => {
                const contents = atom.contents(tree);
                const msg = contents[1 .. contents.len - 1];

                _ = scratch.reset(.retain_capacity);
                const printed_msg = try @import("value.zig").string(msg).allocPrint(scratch.allocator());

                return if (std.unicode.utf8ValidateSlice(printed_msg.items))
                    .{ .ok = Failure{ .msg = String.initAllocated(try arena.dupe(u8, printed_msg.items)) } }
                else
                    .{ .err = Error.initInvalidUtf8(atom) };
            },
            else => return .{
                .err = Error.initExpectedToken(sexpr.Value.initAtom(atom), .string, .at_value),
            },
        }
    }
};

pub const AssertTrap = struct {
    action: IndexedArena.Idx(Action),
    failure: Failure,
};

pub const AssertExhaustion = struct {
    action: IndexedArena.Idx(Action),
    failure: Failure,
};

/// Asserts that a module does not pass validation.
pub const AssertInvalid = struct {
    module: Wast.Module,
    failure: Failure,
};
