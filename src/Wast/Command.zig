const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../IndexedArena.zig");

const sexpr = @import("sexpr.zig");
const ParseContext = sexpr.Parser.Context;

const Wast = @import("../Wast.zig");
const Ident = @import("ident.zig").Ident;
const Name = @import("Name.zig");

const Caches = @import("Caches.zig");

keyword: sexpr.TokenId,
inner: Inner,

pub const Inner = union {
    module: IndexedArena.Idx(Wast.Module),
    register: IndexedArena.Idx(Register),
    action: IndexedArena.Idx(Action),
    assert_return: IndexedArena.Idx(AssertReturn),
    assert_trap: IndexedArena.Idx(AssertTrap), // TODO: Need assert_trap to also accept <module>
    assert_exhaustion: IndexedArena.Idx(AssertExhaustion),
    assert_malformed: IndexedArena.Idx(AssertMalformed),
    assert_invalid: IndexedArena.Idx(AssertInvalid),
    // assert_unlinkable: AssertUnlinkable,
};

pub fn parseConstOrResult(
    parser: *sexpr.Parser,
    comptime T: type,
    ctx: *ParseContext,
    arena: *IndexedArena,
) sexpr.Parser.ParseOrEofError!T {
    const Value: type = T.Value;

    const list = try parser.parseList(ctx);
    var list_parser = sexpr.Parser.init(list.contents(ctx.tree).values(ctx.tree));

    const keyword = try list_parser.parseAtomInList(list, ctx, T.expected);
    const parsed: struct { token: sexpr.TokenId, value: Value } = value: switch (keyword.tag(ctx.tree)) {
        .@"keyword_i32.const" => {
            const c = try list_parser.parseUninterpretedIntegerInList(i32, list, ctx);
            break :value .{ .token = c.token, .value = .{ .i32 = c.value } };
        },
        .@"keyword_f32.const" => {
            const f = try list_parser.parseFloatInList(f32, list, ctx);
            const value: Value = switch (f.value(ctx.tree)) {
                .bits => |bits| .{ .f32 = bits },
                .nan_canonical => if (@hasField(Value, "f32_nan"))
                    .{ .f32_nan = {} }
                else
                    return (try ctx.errorAtToken(
                        f.token,
                        "invalid f32 literal",
                        @errorReturnTrace(),
                    )).err,
                .nan_arithmetic => if (@hasField(Value, "f32_nan"))
                    .{ .f32_nan = {} }
                else
                    return (try ctx.errorAtToken(
                        f.token,
                        "invalid f32 literal",
                        @errorReturnTrace(),
                    )).err,
            };

            break :value .{ .token = f.token, .value = value };
        },
        .@"keyword_i64.const" => {
            const c = try list_parser.parseUninterpretedIntegerInList(i64, list, ctx);
            const alloc = try arena.alignedCreate(i64, 4);
            alloc.set(arena, c.value);
            break :value .{ .token = c.token, .value = .{ .i64 = alloc } };
        },
        .@"keyword_f64.const" => {
            const f = try list_parser.parseFloatInList(f64, list, ctx);
            const value: Value = switch (f.value(ctx.tree)) {
                .bits => |bits| bits: {
                    const alloc = try arena.alignedCreate(u64, 4);
                    alloc.set(arena, bits);
                    break :bits .{ .f64 = alloc };
                },
                .nan_canonical => if (@hasField(Value, "f64_nan"))
                    .{ .f64_nan = {} }
                else
                    return (try ctx.errorAtToken(
                        f.token,
                        "invalid f64 literal",
                        @errorReturnTrace(),
                    )).err,
                .nan_arithmetic => if (@hasField(Value, "f64_nan"))
                    .{ .f64_nan = {} }
                else
                    return (try ctx.errorAtToken(
                        f.token,
                        "invalid f64 literal",
                        @errorReturnTrace(),
                    )).err,
            };

            break :value .{ .token = f.token, .value = value };
        },
        .@"keyword_ref.extern" => {
            const maybe_int: sexpr.TokenId = list_parser.parseAtom(ctx, "unsigned integer") catch |e| switch (e) {
                error.EndOfStream => if (@hasField(Value, "ref_extern_unspecified")) {
                    break :value .{ .token = keyword, .value = .{ .ref_extern_unspecified = {} } };
                } else {
                    return (try ctx.errorAtList(
                        list,
                        .end,
                        "expected natural number",
                        @errorReturnTrace(),
                    )).err;
                },
                else => |err| return err,
            };

            if (maybe_int.tag(ctx.tree) != .integer) {
                return (try ctx.errorAtToken(
                    maybe_int,
                    "expected natural number",
                    @errorReturnTrace(),
                )).err;
            }

            const nat = @import("value.zig").unsignedInteger(u31, maybe_int.contents(ctx.tree)) catch {
                return (try ctx.errorAtToken(
                    maybe_int,
                    "host reference number too large",
                    @errorReturnTrace(),
                )).err;
            };

            break :value .{ .token = maybe_int, .value = .{ .ref_extern = nat } };
        },
        .@"keyword_ref.null" => {
            const heap_type = try list_parser.parseAtom(ctx, "heap type");
            switch (heap_type.tag(ctx.tree)) {
                .keyword_func, .keyword_extern => {},
                else => return (try ctx.errorAtToken(
                    heap_type,
                    "invalid heap type",
                    @errorReturnTrace(),
                )).err,
            }

            break :value .{ .token = heap_type, .value = .{ .ref_null = {} } };
        },
        else => return (try ctx.errorAtToken(
            keyword,
            "expected " ++ T.expected,
            @errorReturnTrace(),
        )).err,
    };

    try list_parser.expectEmpty(ctx);
    return T{
        .keyword = keyword,
        .value_token = parsed.token,
        .value = parsed.value,
    };
}

pub fn parseConstOrResultList(
    contents: *sexpr.Parser,
    comptime T: type,
    ctx: *ParseContext,
    arena: *IndexedArena,
) error{OutOfMemory}!IndexedArena.Slice(T) {
    var values = try IndexedArena.BoundedArrayList(T).initCapacity(arena, contents.remaining.len);
    for (0..values.capacity) |_| {
        const val = parseConstOrResult(contents, T, ctx, arena) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.EndOfStream => unreachable,
            error.ReportedParserError => continue,
        };

        values.appendAssumeCapacity(arena, val);
    }

    std.debug.assert(contents.isEmpty());
    return values.items;
}

pub const Const = struct {
    keyword: sexpr.TokenId,
    value_token: sexpr.TokenId,
    value: Value,

    pub const expected = "const value";

    pub const Value = union {
        /// `keyword.tag == .@"keyword_i32.const"`
        i32: i32,
        f32: u32,
        i64: IndexedArena.IdxAligned(i64, 4),
        f64: IndexedArena.IdxAligned(u64, 4),
        // v128: IndexedArena.IdxAligned([u8; 16], 4),
        ref_null: void,
        ref_extern: u31,
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

    pub const expected = "result value";

    pub const Value = union {
        i32: i32,
        f32: u32,
        i64: IndexedArena.IdxAligned(i64, 4),
        f64: IndexedArena.IdxAligned(u64, 4),
        // v128: IndexedArena.IdxAligned([u8; 16], 4),
        /// `keyword.tag == .@"keyword_f32.const" and
        /// (value_token.tag == .@"keyword_nan:canonical" or value_token.tag == .@"keyword_nan:arithmetic")`
        f32_nan: void,
        f64_nan: void,
        ref_null: void,
        ref_extern: u31,
        ref_extern_unspecified: void,
        ref_func: void,
    };

    comptime {
        std.debug.assert(@alignOf(Result) == @alignOf(u32));
        std.debug.assert(@sizeOf(Result) == switch (@import("builtin").mode) {
            .Debug, .ReleaseSafe => 16,
            .ReleaseFast, .ReleaseSmall => 12,
        });
    }
};

pub const Register = struct {
    /// The `module` name string used to access values from the registered module.
    name: Name,
    /// Identifies which module to register for imports.
    ///
    /// If `.none`, then the latest initialized module is used.
    id: Ident.Opt align(4),
};

pub const Arguments = IndexedArena.Slice(Const);

pub const Action = struct {
    /// Identifies which module contains the function or global export to invoke or get.
    ///
    /// If `.none`, then the latest initialized module is used.
    module: Ident.Symbolic align(4),
    /// The name of the function or global export to invoke or get.
    name: Name,
    /// The `invoke` or `get` keyword.
    keyword: sexpr.TokenId,
    target: Target,

    pub const Target = union {
        get: void,
        invoke: struct { arguments: Arguments },
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        action_keyword: sexpr.TokenId,
        parent_list: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!IndexedArena.Idx(Action) {
        const action = try arena.create(Action);

        const module = try Ident.Symbolic.parse(
            contents,
            ctx.tree,
            caches.allocator,
            &caches.ids,
        );

        _ = scratch.reset(.retain_capacity);
        const name = try Name.parse(
            contents,
            ctx,
            caches.allocator,
            &caches.names,
            arena,
            parent_list,
            scratch,
        );

        const parsed_target: Target = switch (action_keyword.tag(ctx.tree)) {
            .keyword_invoke => .{
                .invoke = .{
                    .arguments = try parseConstOrResultList(
                        contents,
                        Const,
                        ctx,
                        arena,
                    ),
                },
            },
            .keyword_get => .{ .get = {} },
            else => return (try ctx.errorAtToken(
                action_keyword,
                "expected 'invoke' or 'get' keyword",
                @errorReturnTrace(),
            )).err,
        };

        try contents.expectEmpty(ctx);

        action.set(
            arena,
            Action{
                .module = module,
                .name = name,
                .keyword = action_keyword,
                .target = parsed_target,
            },
        );

        return action;
    }

    pub fn parse(
        parser: *sexpr.Parser,
        ctx: *ParseContext,
        arenas: *IndexedArena,
        caches: *Caches,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!IndexedArena.Idx(Action) {
        const action_list = try parser.parseListInList(parent, ctx);

        var contents = sexpr.Parser.init(action_list.contents(ctx.tree).values(ctx.tree));
        const action_keyword = try contents.parseAtomInList(action_list, ctx, "action");
        return parseContents(
            &contents,
            ctx,
            arenas,
            caches,
            action_keyword,
            action_list,
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
        ctx: *ParseContext,
        arena: *IndexedArena,
        list: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!Failure {
        const atom = try parser.parseAtomInList(list, ctx, "failure string");

        switch (atom.tag(ctx.tree)) {
            .string => {
                const contents = atom.contents(ctx.tree);
                const msg = contents[1 .. contents.len - 1];
                // Strings without escape sequences are always valid UTF-8.
                std.debug.assert(std.unicode.utf8ValidateSlice(msg));
                return .{ .msg = try String.initSlice(msg) };
            },
            .string_raw => {
                const contents = atom.contents(ctx.tree);
                const msg = contents[1 .. contents.len - 1];

                _ = scratch.reset(.retain_capacity);
                const printed_msg = try @import("value.zig").string(msg).allocPrint(scratch.allocator());

                return if (std.unicode.utf8ValidateSlice(printed_msg.items))
                    .{ .msg = String.initAllocated(try arena.dupe(u8, printed_msg.items)) }
                else
                    (try ctx.errorAtToken(
                        atom,
                        "failure string must be valid UTF-8",
                        @errorReturnTrace(),
                    )).err;
            },
            else => return (try ctx.errorAtToken(
                atom,
                "expected failure string",
                @errorReturnTrace(),
            )).err,
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

pub const AssertMalformed = struct {
    module: Wast.Module,
    failure: Failure,
};
