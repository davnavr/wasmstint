//! WebAssembly Text ([WAT]) and WebAssembly Specification Text ([`.wast`]) parsing.
//!
//! [WAT]: https://webassembly.github.io/spec/core/index.html
//! [`.wast`]: https://github.com/WebAssembly/spec/blob/d52e42df1314521c6e4cd7331593f2901e1d7b43/interpreter/README.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

pub const Lexer = @import("Wast/Lexer.zig");
pub const sexpr = @import("Wast/sexpr.zig");
pub const Ident = @import("Wast/Ident.zig");
pub const Name = @import("Wast/Name.zig");
pub const Error = @import("Wast/Error.zig");
pub const LineCol = @import("Wast/LineCol.zig");

const value = @import("Wast/value.zig");

tree: *const sexpr.Tree,
interned_ids: Ident.Cache.Entries,
interned_names: Name.Cache.Entries,
commands: std.MultiArrayList(Command),

pub const Command = struct {
    keyword: sexpr.TokenId,
    inner: Inner,

    pub const Register = struct {
        /// The `module` name string used to access values from the registered module.
        name: Name.Id,
        /// Identifies which module to register for imports.
        ///
        /// If `.none`, then the latest initialized module is used.
        id: Ident,

        comptime {
            std.debug.assert(@sizeOf(Register) == 12);
        }
    };

    pub const Action = struct {
        /// Identifies which module contains the function or global export to invoke or get.
        ///
        /// If `.none`, then the latest initialized module is used.
        module: Ident,
        /// The name of the function or global export to invoke or get.
        name: Name.Id,
        /// The `invoke` or `get` keyword.
        keyword: sexpr.TokenId,
        target: Target,

        pub const Target = union(enum) {
            get,
            invoke: struct {
                arguments: Const.PackedList,
            },
        };

        comptime {
            std.debug.assert(@sizeOf(Target) <= 16);
        }
    };

    pub const Inner = union(enum) {
        //module: ,
        register: Register,
        //action,
    };

    comptime {
        std.debug.assert(@sizeOf(Inner) <= 16);
    }
};

pub const Const = union(enum) {
    i32: i32,
    f32: u32,
    i64: i64,
    f64: u64,
    // v128: *const [u8; 16],
    // ref_null,
    // ref_host: usize,

    // Field containing <num>.const or other keyword not included

    pub const PackedList = extern struct {
        len: u32,
        ptr: [*]align(@alignOf(u32)) Const,
    };

    comptime {
        std.debug.assert(@sizeOf(Const) <= 16);
        std.debug.assert(@sizeOf(PackedList) <= 12);
    }

    pub fn parse(
        parser: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arena: *ArenaAllocator,
        errors: *Error.List,
    ) error{ OutOfMemory, EndOfStream }!sexpr.Parser.Result(Const) {
        _ = arena; // Might be used for large v128 values.

        const list: sexpr.List.Id = switch (try parser.parseList()) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        var list_parser = parser.init(list.contents(tree));

        const keyword: sexpr.TokenId = switch (list_parser.parseAtomInList(.keyword_unknown, list)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const parsed: Const = switch (keyword.tag(tree)) {
            .@"keyword_i32.const" => Const{
                .i32 = switch (list_parser.parseUninterpretedIntegerInList(i32, list, tree)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                },
            },
            .@"keyword_i64.const" => Const{
                .i64 = switch (list_parser.parseUninterpretedIntegerInList(i64, list, tree)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                },
            },
            .keyword_unknown => return .{
                .err = Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value),
            },
            else => return .{
                .err = Error.initExpectedToken(sexpr.Value.initAtom(keyword), .keyword_unknown, .at_value),
            },
        };

        try list_parser.expectEmpty(errors);
        return .{ .ok = parsed };
    }
};

const Wast = @This();

pub fn parse(
    tree: *const sexpr.Tree,
    arena: *ArenaAllocator,
    alloca: *ArenaAllocator,
    errors: *Error.List,
) error{OutOfMemory}!Wast {
    // `alloca` is used for allocations that live for the rest of this function call.
    var scratch = ArenaAllocator.init(alloca.allocator());
    defer scratch.deinit();

    const commands_values = tree.values.values(tree);

    var commands = std.MultiArrayList(Command).empty;
    try commands.ensureTotalCapacity(arena.allocator(), commands_values.len);

    var interned_ids = Ident.Cache.empty;
    var interned_names = Name.Cache.empty;

    for (commands_values) |cmd_value| {
        const cmd_list = cmd_value.getList() orelse {
            try errors.append(Error.initUnexpectedValue(cmd_value, .at_value));
            continue;
        };

        var cmd_parser = sexpr.Parser.init(cmd_list.contents(tree).values(tree));

        const cmd_keyword_id = switch (cmd_parser.parseAtomInList(.keyword_unknown, cmd_list)) {
            .ok => |ok| ok,
            .err => |err| {
                try errors.append(err);
                continue;
            },
        };

        const cmd: Command.Inner = cmd: switch (cmd_keyword_id.tag(tree)) {
            .keyword_module => {
                // TODO: Parse id, then check for binary or quote keyword
                unreachable;
            },
            .keyword_register => {
                _ = scratch.reset(.retain_capacity);
                const name_result = try Name.parse(
                    &cmd_parser,
                    tree,
                    alloca,
                    &interned_names,
                    arena,
                    cmd_list,
                    &scratch,
                );

                const name = switch (name_result) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                const id = switch (try Ident.parse(&cmd_parser, tree, &interned_ids, alloca)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                break :cmd .{ .register = Command.Register{ .name = name, .id = id } };
            },
            else => {
                try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(cmd_keyword_id), .at_value));
                continue;
            },
        };

        commands.appendAssumeCapacity(Command{ .keyword = cmd_keyword_id, .inner = cmd });

        try cmd_parser.expectEmpty(errors);
    }

    return Wast{
        .tree = tree,
        .interned_ids = try interned_ids.entries(arena),
        .interned_names = try interned_names.entries(arena),
        .commands = commands,
    };
}

test {
    _ = Lexer;
    _ = value;
    _ = LineCol;
}
