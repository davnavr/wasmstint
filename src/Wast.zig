//! WebAssembly Text ([WAT]) and WebAssembly Specification Text ([`.wast`]) parsing.
//!
//! [WAT]: https://webassembly.github.io/spec/core/index.html
//! [`.wast`]: https://github.com/WebAssembly/spec/blob/d52e42df1314521c6e4cd7331593f2901e1d7b43/interpreter/README.md

const std = @import("std");

pub const Lexer = @import("Wast/Lexer.zig");
pub const sexpr = @import("Wast/sexpr.zig");
pub const Ident = @import("Wast/Ident.zig");
pub const Name = @import("Wast/Name.zig");
pub const Error = @import("Wast/Error.zig");

const value = @import("Wast/value.zig");

tree: sexpr.Tree,
interned_ids: Ident.Cache,
arena: std.heap.ArenaAllocator.State,
commands: std.MultiArrayList(Command),

pub const Command = union(enum) {
    //module: ,
    register: Register,
    //action,

    pub const Register = struct {
        /// The `module` name string used to access values from the registered module.
        import: Name.Id,
        /// Identifies which module to register for imports.
        ///
        /// If `.none`, then the latest initialized module is used.
        module: Ident,
    };

    comptime {
        std.debug.assert(@sizeOf(Command) <= @sizeOf([2]usize));
    }
};

const Wast = @This();

pub fn parseFromTree(
    tree: sexpr.Tree,
    gpa: std.mem.Allocator,
    scratch: *std.heap.ArenaAllocator,
    errors: *Error.List,
) error{OutOfMemory}!Wast {
    var commands = std.MultiArrayList(Command).empty;
    var arena = std.heap.ArenaAllocator.init(gpa);
    var interned_ids = Ident.Cache.empty;

    const commands_values = tree.values.values(&tree);
    try commands.ensureTotalCapacity(gpa, commands_values.len);
    for (commands_values) |cmd_value| {
        const cmd_list = cmd_value.getList() orelse {
            try errors.appendUnexpected(cmd_value);
            continue;
        };

        const cmd_contents = cmd_list.contents(&tree).values(&tree);
        if (cmd_contents.len == 0) {
            try errors.appendUnexpected(cmd_value);
            continue;
        }

        const cmd_keyword_id = cmd_contents[0].getAtom() orelse {
            try errors.appendUnexpected(cmd_value);
            continue;
        };

        switch (cmd_keyword_id.tag(&tree)) {
            .keyword_module => {},
            .keyword_register => {
                // TODO: Parse name
                _ = &interned_ids;
            },
            else => {
                try errors.appendUnexpected(cmd_value);
                continue;
            },
        }

        _ = scratch;
        _ = &arena;
    }

    return Wast{
        .tree = tree,
        .arena = arena.state,
    };
}

pub fn parseFromSlice(
    script: []const u8,
    gpa: std.mem.Allocator,
    scratch: *std.heap.ArenaAllocator,
    errors: *Error.List,
) error{ OutOfMemory, InvalidUtf8 }!Wast {
    const tree = try sexpr.Tree.parseFromSlice(script, gpa, scratch, errors);
    _ = scratch.reset(.retain_capacity);
    return parseFromTree(tree, gpa, scratch, errors);
}

pub fn deinit(wast: *Wast, gpa: std.mem.Allocator) void {
    wast.commands.deinit(gpa);
    wast.arena.promote(gpa).deinit();
    wast.tree.deinit(gpa);
    wast.interned_ids.deinit(gpa);
    wast.* = undefined;
}

test {
    _ = Lexer;
    _ = value;
}
