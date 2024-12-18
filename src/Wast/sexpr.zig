//! Parses a sequence of `Token`s into a list of S-expressions.

const std = @import("std");
const Allocator = std.mem.Allocator;

const Lexer = @import("Lexer.zig");

pub const Token = Lexer.Token;
pub const Offset = Lexer.Offset;

/// An S-expression.
pub const Value = packed struct(u32) {
    tag: Tag,
    case: packed union {
        atom: TokenId,
        list: List.Id,
    },

    pub const Tag = enum(u1) {
        atom,
        list,
    };

    fn initAtom(token: TokenId) Value {
        return Value{ .tag = .atom, .case = .{ .atom = token } };
    }

    fn initList(list: List.Id) Value {
        return Value{ .tag = .list, .case = .{ .list = list } };
    }
};

pub const List = struct {
    parenthesis: Offset,
    contents: Contents,

    pub const Contents = struct {
        start: u32,
        count: u32,

        pub fn values(contents: Contents, tree: *const Tree) []const Value {
            return tree.arenas.values.items[contents.start..][0..contents.count];
        }
    };

    pub const Id = enum(u31) {
        _,

        fn create(list: List, arena: *std.MultiArrayList(List), gpa: Allocator) error{OutOfMemory}!Id {
            const i = std.math.cast(u31, arena.len) orelse return error.OutOfMemory;
            try arena.append(gpa, list);
            return @enumFromInt(i);
        }

        pub fn contents(id: Id, tree: *const Tree) *const Contents {
            return tree.arenas.lists.slice().items(.contents)[@intFromEnum(id)];
        }
    };
};

pub const TokenId = enum(u31) {
    _,

    fn create(token: Token, arena: *std.MultiArrayList(Token), gpa: Allocator) error{OutOfMemory}!TokenId {
        const i = std.math.cast(u31, arena.len) orelse return error.OutOfMemory;
        try arena.append(gpa, token);
        return @enumFromInt(i);
    }

    pub fn tag(id: TokenId, tree: *const Tree) Token.Tag {
        return tree.arenas.tokens.slice().items(.tag)[@intFromEnum(id)];
    }
};

pub const Error = struct {
    value: Value,
    tag: Tag,
    extra: union {
        /// Set when `.tag == Tag.expected_token`.
        expected_token: Token.Tag,
    } = undefined,

    pub const Tag = enum {
        unexpected,
        // missing_closing_quotation_mark,
        // missing_block_comment_end,
        missing_closing_parenthesis,
        expected_token,
    };
};

fn appendError(
    errors: *std.SegmentedList(Error, 0),
    tag: Error.Tag,
    value: Value,
    gpa: Allocator,
) error{OutOfMemory}!void {
    try errors.append(gpa, .{ .tag = tag, .value = value });
}

/// Stores allocations for parsed S-expressions.
pub const Tree = struct {
    /// The UTF-8 source code.
    source: []const u8,
    values: List.Contents,
    errors: std.SegmentedList(Error, 0),
    arenas: struct {
        values: std.ArrayListUnmanaged(Value),
        tokens: std.MultiArrayList(Token),
        lists: std.MultiArrayList(List),
    },

    pub fn parseFromLexer(
        lexer: Lexer,
        gpa: Allocator,
        scratch: *std.heap.ArenaAllocator,
    ) error{OutOfMemory}!Tree {
        // TODO: Get an actual estimate of average bytes/token
        const bytes_per_token: usize = 16;

        // Allocated in `gpa`.
        var tree = Tree{
            .source = lexer.utf8.bytes,
            .values = .{ .start = undefined, .count = 0 },
            .errors = {},
            .arenas = .{
                .values = .empty,
                .tokens = .empty,
                .lists = .empty,
            },
        };

        errdefer tree.deinit(gpa);

        try tree.tokens.ensureTotalCapacity(gpa, lexer.utf8.bytes.len / bytes_per_token);

        const ListHeader = struct {
            open_paren_offset: usize,
            count: u32 = 0,
        };

        // Allocated in `scratch`.
        var list_stack = .{
            .headers = std.SegmentedList(ListHeader, 8){},
            .contents = std.SegmentedList(Value, 16){},
        };

        list_stack.headers.append(gpa, .{ .open_paren_offset = undefined }) catch unreachable;

        var prev_tok: ?Token = null;
        while (lexer.next()) |tok| {
            defer prev_tok = tok;
            switch (tok.tag) {
                .reserved => {
                    const id = try TokenId.create(tok, &tree.arenas.tokens, gpa);
                    try appendError(&tree.errors, .unexpected, Value.initAtom(id), gpa);
                },
                .open_paren => {
                    try list_stack.headers.append(
                        scratch.allocator(),
                        .{ .open_paren_offset = tok.start },
                    );
                },
                .close_paren => switch (list_stack.headers.count()) {
                    0 => unreachable,
                    1 => {
                        // Unmatched closing parenthesis.
                        const id = try TokenId.create(tok, &tree.arenas.tokens, gpa);
                        try appendError(&tree.errors, .unexpected, Value.initAtom(id), gpa);
                    },
                    else => {
                        const popped_list: ListHeader = list_stack.headers.pop() orelse unreachable;

                        {
                            const prev_list_count = list_stack.headers.at(list_stack.headers.count() - 1).*.count;
                            prev_list_count.* = std.math.add(u32, prev_list_count.*, 1) catch return error.OutOfMemory;
                        }

                        const list_contents = List.Contents{
                            .count = popped_list.count,
                            .start = std.math.cast(u32, tree.arenas.values.items.len) orelse
                                return error.OutOfMemory,
                        };

                        try tree.arenas.values.resize(
                            gpa,
                            undefined,
                            std.math.add(usize, tree.arenas.values.items.len, popped_list.count) catch
                                return error.OutOfMemory,
                        );

                        const copied_values_dst = tree.arenas.values.items[list_contents.start..][0..popped_list.count];
                        const remaining_values_count = list_stack.contents.count() - popped_list.count;
                        list_stack.contents.writeToSlice(copied_values_dst, remaining_values_count);
                        list_stack.contents.len = remaining_values_count;

                        const new_list = try List.Id.create(
                            List{
                                .parenthesis = .{
                                    .start = popped_list.open_paren_offset,
                                    .end = tok.offset.end,
                                },
                                .contents = list_contents,
                            },
                            &tree.arenas.lists,
                            gpa,
                        );

                        try list_stack.contents.append(scratch.allocator(), Value.initList(new_list));
                    },
                },
                .unexpected_eof => {
                    const id = try TokenId.create(tok, &tree.arenas.tokens, gpa);
                    try appendError(&tree.errors, .unexpected, Value.initAtom(id), gpa);
                    break;
                },
                else => {
                    const value = Value.initAtom(try TokenId.create(tok, &tree.arenas.tokens, gpa));
                    // Append token to the current list.
                    try list_stack.contents.append(scratch.allocator(), value);
                    const current_count = list_stack.headers.at(list_stack.headers.count() - 1).*.count;
                    current_count.* = std.math.add(u32, current_count.*, 1) catch return error.OutOfMemory;
                },
            }
        }

        if (list_stack.headers.count() > 1) {
            const previous_token = prev_tok.?;
            try appendError(&tree.errors, .missing_closing_parenthesis, Value.initAtom(previous_token), gpa);

            while (list_stack.headers.count() > 1) {
                // TODO: Refactor this duplicated code from `.close_paren` case.
                const popped_list: ListHeader = list_stack.headers.pop() orelse unreachable;

                {
                    const prev_list_count = list_stack.headers.at(list_stack.headers.count() - 1).*.count;
                    prev_list_count.* = std.math.add(u32, prev_list_count.*, 1) catch return error.OutOfMemory;
                }

                const list_contents = List.Contents{
                    .count = popped_list.count,
                    .start = std.math.cast(u32, tree.arenas.values.items.len) orelse
                        return error.OutOfMemory,
                };

                try tree.arenas.values.resize(
                    gpa,
                    undefined,
                    std.math.add(usize, tree.arenas.values.items.len, popped_list.count) catch
                        return error.OutOfMemory,
                );

                const copied_values_dst = tree.arenas.values.items[list_contents.start..][0..popped_list.count];
                const remaining_values_count = list_stack.contents.count() - popped_list.count;
                list_stack.contents.writeToSlice(copied_values_dst, remaining_values_count);
                list_stack.contents.len = remaining_values_count;

                const new_list = try List.Id.create(
                    List{
                        .parenthesis = .{
                            .start = popped_list.open_paren_offset,
                            .end = previous_token.offset.end,
                        },
                        .contents = list_contents,
                    },
                    &tree.arenas.lists,
                    gpa,
                );

                try list_stack.contents.append(scratch.allocator(), Value.initList(new_list));
            }

            {
                const top_level_list_header: ListHeader = list_stack.headers.pop();
                std.debug.assert(list_stack.contents.count() == top_level_list_header.count);

                tree.values = .{
                    .count = top_level_list_header.count,
                    .start = std.math.cast(u32, tree.arenas.values.items.len) orelse
                        return error.OutOfMemory,
                };

                try tree.arenas.values.resize(
                    gpa,
                    undefined,
                    std.math.add(usize, tree.arenas.values.items.len, tree.values.count) catch
                        return error.OutOfMemory,
                );

                list_stack.contents.writeToSlice(tree.arenas.values.items[tree.values.start..][0..tree.values.count], 0);
            }

            std.debug.assert(list_stack.headers.count() == 0);
            return tree;
        }
    }

    pub fn parseFromSlice(
        script: []const u8,
        gpa: Allocator,
        scratch: *std.heap.ArenaAllocator,
    ) error{ OutOfMemory, InvalidUtf8 }!Tree {
        return parseFromLexer(try Lexer.init(script), gpa, scratch);
    }

    pub fn deinit(tree: *Tree, gpa: Allocator) void {
        tree.errors.deinit(gpa);
        tree.arenas.values.deinit(gpa);
        tree.arenas.tokens.deinit(gpa);
        tree.arenas.lists.deinit(gpa);
        tree.* = undefined;
    }
};
