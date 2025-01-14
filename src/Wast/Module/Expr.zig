const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;

const Caches = @import("../Caches.zig");
const Ident = @import("../ident.zig").Ident;

const Instr = @import("Instr.zig");

contents: IndexedArena.Slice(IndexedArena.Word),
count: u32,

const Expr = @This();

fn parseInstrList(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    instr_list_arena: *ArenaAllocator,
    instr_list_pool: *Instr.List.Pool,
    errors: *Error.List,
    alloca: *ArenaAllocator,
) error{OutOfMemory}!Instr.List {
    // Allocated in `instr_list_arena`.
    var output = instr_list_pool.pop() orelse Instr.List.empty;
    std.debug.assert(output.count == 0);
    std.debug.assert(output.buffer.len == 0);

    // Get better estimate of avg. # of instr per sexpr.Value
    try output.growCapacityAdditionalWords(instr_list_arena, (contents.remaining.len +| 7) / 8);

    _ = alloca.reset(.retain_capacity);
    var scratch = ArenaAllocator.init(alloca.allocator());

    const Block = enum {
        block_or_loop,
        @"if",
        @"else",
        // catch,
    };

    // Allocated in `alloca`.
    var block_stack = std.SegmentedList(Block, 8){};

    var previous_instr: ?sexpr.Value = null;
    parse_body: while (@as(?sexpr.Value, contents.parseValue() catch null)) |instr_value| {
        previous_instr = instr_value;
        _ = scratch.reset(.retain_capacity);
        if (instr_value.getAtom()) |keyword| {
            // Parse a plain instruction.
            const instr_result = try Instr.parseArgs(
                keyword,
                contents,
                tree,
                &output,
                instr_list_arena,
                parent,
                arena,
                caches,
                errors,
                &scratch,
            );

            if (instr_result) |err| {
                // If a single instruction fails to parse, then skip parsing the rest of them.
                try errors.append(err);
                _ = contents.empty();
                break :parse_body;
            }

            switch (keyword.tag(tree)) {
                .keyword_block, .keyword_loop => try block_stack.append(alloca.allocator(), .block_or_loop),
                .keyword_if => try block_stack.append(alloca.allocator(), .@"if"),
                .keyword_else => if (block_stack.pop() == .@"if") {
                    block_stack.append(undefined, .@"else") catch unreachable;
                } else {
                    try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value));
                    _ = contents.empty();
                    break :parse_body;
                },
                .keyword_end => if (block_stack.pop() == null) {
                    try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value));
                    _ = contents.empty();
                    break :parse_body;
                },
                else => {},
            }
        } else {
            // Parse a folded instruction.
            var list = instr_value.getList().?;
            var list_contents = sexpr.Parser.init(list.contents(tree).values(tree));

            const keyword: sexpr.TokenId = switch (list_contents.parseAtomInList(.keyword_unknown, parent)) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    _ = contents.empty();
                    break :parse_body;
                },
            };

            var parent_output = Instr.List.empty;
            const instr_result = try Instr.parseArgs(
                keyword,
                &list_contents,
                tree,
                &parent_output,
                instr_list_arena,
                parent,
                arena,
                caches,
                errors,
                &scratch,
            );

            if (instr_result) |err| {
                // If a single instruction fails to parse, then skip parsing the rest of them.
                try errors.append(err);
                _ = contents.empty();
                break :parse_body;
            }

            const parent_tag = keyword.tag(tree);

            const BlockBranch = struct {
                contents: sexpr.Parser,
                /// If `!contents.isEmpty()`, then this *must* be set.
                keyword: sexpr.TokenId.Opt,
                /// Must *not* be accessed if `keyword == .none`.
                list: sexpr.List.Id,

                const empty = @This(){
                    .contents = sexpr.Parser.init(&[0]sexpr.Value{}),
                    .keyword = .none,
                    .list = undefined,
                };
            };

            var then_branch = BlockBranch.empty;
            var else_branch = BlockBranch.empty;
            if (parent_tag == .keyword_if) missing_then: {
                var then_index = list_contents.remaining.len;
                for (list_contents.remaining, 0..) |value, i| {
                    const then_list = value.getList() orelse continue;
                    var then_contents = sexpr.Parser.init(then_list.contents(tree).values(tree));
                    const then_keyword = (then_contents.parseValue() catch continue).getAtom() orelse continue;

                    if (then_keyword.tag(tree) != .keyword_then) continue;

                    then_index = i;
                    then_branch = .{
                        .keyword = sexpr.TokenId.Opt.init(then_keyword),
                        .contents = then_contents,
                        .list = then_list,
                    };

                    break;
                }

                if (then_index == list_contents.remaining.len) break :missing_then;

                var remaining_branches = sexpr.Parser.init(list_contents.remaining[then_index + 1 ..]);
                list_contents.remaining = list_contents.remaining[0..then_index];

                no_else: {
                    const else_list: sexpr.List.Id = switch (remaining_branches.parseList() catch break :no_else) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            break :no_else;
                        },
                    };

                    var else_contents = sexpr.Parser.init(else_list.contents(tree).values(tree));
                    const else_keyword = switch (else_contents.parseAtomInList(.keyword_else, else_list)) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            break :no_else;
                        },
                    };

                    if (else_keyword.tag(tree) != .keyword_else) {
                        try errors.append(
                            Error.initExpectedToken(
                                sexpr.Value.initAtom(else_keyword),
                                .keyword_else,
                                .at_value,
                            ),
                        );

                        break :no_else;
                    }

                    else_branch = .{
                        .keyword = sexpr.TokenId.Opt.init(else_keyword),
                        .contents = else_contents,
                        .list = else_list,
                    };
                }

                try remaining_branches.expectEmpty(errors);
            }

            // Recursive call!
            _ = scratch.reset(.retain_capacity);
            var folded_instructions = try parseInstrList(
                &list_contents,
                tree,
                list,
                arena,
                caches,
                instr_list_arena,
                instr_list_pool,
                errors,
                &scratch,
            );

            std.debug.assert(list_contents.isEmpty());

            // Reserve space to avoid allocating in the `append()` calls.
            try output.growCapacityAdditionalWords(
                instr_list_arena,
                switch (parent_tag) {
                    .keyword_block, .keyword_loop => 2,
                    .keyword_if => if (else_branch.keyword.some) 3 else 2,
                    else => 1,
                },
            );

            // Append a block instruction before its contents.
            switch (parent_tag) {
                .keyword_block, .keyword_loop => {
                    try output.appendMovedList(instr_list_arena, &parent_output, instr_list_pool);
                    parent_output = undefined;
                },
                .keyword_else => unreachable,
                else => {},
            }

            // Append the folded instructions.
            try output.appendMovedList(instr_list_arena, &folded_instructions, instr_list_pool);
            folded_instructions = undefined;

            // Append any implicit end instructions for blocks, or the "parent" of the folded instruction.
            switch (parent_tag) {
                .keyword_block, .keyword_loop => try output.appendImplicitEnd(instr_list_arena, list),
                .keyword_if => {
                    try output.appendMovedList(instr_list_arena, &parent_output, instr_list_pool);

                    if (!then_branch.keyword.some) {
                        try errors.append(Error.initMissingFoldedThen(list));
                        _ = contents.empty();
                        break :parse_body;
                    }

                    {
                        // Recursive call!
                        _ = scratch.reset(.retain_capacity);
                        var then_body: Instr.List = try parseInstrList(
                            &then_branch.contents,
                            tree,
                            list,
                            arena,
                            caches,
                            instr_list_arena,
                            instr_list_pool,
                            errors,
                            &scratch,
                        );

                        try output.appendMovedList(instr_list_arena, &then_body, instr_list_pool);
                    }

                    std.debug.assert(then_branch.contents.isEmpty());
                    then_branch = undefined;

                    if (else_branch.keyword.get()) |else_keyword| {
                        try output.append(instr_list_arena, else_keyword, Ident.Opt.none, tree);

                        // Recursive call!
                        _ = scratch.reset(.retain_capacity);
                        var else_body: Instr.List = try parseInstrList(
                            &else_branch.contents,
                            tree,
                            list,
                            arena,
                            caches,
                            instr_list_arena,
                            instr_list_pool,
                            errors,
                            &scratch,
                        );

                        try output.appendMovedList(instr_list_arena, &else_body, instr_list_pool);
                    }

                    std.debug.assert(else_branch.contents.isEmpty());
                    else_branch = undefined;

                    try output.appendImplicitEnd(instr_list_arena, list);
                },
                .keyword_then, .keyword_else => unreachable,
                else => {
                    try output.appendMovedList(instr_list_arena, &parent_output, instr_list_pool);

                    std.debug.assert(else_branch.contents.isEmpty());
                    std.debug.assert(!else_branch.keyword.some);
                    std.debug.assert(then_branch.contents.isEmpty());
                    std.debug.assert(!then_branch.keyword.some);
                },
            }
        }
    }

    std.debug.assert(contents.isEmpty());

    if (block_stack.len > 0) {
        try errors.append(Error.initExpectedToken(previous_instr.?, .keyword_end, .at_value));
    }

    return output;
}

pub fn parseContents(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
    scratch: *ArenaAllocator,
) error{OutOfMemory}!Expr {
    _ = scratch.reset(.retain_capacity);
    var instr_list_pool = Instr.List.Pool{};
    var actual_scratch = ArenaAllocator.init(scratch.allocator());
    var parsed_instructions = try parseInstrList(
        contents,
        tree,
        parent,
        arena,
        caches,
        scratch,
        &instr_list_pool,
        errors,
        &actual_scratch,
    );

    return .{
        .count = parsed_instructions.count,
        .contents = try parsed_instructions.moveToIndexedArena(arena),
    };
}

// TODO: Make a non-recursive instruction parser
pub fn parseContentsUnused(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arenas: *IndexedArena,
    caches: *Caches,
    instr_arena: *ArenaAllocator,
    errors: *Error.List,
) error{OutOfMemory}!Expr {
    const FoldedInstr = struct {
        /// The plain instruction that is placed after all of the folded ones.
        end: Instr,
        /// Allocated within the `instr_arena`.
        parsed: Parsed,
        list: sexpr.List.Id,
        unmatched_blocks: u32,
        remaining: sexpr.Parser,

        const Parsed = std.SegmentedList(Instr, 0);
    };

    // These are allocated within the `instr_arena`.
    var output = std.SegmentedList(Instr, 16){};
    var stack = std.SegmentedList(FoldedInstr, 4){};
    var parsed_cache = std.SegmentedList(FoldedInstr.Parsed, 2){};

    _ = instr_arena;
    _ = &stack;

    var current_contents: *sexpr.Parser = contents;
    while (@as(?sexpr.Value, current_contents.parseValue() catch null)) |instr_value| {
        // If value is a list, begin processing a folded instruction.
        if (instr_value.getList()) |folded_list| {
            var list_contents = sexpr.Parser.init(folded_list.contents().values(tree));

            // TODO: Parse the keyword!

            // TODO: If folded `if`, check for `then` and `else` and add them to the `stack` (might need a queue or extra list in FoldedInstr?).
            // - maybe make a new SegmentedList, a queue that is checked before the parsed_cache?

            // TODO: Get parser from `folded_list`, then read the keyword
            _ = &list_contents;
        } else {
            // Plain instructions must be appended to the latest stack entry.
            const keyword: sexpr.TokenId = instr_value.getAtom().?;
            const instr_parent = if (parsed_cache.len == 0) parent else parsed_cache.at(parsed_cache.len - 1).list;

            const instr_result = try Instr.parseArgs(
                keyword,
                current_contents,
                tree,
                instr_parent,
                arenas,
                caches,
                errors,
            );

            const instr = switch (instr_result) {
                .ok => |ok| ok,
                .err => |err| {
                    // If a single instruction fails to parse, then skip parsing the rest of them.
                    try errors.append(err);
                    // TODO: Hmm, need some way to stop parsing instructions in the current context!
                },
            };

            //output.append
            _ = instr;
        }

        if (current_contents.isEmpty()) {
            // TODO: Get next thing from stack??
        }
    }

    std.debug.assert(contents.isEmpty());

    const instructions = try arenas.out.allocator().alloc(Instr, output.len);
    errdefer comptime unreachable;
    output.writeToSlice(instructions, 0);
    return .{ .instructions = instructions };
}

//pub const Iterator
