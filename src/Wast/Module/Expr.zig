const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;

const Caches = @import("../Caches.zig");

const Instr = @import("Instr.zig");

instructions: IndexedArena.Slice(Instr),

const Expr = @This();

const InstrList = std.SegmentedList(Instr, 2);
const InstrListCache = std.SegmentedList(InstrList, 2);

fn parseInstrList(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    instr_list_arena: *ArenaAllocator,
    instr_list_cache: *InstrListCache,
    errors: *Error.List,
) error{OutOfMemory}!InstrList {
    var output: InstrList = instr_list_cache.pop() orelse .{};
    std.debug.assert(output.len == 0);

    const output_capacity = std.math.add(
        usize,
        output.len,
        (contents.remaining.len +| 7) / 8,
    ) catch return error.OutOfMemory;

    // Avoids an integer overflow panic.
    if (output_capacity > InstrList.prealloc_count) {
        try output.growCapacity(
            instr_list_arena.allocator(),
            output_capacity,
        );
    }

    var block_nesting_level: u32 = 0;
    var previous_instr: ?sexpr.Value = null;
    while (@as(?sexpr.Value, contents.parseValue() catch null)) |instr_value| {
        previous_instr = instr_value;
        if (instr_value.getAtom()) |keyword| {
            // Parse a plain instruction.
            const instr_result = try Instr.parseArgs(
                keyword,
                contents,
                tree,
                parent,
                arena,
                caches,
                errors,
            );

            const instr = switch (instr_result) {
                .ok => |ok| ok,
                .err => |err| {
                    // If a single instruction fails to parse, then skip parsing the rest of them.
                    try errors.append(err);
                    _ = contents.empty();
                    break;
                },
            };

            switch (keyword.tag(tree)) {
                .keyword_block, .keyword_loop, .keyword_if => {
                    block_nesting_level = std.math.add(u32, block_nesting_level, 1) catch
                        return error.OutOfMemory;
                },
                // TODO: Darn, have to check for more than one else, have a real stack instead of a counter
                .keyword_else => unreachable,
                .keyword_end => {
                    block_nesting_level = std.math.sub(u32, block_nesting_level, 1) catch {
                        try errors.append(
                            Error.initUnexpectedValue(
                                sexpr.Value.initAtom(keyword),
                                .at_value,
                            ),
                        );

                        _ = contents.empty();
                        break;
                    };
                },
                else => {},
            }

            try output.append(instr_list_arena.allocator(), instr);
        } else {
            // Parse a folded instruction.
            var list = instr_value.getList().?;
            var list_contents = sexpr.Parser.init(list.contents(tree).values(tree));

            const keyword: sexpr.TokenId = switch (list_contents.parseAtomInList(.keyword_unknown, parent)) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    _ = contents.empty();
                    break;
                },
            };

            const instr_result = try Instr.parseArgs(
                keyword,
                &list_contents,
                tree,
                parent,
                arena,
                caches,
                errors,
            );

            const parent_instr = switch (instr_result) {
                .ok => |ok| ok,
                .err => |err| {
                    // If a single instruction fails to parse, then skip parsing the rest of them.
                    try errors.append(err);
                    _ = contents.empty();
                    break;
                },
            };

            // TODO: Check for `(then)` and `(else)` branches.

            // Recursive call!
            var folded_instructions: InstrList = try parseInstrList(
                &list_contents,
                tree,
                list,
                arena,
                caches,
                instr_list_arena,
                instr_list_cache,
                errors,
            );

            defer {
                folded_instructions.clearRetainingCapacity(); // .len = 0;
                instr_list_cache.append(instr_list_arena.allocator(), folded_instructions) catch {};
            }

            std.debug.assert(list_contents.isEmpty());

            try output.setCapacity(
                instr_list_arena.allocator(),
                std.math.add(
                    usize,
                    output.len,
                    std.math.add(usize, folded_instructions.len, 1) catch return error.OutOfMemory,
                ) catch return error.OutOfMemory,
            );

            var instrs_append = folded_instructions.constIterator(0);
            while (instrs_append.next()) |instr_to_append| {
                output.append(undefined, instr_to_append.*) catch unreachable;
            }

            output.append(undefined, parent_instr) catch unreachable;

            // TODO: Check for special block instructions, then add an implicit `end`.
        }
    }

    std.debug.assert(contents.isEmpty());

    if (block_nesting_level > 0) {
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
    var instr_list_cache: InstrListCache = .{};
    var parsed_instructions = try parseInstrList(
        contents,
        tree,
        parent,
        arena,
        caches,
        scratch,
        &instr_list_cache,
        errors,
    );

    const instructions = try arena.dupeSegmentedList(Instr, 2, &parsed_instructions);
    return .{ .instructions = instructions };
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
