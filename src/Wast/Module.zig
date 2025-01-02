const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../IndexedArena.zig");

const sexpr = @import("sexpr.zig");
const Error = sexpr.Error;
const ParseResult = sexpr.Parser.Result;

const Ident = @import("Ident.zig");
const Name = @import("Name.zig");

const Caches = @import("Caches.zig");

name: Ident,
format_keyword: sexpr.TokenId.Opt,
format: Format,

const Module = @This();

pub const Format = union {
    text: IndexedArena.Idx(Text),
    binary: IndexedArena.Idx(Binary),
    quote: IndexedArena.Idx(Quote),
};

/// A module in the [WebAssembly Text] format.
///
/// [WebAssembly Text]: https://webassembly.github.io/spec/core/index.html
pub const Text = struct {
    fields: IndexedArena.Slice(Field),

    pub const Field = struct {
        keyword: sexpr.TokenId,
        contents: Contents,
    };

    pub const Contents = union {
        func: IndexedArena.Idx(Func),
    };

    pub const ValType = struct {
        keyword: sexpr.TokenId, // sexpr.Value // GC proposal support
        type: Types,

        const Types = union { simple: void };

        pub fn parse(parser: *sexpr.Parser, tree: *const sexpr.Tree, parent: sexpr.List.Id) ParseResult(ValType) {
            const atom: sexpr.TokenId = switch (parser.parseAtomInList(.keyword_unknown, parent)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            switch (atom.tag(tree)) {
                .keyword_i32, .keyword_i64, .keyword_f32, .keyword_f64, .keyword_funcref, .keyword_externref => {},
                else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(atom), .at_value) },
            }

            return .{ .ok = .{ .keyword = atom, .type = .{ .simple = {} } } };
        }
    };

    pub const Export = struct {
        /// The `export` keyword.
        keyword: sexpr.TokenId,
        name: Name,

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            arena: *IndexedArena,
            caches: *Caches,
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            scratch: *ArenaAllocator,
        ) error{OutOfMemory}!ParseResult(Export) {
            std.debug.assert(keyword.tag(tree) == .keyword_export);
            return switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
                .ok => |name| .{ .ok = Export{ .keyword = keyword, .name = name } },
                .err => |err| .{ .err = err },
            };
        }
    };

    pub const ParamOrLocal = struct {
        /// The `param` or `local` keyword.
        keyword: sexpr.TokenId,
        /// Must be `.none` if `types.len > 1`.
        id: Ident,
        types: IndexedArena.Slice(ValType),

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            arena: *IndexedArena,
            caches: *Caches,
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            errors: *Error.List,
        ) error{OutOfMemory}!ParamOrLocal {
            const ident = switch (try Ident.parse(contents, tree, caches.allocator, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    return .{ .keyword = keyword, .id = .none, .types = .empty };
                },
            };

            var types = try IndexedArena.BoundedArrayList(ValType).initCapacity(arena, contents.remaining.len);
            while (!contents.isEmpty()) {
                const val_type = switch (ValType.parse(contents, tree, parent)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                types.appendAssumeCapacity(arena, val_type);
            }

            return .{ .keyword = keyword, .id = ident, .types = types.items };
        }
    };

    pub const Param = ParamOrLocal;

    pub const Result = struct {
        keyword: sexpr.TokenId,
        types: IndexedArena.Slice(ValType),

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            arena: *IndexedArena,
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            errors: *Error.List,
        ) error{OutOfMemory}!Text.Result {
            std.debug.assert(keyword.tag(tree) == .keyword_result);

            var types = try IndexedArena.BoundedArrayList(ValType).initCapacity(arena, contents.remaining.len);
            while (!contents.isEmpty()) {
                const val_type = switch (ValType.parse(contents, tree, parent)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                types.appendAssumeCapacity(arena, val_type);
            }

            return .{ .keyword = keyword, .types = types.items };
        }
    };

    pub const Local = ParamOrLocal;

    pub const BlockType = union {
        // empty,
        // valtype: ValType, // TODO: Optimize, ValType has unused bit which can be used for empty case
        // inline_type: struct { parameters: CompactMultiSlice(Param), results: CompactMultiSlice(Text.Result), },
    };

    pub const ImportName = struct {
        /// The `import` keyword.
        keyword: sexpr.TokenId,
        module: Name,
        name: Name,

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            arena: *IndexedArena,
            caches: *Caches,
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            scratch: *ArenaAllocator,
        ) error{OutOfMemory}!ParseResult(ImportName) {
            std.debug.assert(keyword.tag(tree) == .keyword_import);

            const module = switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            _ = scratch.reset(.retain_capacity);
            const name = switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            return .{ .ok = ImportName{ .keyword = keyword, .module = module, .name = name } };
        }
    };

    pub const Instr = struct {
        /// For most instructions, this is the `atom` corresponding to the keyword.
        ///
        /// For implicit `end` instuctions in folded instructions, this refers to the list
        /// corresponding to the folded instruction.
        keyword: sexpr.Value,
        args: Args,

        // comptime { std.debug.assert(@sizeOf(Instr) == 8); }

        pub const Args = union {
            none: void,
            end: Ident,
            @"local.get": Ident,
            @"i32.const": i32,
            @"i64.const": i64,
        };

        pub fn parseArgs(
            keyword: sexpr.TokenId,
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            parent: sexpr.List.Id,
            arena: *IndexedArena,
            caches: *Caches,
            errors: *Error.List,
        ) error{OutOfMemory}!ParseResult(Instr) {
            _ = arena;
            const args: Args = args: switch (keyword.tag(tree)) {
                .keyword_nop,
                .keyword_unreachable,
                .keyword_drop,
                .@"keyword_i32.eqz",
                .@"keyword_i32.eq",
                .@"keyword_i32.ne",
                .@"keyword_i32.lt_s",
                .@"keyword_i32.lt_u",
                .@"keyword_i32.gt_s",
                .@"keyword_i32.gt_u",
                .@"keyword_i32.le_s",
                .@"keyword_i32.le_u",
                .@"keyword_i32.ge_s",
                .@"keyword_i32.ge_u",
                .@"keyword_i64.eqz",
                .@"keyword_i64.eq",
                .@"keyword_i64.ne",
                .@"keyword_i64.lt_s",
                .@"keyword_i64.lt_u",
                .@"keyword_i64.gt_s",
                .@"keyword_i64.gt_u",
                .@"keyword_i64.le_s",
                .@"keyword_i64.le_u",
                .@"keyword_i64.ge_s",
                .@"keyword_i64.ge_u",
                .@"keyword_f32.eq",
                .@"keyword_f32.ne",
                .@"keyword_f32.lt",
                .@"keyword_f32.gt",
                .@"keyword_f32.le",
                .@"keyword_f32.ge",
                .@"keyword_f64.eq",
                .@"keyword_f64.ne",
                .@"keyword_f64.lt",
                .@"keyword_f64.gt",
                .@"keyword_f64.le",
                .@"keyword_f64.ge",
                .@"keyword_i32.clz",
                .@"keyword_i32.ctz",
                .@"keyword_i32.popcnt",
                .@"keyword_i32.add",
                .@"keyword_i32.sub",
                .@"keyword_i32.mul",
                .@"keyword_i32.div_s",
                .@"keyword_i32.div_u",
                .@"keyword_i32.rem_s",
                .@"keyword_i32.rem_u",
                .@"keyword_i32.and",
                .@"keyword_i32.or",
                .@"keyword_i32.xor",
                .@"keyword_i32.shl",
                .@"keyword_i32.shr_s",
                .@"keyword_i32.shr_u",
                .@"keyword_i32.rotl",
                .@"keyword_i32.rotr",
                .@"keyword_i64.clz",
                .@"keyword_i64.ctz",
                .@"keyword_i64.popcnt",
                .@"keyword_i64.add",
                .@"keyword_i64.sub",
                .@"keyword_i64.mul",
                .@"keyword_i64.div_s",
                .@"keyword_i64.div_u",
                .@"keyword_i64.rem_s",
                .@"keyword_i64.rem_u",
                .@"keyword_i64.and",
                .@"keyword_i64.or",
                .@"keyword_i64.xor",
                .@"keyword_i64.shl",
                .@"keyword_i64.shr_s",
                .@"keyword_i64.shr_u",
                .@"keyword_i64.rotl",
                .@"keyword_i64.rotr",
                .@"keyword_f32.abs",
                .@"keyword_f32.neg",
                .@"keyword_f32.ceil",
                .@"keyword_f32.floor",
                .@"keyword_f32.trunc",
                .@"keyword_f32.nearest",
                .@"keyword_f32.sqrt",
                .@"keyword_f32.add",
                .@"keyword_f32.sub",
                .@"keyword_f32.mul",
                .@"keyword_f32.div",
                .@"keyword_f32.min",
                .@"keyword_f32.max",
                .@"keyword_f32.copysign",
                .@"keyword_f64.abs",
                .@"keyword_f64.neg",
                .@"keyword_f64.ceil",
                .@"keyword_f64.floor",
                .@"keyword_f64.trunc",
                .@"keyword_f64.nearest",
                .@"keyword_f64.sqrt",
                .@"keyword_f64.add",
                .@"keyword_f64.sub",
                .@"keyword_f64.mul",
                .@"keyword_f64.div",
                .@"keyword_f64.min",
                .@"keyword_f64.max",
                .@"keyword_f64.copysign",
                .@"keyword_i32.wrap_i64",
                .@"keyword_i32.trunc_f32_s",
                .@"keyword_i32.trunc_f32_u",
                .@"keyword_i32.trunc_f64_s",
                .@"keyword_i32.trunc_f64_u",
                .@"keyword_i64.extend_i32_s",
                .@"keyword_i64.extend_i32_u",
                .@"keyword_i64.trunc_f32_s",
                .@"keyword_i64.trunc_f32_u",
                .@"keyword_i64.trunc_f64_s",
                .@"keyword_i64.trunc_f64_u",
                .@"keyword_f32.convert_i32_s",
                .@"keyword_f32.convert_i32_u",
                .@"keyword_f32.convert_i64_s",
                .@"keyword_f32.convert_i64_u",
                .@"keyword_f32.demote_f64",
                .@"keyword_f64.convert_i32_s",
                .@"keyword_f64.convert_i32_u",
                .@"keyword_f64.convert_i64_s",
                .@"keyword_f64.convert_i64_u",
                .@"keyword_f64.promote_f32",
                .@"keyword_i32.reinterpret_f32",
                .@"keyword_i64.reinterpret_f64",
                .@"keyword_f32.reinterpret_i32",
                .@"keyword_f64.reinterpret_i64",
                .@"keyword_i32.extend8_s",
                .@"keyword_i32.extend16_s",
                .@"keyword_i64.extend8_s",
                .@"keyword_i64.extend16_s",
                .@"keyword_i64.extend32_s",
                .@"keyword_i32.trunc_sat_f32_s",
                .@"keyword_i32.trunc_sat_f32_u",
                .@"keyword_i32.trunc_sat_f64_s",
                .@"keyword_i32.trunc_sat_f64_u",
                .@"keyword_i64.trunc_sat_f32_s",
                .@"keyword_i64.trunc_sat_f32_u",
                .@"keyword_i64.trunc_sat_f64_s",
                .@"keyword_i64.trunc_sat_f64_u",
                => Args{ .none = {} },
                .@"keyword_local.get" => {
                    const local = switch (try Ident.parseRequired(contents, tree, parent, caches.allocator, &caches.ids)) {
                        .ok => |ok| ok,
                        .err => |err| return .{ .err = err },
                    };

                    break :args Args{ .@"local.get" = local };
                },
                .@"keyword_i32.const" => {
                    const literal: i32 = literal: switch (contents.parseUninterpretedIntegerInList(i32, parent, tree)) {
                        .ok => |ok| ok.value,
                        .err => |err| {
                            try errors.append(err);
                            break :literal 0;
                        },
                    };

                    break :args Args{ .@"i32.const" = literal };
                },
                .@"keyword_i64.const" => {
                    const literal: i64 = literal: switch (contents.parseUninterpretedIntegerInList(i64, parent, tree)) {
                        .ok => |ok| ok.value,
                        .err => |err| {
                            try errors.append(err);
                            break :literal 0;
                        },
                    };

                    break :args Args{ .@"i64.const" = literal };
                },
                // Unknown instruction.
                else => return .{
                    .err = Error.initExpectedToken(sexpr.Value.initAtom(keyword), .keyword_unknown, .at_value),
                },
            };

            return .{ .ok = Instr{ .keyword = sexpr.Value.initAtom(keyword), .args = args } };
        }
    };

    pub const Expr = struct {
        instructions: IndexedArena.Slice(Instr),

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
    };

    pub const Func = struct {
        id: Ident,
        inline_exports: IndexedArena.Slice(Export),
        inline_import: IndexedArena.Idx(ImportName).Opt,
        parameters: IndexedArena.Slice(Param),
        results: IndexedArena.Slice(Text.Result),
        locals: IndexedArena.Slice(Local),
        body: Expr,

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            parent: sexpr.List.Id,
            arena: *IndexedArena,
            caches: *Caches,
            errors: *Error.List,
            alloca: *ArenaAllocator,
        ) error{OutOfMemory}!ParseResult(Func) {
            // Arena used for allocations that span the lifetime of this function call.
            _ = alloca.reset(.retain_capacity);

            var scratch = ArenaAllocator.init(alloca.allocator());

            const id = switch (try Ident.parse(contents, tree, caches.allocator, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            // All of the `SegmentedList`s are allocated in `alloca`.
            var inline_exports = std.SegmentedList(Export, 1){};
            var inline_import: IndexedArena.Idx(ImportName).Opt = .none;
            var parameters = std.SegmentedList(Param, 4){};
            var results = std.SegmentedList(Text.Result, 1){};
            var locals = std.SegmentedList(Local, 4){};

            before_body: {
                var state: enum {
                    start,
                    exports,
                    import,
                    parameters,
                    results,
                    locals,

                    const State = @This();

                    fn advance(current: *State, to: State) bool {
                        if (@intFromEnum(current.*) <= @intFromEnum(to)) {
                            current.* = to;
                            return true;
                        } else {
                            return false;
                        }
                    }
                } = .start;

                var lookahead = contents.*;
                while (lookahead.parseValue() catch null) |maybe_list| {
                    _ = scratch.reset(.retain_capacity);

                    const field_list: sexpr.List.Id = maybe_list.getList() orelse break :before_body;
                    var list_contents = sexpr.Parser.init(field_list.contents(tree).values(tree));

                    var keyword = (list_contents.parseValue() catch break :before_body).getAtom() orelse break :before_body;
                    switch (keyword.tag(tree)) {
                        .keyword_export => {
                            // Treat an incorrect order of these as an unknown instruction.
                            if (!state.advance(.exports)) break :before_body;

                            const export_result = try Export.parseContents(
                                &list_contents,
                                tree,
                                arena,
                                caches,
                                keyword,
                                field_list,
                                &scratch,
                            );

                            try inline_exports.append(
                                alloca.allocator(),
                                switch (export_result) {
                                    .ok => |ok| ok,
                                    .err => |err| return .{ .err = err },
                                },
                            );
                        },
                        .keyword_import => {
                            if (!state.advance(.import)) break :before_body;

                            if (!inline_import.some) {
                                const import_result = try ImportName.parseContents(
                                    &list_contents,
                                    tree,
                                    arena,
                                    caches,
                                    keyword,
                                    field_list,
                                    &scratch,
                                );

                                switch (import_result) {
                                    .ok => |ok| {
                                        const import = try arena.create(ImportName);
                                        import.set(arena, ok);
                                        inline_import = IndexedArena.Idx(ImportName).Opt.init(import);
                                    },
                                    .err => |err| try errors.append(err),
                                }
                            } else {
                                // An extra inline import is not fatal.
                                try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value));
                            }
                        },
                        .keyword_param => {
                            if (!state.advance(.parameters)) break :before_body;

                            const param = try Param.parseContents(
                                &list_contents,
                                tree,
                                arena,
                                caches,
                                keyword,
                                field_list,
                                errors,
                            );

                            std.debug.assert(list_contents.isEmpty());

                            try parameters.append(alloca.allocator(), param);
                        },
                        .keyword_result => {
                            if (!state.advance(.results)) break :before_body;

                            const result = try Text.Result.parseContents(
                                &list_contents,
                                tree,
                                arena,
                                keyword,
                                field_list,
                                errors,
                            );

                            std.debug.assert(list_contents.isEmpty());

                            try results.append(alloca.allocator(), result);
                        },
                        .keyword_local => {
                            if (!state.advance(.locals)) break :before_body;

                            const local = try Local.parseContents(
                                &list_contents,
                                tree,
                                arena,
                                caches,
                                keyword,
                                field_list,
                                errors,
                            );

                            std.debug.assert(list_contents.isEmpty());

                            try locals.append(alloca.allocator(), local);
                        },
                        else => break :before_body,
                    }

                    contents.* = lookahead;
                    try list_contents.expectEmpty(errors);
                }
            }

            scratch = undefined;

            return .{
                .ok = Func{
                    .id = id,
                    .inline_exports = try arena.dupeSegmentedList(Export, 1, &inline_exports),
                    .inline_import = inline_import,
                    .parameters = try arena.dupeSegmentedList(Param, 4, &parameters),
                    .results = try arena.dupeSegmentedList(Text.Result, 1, &results),
                    .locals = try arena.dupeSegmentedList(Local, 4, &locals),
                    .body = try Expr.parseContents(
                        contents,
                        tree,
                        parent,
                        arena,
                        caches,
                        errors,
                        alloca,
                    ),
                },
            };
        }
    };

    pub fn parseFields(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        errors: *Error.List,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!IndexedArena.Slice(Field) {
        var fields = try IndexedArena.BoundedArrayList(Field).initCapacity(arena, contents.remaining.len);

        arena.ensureUnusedCapacityForBytes(@import("../size.zig").averageOfFields(Field) *| fields.capacity) catch {};

        while (contents.parseList() catch null) |field_list_result| {
            const field_list: sexpr.List.Id = switch (field_list_result) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    continue;
                },
            };

            var field_contents = sexpr.Parser.init(field_list.contents(tree).values(tree));
            const field_keyword = switch (field_contents.parseAtomInList(.keyword_unknown, field_list)) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    continue;
                },
            };

            _ = scratch.reset(.retain_capacity);
            const module_field: Contents = field: switch (field_keyword.tag(tree)) {
                .keyword_func => {
                    const func = try arena.create(Func);

                    const func_result = try Func.parseContents(
                        &field_contents,
                        tree,
                        field_list,
                        arena,
                        caches,
                        errors,
                        scratch,
                    );

                    func.set(
                        arena,
                        switch (func_result) {
                            .ok => |ok| ok,
                            .err => |err| {
                                try errors.append(err);
                                continue;
                            },
                        },
                    );

                    break :field .{ .func = func };
                },
                else => {
                    try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(field_keyword), .at_value));
                    continue;
                },
            };

            try field_contents.expectEmpty(errors);

            fields.appendAssumeCapacity(
                arena,
                .{ .keyword = field_keyword, .contents = module_field },
            );
        }

        std.debug.assert(contents.isEmpty());

        return fields.items;
    }
};

pub const Binary = struct {
    contents: IndexedArena.Slice(String),
};

pub const Quote = struct {
    contents: IndexedArena.Slice(String),
};

pub const String = struct {
    token: sexpr.TokenId,

    /// The contents of the string literal without translating escape sequences.
    pub fn rawContents(string: String, tree: *const sexpr.Tree) []const u8 {
        switch (string.token.tag(tree)) {
            .string, .string_raw => {},
            else => unreachable,
        }

        const contents = string.token.contents(tree);
        return contents[1 .. contents.len - 1];
    }
};

pub fn parseContents(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
    scratch: *ArenaAllocator,
) error{OutOfMemory}!ParseResult(Module) {
    const name: Ident = switch (try Ident.parse(contents, tree, caches.allocator, &caches.ids)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    var format_keyword = sexpr.TokenId.Opt.none;
    const format: Format = format: {
        text: {
            var lookahead = contents.*;
            const peeked_value = lookahead.parseValue() catch break :text;
            const peeked_atom = peeked_value.getAtom() orelse break :text;
            const format_tag = peeked_atom.tag(tree);
            switch (format_tag) {
                .keyword_binary, .keyword_quote => format_keyword = sexpr.TokenId.Opt.init(peeked_atom),
                else => return .{
                    .err = Error.initUnexpectedValue(sexpr.Value.initAtom(peeked_atom), .at_value),
                },
            }

            contents.* = lookahead;
            lookahead = undefined;

            var strings = try IndexedArena.BoundedArrayList(String).initCapacity(arena, contents.remaining.len);
            for (0..strings.capacity) |_| {
                const string_atom: sexpr.TokenId = switch (contents.parseAtom(.string) catch break) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                switch (string_atom.tag(tree)) {
                    .string, .string_raw => strings.appendAssumeCapacity(arena, String{ .token = string_atom }),
                    else => try errors.append(
                        Error.initExpectedToken(sexpr.Value.initAtom(string_atom), .string, .at_value),
                    ),
                }
            }

            std.debug.assert(contents.isEmpty());

            switch (format_tag) {
                .keyword_binary => {
                    const binary = try arena.create(Binary);
                    binary.set(arena, .{ .contents = strings.items });
                    break :format .{ .binary = binary };
                },
                .keyword_quote => {
                    const quoted = try arena.create(Quote);
                    quoted.set(arena, .{ .contents = strings.items });
                    break :format .{ .quote = quoted };
                },
                else => unreachable,
            }

            comptime unreachable;
        }

        const wat = try arena.create(Module.Text);
        _ = scratch.reset(.retain_capacity);
        wat.set(
            arena,
            .{
                .fields = try Text.parseFields(
                    contents,
                    tree,
                    arena,
                    caches,
                    errors,
                    scratch,
                ),
            },
        );

        break :format .{ .text = wat };
    };

    return .{ .ok = Module{ .name = name, .format_keyword = format_keyword, .format = format } };
}

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    arena: *IndexedArena,
    caches: *Caches,
    parent: sexpr.List.Id,
    errors: *Error.List,
    scratch: *ArenaAllocator,
) error{OutOfMemory}!ParseResult(Module) {
    const module_list: sexpr.List.Id = switch (parser.parseListInList(parent)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    var contents = sexpr.Parser.init(module_list.contents(tree).values(tree));

    const module_token: sexpr.TokenId = switch (contents.parseAtomInList(.keyword_module, module_list)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    switch (module_token.tag(tree)) {
        .keyword_module => {
            const module = try parseContents(&contents, tree, arena, caches, errors, scratch);
            if (module == .ok)
                try contents.expectEmpty(errors);

            return module;
        },
        else => return .{
            .err = Error.initExpectedToken(sexpr.Value.initAtom(module_token), .keyword_module, .at_value),
        },
    }
}
