const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const sexpr = @import("sexpr.zig");
const Arenas = @import("Arenas.zig");
const Caches = @import("Caches.zig");
const Ident = @import("Ident.zig");
const Name = @import("Name.zig");
const InlineTaggedUnion = @import("../inline_tagged_union.zig").InlineTaggedUnion;
const CompactMultiSlice = @import("../compact_multi_slice.zig").CompactMultiSlice;
const Error = sexpr.Error;
const ParseResult = sexpr.Parser.Result;

// keyword: sexpr.TokenId,
name: Ident,
format: Format.Ptr(.@"const"),

const Module = @This();

pub const Format = InlineTaggedUnion(union {
    text: Text,
    binary: Binary,
    quote: Quote,
});

/// A module in the [WebAssembly Text] format.
///
/// [WebAssembly Text]: https://webassembly.github.io/spec/core/index.html
pub const Text = struct {
    fields: std.MultiArrayList(Field),

    pub const Field = struct {
        keyword: sexpr.TokenId,
        contents: Contents.Ptr(.@"const"),
    };

    pub const Contents = InlineTaggedUnion(union {
        func: Func,
    });

    pub const ValType = struct {
        keyword: sexpr.TokenId,
        type: Types,

        const Types = enum {
            i32,
            i64,
            f32,
            f64,
            // v128,
            funcref,
            externref,
        };

        pub fn parse(parser: *sexpr.Parser, tree: *const sexpr.Tree, parent: sexpr.List.Id) ParseResult(ValType) {
            const atom: sexpr.TokenId = switch (parser.parseAtomInList(.keyword_unknown, parent)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            const @"type": Types = switch (atom.tag(tree)) {
                .keyword_i32 => Types.i32,
                .keyword_i64 => Types.i64,
                .keyword_f32 => Types.f32,
                .keyword_f64 => Types.f64,
                .keyword_funcref => Types.funcref,
                .keyword_externref => Types.externref,
                else => return .{
                    .err = Error.initUnexpectedValue(sexpr.Value.initAtom(atom), .at_value),
                },
            };

            return .{ .ok = .{ .keyword = atom, .type = @"type" } };
        }

        const SegmentedList = std.SegmentedList(ValType, 8);

        pub const Range = struct {
            start: u32,
            count: u32,

            pub fn slice(
                range: Range,
                types: *const CompactMultiSlice(ValType),
                comptime field: CompactMultiSlice(ValType).Field,
            ) std.meta.fieldInfo(ValType, field).type {
                return types.slice().items(field)[range.start..][0..range.count];
            }
        };
    };

    pub const Export = struct {
        /// The `export` keyword.
        keyword: sexpr.TokenId,
        name: Name,

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            name_cache: *Name.Cache,
            arenas: *Arenas,
        ) error{OutOfMemory}!ParseResult(Export) {
            return switch (try Name.parse(contents, tree, arenas, name_cache, parent)) {
                .ok => |name| .{ .ok = Export{ .keyword = keyword, .name = name } },
                .err => |err| .{ .err = err },
            };
        }
    };

    pub const ParamOrLocal = struct {
        /// The `param` or `local` keyword.
        keyword: sexpr.TokenId,
        inner: struct {
            /// Must be `.none` if `.count > 1`
            id: Ident,
            types: ValType.Range,
        },

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            id_cache: *Ident.Cache,
            types_arena: *ArenaAllocator,
            types: *ValType.SegmentedList,
            arenas: *Arenas,
            errors: *Error.List,
        ) error{OutOfMemory}!ParamOrLocal {
            const ident = switch (try Ident.parse(contents, tree, arenas.parse, id_cache)) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    return .{
                        .keyword = keyword,
                        .inner = .{ .id = .none, .types = .{ .start = 0, .count = 0 } },
                    };
                },
            };

            const start_index = std.math.cast(u32, types.len) orelse return error.OutOfMemory;

            try types.growCapacity(
                types_arena.allocator(),
                std.math.add(usize, types.len, contents.remaining.len) catch return error.OutOfMemory,
            );

            while (!contents.isEmpty()) {
                const val_type = switch (ValType.parse(contents, tree, parent)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                types.append(types_arena.allocator(), val_type) catch unreachable;
            }

            return .{
                .keyword = keyword,
                .inner = .{
                    .id = ident,
                    .types = .{
                        .start = start_index,
                        .count = std.math.cast(u32, types.len - start_index) orelse return error.OutOfMemory,
                    },
                },
            };
        }
    };

    pub const Param = ParamOrLocal;

    pub const Result = struct {
        keyword: sexpr.TokenId,
        types: ValType.Range,

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            types_arena: *ArenaAllocator,
            types: *ValType.SegmentedList,
            errors: *Error.List,
        ) error{OutOfMemory}!Text.Result {
            const start_index = std.math.cast(u32, types.len) orelse return error.OutOfMemory;

            try types.growCapacity(
                types_arena.allocator(),
                std.math.add(usize, types.len, contents.remaining.len) catch return error.OutOfMemory,
            );

            while (!contents.isEmpty()) {
                const val_type = switch (ValType.parse(contents, tree, parent)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                types.append(types_arena.allocator(), val_type) catch unreachable;
            }

            return .{
                .keyword = keyword,
                .types = .{
                    .start = start_index,
                    .count = std.math.cast(u32, types.len - start_index) orelse return error.OutOfMemory,
                },
            };
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
            keyword: sexpr.TokenId,
            parent: sexpr.List.Id,
            name_cache: *Name.Cache,
            arenas: *Arenas,
        ) error{OutOfMemory}!ParseResult(ImportName) {
            const module = switch (try Name.parse(contents, tree, arenas, name_cache, parent)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            const name = switch (try Name.parse(contents, tree, arenas, name_cache, parent)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            return .{
                .ok = ImportName{
                    .keyword = keyword,
                    .module = module,
                    .name = name,
                },
            };
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
            arenas: *Arenas,
            caches: *Caches,
            errors: *Error.List,
        ) error{OutOfMemory}!ParseResult(Instr) {
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
                    const local = switch (try Ident.parseRequired(contents, tree, parent, arenas.parse, &caches.ids)) {
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

            return .{
                .ok = Instr{ .keyword = sexpr.Value.initAtom(keyword), .args = args },
            };
        }
    };

    pub const Expr = struct {
        instructions: []const Instr,

        const InstrList = std.SegmentedList(Instr, 2);
        const InstrListCache = std.SegmentedList(InstrList, 2);

        fn parseInstrList(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            parent: sexpr.List.Id,
            arenas: *Arenas,
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
                        arenas,
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
                        arenas,
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
                        arenas,
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
            arenas: *Arenas,
            instr_arena: *ArenaAllocator,
            caches: *Caches,
            errors: *Error.List,
        ) error{OutOfMemory}!Expr {
            var instr_list_cache: InstrListCache = .{};
            var parsed_instructions = try parseInstrList(
                contents,
                tree,
                parent,
                arenas,
                caches,
                instr_arena,
                &instr_list_cache,
                errors,
            );

            const instructions = try arenas.out.allocator().alloc(Instr, parsed_instructions.len);
            parsed_instructions.writeToSlice(instructions, 0);
            return .{ .instructions = instructions };
        }

        // TODO: Make a non-recursive instruction parser
        pub fn parseContentsUnused(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            parent: sexpr.List.Id,
            arenas: *Arenas,
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
        inline_exports: CompactMultiSlice(Export),
        inline_import: ?*const ImportName,
        parameters: CompactMultiSlice(Param),
        results: CompactMultiSlice(Text.Result),
        locals: CompactMultiSlice(Local),
        types: CompactMultiSlice(ValType),
        body: Expr,

        pub fn parseContents(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            parent: sexpr.List.Id,
            passed_arenas: *Arenas,
            caches: *Caches,
            errors: *Error.List,
        ) error{OutOfMemory}!ParseResult(Func) {
            // For allocations that span the lifetime of this function call.
            const alloca = passed_arenas.scratch;

            var scratch = ArenaAllocator.init(alloca.allocator());
            defer _ = passed_arenas.scratch.reset(.retain_capacity);

            var arenas = Arenas{
                .out = passed_arenas.out,
                .parse = passed_arenas.parse,
                .scratch = &scratch,
            };

            const id = switch (try Ident.parse(contents, tree, arenas.parse, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            // All of the `SegmentedList`s are allocated in `alloca`.
            var inline_exports = std.SegmentedList(Export, 1){};
            var inline_import: ?*const ImportName = null;
            var parameters = std.SegmentedList(Param, 4){};
            var results = std.SegmentedList(Text.Result, 4){};
            var locals = std.SegmentedList(Local, 4){};
            var types = ValType.SegmentedList{};

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
                    _ = arenas.scratch.reset(.retain_capacity);

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
                                keyword,
                                field_list,
                                &caches.names,
                                &arenas,
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

                            if (inline_import == null) {
                                const import_result = try ImportName.parseContents(
                                    &list_contents,
                                    tree,
                                    keyword,
                                    field_list,
                                    &caches.names,
                                    &arenas,
                                );

                                switch (import_result) {
                                    .ok => |ok| {
                                        const import = try arenas.out.allocator().create(ImportName);
                                        import.* = ok;
                                        inline_import = import;
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
                                keyword,
                                field_list,
                                &caches.ids,
                                alloca,
                                &types,
                                &arenas,
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
                                keyword,
                                field_list,
                                alloca,
                                &types,
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
                                keyword,
                                field_list,
                                &caches.ids,
                                alloca,
                                &types,
                                &arenas,
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

            _ = arenas.scratch.reset(.retain_capacity);
            const expr = try Expr.parseContents(
                contents,
                tree,
                parent,
                &arenas,
                alloca,
                caches,
                errors,
            );

            const alloc_out = arenas.out.allocator();
            return .{
                .ok = Func{
                    .id = id,
                    .inline_exports = try CompactMultiSlice(Export).cloneSegmentedList(&inline_exports, alloc_out),
                    .inline_import = inline_import,
                    .parameters = try CompactMultiSlice(Param).cloneSegmentedList(&parameters, alloc_out),
                    .results = try CompactMultiSlice(Text.Result).cloneSegmentedList(&results, alloc_out),
                    .locals = try CompactMultiSlice(Local).cloneSegmentedList(&locals, alloc_out),
                    .types = try CompactMultiSlice(ValType).cloneSegmentedList(&types, alloc_out),
                    .body = expr,
                },
            };
        }
    };

    pub fn parseFields(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arenas: *Arenas,
        caches: *Caches,
        errors: *Error.List,
    ) error{OutOfMemory}!std.MultiArrayList(Field) {
        var fields = std.MultiArrayList(Field).empty;
        try fields.ensureTotalCapacity(arenas.out.allocator(), contents.remaining.len);

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

            _ = arenas.scratch.reset(.retain_capacity);
            const module_field: Contents.Union(.@"const") = field: switch (field_keyword.tag(tree)) {
                .keyword_func => {
                    const func = try Contents.allocate(arenas.out.allocator(), .func);

                    const func_result = try Func.parseContents(
                        &field_contents,
                        tree,
                        field_list,
                        arenas,
                        caches,
                        errors,
                    );

                    func.value = switch (func_result) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    };

                    break :field .{ .func = &func.value };
                },
                else => {
                    try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(field_keyword), .at_value));
                    continue;
                },
            };

            try field_contents.expectEmpty(errors);

            try fields.append(arenas.out.allocator(), Field{
                .keyword = field_keyword,
                .contents = Contents.Ptr(.@"const").init(module_field),
            });
        }

        std.debug.assert(contents.isEmpty());

        return fields;
    }
};

pub const Binary = struct {
    keyword: sexpr.TokenId,
    contents: []const String,
};

pub const Quote = struct {
    keyword: sexpr.TokenId,
    contents: []const String,
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
    arenas: *Arenas,
    caches: *Caches,
    errors: *Error.List,
) error{OutOfMemory}!ParseResult(Module) {
    const name = switch (try Ident.parse(contents, tree, arenas.parse, &caches.ids)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    const format: Format.Union(.@"const") = format: {
        text: {
            var lookahead = contents.*;
            const peeked_value = lookahead.parseValue() catch break :text;
            const peeked_atom = peeked_value.getAtom() orelse break :text;

            const quoted_format: Format.Tag = switch (peeked_atom.tag(tree)) {
                .keyword_binary => .binary,
                .keyword_quote => .quote,
                else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(peeked_atom), .at_value) },
            };

            contents.* = lookahead;
            lookahead = undefined;

            var strings = try std.ArrayListUnmanaged(String).initCapacity(
                arenas.out.allocator(),
                contents.remaining.len,
            );

            for (0..strings.capacity) |_| {
                const string_atom: sexpr.TokenId = switch (contents.parseAtom(.string) catch break) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                switch (string_atom.tag(tree)) {
                    .string, .string_raw => strings.appendAssumeCapacity(String{ .token = string_atom }),
                    else => try errors.append(
                        Error.initExpectedToken(
                            sexpr.Value.initAtom(string_atom),
                            .string,
                            .at_value,
                        ),
                    ),
                }
            }

            std.debug.assert(contents.isEmpty());

            switch (quoted_format) {
                .text => unreachable,
                inline else => |format_tag| {
                    const quoted = try Format.allocate(arenas.out.allocator(), format_tag);
                    quoted.value = .{ .keyword = peeked_atom, .contents = strings.items };
                    break :format @unionInit(Format.Union(.@"const"), @tagName(format_tag), &quoted.value);
                },
            }
        }

        const wat = try Format.allocate(arenas.out.allocator(), .text);
        wat.value = Text{ .fields = try Text.parseFields(contents, tree, arenas, caches, errors) };
        break :format .{ .text = &wat.value };
    };

    return .{
        .ok = Module{
            .name = name,
            .format = Format.Ptr(.@"const").init(format),
        },
    };
}

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    arenas: *Arenas,
    caches: *Caches,
    parent: sexpr.List.Id,
    errors: *Error.List,
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
            const module = try parseContents(&contents, tree, arenas, caches, errors);
            if (module == .ok)
                try contents.expectEmpty(errors);
            return module;
        },
        else => return .{
            .err = Error.initExpectedToken(sexpr.Value.initAtom(module_token), .keyword_module, .at_value),
        },
    }
}
