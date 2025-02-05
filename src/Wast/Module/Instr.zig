const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../../IndexedArena.zig");

const Lexer = @import("../Lexer.zig");
const sexpr = @import("../sexpr.zig");
const TokenId = sexpr.TokenId;
const parseUninterpretedInteger = @import("../value.zig").uninterpretedInteger;
const ParseContext = sexpr.Parser.Context;

const Ident = @import("../ident.zig").Ident;
const Name = @import("../Name.zig");
const Text = @import("Text.zig");
const TypeUse = @import("TypeUse.zig");

const Caches = @import("../Caches.zig");

/// For most instructions, this is the `atom` corresponding to the keyword.
///
/// For implicit `end` instuctions in folded instructions, this refers to the list
/// corresponding to the folded instruction.
keyword: sexpr.Value,
arguments: Arguments,

const Instr = @This();

pub fn tag(instr: *const Instr, tree: *const sexpr.Tree) ?Lexer.Token.InstrTag {
    const atom = instr.keyword.getAtom() orelse return null;
    return Lexer.Token.tagToInstrTag(atom.tag(tree));
}

/// Optimizations (CSE) should ensure accessing argument information simply
/// involves a single pointer arithmetic operation.
pub const Arguments = union {
    none: *align(4) const void,
    block_type: *align(4) const BlockType,
    ident: *align(4) const Ident,
    ident_opt: *align(4) const Ident.Opt,
    label: *align(4) const Ident.Symbolic,
    call_indirect: *align(4) const CallIndirect,
    br_table: *align(4) const BrTable,
    select: *align(4) const Select,
    mem_arg: *align(4) const MemArg,
    i32: *align(4) const i32,
    f32: *align(4) const u32,
    i64: *align(4) const i64,
    f64: *align(4) const u64,

    fn tagFromType(comptime T: type) std.meta.FieldEnum(Arguments) {
        inline for (@typeInfo(Arguments).@"union".fields) |field| {
            if (@typeInfo(field.type).pointer.child == T)
                return @field(std.meta.FieldEnum(Arguments), field.name);
        }

        @compileError(@typeName(T) ++ " is not used as an instruction argument type");
    }
};

pub const List = struct {
    buffer: Buffer,
    count: u32,

    const Buffer = std.SegmentedList(IndexedArena.Word, 4);

    pub const empty = List{ .buffer = .{}, .count = 0 };

    pub const Pool = std.SegmentedList(List, 2);

    pub fn growCapacityAdditionalWords(
        list: *List,
        arena: *ArenaAllocator,
        additional_count: usize,
    ) error{OutOfMemory}!void {
        const new_capacity = std.math.add(usize, list.buffer.len, additional_count) catch return error.OutOfMemory;

        // This check avoids an integer overflow panic.
        if (new_capacity > Buffer.prealloc_count)
            try list.buffer.growCapacity(arena.allocator(), new_capacity);
    }

    fn appendInstrKeyword(list: *List, arena: *ArenaAllocator, keyword: sexpr.Value) error{OutOfMemory}!void {
        try list.buffer.append(arena.allocator(), @enumFromInt(@as(u32, @bitCast(keyword))));
    }

    pub fn append(
        list: *List,
        arena: *ArenaAllocator,
        keyword: TokenId,
        arguments: anytype,
        tree: *const sexpr.Tree,
    ) error{OutOfMemory}!void {
        const Args: type = @TypeOf(arguments);

        const expected = Arguments.tagFromType(Args);
        const actual = argumentTag(Lexer.Token.tagToInstrTag(keyword.tag(tree)));
        if (expected != actual and @import("builtin").mode == .Debug) {
            std.debug.panic("{} != {} for {s}", .{ expected, actual, @typeName(Args) });
        }

        const word_count: usize = comptime (IndexedArena.byteSizeToWordCount(@sizeOf(Args)) catch unreachable) + 1;

        var buffer: [word_count - 1]IndexedArena.Word = undefined;
        @as(*align(4) Args, @ptrCast(&buffer)).* = arguments;

        try list.growCapacityAdditionalWords(arena, word_count);
        list.count = std.math.add(u32, list.count, 1) catch return error.OutOfMemory;

        errdefer comptime unreachable;

        list.appendInstrKeyword(undefined, sexpr.Value.initAtom(keyword)) catch unreachable;
        list.buffer.appendSlice(undefined, &buffer) catch unreachable;
    }

    pub fn appendImplicitEnd(list: *List, arena: *ArenaAllocator, block: sexpr.List.Id) error{OutOfMemory}!void {
        list.count = std.math.add(u32, list.count, 1) catch return error.OutOfMemory;
        try list.appendInstrKeyword(arena, sexpr.Value.initList(block));
    }

    pub fn appendMovedList(list: *List, arena: *ArenaAllocator, other: *List, pool: *Pool) error{OutOfMemory}!void {
        try list.growCapacityAdditionalWords(arena, other.buffer.len);
        list.count = std.math.add(u32, list.count, other.count) catch return error.OutOfMemory;

        errdefer comptime unreachable;

        var items = other.buffer.iterator(0);
        while (items.next()) |src| list.buffer.append(undefined, src.*) catch unreachable;

        other.clearRetainingCapacity();
        pool.append(arena.allocator(), other.*) catch {};
        other.* = .empty;
    }

    pub fn clearRetainingCapacity(list: *List) void {
        list.count = 0;
        list.buffer.clearRetainingCapacity();
    }

    pub fn moveToIndexedArena(list: List, arena: *IndexedArena) error{OutOfMemory}!IndexedArena.Slice(IndexedArena.Word) {
        return arena.dupeSegmentedList(IndexedArena.Word, Buffer.prealloc_count, &list.buffer);
    }
};

pub const BrTable = struct {
    labels: IndexedArena.SliceAligned(Ident, 4),
    default_label: Ident align(4),
};

pub const CallIndirect = struct {
    table: Ident.Opt align(4),
    type: TypeUse,
};

pub const Select = IndexedArena.Slice(Text.Result).Opt;

pub const MemArg = struct {
    offset_token: TokenId.Opt,
    align_token: TokenId.Opt,
    offset: u64 align(4),
    /// If `align_token == .none`, then the *natural alignment* should be used instead.
    align_pow: u5,

    pub const none = MemArg{
        .offset_token = .none,
        .offset = undefined,
        .align_token = .none,
        .align_pow = undefined,
    };

    pub fn parseContents(contents: *sexpr.Parser, ctx: *ParseContext) error{OutOfMemory}!MemArg {
        var mem_arg = MemArg.none;
        var lookahead: sexpr.Parser = contents.*;

        {
            const offset_token = (lookahead.parseValue() catch return mem_arg).getAtom() orelse return mem_arg;
            if (offset_token.tag(ctx.tree) != .keyword_unknown) return mem_arg;
            const offset_contents = offset_token.contents(ctx.tree);
            if (!std.mem.startsWith(u8, offset_contents, "offset=")) return mem_arg;

            const lexer_offset = offset_token.offset(ctx.tree);
            const lexer_bytes = ctx.tree.source[0..lexer_offset.end];
            var offset_lexer = Lexer.initUtf8(.{
                .bytes = lexer_bytes,
                .i = lexer_offset.start + "offset=".len,
            });

            const digits_token = offset_lexer.next() orelse return mem_arg;
            if (digits_token.tag != .integer) {
                _ = try ctx.errorAtToken(offset_token, "expected memarg 'offset' or instruction");
                return mem_arg;
            }

            const offset_value = parseUninterpretedInteger(u64, digits_token.contents(lexer_bytes)) catch {
                _ = try ctx.errorAtToken(offset_token, "invalid offset integer");
                return mem_arg;
            };

            mem_arg.offset_token = TokenId.Opt.init(offset_token);
            mem_arg.offset = offset_value;
        }

        {
            const align_token = (lookahead.parseValue() catch return mem_arg).getAtom() orelse return mem_arg;
            if (align_token.tag(ctx.tree) != .keyword_unknown) return mem_arg;
            const align_contents = align_token.contents(ctx.tree);
            if (!std.mem.startsWith(u8, align_contents, "align=")) return mem_arg;

            const lexer_offset = align_token.offset(ctx.tree);
            var offset_lexer = Lexer.initUtf8(.{
                .bytes = ctx.tree.source[0..lexer_offset.end],
                .i = lexer_offset.start + "align=".len,
            });

            const digits_token = offset_lexer.next() orelse return mem_arg;
            if (digits_token.tag != .integer) {
                _ = try ctx.errorAtToken(align_token, "expected memarg 'align' or instruction");
                return mem_arg;
            }

            const align_value = parseUninterpretedInteger(u32, digits_token.contents(ctx.tree.source)) catch {
                _ = try ctx.errorAtToken(align_token, "invalid offset integer");
                return mem_arg;
            };

            if (!std.math.isPowerOfTwo(align_value))
                _ = try ctx.errorAtToken(align_token, "alignment must be a power of two");

            mem_arg.align_token = TokenId.Opt.init(align_token);
            mem_arg.align_pow = std.math.log2_int(u32, align_value);
        }

        return mem_arg;
    }
};

pub const BlockType = struct {
    label: Ident.Symbolic align(4),
    type: TypeUse,

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!BlockType {
        return .{
            .label = try Ident.Symbolic.parse(contents, ctx.tree, caches.allocator, &caches.ids),
            .type = try TypeUse.parseContents(contents, ctx, arena, caches, scratch),
        };
    }
};

pub fn argumentTag(instr: Lexer.Token.InstrTag) std.meta.FieldEnum(Arguments) {
    return switch (instr) {
        .nop,
        .@"unreachable",
        .@"return",
        .drop,
        .@"i32.eqz",
        .@"i32.eq",
        .@"i32.ne",
        .@"i32.lt_s",
        .@"i32.lt_u",
        .@"i32.gt_s",
        .@"i32.gt_u",
        .@"i32.le_s",
        .@"i32.le_u",
        .@"i32.ge_s",
        .@"i32.ge_u",
        .@"i64.eqz",
        .@"i64.eq",
        .@"i64.ne",
        .@"i64.lt_s",
        .@"i64.lt_u",
        .@"i64.gt_s",
        .@"i64.gt_u",
        .@"i64.le_s",
        .@"i64.le_u",
        .@"i64.ge_s",
        .@"i64.ge_u",
        .@"f32.eq",
        .@"f32.ne",
        .@"f32.lt",
        .@"f32.gt",
        .@"f32.le",
        .@"f32.ge",
        .@"f64.eq",
        .@"f64.ne",
        .@"f64.lt",
        .@"f64.gt",
        .@"f64.le",
        .@"f64.ge",
        .@"i32.clz",
        .@"i32.ctz",
        .@"i32.popcnt",
        .@"i32.add",
        .@"i32.sub",
        .@"i32.mul",
        .@"i32.div_s",
        .@"i32.div_u",
        .@"i32.rem_s",
        .@"i32.rem_u",
        .@"i32.and",
        .@"i32.or",
        .@"i32.xor",
        .@"i32.shl",
        .@"i32.shr_s",
        .@"i32.shr_u",
        .@"i32.rotl",
        .@"i32.rotr",
        .@"i64.clz",
        .@"i64.ctz",
        .@"i64.popcnt",
        .@"i64.add",
        .@"i64.sub",
        .@"i64.mul",
        .@"i64.div_s",
        .@"i64.div_u",
        .@"i64.rem_s",
        .@"i64.rem_u",
        .@"i64.and",
        .@"i64.or",
        .@"i64.xor",
        .@"i64.shl",
        .@"i64.shr_s",
        .@"i64.shr_u",
        .@"i64.rotl",
        .@"i64.rotr",
        .@"f32.abs",
        .@"f32.neg",
        .@"f32.ceil",
        .@"f32.floor",
        .@"f32.trunc",
        .@"f32.nearest",
        .@"f32.sqrt",
        .@"f32.add",
        .@"f32.sub",
        .@"f32.mul",
        .@"f32.div",
        .@"f32.min",
        .@"f32.max",
        .@"f32.copysign",
        .@"f64.abs",
        .@"f64.neg",
        .@"f64.ceil",
        .@"f64.floor",
        .@"f64.trunc",
        .@"f64.nearest",
        .@"f64.sqrt",
        .@"f64.add",
        .@"f64.sub",
        .@"f64.mul",
        .@"f64.div",
        .@"f64.min",
        .@"f64.max",
        .@"f64.copysign",
        .@"i32.wrap_i64",
        .@"i32.trunc_f32_s",
        .@"i32.trunc_f32_u",
        .@"i32.trunc_f64_s",
        .@"i32.trunc_f64_u",
        .@"i64.extend_i32_s",
        .@"i64.extend_i32_u",
        .@"i64.trunc_f32_s",
        .@"i64.trunc_f32_u",
        .@"i64.trunc_f64_s",
        .@"i64.trunc_f64_u",
        .@"f32.convert_i32_s",
        .@"f32.convert_i32_u",
        .@"f32.convert_i64_s",
        .@"f32.convert_i64_u",
        .@"f32.demote_f64",
        .@"f64.convert_i32_s",
        .@"f64.convert_i32_u",
        .@"f64.convert_i64_s",
        .@"f64.convert_i64_u",
        .@"f64.promote_f32",
        .@"i32.reinterpret_f32",
        .@"i64.reinterpret_f64",
        .@"f32.reinterpret_i32",
        .@"f64.reinterpret_i64",
        .@"i32.extend8_s",
        .@"i32.extend16_s",
        .@"i64.extend8_s",
        .@"i64.extend16_s",
        .@"i64.extend32_s",
        .@"ref.is_null",
        .@"i32.trunc_sat_f32_s",
        .@"i32.trunc_sat_f32_u",
        .@"i32.trunc_sat_f64_s",
        .@"i32.trunc_sat_f64_u",
        .@"i64.trunc_sat_f32_s",
        .@"i64.trunc_sat_f32_u",
        .@"i64.trunc_sat_f64_s",
        .@"i64.trunc_sat_f64_u",
        => .none,
        .block, .loop, .@"if" => .block_type,
        .br,
        .br_if,
        .call,
        .@"local.get",
        .@"local.set",
        .@"local.tee",
        .@"global.get",
        .@"global.set",
        .@"elem.drop",
        .@"data.drop",
        .@"ref.func",
        => .ident,
        .@"else",
        .end,
        => .label,
        .@"memory.size",
        .@"memory.grow",
        .@"table.get",
        .@"table.set",
        .@"table.size",
        .@"table.grow",
        .@"table.fill",
        .@"memory.fill",
        => .ident_opt,
        .call_indirect => .call_indirect,
        .br_table => .br_table,
        .select => .select,
        .@"i32.load",
        .@"i64.load",
        .@"f32.load",
        .@"f64.load",
        .@"i32.load8_s",
        .@"i32.load8_u",
        .@"i32.load16_s",
        .@"i32.load16_u",
        .@"i64.load8_s",
        .@"i64.load8_u",
        .@"i64.load16_s",
        .@"i64.load16_u",
        .@"i64.load32_s",
        .@"i64.load32_u",
        .@"i32.store",
        .@"i64.store",
        .@"f32.store",
        .@"f64.store",
        .@"i32.store8",
        .@"i32.store16",
        .@"i64.store8",
        .@"i64.store16",
        .@"i64.store32",
        => .mem_arg,
        .@"memory.init",
        .@"memory.copy",
        .@"table.init",
        .@"table.copy",
        => unreachable, // TODO: two optional indices
        .@"ref.null" => unreachable, // TODO: .heap_type
        .@"i32.const" => .i32,
        .@"i64.const" => .i64,
        .@"f32.const" => .f32,
        .@"f64.const" => .f64,
    };
}

pub fn parseArgs(
    keyword: TokenId,
    contents: *sexpr.Parser,
    ctx: *ParseContext,
    list: *List,
    list_arena: *ArenaAllocator,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    scratch: *ArenaAllocator,
) sexpr.Parser.ParseError!void {
    switch (argumentTag(Lexer.Token.tagToInstrTag(keyword.tag(ctx.tree)))) {
        .none => try list.append(list_arena, keyword, {}, ctx.tree),
        .block_type => {
            _ = scratch.reset(.retain_capacity);
            const block_type = try BlockType.parseContents(
                contents,
                ctx,
                arena,
                caches,
                scratch,
            );

            try list.append(list_arena, keyword, block_type, ctx.tree);
        },
        .ident => {
            const ident = try Ident.parse(
                contents,
                ctx,
                parent,
                caches.allocator,
                &caches.ids,
            );

            try list.append(list_arena, keyword, ident, ctx.tree);
        },
        .label => {
            const ident = try Ident.Symbolic.parse(
                contents,
                ctx.tree,
                caches.allocator,
                &caches.ids,
            );

            try list.append(list_arena, keyword, ident, ctx.tree);
        },
        .ident_opt => {
            const ident = try Ident.Opt.parse(
                contents,
                ctx,
                caches.allocator,
                &caches.ids,
            );

            try list.append(list_arena, keyword, ident, ctx.tree);
        },
        .call_indirect => {
            const table = try Ident.Opt.parse(
                contents,
                ctx,
                caches.allocator,
                &caches.ids,
            );

            const type_use = try TypeUse.parseContents(
                contents,
                ctx,
                arena,
                caches,
                scratch,
            );

            try list.append(
                list_arena,
                keyword,
                CallIndirect{ .table = table, .type = type_use },
                ctx.tree,
            );
        },
        .br_table => {
            _ = scratch.reset(.retain_capacity);
            var labels_buf = std.SegmentedList(Ident, 4){};
            const first_label = try Ident.parse(
                contents,
                ctx,
                parent,
                caches.allocator,
                &caches.ids,
            );

            labels_buf.append(undefined, first_label) catch unreachable;

            while (true) {
                const ident = try Ident.Opt.parse(
                    contents,
                    ctx,
                    caches.allocator,
                    &caches.ids,
                );

                try labels_buf.append(scratch.allocator(), ident.get() orelse break);
            }

            std.debug.assert(labels_buf.len > 0);

            const labels = try arena.alignedAlloc(Ident, 4, labels_buf.len - 1);
            // labels_buf.writeToSlice(labels.items(arena), 0);
            {
                var labels_buf_iter = labels_buf.constIterator(0);
                for (labels.items(arena)) |*l| {
                    l.* = labels_buf_iter.next().?.*;
                }
            }

            try list.append(
                list_arena,
                keyword,
                BrTable{
                    .labels = labels,
                    .default_label = labels_buf.at(labels_buf.len - 1).*,
                },
                ctx.tree,
            );
        },
        .select => {
            _ = scratch.reset(.retain_capacity);
            var result_types = std.SegmentedList(Text.Result, 1){};
            var lookahead: sexpr.Parser = contents.*;

            while (true) {
                const result_list = (lookahead.parseValue() catch break).getList() orelse break;
                var result_contents = sexpr.Parser.init(result_list.contents(ctx.tree).values(ctx.tree));
                const result_token = (result_contents.parseValue() catch break).getAtom() orelse break;
                if (result_token.tag(ctx.tree) != .keyword_result) break;

                const result = try Text.Result.parseContents(
                    &result_contents,
                    ctx,
                    arena,
                    result_token,
                    result_list,
                );

                try result_types.append(scratch.allocator(), result);
                contents.* = lookahead;
                std.debug.assert(result_contents.isEmpty());
            }

            lookahead = undefined;

            const select = if (result_types.len == 0)
                Select.none
            else
                Select.init(try arena.dupeSegmentedList(Text.Result, 1, &result_types));

            try list.append(list_arena, keyword, select, ctx.tree);
        },
        .mem_arg => try list.append(
            list_arena,
            keyword,
            try MemArg.parseContents(contents, ctx),
            ctx.tree,
        ),
        .i32 => {
            const literal = try contents.parseUninterpretedIntegerInList(i32, parent, ctx);
            try list.append(list_arena, keyword, literal.value, ctx.tree);
        },
        .i64 => {
            const literal = try contents.parseUninterpretedIntegerInList(i64, parent, ctx);
            try list.append(list_arena, keyword, literal.value, ctx.tree);
        },
        .f32 => {
            const literal = try contents.parseFloatInList(f32, parent, ctx);
            try list.append(list_arena, keyword, try literal.expectBits(ctx), ctx.tree);
        },
        .f64 => {
            const literal = try contents.parseFloatInList(f64, parent, ctx);
            try list.append(list_arena, keyword, try literal.expectBits(ctx), ctx.tree);
        },
    }
}
