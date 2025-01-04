const std = @import("std");
const IndexedArena = @import("../../IndexedArena.zig");

const Lexer = @import("../Lexer.zig");
const sexpr = @import("../sexpr.zig");
const parseUninterpretedInteger = @import("../value.zig").uninterpretedInteger;
const Error = sexpr.Error;

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
args: Args,

const Instr = @This();

pub const BrTable = struct {
    labels: IndexedArena.Slice(Ident),
    default_label: Ident align(4),
};

pub const CallIndirect = struct {
    table: Ident.Opt align(4),
    type: TypeUse,
};

pub const Select = IndexedArena.Slice(Text.Result);

pub const MemArg = struct {
    offset_token: sexpr.TokenId.Opt,
    align_token: sexpr.TokenId.Opt,
    offset: u64 align(4),
    /// If `align_token == .none`, then the *natural alignment* should be used instead.
    align_pow: u5,

    pub const none = MemArg{
        .offset_token = .none,
        .offset = undefined,
        .align_token = .none,
        .align_pow = undefined,
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        errors: *Error.List,
    ) error{OutOfMemory}!MemArg {
        var mem_arg = MemArg.none;
        var lookahead: sexpr.Parser = contents.*;

        {
            const offset_token = (lookahead.parseValue() catch return mem_arg).getAtom() orelse return mem_arg;
            if (offset_token.tag(tree) != .keyword_unknown) return mem_arg;
            const offset_contents = offset_token.contents(tree);
            if (!std.mem.startsWith(u8, offset_contents, "offset=")) return mem_arg;

            const lexer_offset = offset_token.offset(tree);
            var offset_lexer = Lexer.initUtf8(.{
                .bytes = tree.source[0..lexer_offset.end],
                .i = lexer_offset.start + "offset=".len,
            });

            const digits_token = offset_lexer.next() orelse return mem_arg;
            if (digits_token.tag != .integer) {
                try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(offset_token), .at_value));
                return mem_arg;
            }

            const offset_value = parseUninterpretedInteger(u64, digits_token.contents(tree.source)) catch {
                try errors.append(Error.initIntegerLiteralOverflow(offset_token, 64));
                return mem_arg;
            };

            mem_arg.offset_token = sexpr.TokenId.Opt.init(offset_token);
            mem_arg.offset = offset_value;
        }

        {
            const align_token = (lookahead.parseValue() catch return mem_arg).getAtom() orelse return mem_arg;
            if (align_token.tag(tree) != .keyword_unknown) return mem_arg;
            const align_contents = align_token.contents(tree);
            if (!std.mem.startsWith(u8, align_contents, "align=")) return mem_arg;

            const lexer_offset = align_token.offset(tree);
            var offset_lexer = Lexer.initUtf8(.{
                .bytes = tree.source[0..lexer_offset.end],
                .i = lexer_offset.start + "align=".len,
            });

            const digits_token = offset_lexer.next() orelse return mem_arg;
            if (digits_token.tag != .integer) {
                try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(align_token), .at_value));
                return mem_arg;
            }

            const align_value = parseUninterpretedInteger(u32, digits_token.contents(tree.source)) catch {
                try errors.append(Error.initIntegerLiteralOverflow(align_token, 32));
                return mem_arg;
            };

            if (!std.math.isPowerOfTwo(align_value))
                try errors.append(Error.initMemArgAlignNonPowerOfTwo(align_token));

            mem_arg.align_token = sexpr.TokenId.Opt.init(align_token);
            mem_arg.align_pow = std.math.log2_int(u32, align_value);
        }

        return mem_arg;
    }
};

pub const Args = union {
    none: void,
    block: IndexedArena.Idx(BlockType),
    br_table: IndexedArena.Idx(BrTable),
    id_opt: IndexedArena.Idx(Ident.Unaligned).Opt,
    id: IndexedArena.Idx(Ident.Unaligned),
    call_indirect: IndexedArena.Idx(CallIndirect),
    /// If not `.none`, then the number of result types must be at least one.
    ///
    /// This is set to `.none` if the number of result types is zero as a space optimization.
    select: IndexedArena.Idx(Select).Opt,
    mem_arg: IndexedArena.Idx(MemArg),
    i32: i32,
    i64: IndexedArena.Idx(i64),
    f32: u32,
    f64: IndexedArena.Idx(u64),
};

comptime {
    std.debug.assert(@alignOf(Instr) == @alignOf(u32));
    std.debug.assert(@sizeOf(Instr) == switch (@import("builtin").mode) {
        .Debug, .ReleaseSafe => 12,
        .ReleaseFast, .ReleaseSmall => 8,
    });
}

pub fn initImplicitEnd(block: sexpr.List.Id) Instr {
    return .{
        .keyword = sexpr.Value.initList(block),
        .args = .{ .id_opt = .none },
    };
}

pub const BlockType = struct {
    label: Ident.Opt align(4),
    type: TypeUse,

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        errors: *Error.List,
        scratch: *std.heap.ArenaAllocator,
    ) error{OutOfMemory}!sexpr.Parser.Result(IndexedArena.Idx(BlockType)) {
        const block_type = try arena.create(BlockType);

        const label = switch (try Ident.Opt.parse(contents, tree, caches.allocator, &caches.ids)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const type_use = switch (try TypeUse.parseContents(contents, tree, arena, caches, errors, scratch)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        block_type.set(arena, .{ .label = label, .type = type_use });
        return .{ .ok = block_type };
    }
};

pub fn parseArgs(
    keyword: sexpr.TokenId,
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
    scratch: *std.heap.ArenaAllocator,
) error{OutOfMemory}!sexpr.Parser.Result(Instr) {
    const args: Args = args: switch (keyword.tag(tree)) {
        .keyword_nop,
        .keyword_unreachable,
        .keyword_return,
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

        .keyword_block, .keyword_loop, .keyword_if => {
            _ = scratch.reset(.retain_capacity);
            const block_type = switch (try BlockType.parseContents(contents, tree, arena, caches, errors, scratch)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            break :args Args{ .block = block_type };
        },
        .keyword_br,
        .keyword_br_if,
        .keyword_call,
        .@"keyword_local.get",
        .@"keyword_local.set",
        .@"keyword_local.tee",
        .@"keyword_global.get",
        .@"keyword_global.set",
        .@"keyword_elem.drop",
        .@"keyword_data.drop",
        => {
            const id = try arena.create(Ident.Unaligned);
            const ident = switch (try Ident.parse(contents, tree, parent, caches.allocator, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            id.set(arena, .{ .ident = ident });
            break :args Args{ .id = id };
        },
        .keyword_else,
        .keyword_end,
        .@"keyword_memory.size",
        .@"keyword_memory.grow",
        .@"keyword_table.get",
        .@"keyword_table.set",
        .@"keyword_table.size",
        .@"keyword_table.grow",
        .@"keyword_table.fill",
        => {
            const ident = switch (try Ident.Opt.parse(contents, tree, caches.allocator, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            break :args Args{
                .id_opt = if (ident.get()) |some_id| id: {
                    const allocated = try arena.create(Ident.Unaligned);
                    allocated.set(arena, .{ .ident = some_id });
                    break :id IndexedArena.Idx(Ident.Unaligned).Opt.init(allocated);
                } else .none,
            };
        },
        .keyword_call_indirect => {
            const call_indirect = try arena.create(CallIndirect);

            const table = switch (try Ident.Opt.parse(contents, tree, caches.allocator, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            const type_use = switch (try TypeUse.parseContents(contents, tree, arena, caches, errors, scratch)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            call_indirect.set(arena, .{ .table = table, .type = type_use });
            break :args Args{ .call_indirect = call_indirect };
        },
        .keyword_br_table => {
            const br_table = try arena.create(BrTable);

            _ = scratch.reset(.retain_capacity);
            var labels_buf = std.SegmentedList(Ident, 4){};
            const first_label = switch (try Ident.parse(contents, tree, parent, caches.allocator, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            labels_buf.append(undefined, first_label) catch unreachable;

            while (true) {
                const ident = switch (try Ident.Opt.parse(contents, tree, caches.allocator, &caches.ids)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                };

                try labels_buf.append(scratch.allocator(), ident.get() orelse break);
            }

            std.debug.assert(labels_buf.len > 0);

            const labels = try arena.alloc(Ident, labels_buf.len - 1);
            labels_buf.writeToSlice(labels.items(arena), 0);

            errdefer comptime unreachable;

            br_table.set(
                arena,
                BrTable{ .labels = labels, .default_label = labels_buf.at(labels_buf.len - 1).* },
            );

            break :args Args{ .br_table = br_table };
        },
        .keyword_select => {
            _ = scratch.reset(.retain_capacity);
            var result_types = std.SegmentedList(Text.Result, 1){};
            var lookahead: sexpr.Parser = contents.*;

            while (true) {
                const result_list = (lookahead.parseValue() catch break).getList() orelse break;
                var result_contents = sexpr.Parser.init(result_list.contents(tree).values(tree));
                const result_token = (result_contents.parseValue() catch break).getAtom() orelse break;
                if (result_token.tag(tree) != .keyword_result) break;

                const result = try Text.Result.parseContents(
                    &result_contents,
                    tree,
                    arena,
                    result_token,
                    result_list,
                    errors,
                );

                try result_types.append(scratch.allocator(), result);
                contents.* = lookahead;
                std.debug.assert(result_contents.isEmpty());
            }

            lookahead = undefined;

            if (result_types.len == 0) {
                break :args Args{ .select = .none };
            } else {
                const results = try arena.create(Select);
                results.set(arena, try arena.dupeSegmentedList(Text.Result, 1, &result_types));
                break :args Args{ .select = IndexedArena.Idx(Select).Opt.init(results) };
            }
        },
        .@"keyword_i32.load",
        .@"keyword_i64.load",
        .@"keyword_f32.load",
        .@"keyword_f64.load",
        .@"keyword_i32.load8_s",
        .@"keyword_i32.load8_u",
        .@"keyword_i32.load16_s",
        .@"keyword_i32.load16_u",
        .@"keyword_i64.load8_s",
        .@"keyword_i64.load8_u",
        .@"keyword_i64.load16_s",
        .@"keyword_i64.load16_u",
        .@"keyword_i64.load32_s",
        .@"keyword_i64.load32_u",
        .@"keyword_i32.store",
        .@"keyword_i64.store",
        .@"keyword_f32.store",
        .@"keyword_f64.store",
        .@"keyword_i32.store8",
        .@"keyword_i32.store16",
        .@"keyword_i64.store8",
        .@"keyword_i64.store16",
        .@"keyword_i64.store32",
        => {
            const mem_arg = try arena.create(MemArg);
            mem_arg.set(arena, try MemArg.parseContents(contents, tree, errors));
            break :args Args{ .mem_arg = mem_arg };
        },
        .@"keyword_i32.const" => {
            const literal: i32 = literal: switch (contents.parseUninterpretedIntegerInList(i32, parent, tree)) {
                .ok => |ok| ok.value,
                .err => |err| {
                    try errors.append(err);
                    break :literal 0;
                },
            };

            break :args Args{ .i32 = literal };
        },
        .@"keyword_i64.const" => {
            const literal = try arena.create(i64);
            literal.set(
                arena,
                switch (contents.parseUninterpretedIntegerInList(i64, parent, tree)) {
                    .ok => |ok| ok.value,
                    .err => |err| literal: {
                        try errors.append(err);
                        break :literal 0;
                    },
                },
            );

            break :args Args{ .i64 = literal };
        },
        .@"keyword_f32.const" => {
            const literal: u32 = literal: switch (contents.parseFloatInList(f32, parent, tree)) {
                .ok => |ok| ok.value,
                .err => |err| {
                    try errors.append(err);
                    break :literal 0;
                },
            };

            break :args Args{ .f32 = literal };
        },
        .@"keyword_f64.const" => {
            const literal = try arena.create(u64);
            literal.set(
                arena,
                switch (contents.parseFloatInList(f64, parent, tree)) {
                    .ok => |ok| ok.value,
                    .err => |err| literal: {
                        try errors.append(err);
                        break :literal 0;
                    },
                },
            );

            break :args Args{ .f64 = literal };
        },
        // Unknown instruction.
        else => return .{
            .err = Error.initExpectedToken(sexpr.Value.initAtom(keyword), .keyword_unknown, .at_value),
        },
    };

    return .{ .ok = Instr{ .keyword = sexpr.Value.initAtom(keyword), .args = args } };
}
