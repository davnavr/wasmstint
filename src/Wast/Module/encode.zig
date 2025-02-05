//! Converts modules in the WebAssembly Text format to the [binary format].
//!
//! [binary format]: https://webassembly.github.io/spec/core/binary/index.html

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const SegmentedList = std.SegmentedList;
const writeUleb128 = std.leb.writeUleb128;
const IndexedArena = @import("../../IndexedArena.zig");
const opcodes = @import("../../opcodes.zig");
const Errors = @import("../Errors.zig");

const Ident = @import("../ident.zig").Ident;
const Name = @import("../Name.zig");
const Caches = @import("../Caches.zig");

const Lexer = @import("../Lexer.zig");
const sexpr = @import("../sexpr.zig");
const TextContext = sexpr.Parser.Context;
const escapeStringLiteral = @import("../value.zig").string;
const Module = @import("../Module.zig");
const Text = Module.Text;

const IdentLookup = @import("encode/ident_lookup.zig").IdentLookup;

fn EncodeError(comptime Out: type) type {
    return error{OutOfMemory} || Out.Error;
}

fn encodeIdx(output: anytype, comptime I: type, idx: I) @TypeOf(output).Error!void {
    try writeUleb128(output, @as(@typeInfo(I).@"enum".tag_type, @intFromEnum(idx)));
}

fn encodeVecLen(output: anytype, len: usize) EncodeError(@TypeOf(output))!void {
    try writeUleb128(output, std.math.cast(u32, len) orelse return error.OutOfMemory);
}

fn encodeByteVec(output: anytype, bytes: []const u8) EncodeError(@TypeOf(output))!void {
    try encodeVecLen(output, bytes.len);
    try output.writeAll(bytes);
}

fn addOrOom(comptime T: type, a: T, b: T) Allocator.Error!T {
    return std.math.add(T, a, b) catch |e| switch (e) {
        error.Overflow => error.OutOfMemory,
    };
}

pub const ValType = enum(u8) {
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0x7D,
    f64 = 0x7C,
    v128 = 0x7B,
    funcref = 0x70,
    externref = 0x6F,

    fn fromValType(text: Text.ValType, tree: *const sexpr.Tree) ValType {
        return switch (text.keyword.tag(tree)) {
            .keyword_i32 => .i32,
            .keyword_i64 => .i64,
            .keyword_f32 => .f32,
            .keyword_f64 => .f64,
            .keyword_funcref => .funcref,
            .keyword_externref => .externref,
            else => unreachable,
        };
    }

    fn encode(val_type: ValType, output: anytype) EncodeError(@TypeOf(output))!void {
        try output.writeByte(@intFromEnum(val_type));
    }
};

pub const Type = *const Text.Type.Func;

pub const TypeIdx = enum(u32) { _ };

pub const FuncIdx = enum(u32) {
    probably_invalid = std.math.maxInt(u32),
    _,
};

pub const MemIdx = enum(u32) {
    probably_invalid = std.math.maxInt(u32),
    _,
};

pub const DataIdx = enum(u32) {
    probably_invalid = std.math.maxInt(u32),
    _,
};

const IterParamTypes = struct {
    types: []const Text.ValType,
    params: []const Text.Param,

    fn init(parameters: []const Text.Param) @This() {
        return .{ .types = &[0]Text.ValType{}, .params = parameters };
    }

    fn next(iter: *@This(), tree: *const sexpr.Tree, arena: IndexedArena.ConstData) ?ValType {
        if (iter.types.len == 0 and iter.params.len > 0) {
            iter.types = iter.params[0].types.items(arena);
            iter.params = iter.params[1..];
        }

        if (iter.types.len > 0) {
            const item = iter.types[0];
            iter.types = iter.types[1..];
            return ValType.fromValType(item, tree);
        } else {
            return null;
        }
    }
};

const IterResultTypes = struct {
    types: []const Text.ValType,
    results: []const Text.Result,

    fn init(results: []const Text.Result) @This() {
        return .{ .types = &[0]Text.ValType{}, .results = results };
    }

    fn next(iter: *@This(), tree: *const sexpr.Tree, arena: IndexedArena.ConstData) ?ValType {
        if (iter.types.len == 0 and iter.results.len > 0) {
            iter.types = iter.results[0].types.items(arena);
            iter.results = iter.results[1..];
        }

        if (iter.types.len > 0) {
            const item = iter.types[0];
            iter.types = iter.types[1..];
            return ValType.fromValType(item, tree);
        } else {
            return null;
        }
    }
};

const TypeDedup = struct {
    lookup: std.HashMapUnmanaged(
        Type,
        TypeIdx,
        Context,
        std.hash_map.default_max_load_percentage,
    ),

    const Context = struct {
        arena: IndexedArena.ConstData,
        tree: *const sexpr.Tree,

        pub fn eql(ctx: Context, a: Type, b: Type) bool {
            {
                var a_params_iter = IterParamTypes.init(a.parameters.items(ctx.arena));
                var b_params_iter = IterParamTypes.init(b.parameters.items(ctx.arena));
                while (a_params_iter.next(ctx.tree, ctx.arena)) |a_param| {
                    const b_param = b_params_iter.next(ctx.tree, ctx.arena) orelse return false;
                    if (a_param != b_param)
                        return false;
                }

                if (b_params_iter.next(ctx.tree, ctx.arena) != null) return false;
            }
            {
                var a_results_iter = IterResultTypes.init(a.results.items(ctx.arena));
                var b_results_iter = IterResultTypes.init(b.results.items(ctx.arena));
                while (a_results_iter.next(ctx.tree, ctx.arena)) |a_param| {
                    const b_param = b_results_iter.next(ctx.tree, ctx.arena) orelse return false;
                    if (a_param != b_param)
                        return false;
                }

                if (b_results_iter.next(ctx.tree, ctx.arena) != null) return false;
            }

            return true;
        }

        pub fn hash(ctx: Context, key: Type) u64 {
            var hasher = std.hash.Wyhash.init(0);
            {
                var iter_params = IterParamTypes.init(key.parameters.items(ctx.arena));
                while (iter_params.next(ctx.tree, ctx.arena)) |param| {
                    std.hash.autoHash(&hasher, param);
                }
            }
            {
                var iter_results = IterResultTypes.init(key.results.items(ctx.arena));
                while (iter_results.next(ctx.tree, ctx.arena)) |result| {
                    std.hash.autoHash(&hasher, result);
                }
            }
            return hasher.final();
        }
    };

    const empty = TypeDedup{ .lookup = .empty };
};

const Import = union(enum) {
    // field: IndexedArena.Idx(Text.ImportField),
    inline_func: IndexedArena.Idx(Text.Func),
    inline_table: IndexedArena.Idx(Text.Table),
    inline_mem: IndexedArena.Idx(Text.Mem),
    inline_global: IndexedArena.Idx(Text.Global),

    fn name(import: Import, arena: IndexedArena.ConstData) *const Text.ImportName {
        return switch (import) {
            .inline_func => |func| &func.getPtr(arena).body.inline_import,
            .inline_table => |table| &table.getPtr(arena).inlineImport().?.name,
            .inline_mem => |mem| &mem.getPtr(arena).inlineImport().?.name,
            .inline_global => |global| &global.getPtr(arena).inner.inline_import,
        };
    }

    comptime {
        std.debug.assert(@sizeOf(Import) == 8);
    }
};

const Export = union(enum) {
    // module_field: IndexedArena.Idx(Text.ExportField),
    inline_func: struct { field: IndexedArena.Idx(Text.Func), idx: FuncIdx },
    inline_mem: struct {
        field: IndexedArena.Idx(Text.Mem),
        idx: MemIdx,
    },

    comptime {
        std.debug.assert(@sizeOf(Export) == 12);
    }
};

fn IdxCounter(comptime Idx: type) type {
    return struct {
        next: Idx = @enumFromInt(0),

        const Self = @This();

        const Int = @typeInfo(Idx).@"enum".tag_type;

        pub fn incrementBy(counter: *Self, amount: Int) Allocator.Error!void {
            counter.next = @enumFromInt(try addOrOom(Int, @intFromEnum(counter.next), amount));
        }

        pub fn increment(counter: *Self) Allocator.Error!Idx {
            const give = counter.next;
            try counter.incrementBy(1);
            return give;
        }
    };
}

const Mem = struct {
    idx: IndexedArena.Idx(Text.Mem),
    /// Given in pages. Only set when the memory has an inline data segment.
    inferred_limit: u32,
};

const DataSegment = struct {
    source: packed struct(u32) {
        tag: Tag,
        inner: Inner,
    },
    /// Set only when `.tag == .inline_mem`.
    mem_idx: MemIdx,
    bytes_len: u32,
    bytes: [*]const u8,

    const Inner = packed union {
        module_field: IndexedArena.Idx(Text.Data),
        inline_mem: IndexedArena.Idx(Text.Mem),
    };

    const Tag = std.meta.FieldEnum(Inner);

    const Expanded = union(Tag) {
        module_field: IndexedArena.Idx(Text.Data),
        inline_mem: struct {
            field: IndexedArena.Idx(Text.Mem),
            idx: MemIdx,
        },
    };

    fn init(data: Expanded, bytes: []const u8) Allocator.Error!DataSegment {
        return .{
            .bytes_len = std.math.cast(u32, bytes.len) orelse return error.OutOfMemory,
            .bytes = bytes.ptr,
            .source = .{
                .tag = data,
                .inner = switch (data) {
                    .module_field => |field| .{ .module_field = field },
                    .inline_mem => |mem| .{ .inline_mem = mem.field },
                },
            },
            .mem_idx = switch (data) {
                .module_field => .probably_invalid,
                .inline_mem => |mem| mem.idx,
            },
        };
    }

    fn expanded(data: DataSegment) Expanded {
        return switch (data.source.tag) {
            .module_field => .{ .module_field = data.source.inner.module_field },
            .inline_mem => .{
                .inline_mem = .{
                    .field = data.source.inner.inline_mem,
                    .idx = data.mem_idx,
                },
            },
        };
    }
};

const Wasm = struct {
    /// Types originating from `Text.Type` fields come before those inserted by `TypeUse`s.
    types: std.SegmentedList(IndexedArena.Idx(Text.Type), 8) = .{},
    imports: std.SegmentedList(Import, 4) = .{},
    exports: std.SegmentedList(Export, 4) = .{},
    exports_count: u32 = 0,

    func_count: IdxCounter(FuncIdx) = .{},
    defined_funcs: std.SegmentedList(IndexedArena.Idx(Text.Func), 8) = .{},

    mem_count: IdxCounter(MemIdx) = .{},
    defined_mems: std.SegmentedList(Mem, 1) = .{},

    data_segments: std.SegmentedList(DataSegment, 1) = .{},

    type_uses: std.AutoArrayHashMapUnmanaged(*const Text.TypeUse, TypeIdx) = .empty,
    type_dedup: TypeDedup = .empty,

    type_ids: IdentLookup(TypeIdx) = .empty,
    func_ids: IdentLookup(FuncIdx) = .empty,
    // table_ids: IdentLookup(TableIdx) = .empty,
    mem_ids: IdentLookup(MemIdx) = .empty,
    data_ids: IdentLookup(DataIdx) = .empty,

    fn checkImportOrdering(
        wasm: *const Wasm,
        ctx: *TextContext,
        import_keyword: sexpr.TokenId,
    ) Allocator.Error!void {
        if (wasm.defined_funcs.len > 0 or
            wasm.defined_mems.len > 0)
            _ = try ctx.errorAtToken(import_keyword, "imports must occur before all non-import definitions");
    }

    const TypeSec = std.SegmentedList(Type, 8);

    fn appendTypeUse(wasm: *Wasm, alloca: *ArenaAllocator, type_use: *const Text.TypeUse) Allocator.Error!void {
        try wasm.type_uses.putNoClobber(alloca.allocator(), type_use, undefined);
    }

    fn resolveTypeSec(
        wasm: *Wasm,
        wasm_arena: *ArenaAllocator,
        ctx: *TextContext,
        arena: IndexedArena.ConstData,
        output: *ArenaAllocator,
    ) Allocator.Error!TypeSec {
        // Allocated in `output`.
        var type_sec = TypeSec{};
        if (wasm.types.len > TypeSec.prealloc_count) {
            try type_sec.growCapacity(wasm_arena.allocator(), wasm.types.len);
        }

        {
            var iter_type_fields = wasm.types.constIterator(0);
            while (iter_type_fields.next()) |type_field| {
                type_sec.append(undefined, &type_field.getPtr(arena).func) catch unreachable;
            }
        }
        // Resolve all `TypeUse`s into types to append after all of the defined ones.
        {
            var iter_type_uses = wasm.type_uses.iterator();
            while (iter_type_uses.next()) |entry| {
                const type_use = entry.key_ptr.*;
                entry.value_ptr.* = if (type_use.id.header.is_inline) type_idx: {
                    const dedup_entry = try wasm.type_dedup.lookup.getOrPutContext(
                        wasm_arena.allocator(),
                        &type_use.func,
                        .{ .arena = arena, .tree = ctx.tree },
                    );

                    if (dedup_entry.found_existing) {
                        break :type_idx dedup_entry.value_ptr.*;
                    } else {
                        const type_idx: TypeIdx = @enumFromInt(
                            std.math.cast(u32, type_sec.len) orelse return error.OutOfMemory,
                        );

                        try type_sec.append(output.allocator(), &type_use.func);
                        dedup_entry.value_ptr.* = type_idx;
                        break :type_idx type_idx;
                    }
                } else switch (type_use.id.type.toUnion(ctx.tree)) {
                    .symbolic => |id| type_idx: {
                        const idx = wasm.type_ids.get(
                            ctx,
                            id,
                            type_use.id.type.token,
                        ) catch |e| switch (e) {
                            error.OutOfMemory => |oom| return oom,
                            error.ReportedParserError => break :type_idx undefined,
                        };

                        const actual_signature = &wasm.types.at(@intFromEnum(idx)).getPtr(arena).func;
                        const expected_signature = &type_use.func;
                        const type_cmp_ctx = TypeDedup.Context{ .arena = arena, .tree = ctx.tree };
                        if (!type_cmp_ctx.eql(actual_signature, expected_signature)) {
                            _ = try ctx.errorAtToken(
                                type_use.id.type.token,
                                "type use does not match its definition (TODO: include why)",
                            );
                        }

                        break :type_idx idx;
                    },
                    .numeric => |numeric| @enumFromInt(numeric),
                };
            }
        }
        return type_sec;
    }
};

/// Maps an interned symbolic identifier to where it is first defined.
const IndexLookup = struct {
    map: std.AutoHashMapUnmanaged(Ident.Interned, sexpr.TokenId),

    const empty = IndexLookup{ .map = .empty };

    fn insert(
        lookup: *IndexLookup,
        ctx: *TextContext,
        id: Ident.Symbolic,
        alloca: *ArenaAllocator,
    ) Allocator.Error!void {
        if (!id.some) return;

        const entry = try lookup.map.getOrPut(alloca.allocator(), id.ident);
        if (entry.found_existing) {
            std.debug.assert(id.some);
            _ = try ctx.errorAtToken(id.token, "definition with this identifier already exists");
        }
    }
};

const IndexSpaces = struct {
    functions: IndexLookup = .empty,
};

const wasm_preamble = "\x00asm\x01\x00\x00\x00";

fn encodeSection(output: anytype, id: u8, contents: []const u8) EncodeError(@TypeOf(output))!void {
    try output.writeByte(id);
    try encodeByteVec(output, contents);
}

fn encodeResultType(
    output: anytype,
    comptime Iterator: type,
    comptime T: type,
    types: IndexedArena.Slice(T),
    tree: *const sexpr.Tree,
    arena: IndexedArena.ConstData,
    scratch: *ArenaAllocator,
) EncodeError(@TypeOf(output))!void {
    var text_iter: Iterator = Iterator.init(types.items(arena));
    var types_buf = std.SegmentedList(ValType, 8){};
    try types_buf.setCapacity(scratch.allocator(), types.len);
    while (true) {
        const val_type: ValType = text_iter.next(tree, arena) orelse break;
        try types_buf.append(scratch.allocator(), val_type);
    }

    try encodeVecLen(output, types_buf.len);
    var final_iter = types_buf.constIterator(0);
    while (final_iter.next()) |val_type| {
        try val_type.encode(output);
    }
}

fn encodeTypeSecFunc(
    output: anytype,
    tree: *const sexpr.Tree,
    arena: IndexedArena.ConstData,
    func_type: *const Text.Type.Func,
    scratch: *ArenaAllocator,
) EncodeError(@TypeOf(output))!void {
    try output.writeByte(0x60);
    try encodeResultType(
        output,
        IterParamTypes,
        Text.Param,
        func_type.parameters,
        tree,
        arena,
        scratch,
    );
    try encodeResultType(
        output,
        IterResultTypes,
        Text.Result,
        func_type.results,
        tree,
        arena,
        scratch,
    );
}

pub const LocalIdx = enum(u32) {
    probably_invalid = std.math.maxInt(u32),
    _,
};

pub const FuncContext = struct {
    local_lookup: IdentLookup(LocalIdx) = .empty,
    local_counter: IdxCounter(LocalIdx) = .{},

    fn reset(ctx: *FuncContext) void {
        ctx.local_lookup.inner.map.clearRetainingCapacity();
        ctx.local_counter = .{};
    }
};

fn checkMatchingLabels(
    text: *TextContext,
    popped: ?Ident.Interned,
    label: Ident.Symbolic,
    cache: *const Ident.Cache,
) Allocator.Error!void {
    if (popped) |expected| {
        if (label.some and label.ident != expected) {
            _ = try text.errorFmtAtToken(
                label.token,
                "mismatching label '{s}' != '{s}'",
                .{
                    expected.get(text.tree, cache),
                    label.ident.get(text.tree, cache),
                },
            );
        }
    } else if (label.some) {
        _ = try text.errorAtToken(label.token, "unexpected label");
    }
}

const LabelLookup = struct {
    stack: std.SegmentedList(?Ident.Interned, 4) = .{},
    map: std.AutoHashMapUnmanaged(Ident.Interned, Entry) = .empty,

    const LabelId = enum(u32) { _ };

    const Entry = struct {
        /// Always `>= 0`.
        count: u32,
        id: LabelId,
    };

    fn enter(
        labels: *LabelLookup,
        arena: *ArenaAllocator,
        block: Ident.Symbolic,
    ) Allocator.Error!void {
        const label_id: LabelId = @enumFromInt(std.math.cast(u32, labels.stack.len) orelse return error.OutOfMemory);
        try labels.stack.append(arena.allocator(), if (block.some) block.ident else null);
        if (block.some) {
            const entry = try labels.map.getOrPut(arena.allocator(), block.ident);
            entry.value_ptr.* = .{
                .id = label_id,
                .count = if (entry.found_existing)
                    std.math.add(u32, entry.value_ptr.count, 1) catch
                        return error.OutOfMemory
                else
                    1,
            };
        }
    }

    fn exit(
        labels: *LabelLookup,
        text: *TextContext,
        label: Ident.Symbolic,
        cache: *const Ident.Cache,
    ) Allocator.Error!void {
        // Parser ensures 'end' instructions are nested properly.
        const popped = labels.stack.pop() orelse unreachable;
        try checkMatchingLabels(text, popped, label, cache);

        // Check if a label below the stack was overwritten in the lookup.
        if (popped) |label_id| no_overwritten: {
            const entry = labels.map.getPtr(label_id) orelse break :no_overwritten;
            entry.count -= 1;

            if (entry.count == 0) {
                @branchHint(.likely);
                const removed = labels.map.remove(label_id);
                std.debug.assert(removed);
                break :no_overwritten;
            }

            for (0..labels.stack.len) |i| {
                const idx: u32 = @intCast(labels.stack.len - i - 1);
                const other_label: Ident.Interned = labels.stack.at(idx).* orelse continue;
                if (label_id == other_label) {
                    entry.id = @enumFromInt(idx);
                    break;
                }
            }
        }
    }

    fn getLabel(
        lookup: *LabelLookup,
        text: *TextContext,
        ident: Ident,
    ) Allocator.Error!u32 {
        switch (ident.toUnion(text.tree)) {
            .symbolic => |id| if (lookup.map.get(id)) |entry| {
                return @as(u32, @intCast(lookup.stack.len)) - @intFromEnum(entry.id) - 1;
            } else {
                _ = try text.errorAtToken(ident.token, "undefined label variable");
                return std.math.maxInt(u32);
            },
            .numeric => |idx| return idx,
        }
    }
};

// TODO: Parameter flag to indicate if data count should be emitted.
fn encodeExpr(
    output: std.ArrayList(u8).Writer,
    wasm: *const Wasm,
    expr: *const Text.Expr,
    ctx: *FuncContext,
    text: *TextContext,
    arena: IndexedArena.ConstData,
    caches: *const Caches,
    scratch: *ArenaAllocator,
) Allocator.Error!void {
    // Allocated in `scratch`.
    var label_lookup = LabelLookup{};

    try output.context.ensureUnusedCapacity(expr.count);

    var iter_instrs = expr.iterator(text.tree, arena);
    while (iter_instrs.next()) |instr| {
        try output.context.ensureUnusedCapacity(1);
        const instr_tag = instr.tag(text.tree) orelse {
            output.context.appendAssumeCapacity(@intFromEnum(opcodes.ByteOpcode.end));
            continue;
        };

        switch (instr_tag) {
            .@"memory.init",
            .@"memory.copy",
            .@"table.init",
            .@"table.copy",
            .@"ref.null",
            => unreachable, // TODO: see Instr.argumentTag()
            .select => {
                const select = instr.arguments.select;
                var chosen_type: ?ValType = null;
                if (select.opt()) |results| {
                    for (@as([]const Text.Result, results.items(arena))) |result_list| {
                        for (@as([]const Text.ValType, result_list.types.items(arena))) |result_type| {
                            if (chosen_type == null)
                                chosen_type = ValType.fromValType(result_type, text.tree)
                            else
                                _ = try text.errorAtToken(
                                    instr.keyword.getAtom().?,
                                    "invalid arity in select instruction",
                                );
                        }
                    }
                }

                if (chosen_type) |explicit| {
                    output.context.appendAssumeCapacity(@intFromEnum(opcodes.ByteOpcode.@"select t"));
                    try output.writeByte(1);
                    try explicit.encode(output);
                } else {
                    output.context.appendAssumeCapacity(@intFromEnum(opcodes.ByteOpcode.select));
                }
            },
            inline else => |tag| {
                const tag_name = comptime @tagName(tag);
                if (@hasField(opcodes.ByteOpcode, tag_name)) {
                    output.context.appendAssumeCapacity(@intFromEnum(@field(opcodes.ByteOpcode, tag_name)));
                } else opcode: {
                    inline for (opcodes.PrefixSet.all) |set| {
                        if (!@hasField(set.@"enum", tag_name)) continue;

                        output.context.appendAssumeCapacity(@intFromEnum(set.prefix));
                        try writeUleb128(output, @intFromEnum(@field(set.@"enum", tag_name)));
                        break :opcode;
                    }

                    @compileError("no corresponding opcode enum for " ++ tag_name);
                }

                const arg_tag = comptime Text.Instr.argumentTag(tag);
                const arg = @field(instr.arguments, @tagName(arg_tag));
                switch (arg_tag) {
                    .none => {},
                    .i32 => try std.leb.writeIleb128(output, @as(i32, arg.*)),
                    .i64 => try std.leb.writeIleb128(output, @as(i64, arg.*)),
                    .ident => switch (tag) {
                        .br, .br_if => try writeUleb128(
                            output,
                            try label_lookup.getLabel(text, arg.*),
                        ),
                        .call => try encodeIdx(
                            output,
                            FuncIdx,
                            try wasm.func_ids.getFromIdent(text, arg.*),
                        ),
                        .@"local.get", .@"local.set", .@"local.tee" => try encodeIdx(
                            output,
                            LocalIdx,
                            try ctx.local_lookup.getFromIdent(text, arg.*),
                        ),
                        else => std.debug.panic("cannot encode id for {}", .{tag}),
                    },
                    .label => switch (tag) {
                        .end => try label_lookup.exit(text, arg.*, &caches.ids),
                        .@"else" => {
                            // Parser ensures `else` instructions are correctly nested.
                            const if_label = label_lookup.stack.at(label_lookup.stack.len - 1).*;
                            try checkMatchingLabels(text, if_label, arg.*, &caches.ids);
                        },
                        else => std.debug.panic("cannot encode label for {}", .{tag}),
                    },
                    .block_type => block_type: {
                        const block_type: *align(4) const Text.Instr.BlockType = arg;
                        try label_lookup.enter(scratch, block_type.label);

                        const results: []const Text.Result = block_type.type.func.results.items(arena);
                        if (block_type.type.func.parameters.isEmpty()) inline_idx: {
                            var result_type: ?ValType = null;
                            for (results) |*result_list| {
                                const types: []const Text.ValType = result_list.types.items(arena);
                                switch (types.len) {
                                    0 => continue,
                                    1 => if (result_type == null) {
                                        result_type = ValType.fromValType(types[0], text.tree);
                                        continue;
                                    },
                                    else => {},
                                }

                                break :inline_idx;
                            }

                            try output.writeByte(if (result_type) |ty| @intFromEnum(ty) else 0x40);
                            break :block_type;
                        }

                        try encodeIdx(
                            output,
                            TypeIdx,
                            wasm.type_uses.get(&block_type.type).?,
                        );
                    },
                    .br_table => {
                        std.debug.assert(tag == .br_table);
                        const non_default_labels: []align(4) const Ident = arg.*.labels.items(arena);
                        try encodeVecLen(output, non_default_labels.len);

                        for (non_default_labels) |label| {
                            try writeUleb128(
                                output,
                                try label_lookup.getLabel(text, label),
                            );
                        }

                        try writeUleb128(
                            output,
                            try label_lookup.getLabel(text, arg.default_label),
                        );
                    },
                    .select => unreachable,
                    .mem_arg => {
                        const alignment: u5 = if (arg.align_token.some) arg.align_pow else 0;
                        const offset: u64 = if (arg.offset_token.some) arg.offset else 0;
                        try writeUleb128(output, alignment);
                        try writeUleb128(output, offset);
                    },
                    .f32 => try output.writeInt(u32, arg.*, .little),
                    .f64 => try output.writeInt(u64, arg.*, .little),
                    else => {
                        std.debug.panic("TODO: {}", .{arg_tag});
                    },
                }
            },
        }
    }
}

fn encodeLimits(
    output: std.ArrayList(u8).Writer,
    limits: *const Text.Limits,
) Allocator.Error!void {
    try output.writeByte(if (limits.max_token.some) 0x01 else 0x00);
    try writeUleb128(output, limits.min);
    if (limits.max_token.some) try writeUleb128(output, limits.max);
}

fn encodeMemType(
    output: std.ArrayList(u8).Writer,
    mem_type: *const Text.MemType,
) Allocator.Error!void {
    try encodeLimits(output, &mem_type.limits);
}

fn encodeText(
    module: *const Text,
    text_ctx: *TextContext,
    arena: IndexedArena.ConstData,
    caches: *const Caches,
    final_output: anytype,
    alloca: *ArenaAllocator,
) EncodeError(@TypeOf(final_output))!void {
    _ = alloca.reset(.retain_capacity);

    var scratch = ArenaAllocator.init(alloca.allocator());

    // Allocated in `alloca`.
    var wasm = Wasm{};
    var code_needs_data_count = false;
    for (@as([]const Text.Field, module.fields.items(arena))) |field| {
        switch (field.keyword.tag(text_ctx.tree)) {
            // .keyword_import => {wasm.checkImportOrdering();},
            .keyword_type => {
                const type_field = field.contents.type;
                const type_field_ptr: *const Text.Type = type_field.getPtr(arena);
                const type_idx: TypeIdx = @enumFromInt(std.math.cast(u32, wasm.types.len) orelse return error.OutOfMemory);

                try wasm.type_ids.insert(text_ctx, type_field_ptr.id, type_idx, alloca);
                try wasm.types.append(alloca.allocator(), field.contents.type);
                try wasm.type_dedup.lookup.putNoClobberContext(
                    alloca.allocator(),
                    &type_field_ptr.func,
                    type_idx,
                    .{ .arena = arena, .tree = text_ctx.tree },
                );
            },
            .keyword_func => {
                const func_field = field.contents.func;
                const func_field_ptr: *const Text.Func = func_field.getPtr(arena);
                const func_idx = try wasm.func_count.increment();

                try wasm.func_ids.insert(
                    text_ctx,
                    func_field_ptr.id,
                    func_idx,
                    alloca,
                );

                if (!func_field_ptr.inline_exports.isEmpty()) {
                    wasm.exports_count = try addOrOom(u32, wasm.exports_count, func_field_ptr.inline_exports.len);
                    try wasm.exports.append(
                        alloca.allocator(),
                        Export{ .inline_func = .{ .field = func_field, .idx = func_idx } },
                    );
                }

                try wasm.appendTypeUse(alloca, &func_field_ptr.type_use);

                if (func_field_ptr.inline_import.get()) |import_keyword| {
                    try wasm.checkImportOrdering(text_ctx, import_keyword);
                    try wasm.imports.append(
                        alloca.allocator(),
                        Import{ .inline_func = func_field },
                    );
                } else {
                    try wasm.defined_funcs.append(alloca.allocator(), func_field);

                    const body: *const Text.Expr = &func_field_ptr.body.defined;
                    var instr_iter = body.iterator(text_ctx.tree, arena);
                    while (instr_iter.next()) |instr| {
                        _ = &code_needs_data_count;
                        const type_use: *const Text.TypeUse = switch (instr.tag(text_ctx.tree) orelse continue) {
                            .@"memory.init",
                            .@"memory.copy",
                            .@"table.init",
                            .@"table.copy",
                            .@"ref.null",
                            => unreachable, // TODO: see Instr.argumentTag()
                            // .@"data.drop", .@"memory.init" => code_needs_data_count = true,
                            inline else => |tag| switch (comptime Text.Instr.argumentTag(tag)) {
                                .block_type => &instr.arguments.block_type.type,
                                .call_indirect => &instr.arguments.call_indirect.type,
                                .none,
                                .ident,
                                .ident_opt,
                                .label,
                                .br_table,
                                .select,
                                .mem_arg,
                                .i32,
                                .f32,
                                .i64,
                                .f64,
                                => continue,
                            },
                        };

                        try wasm.appendTypeUse(alloca, type_use);
                    }
                }
            },
            // .keyword_table => {},
            .keyword_memory => {
                const mem_field = field.contents.mem;
                const mem_field_ptr: *const Text.Mem = mem_field.getPtr(arena);
                const mem_idx = try wasm.mem_count.increment();

                try wasm.mem_ids.insert(
                    text_ctx,
                    mem_field_ptr.id,
                    mem_idx,
                    alloca,
                );

                if (!mem_field_ptr.inline_exports.isEmpty()) {
                    wasm.exports_count = try addOrOom(u32, wasm.exports_count, mem_field_ptr.inline_exports.len);
                    try wasm.exports.append(
                        alloca.allocator(),
                        Export{ .inline_mem = .{ .field = mem_field, .idx = mem_idx } },
                    );
                }

                const has_data = mem_field_ptr.data_keyword.some;

                var data_bytes: []const u8 = undefined;
                if (has_data) {
                    _ = scratch.reset(.retain_capacity);
                    const temp_buf = try mem_field_ptr.inner.data.writeToBuf(
                        text_ctx.tree,
                        arena,
                        scratch.allocator(),
                    );

                    data_bytes = try alloca.allocator().dupe(u8, temp_buf.items);
                }

                if (!has_data and mem_field_ptr.inner.no_data.inline_import.keyword.some) {
                    try wasm.checkImportOrdering(
                        text_ctx,
                        mem_field_ptr.inner.no_data.inline_import.keyword.inner_id,
                    );
                    try wasm.imports.append(
                        alloca.allocator(),
                        Import{ .inline_mem = mem_field },
                    );
                } else {
                    const page_size = 65536;
                    try wasm.defined_mems.append(
                        alloca.allocator(),
                        .{
                            .idx = mem_field,
                            .inferred_limit = if (has_data)
                                std.math.divFloor(
                                    u32,
                                    @intCast(data_bytes.len),
                                    page_size,
                                ) catch return error.OutOfMemory
                            else
                                undefined,
                        },
                    );
                }

                if (has_data) {
                    try wasm.data_segments.append(
                        alloca.allocator(),
                        try DataSegment.init(
                            .{
                                .inline_mem = .{
                                    .field = mem_field,
                                    .idx = mem_idx,
                                },
                            },
                            data_bytes,
                        ),
                    );
                }
            },
            .keyword_data => {
                const data_field = field.contents.data;
                const data_field_ptr: *const Text.Data = data_field.getPtr(arena);
                const data_idx: DataIdx = @enumFromInt(
                    std.math.cast(u32, wasm.data_segments.len) orelse return error.OutOfMemory,
                );

                try wasm.data_ids.insert(
                    text_ctx,
                    data_field_ptr.id,
                    data_idx,
                    alloca,
                );
                _ = scratch.reset(.retain_capacity);
                const temp_buf = try data_field_ptr.data.writeToBuf(
                    text_ctx.tree,
                    arena,
                    scratch.allocator(),
                );

                const data_bytes = try alloca.allocator().dupe(u8, temp_buf.items);

                try wasm.data_segments.append(
                    alloca.allocator(),
                    try DataSegment.init(
                        .{ .module_field = data_field },
                        data_bytes,
                    ),
                );
            },
            // .keyword_global => {},
            else => |bad| if (@import("builtin").mode == .Debug)
                std.debug.panic("TODO: handle module field {s}", .{@tagName(bad)})
            else
                unreachable,
        }
    }

    _ = scratch.reset(.retain_capacity);

    var section_buf = std.ArrayList(u8).init(alloca.allocator());

    try final_output.writeAll(wasm_preamble);

    encode_type_sec: {
        const type_sec = try wasm.resolveTypeSec(alloca, text_ctx, arena, &scratch);
        if (type_sec.len == 0) break :encode_type_sec;
        std.debug.assert(section_buf.items.len == 0);

        try encodeVecLen(section_buf.writer(), type_sec.len);

        var types_iter = type_sec.constIterator(0);
        var func_type_arena = ArenaAllocator.init(scratch.allocator());
        while (types_iter.next()) |func_type| {
            try encodeTypeSecFunc(section_buf.writer(), text_ctx.tree, arena, func_type.*, &func_type_arena);
            _ = func_type_arena.reset(.retain_capacity);
        }

        try encodeSection(final_output, 1, section_buf.items);
    }

    if (wasm.imports.len > 0) {
        section_buf.clearRetainingCapacity();

        const output = section_buf.writer();
        try encodeVecLen(output, wasm.imports.len);

        var iter_imports = wasm.imports.constIterator(0);
        while (iter_imports.next()) |import| {
            const name = import.name(arena);
            try encodeByteVec(output, name.module.id.bytes(arena, &caches.names));
            try encodeByteVec(output, name.name.id.bytes(arena, &caches.names));
            switch (import.*) {
                .inline_func => |func_field| {
                    try output.writeByte(0);
                    try encodeIdx(
                        output,
                        TypeIdx,
                        wasm.type_uses.get(&func_field.getPtr(arena).type_use).?,
                    );
                },
                else => unreachable, // TODO
            }
        }

        try encodeSection(final_output, 2, section_buf.items);
    }

    if (wasm.defined_funcs.len > 0) {
        section_buf.clearRetainingCapacity();

        try encodeVecLen(section_buf.writer(), wasm.defined_funcs.len);

        var iter_funcs = wasm.defined_funcs.constIterator(0);
        while (iter_funcs.next()) |func| {
            try encodeIdx(
                section_buf.writer(),
                TypeIdx,
                wasm.type_uses.get(&func.getPtr(arena).type_use).?,
            );
        }

        try encodeSection(final_output, 3, section_buf.items);
    }

    // table

    if (wasm.defined_mems.len > 0) {
        section_buf.clearRetainingCapacity();

        const output = section_buf.writer();
        try encodeVecLen(output, wasm.defined_mems.len);

        var iter_mems = wasm.defined_mems.constIterator(0);
        while (iter_mems.next()) |mem| {
            const mem_field: *const Text.Mem = mem.idx.getPtr(arena);
            if (mem_field.data_keyword.some) {
                try output.writeByte(0x01);

                var limit_buf = std.BoundedArray(u8, 5){};
                writeUleb128(limit_buf.writer(), mem.inferred_limit) catch unreachable;

                try output.writeBytesNTimes(limit_buf.constSlice(), 2);
            } else {
                try encodeMemType(output, &mem_field.inner.no_data.mem_type);
            }
        }

        try encodeSection(final_output, 5, section_buf.items);
    }

    // global

    std.debug.assert(wasm.exports.len <= wasm.exports_count);
    if (wasm.exports_count > 0) {
        section_buf.clearRetainingCapacity();

        const output = section_buf.writer();
        try encodeVecLen(output, wasm.exports_count);

        var iter_exports = wasm.exports.constIterator(0);
        while (iter_exports.next()) |exp| {
            // 1 byte ID + 5 bytes maximum LEB128 encoding of u32
            var export_desc_buf = std.BoundedArray(u8, 6){};
            const export_list: Text.InlineExports = exports: switch (exp.*) {
                .inline_func => |func| {
                    export_desc_buf.appendAssumeCapacity(0x00);
                    encodeIdx(export_desc_buf.writer(), FuncIdx, func.idx) catch unreachable;
                    break :exports func.field.getPtr(arena).inline_exports;
                },
                .inline_mem => |mem| {
                    export_desc_buf.appendAssumeCapacity(0x02);
                    encodeIdx(export_desc_buf.writer(), MemIdx, mem.idx) catch unreachable;
                    break :exports mem.field.getPtr(arena).inline_exports;
                },
            };

            std.debug.assert(export_desc_buf.len >= 2);
            std.debug.assert(export_list.len > 0);
            for (export_list.items(arena)) |inline_export| {
                try encodeByteVec(output, inline_export.name.id.bytes(arena, &caches.names));
                try output.writeAll(export_desc_buf.constSlice());
            }
        }

        try encodeSection(final_output, 7, section_buf.items);
    }

    if (code_needs_data_count) {
        std.debug.assert(wasm.data_segments.len > 0);
        section_buf.clearRetainingCapacity();

        try encodeVecLen(section_buf.writer(), wasm.data_segments.len);
        try encodeSection(final_output, 12, section_buf.items);
    }

    if (wasm.defined_funcs.len > 0) {
        _ = scratch.reset(.retain_capacity); // Must not be reset until all function bodies have been written.
        section_buf.clearRetainingCapacity();

        const section_output = section_buf.writer();
        try encodeVecLen(section_output, wasm.defined_funcs.len);

        var code_buffer = std.ArrayList(u8).init(scratch.allocator());
        const code_output = code_buffer.writer();

        // Allocated in `scratch`,
        var func_context = FuncContext{};

        var expr_arena = ArenaAllocator.init(scratch.allocator());

        var iter_funcs = wasm.defined_funcs.constIterator(0);
        while (iter_funcs.next()) |func_field| {
            code_buffer.clearRetainingCapacity();
            func_context.reset();

            const func: *const Text.Func = func_field.getPtr(arena);

            // Assign local indices to parameters with ids.
            for (@as([]const Text.Param, func.type_use.func.parameters.items(arena))) |param| {
                if (param.id.some) {
                    const local_idx = try func_context.local_counter.increment();
                    std.debug.assert(param.types.len == 1);
                    try func_context.local_lookup.insert(text_ctx, param.id, local_idx, &scratch);
                } else {
                    try func_context.local_counter.incrementBy(param.types.len);
                }
            }

            const locals: []const Text.Local = func.locals.items(arena);
            if (locals.len == 0) {
                try code_buffer.append(0);
            } else {
                const LocalGroup = packed struct(u32) {
                    count: u24,
                    type: ValType,
                };

                _ = expr_arena.reset(.retain_capacity);
                var local_groups = std.SegmentedList(LocalGroup, 4){};

                for (locals) |local_group| {
                    const local_types: []const Text.ValType = local_group.types.items(arena);
                    std.debug.assert(local_types.len >= 1);

                    if (local_group.id.some) {
                        const local_idx = try func_context.local_counter.increment();
                        std.debug.assert(local_types.len == 1);
                        try func_context.local_lookup.insert(text_ctx, local_group.id, local_idx, &scratch);
                    } else {
                        try func_context.local_counter.incrementBy(local_group.types.len);
                    }

                    var remaining_local_types = local_types;
                    while (remaining_local_types.len > 0) {
                        const current_type = ValType.fromValType(remaining_local_types[0], text_ctx.tree);
                        var next_group_idx = remaining_local_types.len;
                        for (1..remaining_local_types.len) |i| {
                            if (ValType.fromValType(remaining_local_types[i], text_ctx.tree) != current_type) {
                                next_group_idx = i;
                                break;
                            }
                        }

                        const new_entry = LocalGroup{
                            .type = current_type,
                            .count = std.math.cast(u24, next_group_idx) orelse
                                return error.OutOfMemory,
                        };

                        if (local_groups.len == 0) {
                            local_groups.append(undefined, new_entry) catch unreachable;
                        } else {
                            const prev_group = local_groups.at(local_groups.len - 1);
                            if (prev_group.type == current_type) {
                                // Coalesce two local groups with the same type
                                prev_group.count = std.math.add(
                                    u24,
                                    prev_group.count,
                                    new_entry.count,
                                ) catch return error.OutOfMemory;
                            } else {
                                try local_groups.append(expr_arena.allocator(), new_entry);
                            }
                        }

                        remaining_local_types = remaining_local_types[next_group_idx..];
                    }
                }

                try encodeVecLen(code_output, local_groups.len);
                for (0..local_groups.len) |i| {
                    const group: LocalGroup = local_groups.at(i).*;
                    try writeUleb128(code_output, group.count);
                    try group.type.encode(code_output);
                }
            }

            _ = expr_arena.reset(.retain_capacity);
            try encodeExpr(
                code_output,
                &wasm,
                &func.body.defined,
                &func_context,
                text_ctx,
                arena,
                caches,
                &expr_arena,
            );

            std.debug.dumpHex(code_buffer.items);

            try encodeByteVec(section_output, code_buffer.items);
        }

        try encodeSection(final_output, 10, section_buf.items);
    }

    if (wasm.data_segments.len > 0) {
        section_buf.clearRetainingCapacity();

        const output = section_buf.writer();
        try encodeVecLen(output, wasm.data_segments.len);

        var iter_datas = wasm.data_segments.constIterator(0);
        while (iter_datas.next()) |data_segment| {
            const bytes = data_segment.bytes[0..data_segment.bytes_len];
            const data: DataSegment.Expanded = data_segment.expanded();
            switch (data) {
                .module_field => |field| {
                    const data_field: *const Text.Data = field.getPtr(arena);
                    if (data_field.active.has_offset) {
                        try output.writeByte(0x00); // active data segment
                        _ = scratch.reset(.retain_capacity);
                        var func_ctx = FuncContext{};
                        try encodeExpr(
                            output,
                            &wasm,
                            &data_field.offset.expr,
                            &func_ctx,
                            text_ctx,
                            arena,
                            caches,
                            &scratch,
                        );
                    } else {
                        try output.writeByte(0x01); // passive data segment
                    }
                },
                .inline_mem => {
                    try output.writeAll(&[_]u8{
                        0x00, // active data segment

                        // offset expression
                        @intFromEnum(opcodes.ByteOpcode.@"i32.const"),
                        0,
                        @intFromEnum(opcodes.ByteOpcode.end),
                    });
                },
            }

            try encodeByteVec(output, bytes);
        }

        try encodeSection(final_output, 11, section_buf.items);
    }

    // std.debug.print("MODULE DUMP START:\n", .{});
    // std.debug.dumpHex(final_output.context.items);
    // std.debug.print("MODULE DUMP END:\n", .{});
}

/// Writes the binary representation of a given WebAssembly Text format module.
///
/// Callers must ensure that the `module` was parsed successfully.
pub fn encode(
    module: *const Module,
    tree: *const sexpr.Tree,
    arena: IndexedArena.ConstData,
    caches: *const Caches,
    output: anytype,
    errors: *Errors,
    alloca: *ArenaAllocator,
) EncodeError(@TypeOf(output))!void {
    _ = alloca.reset(.retain_capacity);
    var text_ctx = TextContext{ .tree = tree, .errors = errors };
    switch (module.taggedFormat(tree)) {
        .text => |text| try encodeText(
            text.getPtr(arena),
            &text_ctx,
            arena,
            caches,
            output,
            alloca,
        ),
        .quote => |quote_idx| {
            // Allocated in `alloca`.
            const module_text: []const u8 = text: {
                var contents = std.ArrayListUnmanaged(u8).empty;

                const quote: *const Module.Quote = quote_idx.getPtr(arena);
                for (@as([]const Module.String, quote.contents.items(arena))) |str| {
                    var parts = escapeStringLiteral(str.rawContents(tree));
                    while (parts.next()) |esc|
                        try contents.appendSlice(alloca.allocator(), esc.bytes());
                }

                break :text contents.items;
            };

            var scratch = std.heap.ArenaAllocator.init(alloca.allocator());
            const quoted_tree = tree: {
                const lexer = Lexer.init(module_text) catch |e| switch (e) {
                    error.InvalidUtf8 => {
                        _ = try text_ctx.errorAtToken(
                            module.format_keyword.get().?,
                            "WebAssembly Text is not valid UTF-8",
                        );
                        return;
                    },
                };

                break :tree try sexpr.Tree.parseFromLexer(
                    lexer,
                    alloca.allocator(),
                    &scratch,
                    errors,
                );
            };

            var quoted_arena = IndexedArena.init(alloca.allocator());
            var quoted_caches = Caches.init(alloca.allocator());

            var tree_parser = sexpr.Parser.init(quoted_tree.values.values(&quoted_tree));
            const quoted_module = Module.parseOrEmpty(
                &tree_parser,
                &text_ctx,
                &quoted_arena,
                &quoted_caches,
                &scratch,
            ) catch |e| switch (e) {
                error.OutOfMemory => |oom| return oom,
                error.EndOfStream => {
                    _ = try text_ctx.errorAtToken(
                        module.format_keyword.get().?,
                        "expected a module, but got end of file",
                    );
                    return;
                },
                error.ReportedParserError => return,
            };

            try tree_parser.expectEmpty(&text_ctx);

            var new_alloca = ArenaAllocator.init(alloca.allocator());
            // Recursive call!
            return encode(
                &quoted_module,
                &quoted_tree,
                quoted_arena.dataSlice(),
                &quoted_caches,
                output,
                errors,
                &new_alloca,
            );
        },
        .binary => |binary_idx| {
            const binary: *const Module.Binary = binary_idx.getPtr(arena);
            for (@as([]const Module.String, binary.contents.items(arena))) |str| {
                var parts = escapeStringLiteral(str.rawContents(tree));
                while (parts.next()) |esc|
                    try output.writeAll(esc.bytes());
            }
        },
    }
}
