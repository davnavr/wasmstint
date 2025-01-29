//! Converts modules in the WebAssembly Text format to the [binary format].
//!
//! [binary format]: https://webassembly.github.io/spec/core/binary/index.html

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const SegmentedList = std.SegmentedList;
const writeUleb128 = std.leb.writeUleb128;
const IndexedArena = @import("../../IndexedArena.zig");

const Ident = @import("../ident.zig").Ident;
const Name = @import("../Name.zig");
const Caches = @import("../Caches.zig");

const Lexer = @import("../Lexer.zig");
const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;
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
pub const FuncIdx = enum(u32) { _ };

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
                    if (@intFromEnum(a_param) != @intFromEnum(b_param))
                        return false;
                }

                if (b_params_iter.next(ctx.tree, ctx.arena) != null) return false;
            }
            {
                var a_results_iter = IterResultTypes.init(a.results.items(ctx.arena));
                var b_results_iter = IterResultTypes.init(b.results.items(ctx.arena));
                while (a_results_iter.next(ctx.tree, ctx.arena)) |a_param| {
                    const b_param = b_results_iter.next(ctx.tree, ctx.arena) orelse return false;
                    if (@intFromEnum(a_param) != @intFromEnum(b_param))
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
            .inline_table => |table| &table.getPtr(arena).inner.no_elements.inline_import.name,
            .inline_mem => |mem| &mem.getPtr(arena).import_exports.import.name,
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

    fn name(@"export": Export, arena: IndexedArena.ConstData) Text.InlineExports {
        const list = switch (@"export") {
            .inline_func => |func| func.field.getPtr(arena).inline_exports,
        };

        std.debug.assert(!list.isEmpty());
        return list;
    }

    comptime {
        std.debug.assert(@sizeOf(Export) == 8);
    }
};

fn IdxCounter(comptime Idx: type) type {
    return struct {
        next: Idx = @enumFromInt(0),

        const Self = @This();

        pub fn increment(counter: *Self) Allocator.Error!Idx {
            const give = counter.next;
            counter.next = @enumFromInt(
                try addOrOom(
                    @typeInfo(Idx).@"enum".tag_type,
                    @intFromEnum(counter.next),
                    1,
                ),
            );
            return give;
        }
    };
}

const Wasm = struct {
    /// Types originating from `Text.Type` fields come before those inserted by `TypeUse`s.
    types: std.SegmentedList(IndexedArena.Idx(Text.Type), 8) = .{},
    imports: std.SegmentedList(Import, 4) = .{},
    exports: std.SegmentedList(Export, 4) = .{},
    exports_count: u32 = 0,

    func_count: IdxCounter(FuncIdx) = .{},
    defined_funcs: std.SegmentedList(IndexedArena.Idx(Text.Func), 8) = .{},

    type_uses: std.AutoArrayHashMapUnmanaged(*const Text.TypeUse, TypeIdx) = .empty,
    type_dedup: TypeDedup = .empty,

    type_ids: IdentLookup(TypeIdx) = .empty,
    func_ids: IdentLookup(FuncIdx) = .empty,

    fn checkImportOrdering(
        state: *const Wasm,
        import_keyword: sexpr.TokenId,
        errors: *Error.List,
    ) Allocator.Error!void {
        if (state.defined_funcs.len > 0)
            try errors.append(Error.initImportAfterDefinition(import_keyword));
    }

    const TypeSec = std.SegmentedList(Type, 8);

    fn resolveTypeSec(
        wasm: *Wasm,
        wasm_arena: *ArenaAllocator,
        tree: *const sexpr.Tree,
        arena: IndexedArena.ConstData,
        errors: *Error.List,
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
                        .{ .arena = arena, .tree = tree },
                    );

                    if (dedup_entry.found_existing) {
                        break :type_idx dedup_entry.value_ptr.*;
                    } else {
                        const type_idx: TypeIdx = @enumFromInt(
                            std.math.cast(u32, wasm.types.len) orelse
                                return error.OutOfMemory,
                        );

                        try type_sec.append(output.allocator(), &type_use.func);
                        dedup_entry.value_ptr.* = type_idx;
                        break :type_idx type_idx;
                    }
                } else switch (type_use.id.type.toUnion(tree)) {
                    .symbolic => |id| type_idx: switch (wasm.type_ids.get(id, type_use.id.type.token)) {
                        .ok => |ok| {
                            const type_cmp_ctx = TypeDedup.Context{ .arena = arena, .tree = tree };
                            if (!type_cmp_ctx.eql(&wasm.types.at(@intFromEnum(ok)).getPtr(arena).func, &type_use.func)) {
                                try errors.append(Error.initTypeUseMismatch(type_use.id.type));
                            }

                            break :type_idx ok;
                        },
                        .err => |err| {
                            try errors.append(err);
                            break :type_idx undefined;
                        },
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
        id: Ident.Symbolic,
        alloca: *ArenaAllocator,
        errors: *Error.List,
    ) Allocator.Error!void {
        if (!id.some) return;

        const entry = try lookup.map.getOrPut(alloca.allocator(), id.ident);
        if (entry.found_existing) {
            try errors.append(Error.initDuplicateIdent(id, entry.value_ptr.*));
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

fn encodeText(
    module: *const Text,
    tree: *const sexpr.Tree,
    arena: IndexedArena.ConstData,
    caches: *const Caches,
    output: anytype,
    errors: *Error.List,
    alloca: *ArenaAllocator,
) EncodeError(@TypeOf(output))!void {
    _ = alloca.reset(.retain_capacity);

    // Allocated in `alloca`.
    var wasm = Wasm{};
    for (@as([]const Text.Field, module.fields.items(arena))) |field| {
        switch (field.keyword.tag(tree)) {
            // .keyword_import => {wasm.checkImportOrdering();},
            .keyword_type => {
                const type_field = field.contents.type;
                const type_field_ptr: *const Text.Type = type_field.getPtr(arena);
                const type_idx: TypeIdx = @enumFromInt(std.math.cast(u32, wasm.types.len) orelse return error.OutOfMemory);

                try wasm.type_ids.insert(type_field_ptr.id, type_idx, alloca, errors);
                try wasm.types.append(alloca.allocator(), field.contents.type);
                try wasm.type_dedup.lookup.putNoClobberContext(
                    alloca.allocator(),
                    &type_field_ptr.func,
                    type_idx,
                    .{ .arena = arena, .tree = tree },
                );
            },
            .keyword_func => {
                const func_field = field.contents.func;
                const func_field_ptr: *const Text.Func = func_field.getPtr(arena);
                const func_idx = try wasm.func_count.increment();

                try wasm.func_ids.insert(
                    func_field_ptr.id,
                    func_idx,
                    alloca,
                    errors,
                );

                if (!func_field_ptr.inline_exports.isEmpty()) {
                    wasm.exports_count = try addOrOom(u32, wasm.exports_count, func_field_ptr.inline_exports.len);
                    try wasm.exports.append(
                        alloca.allocator(),
                        Export{ .inline_func = .{ .field = func_field, .idx = func_idx } },
                    );
                }

                try wasm.type_uses.putNoClobber(alloca.allocator(), &func_field_ptr.type_use, undefined);

                if (func_field_ptr.inline_import.get()) |import_keyword| {
                    try wasm.checkImportOrdering(import_keyword, errors);
                    try wasm.imports.append(
                        alloca.allocator(),
                        Import{ .inline_func = func_field },
                    );
                } else {
                    try wasm.defined_funcs.append(alloca.allocator(), func_field);

                    const body: *const Module.Text.Expr = &func_field_ptr.body.defined;
                    var instr_iter = body.iterator(tree, arena);
                    while (instr_iter.next()) |instr| {
                        _ = instr;
                    }

                    // TODO: Get `TypeUse`s from the function's body.
                }
            },
            // .keyword_table => {},
            // .keyword_memory => {},
            // .keyword_global => {},
            else => unreachable,
        }
    }

    var scratch = ArenaAllocator.init(alloca.allocator());
    var section_buf = std.ArrayList(u8).init(alloca.allocator());

    try output.writeAll(wasm_preamble);

    encode_type_sec: {
        const type_sec = try wasm.resolveTypeSec(alloca, tree, arena, errors, &scratch);
        if (type_sec.len == 0) break :encode_type_sec;

        try encodeVecLen(section_buf.writer(), type_sec.len);

        var types_iter = type_sec.constIterator(0);
        var func_type_arena = ArenaAllocator.init(scratch.allocator());
        while (types_iter.next()) |func_type| {
            try encodeTypeSecFunc(section_buf.writer(), tree, arena, func_type.*, &func_type_arena);
            _ = func_type_arena.reset(.retain_capacity);
        }

        try encodeSection(output, 1, section_buf.items);
    }

    if (wasm.imports.len > 0) {
        _ = scratch.reset(.retain_capacity);
        section_buf.clearRetainingCapacity();

        try encodeVecLen(section_buf.writer(), wasm.imports.len);

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

        try encodeSection(output, 2, section_buf.items);
    }

    if (wasm.defined_funcs.len > 0) {
        _ = scratch.reset(.retain_capacity);
        section_buf.clearRetainingCapacity();

        try encodeVecLen(section_buf.writer(), wasm.defined_funcs.len);

        var iter_funcs = wasm.defined_funcs.constIterator(0);
        while (iter_funcs.next()) |func| {
            try encodeIdx(
                output,
                TypeIdx,
                wasm.type_uses.get(&func.getPtr(arena).type_use).?,
            );
        }

        try encodeSection(output, 3, section_buf.items);
    }
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
    errors: *Error.List,
    alloca: *ArenaAllocator,
) EncodeError(@TypeOf(output))!void {
    _ = alloca.reset(.retain_capacity);
    switch (module.taggedFormat(tree)) {
        .text => |text| try encodeText(
            text.getPtr(arena),
            tree,
            arena,
            caches,
            output,
            errors,
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
                        try errors.append(Error.initInvalidUtf8(module.format_keyword.get().?));
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
            const quoted_module_result = Module.parseOrEmpty(
                &tree_parser,
                &quoted_tree,
                &quoted_arena,
                &quoted_caches,
                errors,
                &scratch,
            ) catch |e| switch (e) {
                error.OutOfMemory => |oom| return oom,
                error.EndOfStream => {
                    // A more detailed error would be better here.
                    try errors.append(
                        Error.initUnexpectedValue(
                            sexpr.Value.initAtom(module.format_keyword.get().?),
                            .at_value,
                        ),
                    );

                    return;
                },
            };

            try tree_parser.expectEmpty(errors);

            switch (quoted_module_result) {
                .ok => |quoted_module| {
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
                .err => |err| try errors.append(err),
            }
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
