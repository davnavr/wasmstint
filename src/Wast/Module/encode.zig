//! Converts modules in the WebAssembly Text format to the [binary format].
//!
//! [binary format]: https://webassembly.github.io/spec/core/binary/index.html

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const SegmentedList = std.SegmentedList;
const writeUleb128 = std.leb.writeUleb128;
const IndexedArena = @import("../../IndexedArena.zig");

const Ident = @import("../ident.zig").Ident;
const Name = @import("../Name.zig");
const Caches = @import("../Caches.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;
const escapeStringLiteral = @import("../value.zig").string;
const Module = @import("../Module.zig");
const Text = Module.Text;

fn EncodeError(comptime Out: type) type {
    return error{OutOfMemory} || Out.Error;
}

fn writeByteVec(output: anytype, bytes: []const u8) EncodeError(output) {
    try writeUleb128(output, std.math.cast(u32, bytes.len) orelse return error.OutOfMemory);
}

/// A model of the WebAssembly [abstract syntax].
///
/// [abstract syntax]: https://webassembly.github.io/spec/core/syntax/index.html
const Wasm = struct {
    const Type = union(enum) {
        field: IndexedArena.Idx(Text.Type),
        // block_type
        // func: IndexedArena.Idx(Text.Func),

        const Idx = enum(u32) { _ };

        const Sec = struct {
            sec: std.SegmentedList(Type, 8),
            ids: std.AutoHashMapUnmanaged(Ident.Interned, Idx),

            const empty = Sec{ .sec = .{}, .ids = .empty };
        };

        // TODO: Use this for comparisons when inserting new TypeUses
        // fn funcType(ty: Type) *const Text.Type.Func
    };

    const Import = union(enum) {
        // field: IndexedArena.Idx(Text.ImportOrSomething), // reference to import field
        inline_func: IndexedArena.Idx(Text.Func),

        fn name(import: Import, arena: *const IndexedArena) *const Text.ImportName {
            switch (import) {
                .inline_func => |func| &func.getPtr(arena).body.inline_import,
            }
        }
    };

    const Func = struct {
        decl: IndexedArena.Idx(Text.Func),
        type_idx: Type.Idx,
    };

    const CodeSec = struct {
        const Fixup = packed struct(u32) {
            tag: enum(u2) {
                bytes,
                // type_use,
            },
            payload: packed union {
                bytes: packed struct(u30) { len: u30 },
            },
        };
    };

    const Export = union(enum) {
        // field: ,
        inline_func: IndexedArena.Idx(Text.Func),

        // fn names(def: Export, arena: *const IndexedArena) Text.InlineExports {
        //     switch (def) {
        //         .inline_func => |func| func.getPtr(arena).inline_exports,
        //     }
        // }
    };

    types: Type.Sec = .empty,
    imports: std.SegmentedList(Import, 8) = .{},
    exports: std.SegmentedList(Export, 8) = .{},
    funcs: std.SegmentedList(Func, 8) = .{},
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
    ) error{OutOfMemory}!void {
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

fn encodeText(
    module: *const Text,
    tree: *const sexpr.Tree,
    arena: *const IndexedArena,
    caches: *const Caches,
    output: anytype,
    errors: *Error.List,
    alloca: *ArenaAllocator,
) EncodeError(@TypeOf(output))!void {
    // Allocated in `alloca`.
    var wasm = Wasm{};
    var index_spaces = IndexSpaces{};
    // TODO: Need way to determine total # of funcs, especially when imports come into the picture
    for (@as([]const Text.Field, module.fields.items(arena))) |field| {
        switch (field.keyword.tag(tree)) {
            .keyword_type => {
                const type_idx = field.contents.type;
                const func_type: *const Text.Type = type_idx.getPtr(arena);

                std.debug.assert(func_type.keyword.tag(tree) == .keyword_func);

                const num_id = std.math.cast(u32, wasm.types.sec.len) orelse return error.OutOfMemory;
                try wasm.types.sec.append(alloca.allocator(), type_idx);

                const id = func_type.id.ident;
                if (id.some) {
                    const entry = try wasm.types.ids.getOrPut(alloca.allocator(), id.ident);
                    if (entry.found_existing) {
                        try errors.append(Error.initDuplicateIdent(id, entry.value_ptr.*));
                    } else {
                        entry.value_ptr.* = @as(Wasm.Type.Idx, @enumFromInt(num_id));
                    }
                }
            },
            .keyword_func => {
                const func_idx = field.contents.func;
                const func: *const Text.Func = func_idx.getPtr(arena);

                try index_spaces.functions.insert(func.id, alloca, errors);

                // TODO: Add TypeUse to typesec
                // - how to get the type index used?
                // - add an std.SegmentedList(u32) for func types? or Func = struct { decl: IndexedArena.Idx(Text.Func), type_idx: u32 };

                if (func.inline_import.some) {
                    try wasm.imports.append(alloca.allocator(), .{ .inline_func = func_idx });
                } else {
                    try wasm.funcs.append(alloca.allocator(), func_idx);
                }

                try wasm.exports.append(alloca.allocator(), .{ .inline_func = func_idx });
            },
            else => unreachable,
        }
    }

    var section_arena = ArenaAllocator.init(alloca.allocator());
    var section_buffer = std.ArrayList(u8).init(section_arena.allocator()); // std.SegmentedList(u8, 0x200)
    const section: std.ArrayList(u8).Writer = section_buffer.writer();

    _ = section;
    _ = caches;
    unreachable; // TODO

    // var iter_imports = fixed_sections.imports.constIterator(0);
    // while (iter_imports.next()) |import| {
    // const ImportDesc = union {
    //     // type
    // };

    // var name = switch (import.*); // Don't switch twice,

    // const import_desc = switch (import.*) {
    //     .inline_func => |func_idx| {
    //         // writeByteVec(section, func.);
    //     },
    // };

    // // TODO: Switches above set variables, do writing here
    // }

    // TODO: May need to wait for sections that might use typeuse to be written to buffers before finally writing the typesec

    // if (fixed_sections.imports.len > 0) {
    //     const import_sec_len = std.math.cast(u32, section_buffer.items.len) orelse return error.OutOfMemory;
    //     try output.writeByte(2);
    //     try writeUleb128(output, import_sec_len);
    //     try output.writeAll(section_buffer.items);
    //     section_buffer.clearRetainingCapacity();
    //     _ = section_arena.reset(.retain_capacity);
    // }

    // TODO: How to ensure `index_spaces` allows retrieval of u32 index?
    // - Indices must only be assigned after all definitions + imports are parsed
    // - type use ensures insertion of new types in Expr only appends to the end of the module
    // - should write to index_spaces occur when field is first processed, or after all functions are known?

    // Implement encoding of name section.
}

/// Writes the binary representation of a given WebAssembly Text format module.
///
/// Callers must ensure that the `module` was parsed successfully.
pub fn encode(
    module: *const Module,
    tree: *const sexpr.Tree,
    arena: *const IndexedArena,
    caches: *const Caches,
    output: anytype,
    errors: Error.List,
    alloca: *ArenaAllocator,
) EncodeError(@TypeOf(output))!void {
    // preamble
    try output.writeAll("\x00asm\x01\x00\x00\x00");

    _ = alloca.reset(.retain_capacity);
    switch (module.format) {
        .text => |text| try encodeText(
            text.getPtr(arena),
            tree,
            arena,
            caches,
            output,
            errors,
            &alloca,
        ),
        .quote => |quote_idx| {
            // Allocated in `alloca`.
            const module_text: []const u8 = text: {
                var contents = std.ArrayListUnmanaged(u8).empty;

                const quote: *const Module.Quote = quote_idx.getPtr(arena);
                for (@as([]const Module.String, quote.contents.items(arena))) |str| {
                    var parts = escapeStringLiteral(str.rawContents(tree));
                    while (parts.next()) |esc|
                        contents.appendSlice(alloca.allocator(), esc.bytes());
                }

                break :text contents.items;
            };

            var scratch = std.heap.ArenaAllocator.init(alloca.allocator());
            const quoted_tree = tree: {
                var lexer = sexpr.Lexer.init(module_text) catch |e| switch (e) {
                    error.InvalidUtf8 => {
                        errors.append(Error.initInvalidUtf8(module.format_keyword.get().?));
                        return;
                    },
                };

                break :tree try sexpr.Tree.parseFromLexer(&lexer, alloca.allocator(), &scratch, errors);
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
                            sexpr.Value.initAtom(module.format_keyword),
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
                        &quoted_arena,
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
