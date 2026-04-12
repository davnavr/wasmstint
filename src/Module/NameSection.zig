//! Represents the contents of a `Module`'s [custom `name` section].
//!
//! Optimized for low memory usage by using binary search over a sorted array rather than fast
//! lookup with a hashmap. Currently provides basic functionality for retrieving names for stack
//! traces.
//!
//! [custom `name` section]: https://webassembly.github.io/spec/core/appendix/custom.html

const NameSection = @This();

first_byte: [*]const u8,
/// The name of the module, or `.none` if one was not provided.
///
/// For more information, see
/// https://webassembly.github.io/spec/core/appendix/custom.html#binary-modulenamesec
module_name: Name.Optional,

func_count: u32,
/// Sorted in increasing index value, without duplicates. Has `func_count` entries.
func_indices_ptr: [*]const FuncIdx,
/// See `Name.offset`.
func_name_offsets_ptr: [*]const Name.Offset,
/// See `Name.len`.
func_name_lens_ptr: [*]const Name.Len,

/// The number of functions with corresponding local name information.
local_count: u32,
/// Sorted in increasing index value, without duplicates. Has `local_count` entries.
local_funcs_ptr: [*]const FuncIdx,
/// For the corresponding function, indicates the number of named locals.
local_counts_ptr: [*]const u16,
local_starts_ptr: [*]const LocalNames.Start,

total_locals_count: usize,
/// Stored in increasing index value within each group of entries declared for each function index
/// (with local name information) in increasing index value.
///
/// Has `total_locals_count` entries.
local_indices_ptr: [*]const LocalIdx,
/// See `Name.offset`.
local_name_offsets_ptr: [*]const Name.Offset,
/// See `Name.len`.
local_name_lens_ptr: [*]const Name.Len,

pub const absent = NameSection{
    .first_byte = undefined,
    .module_name = .none,

    .func_count = 0,
    .func_indices_ptr = &[0]FuncIdx{},
    .func_name_offsets_ptr = &[0]Name.Offset{},
    .func_name_lens_ptr = &[0]Name.Len{},

    .local_count = 0,
    .local_funcs_ptr = &[0]FuncIdx{},
    .local_counts_ptr = &[0]u16{},
    .local_starts_ptr = &[0]LocalNames.Start{},

    .total_locals_count = 0,
    .local_indices_ptr = &[0]LocalIdx{},
    .local_name_offsets_ptr = &[0]Name.Offset{},
    .local_name_lens_ptr = &[0]Name.Len{},
};

/// Index referring to a local variable within a function.
const LocalIdx = enum(u16) { _ };

/// Used to read the names of local variables for a function.
///
/// Random access of names is not expected for locals, usage of the `Iterator` is preferred.
pub const LocalNames = struct {
    start: Start,
    count: u16,

    /// An integer index referring to the first local `Name` for a function. Essentially acts
    /// as a `[]const Name`, with the length stored externally.
    const Start = enum(u32) { _ };

    pub const Entry = packed struct(u64) {
        local: LocalIdx,
        name: Name,
    };

    /// Used to iterate over the names of all local variables for a given function.
    pub const Iterator = struct {
        index: u32,
        remaining: u16,

        pub fn next(iter: *Iterator, names: *const NameSection) ?Entry {
            if (iter.remaining == 0) {
                return null;
            } else {
                defer {
                    iter.index += 1;
                    iter.remaining -= 1;
                }

                const name = Name{
                    .offset = names.local_name_offsets_ptr[0..names.total_locals_count][iter.index],
                    .len = names.local_name_lens_ptr[0..names.total_locals_count][iter.index],
                };

                return Entry{
                    .local = names.local_indices_ptr[0..names.total_locals_count][iter.index],
                    .name = name,
                };
            }
        }
    };

    pub fn iterator(names: LocalNames) Iterator {
        return Iterator{
            .index = @intFromEnum(names.start),
            .remaining = names.count,
        };
    }
};

/// A UTF-8 encoded name for the definitions of a `Module`.
pub const Name = packed struct(u48) {
    /// Offset from the first byte of the `name` custom section.
    offset: Offset,
    len: Len,

    const Offset = enum(u32) {
        _,

        fn ptr(off: Offset, section: *const NameSection) [*]const u8 {
            return section.first_byte[@intFromEnum(off)..];
        }
    };

    /// Could be a `u31`, but this reduces memory usage of the `NameSection` as a whole, since
    /// names shouldn't be excessively large anyway.
    const Len = u16;

    pub fn bytes(name: Name, section: *const NameSection) []const u8 {
        return name.offset.ptr(section)[0..name.len];
    }

    pub fn formatIdentifier(
        name: Name,
        section: *const NameSection,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        return try Module.Name.formatIdentifier(Module.Name.init(name.bytes(section)), writer);
    }

    pub fn fmtIdentifier(
        name: Name,
        section: *const NameSection,
    ) std.fmt.Alt(Module.Name, Module.Name.formatIdentifier) {
        return Module.Name.init(name.bytes(section)).fmtIdentifier();
    }

    pub const Optional = packed struct(u49) {
        inner_unsafe: Name,
        is_some: bool,

        pub const none = Optional{
            .inner_unsafe = undefined,
            .is_some = false,
        };

        pub fn init(name: ?Name) Optional {
            return Optional{
                .inner_unsafe = name orelse undefined,
                .is_some = name != null,
            };
        }

        pub fn get(name: Optional) ?Name {
            return if (name.is_some) name.inner_unsafe else null;
        }

        pub fn bytes(name: Optional, section: *const NameSection) ?[]const u8 {
            return if (name.get()) |inner| inner.bytes(section) else null;
        }
    };

    fn parse(reader: Reader, start: [*]const u8, diag: Reader.Diagnostics) Error!Name {
        const name = try reader.readName(diag);
        if (name.bytes.len > std.math.maxInt(Len)) {
            return Error.WasmImplementationLimit; // name too long
        }

        return Name{
            .offset = @enumFromInt(name.bytes.ptr - start),
            .len = @intCast(name.bytes.len),
        };
    }
};

fn compareFuncIdx(context: FuncIdx, item: FuncIdx) Order {
    return std.math.order(@intFromEnum(context), @intFromEnum(item));
}

/// Does a binary search to find the name of the given function.
pub fn functionName(names: *const NameSection, f: FuncIdx) Name.Optional {
    const i = std.sort.binarySearch(
        FuncIdx,
        names.func_indices_ptr[0..names.func_count],
        f,
        compareFuncIdx,
    ) orelse return .none;

    return Name.Optional.init(Name{
        .offset = names.func_name_offsets_ptr[0..names.func_count][i],
        .len = names.func_name_lens_ptr[0..names.func_count][i],
    });
}

/// Does a binary search to find the names of the locals for the given function.
pub fn localNames(names: *const NameSection, f: FuncIdx) ?LocalNames {
    const i = std.sort.binarySearch(
        FuncIdx,
        names.local_funcs_ptr[0..names.local_count],
        f,
        compareFuncIdx,
    ) orelse return null;

    return LocalNames{
        .start = names.local_starts_ptr[0..names.local_count][i],
        .count = names.local_counts_ptr[0..names.local_count][i],
    };
}

const Sections = struct {
    buffers: *Buffers,
    readers: Readers,
    present: std.EnumSet(Id),

    const Buffers = @Struct(
        .auto,
        null,
        id_field_names,
        &(.{[]const u8} ** id_field_names.len),
        &(.{std.builtin.Type.StructField.Attributes{}} ** id_field_names.len),
    );
    const Readers = @Struct(
        .auto,
        null,
        id_field_names,
        &(.{Reader} ** id_field_names.len),
        &(.{std.builtin.Type.StructField.Attributes{}} ** id_field_names.len),
    );

    const id_field_names = std.meta.fieldNames(Id);

    const Id = enum(u8) {
        module = 0,
        function = 1,
        local = 2,
        // @"type" = 4,
        // field = 10,
        // tag = 11,
    };

    fn parse(reader: Reader, buffers: *Buffers, diag: Reader.Diagnostics) Error!Sections {
        var last: ?Id = null;
        var readers: Readers = undefined;
        var present = std.EnumSet(Id).initEmpty();

        // TODO: Actually read sections one-by-one, allowing at least some name subsections to be parsed
        // even when unknown subsections are present

        // TODO: On parse error, don't discard all name information

        while (!reader.isEmpty()) {
            const id_byte = try reader.readByte(diag, "name subsection id");
            const section_contents = try reader.readByteVec(diag, "section contents");
            // Silently skip unknown subsections.
            // LLVM appears to emit custom subsections for global and data segment names. These are
            // not documented in the appendix of the 3.0 WebAssembly standard nor the WASM tool
            // conventions.
            const id = std.enums.fromInt(Id, id_byte) orelse continue;
            if (last) |prev| {
                if (prev == id) {
                    return diag.print(
                        .parse,
                        "unexpected content after last section: duplicate '{t}' section",
                        .{id},
                    );
                } else if (@intFromEnum(id) < @intFromEnum(prev)) {
                    return diag.print(
                        .parse,
                        "unexpected content after last section: '{t}' was placed after {t}",
                        .{ id, prev },
                    );
                }
            }

            std.debug.assert(!present.contains(id));
            present.insert(id);
            switch (id) {
                inline else => |section_id| {
                    const name = @tagName(section_id);
                    @field(buffers, name) = section_contents;
                    @field(readers, name) = Reader.init(&@field(buffers, name));
                },
            }

            last = id;
        }

        return Sections{ .buffers = buffers, .readers = readers, .present = present };
    }
};

pub fn parse(
    arena: *std.heap.ArenaAllocator,
    contents: []const u8,
    scratch: *std.heap.ArenaAllocator,
    diag: Reader.Diagnostics,
    counts: struct {
        func: u32,
    },
) Error!*const NameSection {
    std.debug.assert(contents.len <= std.math.maxInt(u32));

    var name_section = contents;
    const section_reader = Reader.init(&name_section);
    var section_buffers: Sections.Buffers = undefined;
    var sections = try Sections.parse(section_reader, &section_buffers, diag);
    std.debug.assert(section_reader.isEmpty());

    const module_name = if (sections.present.contains(.module)) name: {
        const name = try Name.parse(sections.readers.module, contents.ptr, diag);
        try sections.readers.module.expectEnd(
            diag,
            "section size mismatch, expected end of module name subsection",
        );
        break :name Name.Optional.init(name);
    } else Name.Optional.none;

    const func_count = if (sections.present.contains(.function))
        try sections.readers.function.readUleb128(u32, diag, "function name count")
    else
        0;

    const local_count = if (sections.present.contains(.local))
        try sections.readers.function.readUleb128(u32, diag, "local name map count")
    else
        0;

    var main_layout = allocators.Reservation{};
    try main_layout.reserve(NameSection, 1);
    {
        try main_layout.reserve(FuncIdx, func_count);
        try main_layout.reserve(Name.Offset, func_count);
        try main_layout.reserve(Name.Len, func_count);
    }
    {
        try main_layout.reserve(FuncIdx, local_count);
        try main_layout.reserve(u16, local_count);
        try main_layout.reserve(LocalNames.Start, local_count);
    }

    var main_buffer_allocator = try main_layout.bufferAllocator(arena.allocator());
    const main_allocator = main_buffer_allocator.allocator();

    const header = main_allocator.create(NameSection) catch unreachable;
    std.debug.assert(@intFromPtr(header) == @intFromPtr(main_buffer_allocator.buffer.ptr));
    header.first_byte = contents.ptr;
    header.module_name = module_name;
    header.func_count = func_count;
    {
        const func_indices = main_allocator.alloc(FuncIdx, func_count) catch unreachable;
        const name_offsets = main_allocator.alloc(Name.Offset, func_count) catch unreachable;
        const name_lens = main_allocator.alloc(Name.Len, func_count) catch unreachable;
        for (func_indices, name_offsets, name_lens, 0..) |*func_idx, *name_off, *name_l, i| {
            const reader: Reader = sections.readers.function;
            func_idx.* = try reader.readIdx(
                FuncIdx,
                counts.func,
                diag,
                &.{ "function", "in function name subsection" },
            );

            if (i > 0 and @intFromEnum(func_idx.*) <= @intFromEnum(func_indices[i - 1])) {
                return diag.print(
                    .parse,
                    "out-of-order or duplicate funcidx {d} in function name subsection",
                    .{@intFromEnum(func_idx.*)},
                );
            }

            const name = try Name.parse(reader, contents.ptr, diag);
            name_off.* = name.offset;
            name_l.* = name.len;
        }

        try sections.readers.module.expectEnd(
            diag,
            "section size mismatch, expected end of function name subsection",
        );
        sections.buffers.module = undefined;

        header.func_indices_ptr = func_indices.ptr;
        header.func_name_offsets_ptr = name_offsets.ptr;
        header.func_name_lens_ptr = name_lens.ptr;
    }

    const Local = struct {
        local: LocalIdx,
        name_offset: Name.Offset,
        name_len: Name.Len,
    };

    if (local_count > 0) {
        _ = scratch.reset(.retain_capacity);
        var local_names = try std.MultiArrayList(Local).initCapacity(
            scratch.allocator(),
            local_count,
        );
        const func_indices = main_allocator.alloc(FuncIdx, local_count) catch unreachable;
        const func_local_counts = main_allocator.alloc(u16, local_count) catch unreachable;
        const local_starts = main_allocator.alloc(LocalNames.Start, local_count) catch unreachable;
        for (
            func_indices,
            func_local_counts,
            local_starts,
            0..local_count,
        ) |*func_idx, *loc_count, *loc_start, i| {
            const reader: Reader = sections.readers.function;
            func_idx.* = try reader.readIdx(
                FuncIdx,
                counts.func,
                diag,
                &.{ "function", "in local name subsection" },
            );

            if (i > 0 and @intFromEnum(func_idx.*) <= @intFromEnum(func_indices[i - 1])) {
                return diag.print(
                    .parse,
                    "out-of-order or duplicate funcidx {d} in local name subsection",
                    .{@intFromEnum(func_idx.*)},
                );
            }

            loc_count.* = try reader.readUleb128Casted(u32, u16, diag, "local name map count");
            try local_names.ensureUnusedCapacity(scratch.allocator(), loc_count.*);
            loc_start.* = @enumFromInt(local_names.len);
            var last_local_idx: ?LocalIdx = null;
            for (0..loc_count.*) |_| {
                const local_idx = try reader.readIdx(
                    LocalIdx,
                    std.math.maxInt(usize),
                    diag,
                    &.{ "local", "in local name subsection" },
                );
                if (last_local_idx) |prev_idx| {
                    if (@intFromEnum(local_idx) <= @intFromEnum(prev_idx)) {
                        return diag.print(
                            .parse,
                            "out-of-order or duplicate localidx {d} for function {d} in local " ++
                                "name subsection",
                            .{ @intFromEnum(local_idx), @intFromEnum(func_idx.*) },
                        );
                    }
                }

                last_local_idx = local_idx;

                const name = try Name.parse(reader, contents.ptr, diag);
                local_names.appendAssumeCapacity(Local{
                    .local = local_idx,
                    .name_offset = name.offset,
                    .name_len = name.len,
                });
            }
        }

        header.local_funcs_ptr = func_indices.ptr;
        header.local_counts_ptr = func_local_counts.ptr;
        header.local_starts_ptr = local_starts.ptr;

        header.total_locals_count = local_names.len;
        var locals_dst = std.MultiArrayList(Local).empty;
        try locals_dst.setCapacity(arena.allocator(), local_names.len);

        const locals_src_slices = local_names.slice();
        const locals_dst_slices = locals_dst.slice();
        inline for (std.enums.values(std.meta.FieldEnum(Local))) |field| {
            @memcpy(locals_dst_slices.items(field), locals_src_slices.items(field));
        }
    }

    return header;
}

const std = @import("std");
const Order = std.math.Order;
const allocators = @import("allocators");
const Module = @import("../Module.zig");
const Error = Module.ParseError;
const FuncIdx = Module.FuncIdx;
const Reader = @import("Reader.zig");
