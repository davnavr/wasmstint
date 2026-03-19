//! API for building WebAssembly modules.
//!
//! Since `wasmstint` does not have functionality for parsing the WebAssembly Text Format (since
//! it's a pain), this allows creating WASM modules without writing inline byte array literals by
//! hand or depending on build script logic to invoke `wat2wasm` from WABT.

const WasmBuilder = @This();

pub const String = enum(u32) {
    _,

    const Payload = packed struct(u64) {
        offset: u32,
        len: u32,
    };

    pub fn slice(s: String, b: *const WasmBuilder) []const u8 {
        const payload = b.string_payloads.items[@intFromEnum(s)];
        return b.string_contents.items[payload.offset..][0..payload.len];
    }
};

pub const ValType = enum(u8) {
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0x7D,
    f64 = 0x7C,
    v128 = 0x7B,
    funcref = 0x70,
    externref = 0x6F,

    const Index = enum(u32) {
        _,

        fn slice(idx: Index, b: *const WasmBuilder, len: usize) []const ValType {
            return b.val_types.items[@intFromEnum(idx)..][0..len];
        }
    };
};

pub const TypeIdx = enum(u32) {
    _,

    const FuncType = packed struct(u64) {
        types: ValType.Index,
        param_count: u16,
        result_count: u16,
    };

    fn funcType(ty: TypeIdx, b: *const WasmBuilder) FuncType {
        return b.type_section.items[@intFromEnum(ty)];
    }

    pub fn paramTypes(ty: TypeIdx, b: *const WasmBuilder) []const ValType {
        const info = ty.funcType(b);
        return info.types.slice(b, info.param_count);
    }

    pub fn resultTypes(ty: TypeIdx, b: *const WasmBuilder) []const ValType {
        const info = ty.funcType(b);
        return info.types
            .slice(b, @as(usize, info.param_count) + info.result_count)[info.param_count..];
    }
};

pub const FuncIdx = enum(u32) {
    _,

    pub fn signature(f: FuncIdx, b: *const WasmBuilder) TypeIdx {
        return b.func_types.items[@intFromEnum(f)];
    }

    pub fn writeCode(
        f: FuncIdx,
        allocator: Allocator,
        b: *WasmBuilder,
        arena: *ArenaAllocator,
        options: struct {
            uleb_min_len: Writer.UlebLen = .smallest,
        },
    ) CodeWriter {
        _ = arena.reset(.retain_capacity);
        return CodeWriter{
            .builder = b,
            .function = f,
            .signature = f.signature(b).funcType(b),
            .body = Writer{ .gpa = allocator, .buf = .empty },
            .locals = .empty,
            .arena = arena,
            .val_stack = .empty,
            .uleb_min_len = options.uleb_min_len,
        };
    }
};

const Code = struct {
    body_size: u32,
    /// Allocated in the arena.
    body_ptr: [*]const u8,

    const placeholder = Code{
        .body_ptr = @as([]const u8, &[0]u8{}).ptr,
        .body_len = 0,
    };
};

const ExportOrImportKind = enum(u8) {
    func = 0x00,
};

pub const Import = struct {
    module: String,
    name: String,
    value: Desc,

    pub const Desc = union(ExportOrImportKind) {
        func: TypeIdx,
    };
};

pub const ExportDesc = union(ExportOrImportKind) {
    func: FuncIdx,

    const LookupContext = struct {
        b: *const WasmBuilder,

        pub fn hash(ctx: LookupContext, name: String) u32 {
            return std.array_hash_map.hashString(name.slice(ctx.b));
        }

        pub fn eql(ctx: LookupContext, a: String, b: String, _: usize) bool {
            return a == b or std.mem.eql(u8, a.slice(ctx.b), b.slice(ctx.b));
        }
    };
};

gpa: Allocator,
/// Allocated with `gpa`.
arena_state: ArenaAllocator.State,

string_contents: std.ArrayList(u8),
string_payloads: std.ArrayList(String.Payload),

val_types: std.ArrayList(ValType),
type_section: std.ArrayList(TypeIdx.FuncType),
/// The types of all imported then defined functions.
func_types: std.ArrayList(TypeIdx),

// imports: std.MultiArrayList(Import),
func_import_count: u32,

exports: std.ArrayHashMapUnmanaged(String, ExportDesc, ExportDesc.LookupContext, true),

code: std.MultiArrayList(Code),

// module_name: ?String,

pub fn init(gpa: Allocator) WasmBuilder {
    return .{
        .gpa = gpa,
        .arena_state = ArenaAllocator.init(gpa).state,

        .string_contents = .empty,
        .string_payloads = .empty,

        .val_types = .empty,
        .type_section = .empty,
        .func_types = .empty,

        .func_import_count = 0,

        .exports = .empty,

        .code = .empty,

        // .module_name = null,
    };
}

pub fn deinit(b: *WasmBuilder) void {
    b.arena_state.promote(b.gpa).deinit();

    b.string_contents.deinit(b.gpa);
    b.string_payloads.deinit(b.gpa);

    b.val_types.deinit(b.gpa);
    b.type_section.deinit(b.gpa);
    b.func_types.deinit(b.gpa);

    b.exports.deinit(b.gpa);

    b.code.deinit(b.gpa);

    b.* = undefined;
}

fn castToU32(value: anytype) Oom!u32 {
    return std.math.cast(u32, value) orelse return Oom.OutOfMemory;
}

pub fn string(b: *WasmBuilder, bytes: []const u8) Oom!String {
    const len = try castToU32(u32, bytes.len);
    try b.string_contents.ensureUnusedCapacity(b.gpa, len);
    try b.string_payloads.ensureUnusedCapacity(b.gpa, 1);
    const str: String = @enumFromInt(b.string_payloads.items.len);
    const offset = try castToU32(b.string_contents.items.len);
    b.string_contents.appendSliceAssumeCapacity(bytes);
    b.string_payloads.appendAssumeCapacity(.{ .len = len, .offset = offset });
    return str;
}

pub fn funcType(
    b: *WasmBuilder,
    parameters: []const ValType,
    results: []const ValType,
) Oom!TypeIdx {
    const param_count = std.math.cast(u16, parameters.len) orelse return Oom.OutOfMemory;
    const result_count = std.math.cast(u16, results.len) orelse return Oom.OutOfMemory;
    try b.val_types.ensureUnusedCapacity(b.gpa, @as(u32, param_count) + result_count);
    try b.type_section.ensureUnusedCapacity(b.gpa, 1);
    const types_idx: ValType.Index = @enumFromInt(b.val_types.items.len);
    b.val_types.appendSliceAssumeCapacity(parameters);
    b.val_types.appendSliceAssumeCapacity(results);

    const func_type: TypeIdx = @enumFromInt(b.type_section.items.len);
    b.type_section.appendAssumeCapacity(b.gpa, .{
        .types = types_idx,
        .param_count = param_count,
        .result_count = result_count,
    });
    return func_type;
}

pub const ExportError = Oom || error{
    DuplicateExportName,
};

pub fn @"export"(b: *WasmBuilder, name: String, value: ExportDesc) ExportError!void {
    const result = try b.exports.getOrPutContext(b.gpa, name, .{ .b = b });
    if (result.found_existing) {
        return error.DuplicateExportName;
    }

    result.value_ptr.* = value;
    switch (value) {
        .func => |f| assert(@intFromEnum(f) < b.func_types.items.len),
    }
}

pub const LocalIdx = enum(u32) {
    _,
};

pub const CodeWriter = struct {
    builder: *const WasmBuilder,
    function: FuncIdx,
    signature: TypeIdx.FuncType,
    body: Writer,
    /// Does not include parameters.
    ///
    /// Allocated in `body.gpa`.
    locals: std.ArrayList(ValType),
    /// Lasts until `CodeWriter.finish()` is called.
    arena: *ArenaAllocator,
    /// Allocated in `arena`.
    val_stack: std.ArrayList(ValType),
    // /// Allocated in `arena`.
    // ctrl_stack: std.ArrayList,
    uleb_min_len: Writer.UlebLen,

    fn PrefixedOpcode(comptime opcode: opcodes.ByteOpcode) type {
        return switch (opcode) {
            .@"0xFC" => opcodes.FCPrefixOpcode,
            .@"0xFD" => opcodes.FDPrefixOpcode,
            else => void,
        };
    }

    fn OpcodeArgs(
        comptime opcode: opcodes.ByteOpcode,
        comptime prefixed_opcode: PrefixedOpcode(opcode),
    ) type {
        return switch (opcode) {
            .@"unreachable",
            .nop,
            .end,
            => void,
            .@"0xFC" => @compileError("argument type for " ++ @tagName(prefixed_opcode)),
            .@"0xFD" => @compileError("argument type for " ++ @tagName(prefixed_opcode)),
            else => @compileError("argument type for " ++ @tagName(opcode)),
        };
    }

    fn markUnreachable(w: *CodeWriter) void {
        _ = w;
    }

    pub fn localType(w: *const CodeWriter, idx: LocalIdx) ValType {
        const i = @intFromEnum(idx);
        return if (i < w.signature.param_count)
            w.signature.types.slice(w.builder, w.signature.param_count)[i]
        else
            w.locals.items[i - w.signature.param_count];
    }

    pub fn declareLocal(w: *CodeWriter, ty: ValType) Oom!LocalIdx {
        try w.locals.ensureUnusedCapacity(w.body.gpa, 1);
        const i = w.locals.items.len;
        w.locals.appendAssumeCapacity(ty);
        return @enumFromInt(i + w.signature.param_count);
    }

    pub fn op(
        w: *CodeWriter,
        comptime opcode: opcodes.ByteOpcode,
        comptime prefixed_opcode: PrefixedOpcode(opcode),
        args: OpcodeArgs(opcode, prefixed_opcode),
    ) Oom!void {
        try w.body.writeByte(@intFromEnum(opcode));
        if (comptime @TypeOf(prefixed_opcode) != void) {
            try w.body.writeUleb(@intFromEnum(prefixed_opcode), w.uleb_min_len);
        }

        switch (comptime @TypeOf(args)) {
            void => {},
            LocalIdx => try w.body.writeUleb(@intFromEnum(args), w.uleb_min_len),
            else => |ArgsType| @compileError(
                "handle " ++ @typeName(ArgsType) ++ " for " ++ @tagName(opcode),
            ),
        }

        switch (opcode) {
            .@"unreachable" => w.markUnreachable(),
            // .end => {}, // TODO: pop ctrl stack and results
            .@"local.get" => try w.val_stack.append(w.arena.allocator(), w.localType(args)),
            else => {},
        }
    }

    pub fn byte(
        w: *CodeWriter,
        comptime opcode: opcodes.ByteOpcode,
        args: OpcodeArgs(opcode, {}),
    ) Oom!void {
        comptime {
            switch (opcode) {
                .@"0xFC", .@"0xFD" => @compileError("no prefix allowed"),
                else => {},
            }
        }
        try w.op(opcode, {}, args);
    }

    /// Don't forget to write the last `end` opcode.
    pub fn finish(w: *CodeWriter, scratch: *ArenaAllocator) Oom!void {
        // TODO: check ctrl stack is empty
        assert(w.signature.result_count == w.val_stack.items.len);

        const LocalGroup = struct {
            ty: ValType,
            count: u32,
        };

        var local_groups = try std.ArrayList(LocalGroup).initCapacity(
            scratch.allocator(),
            @intFromBool(w.locals.items.len > 0),
        );
        for (w.locals.items) |ty| {
            if (local_groups.items.len > 0) {
                const current_group = &local_groups.items[local_groups.items.len - 1];
                if (current_group.ty == ty) {
                    current_group.count += 1;
                    continue;
                }
            }

            local_groups.append(scratch.allocator(), .{ .ty = ty, .count = 1 });
        }

        var encoded_locals = try Writer.init(scratch.allocator(), 1 + (2 * local_groups.items.len));
        try encoded_locals.writeUleb(@intCast(local_groups.items.len), w.uleb_min_len);
        for (local_groups.items) |group| {
            try encoded_locals.writeUleb(group.count, w.uleb_min_len);
            try encoded_locals.writeByte(@intFromEnum(group.ty));
        }

        const body = body: {
            var arena = w.builder.arena_state.promote(w.builder.gpa);
            defer w.builder.arena_state = arena.state;

            break :body try arena.allocator().alloc(
                u8,
                encoded_locals.buf.items.len + w.body.buf.items.len,
            );
        };

        @memcpy(body[0..encoded_locals.buf.items.len], encoded_locals.buf.items);
        @memcpy(body[encoded_locals.buf.items.len..], w.body.buf.items);

        w.builder.code.items[@intFromEnum(w.function)].* = Code{
            .body_size = @intCast(body.len),
            .body_ptr = body.ptr,
        };

        w.locals.deinit(w.body.gpa);
        w.body.deinit();
        _ = w.arena.reset(.retain_capacity);
        w.* = undefined;
    }
};

const wasm_preamble: [8]u8 = std.wasm.magic ++ std.wasm.version;

pub fn toBinary(
    b: *const WasmBuilder,
    /// Used to allocate the result.
    allocator: Allocator,
    scratch: *ArenaAllocator,
    options: struct {
        uleb_min_len: Writer.UlebLen = .smallest,
    },
) Oom!std.ArrayList(u8) {
    const type_sec_capacity = 3 * b.type_section.items.len;
    const defined_func_count = @as(u32, @intCast(b.func_types.items.len)) - b.func_import_count;
    assert(defined_func_count == b.code.len);
    const export_sec_capacity = 3 * b.exports.count();
    const code_sec_capacity = 3 * defined_func_count;

    var w = try Writer.init(allocator, (8 + type_sec_capacity) +
        defined_func_count +
        export_sec_capacity +
        code_sec_capacity);

    try w.writeSlice(&(std.wasm.magic ++ std.wasm.version));
    if (b.type_section.items.len > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + type_sec_capacity);
        try s.writeUleb(@intCast(b.type_section.items.len), options.uleb_min_len);
        for (b.type_section.items) |*func_types| {
            const type_len = func_types.param_count + func_types.result_count;
            try s.buf.ensureUnusedCapacity(scratch.allocator(), 3 + type_len);
            s.buf.appendAssumeCapacity(0x60);

            const types = func_types.types.slice(b, type_len);
            // Works since `ValType` currently is just a `u8`.
            try s.writeByteVec(@ptrCast(types[0..func_types.param_count]), options.uleb_min_len);
            try s.writeByteVec(@ptrCast(types[func_types.result_count..]), options.uleb_min_len);
        }

        try w.writeSection(1, s.buf.items, options.uleb_min_len);
    }

    if (defined_func_count > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + defined_func_count);
        try s.writeUleb(defined_func_count, options.uleb_min_len);
        for (b.func_types.items[b.func_import_count..]) |func_idx| {
            try s.writeUleb(@intFromEnum(func_idx), options.uleb_min_len);
        }

        try w.writeSection(3, s.buf.items, options.uleb_min_len);
    }

    if (b.exports.count() > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + export_sec_capacity);
        try s.writeUleb(@intCast(b.exports.count()), options.uleb_min_len);
        for (b.exports.keys(), b.exports.values()) |name, value| {
            try s.writeByteVec(name.slice(b), options.uleb_min_len);
            try s.writeByte(@intFromEnum(value));
            try s.writeUleb(switch (value) {
                inline else => |idx| @intFromEnum(idx),
            }, options.uleb_min_len);
        }

        try w.writeSection(7, s.buf.items, options.uleb_min_len);
    }

    if (defined_func_count > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + code_sec_capacity);
        try s.writeUleb(defined_func_count, options.uleb_min_len);
        for (b.code.items(.body_ptr), b.code.items(.body_size)) |body_ptr, body_size| {
            assert(body_size >= 2); // no code provided?
            try s.writeByteVec(body_ptr[0..body_size], options.uleb_min_len);
        }

        try w.writeSection(10, s.buf.items, options.uleb_min_len);
    }

    return w.buf;
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const assert = std.debug.assert;
const Oom = Allocator.Error;
const opcodes = @import("opcodes");
const Writer = @import("WasmBuilder/Writer.zig");

test {
    _ = Writer;
}
