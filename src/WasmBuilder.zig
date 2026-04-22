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

    pub fn isRefType(ty: ValType) bool {
        return switch (ty) {
            .funcref, .externref => true,
            else => false,
        };
    }
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
        b: *WasmBuilder,
        allocator: Allocator,
        options: struct { uleb_min_len: Writer.LebLen = .smallest },
    ) CodeWriter {
        return CodeWriter{
            .builder = b,
            .function = f,
            .signature = f.signature(b).funcType(b),
            .body = Writer{ .gpa = allocator, .buf = .empty },
            .locals = .empty,
            .val_stack = .empty,
            .uleb_min_len = options.uleb_min_len,
        };
    }

    pub fn @"export"(f: FuncIdx, b: *WasmBuilder, name: String) ExportError!void {
        try b.@"export"(name, .{ .func = f });
    }
};

pub const TableIdx = enum(u32) {
    _,

    pub fn tableType(t: TableIdx, b: *const WasmBuilder) *const TableType {
        return b.table_types.items[@intFromEnum(t)];
    }
};

pub const MemIdx = enum(u32) {
    _,

    pub fn memType(m: MemIdx, b: *const WasmBuilder) *const MemType {
        return b.mem_types.items[@intFromEnum(m)];
    }

    pub fn addrType(m: MemIdx, b: *const WasmBuilder) ValType {
        std.debug.assert(@intFromEnum(m) < b.mem_types.items.len);
        return .i32;
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
    // table = 0x01,
    // memory = 0x02,
};

pub const Import = struct {
    module: String,
    name: String,
    desc: Desc,

    pub const Desc = union(ExportOrImportKind) {
        func: FuncIdx,
        // table: TableIdx,
        // memory: MemIdx,
    };
};

pub const ExportDesc = union(ExportOrImportKind) {
    func: FuncIdx,
    // table: TableIdx,
    // memory: MemIdx,

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

pub const TableType = struct {
    /// Must be a reference type.
    elem_type: ValType,
    minimum: u32,
    maximum: ?u32,

    pub fn init(elem_type: ValType, limits: struct {
        minimum: u32 = 0,
        maximum: ?u32 = null,
    }) TableType {
        assert(elem_type.isRefType());
        if (limits.maximum) |max| {
            assert(limits.minimum <= max);
        }
        return TableType{
            .elem_type = elem_type,
            .minimum = limits.minimum,
            .maximum = limits.maximum,
        };
    }
};

pub const MemType = struct {
    minimum: u32,
    maximum: ?u32,

    pub fn init(limits: struct { minimum: u32 = 0, maximum: ?u32 = null }) MemType {
        if (limits.maximum) |max| {
            assert(limits.minimum <= max);
        }

        return MemType{ .minimum = limits.minimum, .maximum = limits.maximum };
    }
};

gpa: Allocator,
/// Allocated with `gpa`.
arena_state: ArenaAllocator.State,

string_contents: std.ArrayList(u8),
string_payloads: std.ArrayList(String.Payload),

val_types: std.ArrayList(ValType),
type_section: std.ArrayList(TypeIdx.FuncType),
/// Contains the types of all imported then defined functions.
func_types: std.ArrayList(TypeIdx),
/// Contains the types of all imported then defined tables.
table_types: std.ArrayList(TableType),
/// Contains the types of all imported then defined memories.
mem_types: std.ArrayList(MemType),

// imports: std.MultiArrayList(Import),
func_import_count: u32,
table_import_count: u32,
mem_import_count: u32,

exports: std.array_hash_map.Custom(String, ExportDesc, ExportDesc.LookupContext, true),

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
        .table_types = .empty,
        .mem_types = .empty,

        .func_import_count = 0,
        .table_import_count = 0,
        .mem_import_count = 0,

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
    b.table_types.deinit(b.gpa);
    b.mem_types.deinit(b.gpa);

    b.exports.deinit(b.gpa);

    b.code.deinit(b.gpa);

    b.* = undefined;
}

fn castToU32(value: anytype) Oom!u32 {
    return std.math.cast(u32, value) orelse return Oom.OutOfMemory;
}

pub fn string(b: *WasmBuilder, bytes: []const u8) Oom!String {
    const len = try castToU32(bytes.len);
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
    b.type_section.appendAssumeCapacity(.{
        .types = types_idx,
        .param_count = param_count,
        .result_count = result_count,
    });
    return func_type;
}

// TODO: Check that no definitions were defined, ensures imports are defined first
// /// Imports must be defined before any definitions are added.
// pub fn import(b: *WasmBuilder, module: String, name: String, desc: Import.Desc) Oom!void {}

pub fn function(b: *WasmBuilder, signature: TypeIdx) Oom!FuncIdx {
    const idx = b.func_types.items.len;
    assert(idx == b.func_import_count + b.code.len);
    try b.func_types.ensureUnusedCapacity(b.gpa, 1);
    try b.code.ensureUnusedCapacity(b.gpa, 1);
    b.func_types.appendAssumeCapacity(signature);
    _ = b.code.addOneAssumeCapacity();
    return @enumFromInt(idx);
}

pub fn table(b: *WasmBuilder, table_type: TableType) Oom!TableIdx {
    const idx = b.table_types.items.len;
    std.debug.assert(idx >= b.table_import_count);
    try b.table_types.append(b.gpa, table_type);
    return @enumFromInt(idx);
}

pub fn memory(b: *WasmBuilder, mem_type: MemType) Oom!MemIdx {
    const idx = b.mem_types.items.len;
    std.debug.assert(idx >= b.mem_import_count);
    try b.mem_types.append(b.gpa, mem_type);
    return @enumFromInt(idx);
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
    builder: *WasmBuilder,
    function: FuncIdx,
    signature: TypeIdx.FuncType,
    body: Writer,
    /// Does not include parameters.
    ///
    /// Allocated in `body.gpa`.
    locals: std.ArrayList(ValType),
    val_stack: std.ArrayList(ValType),
    // ctrl_stack: std.ArrayList,
    uleb_min_len: Writer.LebLen,

    fn PrefixedOpcode(comptime opcode: opcodes.ByteOpcode) type {
        return switch (opcode) {
            .@"0xFC" => opcodes.FCPrefixOpcode,
            .@"0xFD" => opcodes.FDPrefixOpcode,
            else => void,
        };
    }

    pub const CallIndirect = struct {
        signature: TypeIdx,
        table: TableIdx,
    };

    pub const MemArg = struct {
        memory: MemIdx,
        alignment: Alignment = .natural,
        offset: u32 = 0,

        pub const Alignment = enum(u8) {
            @"1" = 0,
            @"2" = 1,
            @"4" = 2,
            @"8" = 3,
            @"16" = 4,
            natural = 255,
        };

        fn write(arg: MemArg, w: *CodeWriter, natural_alignment: Alignment) Oom!void {
            const mem_idx = @intFromEnum(arg.memory);
            std.debug.assert(mem_idx == 0);
            std.debug.assert(mem_idx < w.builder.mem_types.items.len);
            std.debug.assert(natural_alignment != .natural);
            const a = @intFromEnum(
                if (arg.alignment == .natural) natural_alignment else arg.alignment,
            );
            std.debug.assert(a <= @intFromEnum(natural_alignment));
            try w.body.writeLeb(u32, a, w.uleb_min_len);
            try w.body.writeLeb(u32, arg.offset, w.uleb_min_len);
        }
    };

    fn OpcodeArgs(
        comptime opcode: opcodes.ByteOpcode,
        comptime prefixed_opcode: PrefixedOpcode(opcode),
    ) type {
        return switch (opcode) {
            .@"unreachable",
            .nop,
            .end,
            .drop,
            => void,
            .call => FuncIdx,
            .@"local.get", .@"local.set", .@"local.tee" => LocalIdx,
            .@"i32.const" => i32,
            .call_indirect => CallIndirect,
            .@"i32.store",
            .@"i64.store",
            .@"f32.store",
            .@"f64.store",
            => MemArg,
            .@"0xFC" => switch (prefixed_opcode) {
                else => @compileError("argument type for " ++ @tagName(prefixed_opcode)),
            },
            .@"0xFD" => switch (prefixed_opcode) {
                .@"v128.load",
                .@"v128.load8_splat",
                .@"v128.load16_splat",
                .@"v128.load32_splat",
                .@"v128.load64_splat",
                => MemArg,
                else => @compileError("argument type for " ++ @tagName(prefixed_opcode)),
            },
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

    pub fn param(w: *CodeWriter, i: u32) LocalIdx {
        std.debug.assert(i < w.signature.param_count);
        return @enumFromInt(i);
    }

    pub fn declareLocal(w: *CodeWriter, ty: ValType) Oom!LocalIdx {
        try w.locals.ensureUnusedCapacity(w.body.gpa, 1);
        const i = w.locals.items.len;
        w.locals.appendAssumeCapacity(ty);
        return @enumFromInt(i + w.signature.param_count);
    }

    fn pushVal(w: *CodeWriter, ty: ValType) Oom!void {
        try w.val_stack.append(w.body.gpa, ty);
    }

    fn popVal(w: *CodeWriter) ?ValType {
        // TODO: If `null`, assert ctrl frame unreachable
        return w.val_stack.pop();
    }

    fn popValExpecting(w: *CodeWriter, expecting: ValType) Oom!void {
        const popped = w.popVal() orelse
            @panic("TODO: stack underflow/handle polymorphic stack");
        std.debug.assert(expecting == popped);
    }

    fn popManyValsExpecting(w: *CodeWriter, expecting: []const ValType) Oom!void {
        for (0..expecting.len) |i| {
            try w.popValExpecting(expecting[expecting.len - 1 - i]);
        }
    }

    pub fn op(
        w: *CodeWriter,
        comptime opcode: opcodes.ByteOpcode,
        comptime prefixed_opcode: PrefixedOpcode(opcode),
        args: OpcodeArgs(opcode, prefixed_opcode),
    ) Oom!void {
        try w.body.writeByte(@intFromEnum(opcode));
        if (comptime @TypeOf(prefixed_opcode) != void) {
            try w.body.writeLeb(u32, @intFromEnum(prefixed_opcode), w.uleb_min_len);
        }

        const ArgsType = @TypeOf(args);
        switch (ArgsType) {
            void => {},
            i32, i64 => try w.body.writeLeb(ArgsType, args, w.uleb_min_len),
            LocalIdx => {
                std.debug.assert(@intFromEnum(args) < w.locals.items.len + w.signature.param_count);
                try w.body.writeLeb(u32, @intFromEnum(args), w.uleb_min_len);
            },
            FuncIdx => {
                std.debug.assert(@intFromEnum(args) < w.builder.func_types.items.len);
                try w.body.writeLeb(u32, @intFromEnum(args), w.uleb_min_len);
            },
            CallIndirect => {
                try w.body.writeLeb(u32, @intFromEnum(args.signature), w.uleb_min_len);
                std.debug.assert(@intFromEnum(args.table) < w.builder.table_types.items.len);
                try w.body.writeLeb(u32, @intFromEnum(args.table), w.uleb_min_len);
            },
            MemArg => {
                try MemArg.write(args, w, switch (opcode) {
                    .@"i32.store",
                    .@"f32.store",
                    .@"i32.load",
                    .@"f32.load",
                    => .@"4",
                    .@"i64.store",
                    .@"f64.store",
                    .@"i64.load",
                    .@"f64.load",
                    => .@"8",
                    .@"0xFD" => switch (prefixed_opcode) {
                        .@"v128.load" => .@"16",
                        .@"v128.load8_splat" => .@"1",
                        .@"v128.load16_splat" => .@"2",
                        .@"v128.load32_splat" => .@"4",
                        .@"v128.load64_splat" => .@"8",
                        else => @compileError(@tagName(prefixed_opcode)),
                    },
                    else => @compileError("specify natural alignment for " ++ @tagName(opcode)),
                });
            },
            else => @compileError("handle " ++ @typeName(ArgsType) ++ " for " ++ @tagName(opcode)),
        }

        switch (opcode) {
            .@"unreachable" => w.markUnreachable(),
            // .end => {}, // TODO: pop ctrl stack and results
            .call => {
                // TODO: push and pop arguments
            },
            .call_indirect => {
                try w.popValExpecting(.i32);
                // TODO: push and pop arguments
            },
            .drop => {
                _ = w.popVal();
            },
            .@"local.get" => try w.pushVal(w.localType(args)),
            .@"i32.store" => try w.popManyValsExpecting(&[2]ValType{ .i32, .i32 }),
            .@"i64.store" => try w.popManyValsExpecting(&[2]ValType{ .i32, .i64 }),
            .@"f32.store" => try w.popManyValsExpecting(&[2]ValType{ .i32, .f32 }),
            .@"f64.store" => try w.popManyValsExpecting(&[2]ValType{ .i32, .f64 }),
            .@"i32.const" => try w.pushVal(.i32),
            .@"i64.const" => try w.pushVal(.i64),
            .@"0xFC" => switch (prefixed_opcode) {
                .@"v128.load",
                .@"v128.load8_splat",
                .@"v128.load16_splat",
                .@"v128.load32_splat",
                .@"v128.load64_splat",
                => {
                    try w.popValExpecting(args.memory.addrType(w.builder));
                    try w.pushVal(.v128);
                },
                else => {},
            },
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

    pub fn simd(
        w: *CodeWriter,
        comptime opcode: opcodes.FDPrefixOpcode,
        args: OpcodeArgs(.@"0xFD", opcode),
    ) Oom!void {
        try w.op(.@"0xFD", opcode, args);
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

            try local_groups.append(scratch.allocator(), .{ .ty = ty, .count = 1 });
        }

        var encoded_locals = try Writer.init(scratch.allocator(), 1 + (2 * local_groups.items.len));
        try encoded_locals.writeLeb(u32, @intCast(local_groups.items.len), w.uleb_min_len);
        for (local_groups.items) |group| {
            try encoded_locals.writeLeb(u32, group.count, w.uleb_min_len);
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

        w.builder.code.set(@intFromEnum(w.function), Code{
            .body_size = @intCast(body.len),
            .body_ptr = body.ptr,
        });

        w.locals.deinit(w.body.gpa);
        w.val_stack.deinit(w.body.gpa);
        // w.ctrl_stack.deinit(w.body.gpa);
        w.body.deinit();
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
        uleb_min_len: Writer.LebLen = .smallest,
    },
) Oom!std.ArrayList(u8) {
    const type_sec_capacity = 3 * b.type_section.items.len;
    const defined_func_count = @as(u32, @intCast(b.func_types.items.len)) - b.func_import_count;
    assert(defined_func_count == b.code.len);
    const defined_table_count = @as(u32, @intCast(b.table_types.items.len)) - b.table_import_count;
    const table_sec_capacity = 3 * defined_table_count;
    const defined_mem_count = @as(u32, @intCast(b.mem_types.items.len)) - b.mem_import_count;
    const mem_sec_capacity = 2 * defined_mem_count;
    const export_sec_capacity = 3 * b.exports.count();
    const code_sec_capacity = 3 * defined_func_count;

    var w = try Writer.init(allocator, (8 + type_sec_capacity) +
        defined_func_count +
        table_sec_capacity +
        mem_sec_capacity +
        export_sec_capacity +
        code_sec_capacity);

    try w.writeSlice(&(std.wasm.magic ++ std.wasm.version));
    if (b.type_section.items.len > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + type_sec_capacity);
        try s.writeLeb(u32, @intCast(b.type_section.items.len), options.uleb_min_len);
        for (b.type_section.items) |*func_types| {
            const type_len = func_types.param_count + func_types.result_count;
            try s.buf.ensureUnusedCapacity(scratch.allocator(), 3 + type_len);
            s.buf.appendAssumeCapacity(0x60);

            const types = func_types.types.slice(b, type_len);
            // Works since `ValType` currently is just a `u8`.
            try s.writeByteVec(@ptrCast(types[0..func_types.param_count]), options.uleb_min_len);
            try s.writeByteVec(@ptrCast(types[func_types.param_count..]), options.uleb_min_len);
        }

        try w.writeSection(1, s.buf.items, options.uleb_min_len);
    }

    if (defined_func_count > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + defined_func_count);
        try s.writeLeb(u32, defined_func_count, options.uleb_min_len);
        for (b.func_types.items[b.func_import_count..]) |type_idx| {
            try s.writeLeb(u32, @intFromEnum(type_idx), options.uleb_min_len);
        }

        try w.writeSection(3, s.buf.items, options.uleb_min_len);
    }

    if (defined_table_count > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + table_sec_capacity);
        try s.writeLeb(u32, defined_table_count, options.uleb_min_len);
        for (b.table_types.items[b.table_import_count..]) |table_type| {
            try s.writeByte(@intFromEnum(table_type.elem_type));
            try s.writeByte(@intFromBool(table_type.maximum != null));
            try s.writeLeb(u32, table_type.minimum, options.uleb_min_len);
            if (table_type.maximum) |max| {
                try s.writeLeb(u32, max, options.uleb_min_len);
            }
        }

        try w.writeSection(4, s.buf.items, options.uleb_min_len);
    }

    if (defined_mem_count > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + mem_sec_capacity);
        try s.writeLeb(u32, defined_mem_count, options.uleb_min_len);
        for (b.mem_types.items[b.mem_import_count..]) |mem_type| {
            try s.writeByte(@intFromBool(mem_type.maximum != null));
            try s.writeLeb(u32, mem_type.minimum, options.uleb_min_len);
            if (mem_type.maximum) |max| {
                try s.writeLeb(u32, max, options.uleb_min_len);
            }
        }

        try w.writeSection(5, s.buf.items, options.uleb_min_len);
    }

    if (b.exports.count() > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + export_sec_capacity);
        try s.writeLeb(u32, @intCast(b.exports.count()), options.uleb_min_len);
        for (b.exports.keys(), b.exports.values()) |name, value| {
            try s.writeByteVec(name.slice(b), options.uleb_min_len);
            try s.writeByte(@intFromEnum(value));
            try s.writeLeb(u32, switch (value) {
                inline else => |idx| @intFromEnum(idx),
            }, options.uleb_min_len);
        }

        try w.writeSection(7, s.buf.items, options.uleb_min_len);
    }

    if (defined_func_count > 0) {
        var s = try Writer.initWithinScratch(scratch, 1 + code_sec_capacity);
        try s.writeLeb(u32, defined_func_count, options.uleb_min_len);
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
