//! A [**constant** expression].
//!
//! [**constant** expression]: https://webassembly.github.io/spec/core/valid/instructions.html#valid-constant

slice: Module.WasmSlice,

const ConstExpr = @This();

pub fn bytes(
    expr: ConstExpr,
    base: [*]const u8,
    module: Module,
) [:@intFromEnum(opcodes.ByteOpcode.end)]const u8 {
    const b = expr.slice.slice(base, module.inner.wasm);
    std.debug.assert(b.len >= 2);
    return b[0 .. b.len - 1 :@intFromEnum(opcodes.ByteOpcode.end)];
}

fn popVal(
    stack: *std.ArrayList(ValType),
    expecting: ValType,
    diag: Reader.Diagnostics,
    desc: []const u8,
) Reader.ValidationError!void {
    const actual = stack.pop() orelse return diag.print(
        .validation,
        "expected type {t}, but stack was empty in {s}",
        .{ expecting, desc },
    );

    if (actual != expecting) return diag.print(
        .validation,
        "expected type {t}, but got {t} in {s}",
        .{ expecting, actual, desc },
    );
}

fn binOp(
    stack: *std.ArrayList(ValType),
    operand_type: ValType,
    diag: Reader.Diagnostics,
    desc: []const u8,
) Reader.ValidationError!void {
    try popVal(stack, operand_type, diag, desc);
    try popVal(stack, operand_type, diag, desc);
    stack.appendAssumeCapacity(operand_type);
}

const Parsed = struct {
    expr: ConstExpr,
    /// Maximum height of value stack needed to evaulate the expression.
    max_stack: u16,
    /// Does not count the `end` instruction.
    instr_count: u16,
};

fn nonConstOpcode(
    opcode: anytype,
    diag: Reader.Diagnostics,
    desc: []const u8,
) Reader.ValidationError {
    return diag.print(
        .validation,
        "constant expression required: got opcode {t} in {s}",
        .{ opcode, desc },
    );
}

pub fn parse(
    reader: Reader,
    base: [*]const u8,
    expected_type: ValType,
    func_count: u32,
    /// Should refer to global imports only.
    global_types: []const Module.GlobalType,
    func_refs: *FuncRefs,
    diag: Reader.Diagnostics,
    desc: []const u8,
    scratch: *std.heap.ArenaAllocator,
) Module.ParseError!Parsed {
    _ = scratch.reset(.retain_capacity);
    var val_stack = std.ArrayList(ValType).empty;
    var max_stack: u16 = 0;
    var instr_count: u16 = 0;

    const expr_ptr = reader.bytes.ptr;
    std.debug.assert(expr_ptr - base <= std.math.maxInt(u32));
    const end_ptr: [*]const u8 = end: while (true) {
        const opcode_ptr = reader.bytes.ptr;
        const opcode = try reader.readByteTag(opcodes.ByteOpcode, diag, "illegal opcode");
        switch (opcode) {
            .@"i32.const" => {
                try val_stack.append(scratch.allocator(), .i32);
                _ = try reader.readIleb128(i32, diag, "i32.const");
            },
            .@"i64.const" => {
                try val_stack.append(scratch.allocator(), .i64);
                _ = try reader.readIleb128(i64, diag, "i64.const");
            },
            .@"f32.const" => {
                try val_stack.append(scratch.allocator(), .f32);
                _ = try reader.readArray(4, diag, "f32.const");
            },
            .@"f64.const" => {
                try val_stack.append(scratch.allocator(), .f64);
                _ = try reader.readArray(8, diag, "f64.const");
            },
            .@"ref.null" => {
                const ref_type = try ValType.parse(reader, diag);
                if (!ref_type.isRefType()) return diag.print(
                    .validation,
                    "type mismatch: expected reference type for ref.null, but got {t} in {s}",
                    .{ ref_type, desc },
                );

                try val_stack.append(scratch.allocator(), ref_type);
            },
            .@"ref.func" => {
                try val_stack.append(scratch.allocator(), .funcref);
                const func_idx = try reader.readIdx(
                    Module.FuncIdx,
                    func_count,
                    diag,
                    &.{ "function", desc },
                );

                try func_refs.insert(func_idx);
            },
            .@"global.get" => {
                const global_idx = try reader.readIdx(
                    Module.GlobalIdx,
                    global_types.len,
                    diag,
                    &.{ "global", desc },
                );

                const global_type: *const Module.GlobalType =
                    &global_types[@intFromEnum(global_idx)];

                if (global_type.mut == .@"var") return diag.print(
                    .validation,
                    "constant expression required: global.get {} in {s} must be const",
                    .{ @intFromEnum(global_idx), desc },
                );

                try val_stack.append(scratch.allocator(), global_type.val_type);
            },
            .end => break :end opcode_ptr,
            // Extended constant proposal (https://github.com/WebAssembly/extended-const) support:
            .@"i32.add",
            .@"i32.sub",
            .@"i32.mul",
            => try binOp(&val_stack, .i32, diag, desc),
            .@"i64.add",
            .@"i64.sub",
            .@"i64.mul",
            => try binOp(&val_stack, .i64, diag, desc),
            .@"0xFC" => return nonConstOpcode(
                try reader.readUleb128Enum(
                    u32,
                    opcodes.FCPrefixOpcode,
                    diag,
                    "0xFC prefixed opcode",
                ),
                diag,
                desc,
            ),
            // SIMD proposal (https://github.com/WebAssembly/simd) support:
            .@"0xFD" => switch (try reader.readUleb128Enum(
                u8,
                opcodes.FDPrefixOpcode,
                diag,
                "SIMD opcode",
            )) {
                .@"v128.const" => {
                    _ = try reader.readArray(16, diag, "v128.const immediate");
                    try val_stack.append(scratch.allocator(), .v128);
                },
                else => |bad| return nonConstOpcode(bad, diag, desc),
            },
            else => return nonConstOpcode(opcode, diag, desc),
        }

        max_stack = @max(
            max_stack,
            std.math.cast(u16, val_stack.items.len) orelse return error.WasmImplementationLimit,
        );

        instr_count = std.math.add(u16, instr_count, 1) catch return error.WasmImplementationLimit;

        if (reader.isEmpty()) {
            // Spec thinks reading into code section is ok!?
            return diag.print(.parse, "illegal opcode or unexpected end in {s}", .{desc});
        }
    };

    return switch (val_stack.items.len) {
        0 => diag.print(
            .validation,
            "type mismatch: expected {t}, but got opcode END at end of {s}",
            .{ expected_type, desc },
        ),
        1 => if (expected_type.eql(val_stack.items[0])) Parsed{
            .expr = ConstExpr{
                .slice = Module.WasmSlice{
                    .offset = @intCast(expr_ptr - base),
                    .size = @intCast((end_ptr - expr_ptr) + 1),
                },
            },
            .max_stack = max_stack,
            .instr_count = instr_count,
        } else diag.print(
            .validation,
            "type mismatch: expected {t}, but got {t} in {s}",
            .{ expected_type, val_stack.items[0], desc },
        ),
        else => |too_many| diag.print(
            .validation,
            "type mismatch: expected {t}, but got {d} values in {s}",
            .{ expected_type, too_many, desc },
        ),
    };
}

const std = @import("std");
const builtin = @import("builtin");
const opcodes = @import("../opcodes.zig");
const ValType = @import("val_type.zig").ValType;
const Reader = @import("Reader.zig");
const FuncRefs = @import("FuncRefs.zig");
const Module = @import("../Module.zig");
