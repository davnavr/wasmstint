pub const Ptr = Module.Code.Ip;
pub const End = *const Module.Code.End;

/// Invariant that `start <= next and next <= end + 1`.
next: Ptr,
end: End,

const Instr = @This();

pub inline fn init(ip: Ptr, eip: End) Instr {
    const instr = Instr{ .next = ip, .end = eip };
    _ = instr.bytes();
    return instr;
}

pub inline fn bytes(i: Instr) []const u8 {
    return i.next[0..(@intFromPtr(i.end) + 1 - @intFromPtr(i.next))];
}

pub inline fn readByteArray(i: *Instr, comptime n: usize) *const [n]u8 {
    const arr = i.bytes()[0..n];
    i.next += n;
    _ = i.bytes();
    return arr;
}

pub inline fn readByte(i: *Instr) u8 {
    const b = i.readByteArray(1)[0];
    return b;
}

fn readIdxRawRemaining(i: *Instr, first_bits: u7) u32 {
    var value: u32 = first_bits;
    for (1..5) |idx| {
        const next_byte = i.readByte();
        value |= @shlExact(
            @as(u32, next_byte & 0x7F),
            @as(u5, @intCast(idx * 7)),
        );

        if (next_byte & 0x80 == 0) {
            return value;
        }
    }

    unreachable;
}

pub inline fn readIdxRaw(i: *Instr) u32 {
    defer coz.progressNamed("wasmstint.Interpreter.Instr.readIdxRaw");
    const first_byte = i.readByte();
    if (first_byte & 0x80 == 0) {
        return first_byte;
    } else {
        @branchHint(.unlikely);
        return i.readIdxRawRemaining(@truncate(first_byte));
    }
}

fn testReadIdxRaw(comptime input: []const u8, comptime expected: u32) !void {
    const full_input: []const u8 = input ++ "\x0B";
    var i = Instr.init(@ptrCast(full_input.ptr), @ptrCast(full_input.ptr + full_input.len - 1));
    try std.testing.expectEqual(expected, i.readIdxRaw());
    try std.testing.expectEqual(0x0B, i.readByte()); // end byte
}

test readIdxRaw {
    try testReadIdxRaw("\x01", 1);
    try testReadIdxRaw("\x95\x7E", 16149); // br_table.wast:110
    try testReadIdxRaw("\x80\x00", 0);
    try testReadIdxRaw("\x80\x80\x00", 0);
}

pub inline fn readIdx(reader: *Instr, comptime I: type) I {
    return @enumFromInt(
        @as(@typeInfo(I).@"enum".tag_type, @intCast(reader.readIdxRaw())),
    );
}

pub inline fn readIleb128(reader: *Instr, comptime I: type) I {
    comptime {
        std.debug.assert(@typeInfo(I).int.signedness == .signed);
    }

    const U = std.meta.Int(.unsigned, @typeInfo(I).int.bits);
    const max_byte_len =
        comptime std.math.divCeil(u16, @typeInfo(I).int.bits, 7) catch unreachable;
    const Result = std.meta.Int(.unsigned, max_byte_len * 8);

    var result: Result = 0;
    for (0..max_byte_len) |i| {
        const shift: std.math.Log2Int(I) = @intCast(i * 7);
        const byte = reader.readByte();

        result |= @shlExact(@as(Result, byte & 0x7F), shift);

        if (byte & 0x80 == 0) {
            if (i < max_byte_len - 1 and byte & 0x40 != 0) {
                // value is signed, sign extension is needed
                result |= @bitCast(
                    std.math.shl(
                        std.meta.Int(.signed, @typeInfo(Result).int.bits),
                        -1,
                        shift + 7,
                    ),
                );
            }

            return @bitCast(@as(U, @truncate(result)));
        }
    }

    unreachable;
}

test readIleb128 {
    const input: []const u8 = "\x02\x3F\x7E\x40\x80\x80\x80\x80\x78\x0B";
    var i = Instr.init(@ptrCast(input.ptr), @ptrCast(input.ptr + input.len - 1));
    try std.testing.expectEqual(2, i.readIleb128(i32));
    try std.testing.expectEqual(63, i.readIleb128(i32));
    try std.testing.expectEqual(-2, i.readIleb128(i32));
    try std.testing.expectEqual(-64, i.readIleb128(i32));
    try std.testing.expectEqual(std.math.minInt(i32), i.readIleb128(i32));
    try std.testing.expectEqual(0x0B, i.readByte());
}

// `inline` to avoid Zig complaining about mismatch in function signature in tail calls
pub inline fn readNextOpcodeHandler(
    reader: *Instr,
    fuel: *Fuel,
    locals: handlers.Locals,
    module: runtime.ModuleInst,
    interp: *const Interpreter,
) *const handlers.OpcodeHandler {
    if (builtin.mode == .Debug) {
        const current_frame: *const Stack.Frame = interp.stack.currentFrame().?;
        const current_function = current_frame.function.expanded();
        const stack_frame_module = current_function.wasm.module;
        if (@intFromPtr(module.inner) != @intFromPtr(stack_frame_module.inner)) {
            std.debug.panic( // module mismatch
                "opcode handler receives module {X}, but stack frame says {X}" ++
                    "\n...in {f}" ++
                    "\n...IP = {f} @ {X}",
                .{
                    @intFromPtr(module.inner),
                    @intFromPtr(stack_frame_module.inner),
                    current_function,
                    std.fmt.Alt(Ptr, Stack.Walker.formatIp){ .data = reader.next },
                    @intFromPtr(reader.next),
                },
            );
        }

        const actual_locals: []align(@sizeOf(Value)) const Value =
            current_frame.localValues(&interp.stack);

        if (@intFromPtr(locals.ptr) != @intFromPtr(actual_locals.ptr)) {
            std.debug.panic(
                "expected locals {*}, got {*}\nwhile calling {f}",
                .{ locals.ptr, actual_locals.ptr, current_frame.function },
            );
        }
    }

    defer coz.progressNamed("wasmstint.Interpreter.Instr.readNextOpcodeHandler");
    if (fuel.remaining == 0) {
        @branchHint(.unlikely);
        return handlers.outOfFuelHandler;
    } else {
        const next_opcode = reader.readByte();

        // std.debug.print(
        //     "TRACE[{X:0>6}]: {s}\n",
        //     .{
        //         @intFromPtr(reader.p) - 1 -
        //             @intFromPtr(interp.currentFrame().function.expanded().wasm.module.header().module.wasm.ptr),
        //         @tagName(@as(opcodes.ByteOpcode, @enumFromInt(next_opcode))),
        //     },
        // );

        return handlers.byte_dispatch_table[next_opcode];
    }
}

/// `inline` since a tail call is used to jump to the next opcode handler.
pub inline fn dispatchNextOpcode(
    reader: Instr,
    sp: Stack.Top,
    fuel: *Fuel,
    stp: SideTable.Ptr,
    locals: handlers.Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
) handlers.Transition {
    defer coz.progressNamed("wasmstint.Interpreter.Instr.dispatchNextOpcode");
    if (builtin.mode == .Debug) {
        const current_frame: *const Stack.Frame = interp.stack.currentFrame().?;
        const wasm_func = current_frame.function.expanded().wasm;
        std.debug.assert(@intFromPtr(module.inner) == @intFromPtr(wasm_func.module.inner));
        const max_val_stack = wasm_func.code().inner.max_values;
        const val_stack_limit = current_frame.valueStackBase() + max_val_stack;
        // std.debug.print("SP = {*} < MAX = {*}\n", .{ vals.stack.ptr, val_stack_limit });
        if (@intFromPtr(sp.ptr) > @intFromPtr(val_stack_limit)) {
            std.debug.panic(
                "value stack {*} cannot exceed {*}, function has maximum of {} but sp is {}",
                .{
                    sp.ptr,
                    val_stack_limit,
                    max_val_stack,
                    sp.ptr - current_frame.valueStackBase(),
                },
            );
        }
    }

    var i = reader;
    const handler = i.readNextOpcodeHandler(fuel, locals, module, interp);
    // std.debug.print("DISP {*}, ip={X}\n", .{ module.inner, @intFromPtr(reader.next) });
    return @call(
        .always_tail,
        handler,
        .{
            i.next,
            sp,
            fuel,
            stp,
            locals,
            module,
            interp,
            i.end,
        },
    );
}

pub inline fn skipValType(reader: *Instr) void {
    const b = reader.readByte();
    _ = @as(Module.ValType, @enumFromInt(b));
}

pub inline fn skipBlockType(reader: *Instr) void {
    {
        // Assume that most block types are one byte long
        const first_byte = reader.readByte();
        // Does this even have a performance impact?
        if (first_byte & 0x80 == 0) {
            @branchHint(.likely);
            return;
        }
    }

    for (0..4) |_| {
        const byte = reader.readByte();
        if (byte & 0x80 == 0) {
            return;
        }
    }

    unreachable;
}

const std = @import("std");
const builtin = @import("builtin");
const coz = @import("coz");
const Module = @import("../Module.zig");
const Interpreter = @import("../Interpreter.zig");
const Fuel = Interpreter.Fuel;
const Stack = @import("Stack.zig");
const Value = @import("value.zig").Value;
const SideTable = @import("side_table.zig").SideTable;
const handlers = @import("handlers.zig");
const runtime = @import("../runtime.zig");
