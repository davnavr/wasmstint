//! Implementation of instructions introduced in the
//! [fixed-width SIMD proposal](https://github.com/WebAssembly/simd).

/// Calculates a poitner to the first byte of the instruction based on a pointer to the first byte
/// after it's opcode.
///
/// NOTE: Might have to move this to `../handlers.zig` in case other prefixed opcodes use LEB128.
fn calculateTrapIp(base_ip: Ip, comptime opcode: FDPrefixOpcode) Ip {
    var ip = base_ip - 1;
    var decoded: u32 = ip[0];
    for (0..4) |_| {
        ip -= 1;
        if (decoded == @intFromEnum(opcode)) {
            @branchHint(.likely); // Initial SIMD proposal only introduces opcodes <= 0x7F
            break;
        }

        decoded <<= 7;
        decoded |= (0x7F & ip[0]);
    } else unreachable;

    std.debug.assert(ip[0] == 0xFD);
    return ip;
}

test calculateTrapIp {
    {
        const bytes = [_:0x0B]u8{ 0xAA, 0xFD, 0x6B, 0xAA };
        try std.testing.expectEqual(&bytes[1], &calculateTrapIp(bytes[3..], .@"i8x16.shl")[0]);
    }
    {
        // WASM spec seems to allow over-long instruction opcodes
        const bytes = [_:0x0B]u8{ 0xAA, 0xFD, 0xEB, 0x00, 0xAA };
        try std.testing.expectEqual(&bytes[1], &calculateTrapIp(bytes[4..], .@"i8x16.shl")[0]);
    }
    {
        const bytes = [_:0x0B]u8{ 0xAA, 0xFD, 0x0C, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xAA };
        try std.testing.expectEqual(&bytes[1], &calculateTrapIp(bytes[3..], .@"v128.const")[0]);
    }
}

pub fn @"v128.load"(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
    eip: Eip,
) callconv(ohcc) Transition {
    var instr = Instr.init(ip, eip);
    var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

    const mem_arg = MemArg.read(&instr, module);
    const base_addr: u32 = @bitCast(vals.popTyped(&.{.i32}).@"0");
    vals.assertRemainingCountIs(0);

    const trap_info = mem_arg.trap(base_addr, .@"16");
    const effective_addr = std.math.add(u32, base_addr, mem_arg.offset) catch {
        return Transition.trap(calculateTrapIp(ip, .@"v128.load"), eip, sp, stp, interp, trap_info);
    };

    const end_addr = std.math.add(u32, effective_addr, 15) catch {
        return Transition.trap(calculateTrapIp(ip, .@"v128.load"), eip, sp, stp, interp, trap_info);
    };

    if (mem_arg.mem.size <= end_addr) {
        return Transition.trap(calculateTrapIp(ip, .@"v128.load"), eip, sp, stp, interp, trap_info);
    }

    const accessed_bytes = mem_arg.mem.bytes()[effective_addr..][0..16];
    vals.pushTyped(&.{.v128}, .{V128.init(.u8, accessed_bytes.*)});

    return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
}

pub fn @"v128.const"(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
    eip: Eip,
) callconv(ohcc) Transition {
    var instr = Instr.init(ip, eip);
    var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

    const bytes = instr.readByteArray(16);
    vals.pushArray(1)[0] = Value{ .v128 = V128.init(.u8, bytes.*) };

    return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
}

// /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-vbinop
// pub fn defineBinOp(
//     comptime opcode: FDPrefixOpcode,
//     comptime interpretation: V128.Interpretation,
//     /// Function that takes two operands as an input and returns the result of the operation.
//     ///
//     /// May return an error.
//     comptime op: anytype,
//     /// Function that takes an error returned by `op` and returns a `Trap`.
//     comptime trap: anytype,
// ) OpcodeHandler {
//     return struct {
//         const field_name = interpretation.fieldName();
//         fn vBinOp(c_1: V128, c_2: V128) !V128 {
//             return @unionInit(
//                 V128,
//                 field_name,
//                 try op(@field(c_1, field_name), @field(c_2, field_name)),
//             );
//         }
//         const vBinOpHandler = handlers.defineBinOp(
//             .v128,
//             opcodePrefixLen(opcode),
//             vBinOp,
//             trap,
//         );
//     }.vBinOpHandler;
// }

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-vshiftop
fn defineShiftOp(
    comptime interpretation: V128.Interpretation,
    comptime op: fn (c_1: interpretation.Type(), i: i32) interpretation.Type(),
) OpcodeHandler {
    return struct {
        fn vShiftOpHandler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) callconv(ohcc) Transition {
            var vals = Stack.Values.init(sp, &interp.stack, 2, 2);

            const operands = vals.popTyped(&(.{ .v128, .i32 }));
            vals.assertRemainingCountIs(0);
            const i = operands[1];
            const c_1 = operands[0];
            const result = @call(.always_inline, op, .{ c_1.interpret(interpretation), i });
            vals.pushTyped(&.{.v128}, .{V128.init(interpretation, result)});

            const instr = Instr.init(ip, eip);
            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }
    }.vShiftOpHandler;
}

fn integerOpcodeHandlers(comptime Signed: type) type {
    return struct {
        const lane_size = @typeInfo(SignedInt).int.bits;
        const SignedInt = @typeInfo(Signed).vector.child;
        const UnsignedInt = std.meta.Int(.unsigned, lane_size);
        const interpretation = V128.Interpretation.fromLaneType(SignedInt);
        const lane_count = interpretation.laneCount();
        const Unsigned = @Vector(lane_count, UnsignedInt);

        comptime {
            std.debug.assert(@typeInfo(SignedInt).int.signedness == .signed);
            std.debug.assert(@typeInfo(Signed).vector.len == lane_count);
        }

        const operators = struct {
            const ShiftInt = std.math.Log2Int(UnsignedInt);

            inline fn bitShiftAmt(y: i32) @Vector(lane_count, ShiftInt) {
                return @splat(@intCast(@mod(y, lane_size)));
            }

            fn shl(a: Signed, y: i32) Signed {
                return a << bitShiftAmt(y);
            }

            fn shr_s(a: Signed, y: i32) Signed {
                // Currently assumes Zig sign-extends when shifting right.
                return a >> bitShiftAmt(y);
            }

            fn shr_u(a: Signed, y: i32) Signed {
                return @bitCast(@as(Unsigned, @bitCast(a)) >> bitShiftAmt(y));
            }
        };

        // fn opcode(comptime name: []const u8) FDPrefixOpcode {
        //     return @field(FDPrefixOpcode, interpretation.fieldName() ++ "." ++ name);
        // }

        pub const shl = defineShiftOp(interpretation, operators.shl);
        pub const shr_s = defineShiftOp(interpretation, operators.shr_s);
        pub const shr_u = defineShiftOp(interpretation, operators.shr_u);
    };
}

const i8x16_opcode_handlers = integerOpcodeHandlers(@Vector(16, i8));
const i16x8_opcode_handlers = integerOpcodeHandlers(@Vector(8, i16));
const i32x4_opcode_handlers = integerOpcodeHandlers(@Vector(4, i32));
const i64x2_opcode_handlers = integerOpcodeHandlers(@Vector(2, i64));

pub const @"i8x16.shl" = i8x16_opcode_handlers.shl;
pub const @"i8x16.shr_s" = i8x16_opcode_handlers.shr_s;
pub const @"i8x16.shr_u" = i8x16_opcode_handlers.shr_u;

pub const @"i16x8.shl" = i16x8_opcode_handlers.shl;
pub const @"i16x8.shr_s" = i16x8_opcode_handlers.shr_s;
pub const @"i16x8.shr_u" = i16x8_opcode_handlers.shr_u;

pub const @"i32x4.shl" = i32x4_opcode_handlers.shl;
pub const @"i32x4.shr_s" = i32x4_opcode_handlers.shr_s;
pub const @"i32x4.shr_u" = i32x4_opcode_handlers.shr_u;

pub const @"i64x2.shl" = i64x2_opcode_handlers.shl;
pub const @"i64x2.shr_s" = i64x2_opcode_handlers.shr_s;
pub const @"i64x2.shr_u" = i64x2_opcode_handlers.shr_u;

const std = @import("std");
const Interpreter = @import("../../Interpreter.zig");
const handlers = @import("../handlers.zig");
const ohcc = handlers.ohcc;
const OpcodeHandler = handlers.OpcodeHandler;
const dispatchNextOpcode = handlers.dispatchNextOpcode;
const Ip = handlers.Ip;
const Eip = handlers.Eip;
const Sp = handlers.Sp;
const Stp = handlers.Stp;
const Instr = @import("../Instr.zig");
const Stack = @import("../Stack.zig");
const Locals = handlers.Locals;
const Fuel = Interpreter.Fuel;
const Transition = handlers.Transition;
const MemArg = handlers.MemArg;
const Value = @import("../value.zig").Value;
const V128 = @import("../../v128.zig").V128;
const opcodes = @import("../../opcodes.zig");
const FDPrefixOpcode = opcodes.FDPrefixOpcode;
const runtime = @import("../../runtime.zig");
