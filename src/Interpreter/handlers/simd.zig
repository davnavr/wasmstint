//! Implementation of instructions introduced in the
//! [fixed-width SIMD proposal](https://github.com/WebAssembly/simd).

/// Calculates a poitner to the first byte of the instruction based on a pointer to the first byte
/// after it's opcode.
///
/// NOTE: Move this to `../handlers.zig`, and use it to handle other prefixed opcodes.
fn calculateTrapIp(base_ip: Ip, opcode: FDPrefixOpcode) Ip {
    var ip = base_ip - 1;
    var decoded: u32 = ip[0];
    for (0..4) |_| {
        ip -= 1;
        std.debug.assert(decoded <= @intFromEnum(opcode)); // wrong expected opcode?
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

pub fn @"v128.store"(
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
    var vals = Stack.Values.init(sp, &interp.stack, 2, 2);

    const mem_arg = MemArg.read(&instr, module);
    const popped = vals.popArray(2);
    vals.assertRemainingCountIs(0);
    const base_addr: u32 = @bitCast(popped[0].i32);
    const to_store: *const V128 = &popped[1].v128;

    const trap_info = mem_arg.trap(base_addr, .@"16");
    const effective_addr = std.math.add(u32, base_addr, mem_arg.offset) catch {
        return Transition.trap(calculateTrapIp(ip, .@"v128.store"), eip, sp, stp, interp, trap_info);
    };

    const end_addr = std.math.add(u32, effective_addr, 15) catch {
        return Transition.trap(calculateTrapIp(ip, .@"v128.store"), eip, sp, stp, interp, trap_info);
    };

    if (mem_arg.mem.size <= end_addr) {
        return Transition.trap(calculateTrapIp(ip, .@"v128.store"), eip, sp, stp, interp, trap_info);
    }

    mem_arg.mem.bytes()[effective_addr..][0..16].* = to_store.u8x16;

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

pub fn @"v128.not"(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
    eip: Eip,
) callconv(ohcc) Transition {
    var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

    const c_1 = vals.popTyped(&(.{.v128}))[0];
    vals.assertRemainingCountIs(0);
    vals.pushTyped(&.{.v128}, .{c_1.not()});

    const instr = Instr.init(ip, eip);
    return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-vvbinop
fn defineBinOp(comptime op: fn (c_1: V128, c_2: V128) V128) OpcodeHandler {
    return struct {
        fn vvBinOp(
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

            const operands = vals.popTyped(&(.{.v128} ** 2));
            vals.assertRemainingCountIs(0);
            const result = @call(.always_inline, op, operands);
            vals.pushTyped(&.{.v128}, .{result});

            const instr = Instr.init(ip, eip);
            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }
    }.vvBinOp;
}

pub const @"v128.and" = defineBinOp(V128.@"and");
pub const @"v128.andnot" = defineBinOp(V128.andnot);
pub const @"v128.or" = defineBinOp(V128.@"or");
pub const @"v128.xor" = defineBinOp(V128.xor);

pub fn @"v128.bitselect"(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
    eip: Eip,
) callconv(ohcc) Transition {
    var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

    const operands = vals.popTyped(&(.{.v128} ** 3));
    vals.assertRemainingCountIs(0);
    vals.pushTyped(&.{.v128}, .{@call(.always_inline, V128.bitselect, operands)});

    const instr = Instr.init(ip, eip);
    return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
}

pub fn @"v128.any_true"(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
    eip: Eip,
) callconv(ohcc) Transition {
    var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

    const result = vals.popTyped(&(.{.v128}))[0].anyTrue();
    vals.assertRemainingCountIs(0);
    vals.pushTyped(&.{.i32}, .{@intFromBool(result)});

    const instr = Instr.init(ip, eip);
    return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-vbinop
fn defineLaneWiseBinOp(
    comptime interpretation: V128.Interpretation,
    /// Function that takes two operands as an input and returns the result of the operation.
    comptime op: fn (
        c_1: interpretation.Type(),
        c_2: interpretation.Type(),
    ) interpretation.Type(),
) OpcodeHandler {
    return struct {
        fn vBinOp(
            c_1: V128,
            c_2: V128,
        ) V128 {
            const field_name = comptime interpretation.fieldName();
            return V128.init(
                interpretation,
                @call(
                    .always_inline,
                    op,
                    .{ @field(c_1, field_name), @field(c_2, field_name) },
                ),
            );
        }

        const vBinOpHandler = defineBinOp(vBinOp);
    }.vBinOpHandler;
}

fn defineUnaryOrConversionOp(comptime op: fn (c_1: V128) V128) OpcodeHandler {
    return struct {
        fn unaryOrConversionHandler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) callconv(ohcc) Transition {
            var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

            const operands = vals.popTyped(&(.{.v128} ** 1));
            vals.assertRemainingCountIs(0);
            vals.pushTyped(&.{.v128}, .{@call(.always_inline, op, operands)});

            const instr = Instr.init(ip, eip);
            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }
    }.unaryOrConversionHandler;
}

/// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#conversions
const conversions = struct {
    fn @"f32x4.demote_f64x2_zero"(v: V128) V128 {
        const low: @Vector(2, f32) = @floatCast(v.f64x2);
        return V128{ .f32x4 = std.simd.join(low, @as(@Vector(2, f32), @splat(0))) };
    }

    fn @"f64x2.promote_low_f32x4"(v: V128) V128 {
        const low_f32x2: @Vector(2, f32) = std.simd.extract(@as([4]f32, v.f32x4), 0, 2);
        return V128{ .f64x2 = low_f32x2 };
    }

    /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-to-single-precision-floating-point
    fn @"f32x4.convert_i32x4_s"(v: V128) V128 {
        return V128{ .f32x4 = @floatFromInt(v.i32x4) };
    }

    fn @"f32x4.convert_i32x4_u"(v: V128) V128 {
        return V128{ .f32x4 = @floatFromInt(v.u32x4) };
    }

    /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-to-double-precision-floating-point
    fn @"f64x2.convert_low_i32x4_s"(v: V128) V128 {
        const low: @Vector(2, i32) = std.simd.extract(v.i32x4, 0, 2);
        return V128{ .f64x2 = @floatFromInt(low) };
    }

    fn @"f64x2.convert_low_i32x4_u"(v: V128) V128 {
        const low: @Vector(2, u32) = std.simd.extract(v.u32x4, 0, 2);
        return V128{ .f64x2 = @floatFromInt(low) };
    }
};

pub const @"f32x4.demote_f64x2_zero" = defineUnaryOrConversionOp(conversions.@"f32x4.demote_f64x2_zero");
pub const @"f64x2.promote_low_f32x4" = defineUnaryOrConversionOp(conversions.@"f64x2.promote_low_f32x4");
pub const @"f32x4.convert_i32x4_s" = defineUnaryOrConversionOp(conversions.@"f32x4.convert_i32x4_s");
pub const @"f32x4.convert_i32x4_u" = defineUnaryOrConversionOp(conversions.@"f32x4.convert_i32x4_u");
pub const @"f64x2.convert_low_i32x4_s" = defineUnaryOrConversionOp(conversions.@"f64x2.convert_low_i32x4_s");
pub const @"f64x2.convert_low_i32x4_u" = defineUnaryOrConversionOp(conversions.@"f64x2.convert_low_i32x4_u");

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-vunop
fn defineUnaryOp(
    comptime interpretation: V128.Interpretation,
    comptime op: fn (c_1: interpretation.Type()) interpretation.Type(),
) OpcodeHandler {
    return struct {
        fn vUnOp(c_1: V128) V128 {
            const field_name = comptime interpretation.fieldName();
            return @unionInit(
                V128,
                field_name,
                @call(.always_inline, op, .{@field(c_1, field_name)}),
            );
        }

        const vUnOpHandler = defineUnaryOrConversionOp(vUnOp);
    }.vUnOpHandler;
}

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

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vnarrow
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-to-integer-narrowing
fn defineNarrowingOp(
    /// Has lanes twice the width of `To`. Must be signed.
    comptime From: type,
    comptime To: type,
) OpcodeHandler {
    return struct {
        comptime {
            std.debug.assert(@divExact(@typeInfo(From).int.bits, 2) == @typeInfo(To).int.bits);
            std.debug.assert(@typeInfo(From).int.signedness == .signed);
        }

        const interpret_from = V128.Interpretation.fromLaneType(From);
        const from_lane_count = interpret_from.laneCount();
        const interpret_to = V128.Interpretation.fromLaneType(To);
        const to_signedness = @typeInfo(To).int.signedness;

        const BoundsVec = @Vector(from_lane_count, To);
        const min_bounds: BoundsVec = @splat(std.math.minInt(To));
        const max_bounds: BoundsVec = @splat(std.math.maxInt(To));

        fn vNarrowOp(a: V128, b: V128) V128 {
            const low = a.interpret(interpret_from);
            const high = b.interpret(interpret_from);

            const low_bounded = @min(@max(min_bounds, low), max_bounds);
            const high_bounded = @min(@max(min_bounds, high), max_bounds);

            const low_casted: BoundsVec = @intCast(low_bounded);
            const high_casted: BoundsVec = @intCast(high_bounded);

            return V128.init(interpret_to, std.simd.join(low_casted, high_casted));
        }

        const vNarrowOpHandler = defineBinOp(vNarrowOp);
    }.vNarrowOpHandler;
}

fn integerOpcodeHandlers(comptime Signed: type) type {
    return struct {
        const SignedInt = @typeInfo(Signed).vector.child;

        const interpretation = V128.Interpretation.fromLaneType(SignedInt);
        const lane_width = interpretation.laneWidth();
        const lane_count = interpretation.laneCount();

        const UnsignedInt = @Int(.unsigned, lane_width.toBits());
        const Unsigned = @Vector(lane_count, UnsignedInt);

        comptime {
            std.debug.assert(@typeInfo(SignedInt).int.signedness == .signed);
            std.debug.assert(@typeInfo(SignedInt).int.bits == lane_width.toBits());
            std.debug.assert(@typeInfo(Signed).vector.len == lane_count);
        }

        const operators = struct {
            const ShiftInt = std.math.Log2Int(UnsignedInt);

            inline fn bitShiftAmt(y: i32) @Vector(lane_count, ShiftInt) {
                return @splat(@intCast(@mod(y, lane_width.toBits())));
            }

            fn abs(v: Signed) Signed {
                return @as(Signed, @bitCast(@abs(v)));
            }

            fn neg(v: Signed) Signed {
                return -%v;
            }

            fn popcnt(v: Signed) Signed {
                return @bitCast(@as(Unsigned, @popCount(v)));
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

            fn add(i_1: Signed, i_2: Signed) Signed {
                return i_1 +% i_2;
            }

            fn sub(i_1: Signed, i_2: Signed) Signed {
                return i_1 -% i_2;
            }

            fn mul(i_1: Signed, i_2: Signed) Signed {
                return i_1 *% i_2;
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-imin
            fn min_s(i_1: Signed, i_2: Signed) Signed {
                return @min(i_1, i_2);
            }

            fn min_u(i_1: Signed, i_2: Signed) Signed {
                return @bitCast(@min(@as(Unsigned, @bitCast(i_1)), @as(Unsigned, @bitCast(i_2))));
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-imax
            fn max_s(i_1: Signed, i_2: Signed) Signed {
                return @max(i_1, i_2);
            }

            fn max_u(i_1: Signed, i_2: Signed) Signed {
                return @bitCast(@max(@as(Unsigned, @bitCast(i_1)), @as(Unsigned, @bitCast(i_2))));
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-iavgr
            fn avgr_u(i_1: Signed, i_2: Signed) Signed {
                const Avgr = @Vector(lane_count, std.meta.Int(.unsigned, lane_width.toBits() + 1));
                const v_1: Avgr = @as(Unsigned, @bitCast(i_1));
                const v_2: Avgr = @as(Unsigned, @bitCast(i_2));
                const j: Avgr = v_1 + v_2 + @as(Avgr, @splat(1));
                const result: Avgr = @divTrunc(j, @as(Avgr, @splat(2)));
                return @bitCast(@as(Unsigned, @intCast(result)));
            }
        };

        pub const abs = defineUnaryOp(interpretation, operators.abs);
        pub const neg = defineUnaryOp(interpretation, operators.neg);
        pub const popcnt = defineUnaryOp(interpretation, operators.popcnt);

        pub fn all_true(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) callconv(ohcc) Transition {
            var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

            const result = V128.allTrue(vals.popTyped(&(.{.v128}))[0], lane_width);
            vals.assertRemainingCountIs(0);
            vals.pushTyped(&.{.i32}, .{@intFromBool(result)});

            const instr = Instr.init(ip, eip);
            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }

        pub fn bitmask(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) callconv(ohcc) Transition {
            var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

            const result = V128.bitmask(vals.popTyped(&(.{.v128}))[0], lane_width);
            const result_int: std.meta.Int(.unsigned, lane_width.count()) = @bitCast(result);
            vals.assertRemainingCountIs(0);
            vals.pushTyped(&.{.i32}, .{@bitCast(@as(u32, result_int))});

            const instr = Instr.init(ip, eip);
            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }

        pub const shl = defineShiftOp(interpretation, operators.shl);
        pub const shr_s = defineShiftOp(interpretation, operators.shr_s);
        pub const shr_u = defineShiftOp(interpretation, operators.shr_u);

        fn opcode(comptime name: []const u8) FDPrefixOpcode {
            return @field(FDPrefixOpcode, interpretation.fieldName() ++ "." ++ name);
        }

        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-addition
        pub const add = defineLaneWiseBinOp(interpretation, operators.add);

        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-subtraction
        pub const sub = defineLaneWiseBinOp(interpretation, operators.sub);

        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-multiplication
        pub const mul = defineLaneWiseBinOp(interpretation, operators.mul);
        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#lane-wise-integer-minimum
        pub const min_s = defineLaneWiseBinOp(interpretation, operators.min_s);
        pub const min_u = defineLaneWiseBinOp(interpretation, operators.min_u);
        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#lane-wise-integer-maximum
        pub const max_s = defineLaneWiseBinOp(interpretation, operators.max_s);
        pub const max_u = defineLaneWiseBinOp(interpretation, operators.max_u);
        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#lane-wise-integer-rounding-average
        pub const avgr_u = defineLaneWiseBinOp(interpretation, operators.avgr_u);
    };
}

const i8x16_opcode_handlers = integerOpcodeHandlers(@Vector(16, i8));
const i16x8_opcode_handlers = integerOpcodeHandlers(@Vector(8, i16));
const i32x4_opcode_handlers = integerOpcodeHandlers(@Vector(4, i32));
const i64x2_opcode_handlers = integerOpcodeHandlers(@Vector(2, i64));

pub const @"i8x16.abs" = i8x16_opcode_handlers.abs;
pub const @"i8x16.neg" = i8x16_opcode_handlers.neg;
pub const @"i8x16.popcnt" = i8x16_opcode_handlers.popcnt;
pub const @"i8x16.all_true" = i8x16_opcode_handlers.all_true;
pub const @"i8x16.bitmask" = i8x16_opcode_handlers.bitmask;
pub const @"i8x16.narrow_i16x8_s" = defineNarrowingOp(i16, i8);
pub const @"i8x16.narrow_i16x8_u" = defineNarrowingOp(i16, u8);

pub const @"i8x16.shl" = i8x16_opcode_handlers.shl;
pub const @"i8x16.shr_s" = i8x16_opcode_handlers.shr_s;
pub const @"i8x16.shr_u" = i8x16_opcode_handlers.shr_u;

pub const @"i8x16.add" = i8x16_opcode_handlers.add;
pub const @"i8x16.sub" = i8x16_opcode_handlers.sub;

pub const @"i8x16.min_s" = i8x16_opcode_handlers.min_s;
pub const @"i8x16.min_u" = i8x16_opcode_handlers.min_u;
pub const @"i8x16.max_s" = i8x16_opcode_handlers.max_s;
pub const @"i8x16.max_u" = i8x16_opcode_handlers.max_u;
pub const @"i8x16.avgr_u" = i8x16_opcode_handlers.avgr_u;

pub const @"i16x8.abs" = i16x8_opcode_handlers.abs;
pub const @"i16x8.neg" = i16x8_opcode_handlers.neg;
pub const @"i16x8.all_true" = i16x8_opcode_handlers.all_true;
pub const @"i16x8.bitmask" = i16x8_opcode_handlers.bitmask;
pub const @"i16x8.narrow_i32x4_s" = defineNarrowingOp(i32, i16);
pub const @"i16x8.narrow_i32x4_u" = defineNarrowingOp(i32, u16);

pub const @"i16x8.shl" = i16x8_opcode_handlers.shl;
pub const @"i16x8.shr_s" = i16x8_opcode_handlers.shr_s;
pub const @"i16x8.shr_u" = i16x8_opcode_handlers.shr_u;

pub const @"i16x8.add" = i16x8_opcode_handlers.add;
pub const @"i16x8.sub" = i16x8_opcode_handlers.sub;

pub const @"i16x8.min_s" = i16x8_opcode_handlers.min_s;
pub const @"i16x8.min_u" = i16x8_opcode_handlers.min_u;
pub const @"i16x8.max_s" = i16x8_opcode_handlers.max_s;
pub const @"i16x8.max_u" = i16x8_opcode_handlers.max_u;
pub const @"i16x8.avgr_u" = i16x8_opcode_handlers.avgr_u;

pub const @"i32x4.abs" = i32x4_opcode_handlers.abs;
pub const @"i32x4.neg" = i32x4_opcode_handlers.neg;
pub const @"i32x4.all_true" = i32x4_opcode_handlers.all_true;
pub const @"i32x4.bitmask" = i32x4_opcode_handlers.bitmask;

pub const @"i32x4.shl" = i32x4_opcode_handlers.shl;
pub const @"i32x4.shr_s" = i32x4_opcode_handlers.shr_s;
pub const @"i32x4.shr_u" = i32x4_opcode_handlers.shr_u;

pub const @"i32x4.add" = i32x4_opcode_handlers.add;
pub const @"i32x4.sub" = i32x4_opcode_handlers.sub;

pub const @"i32x4.min_s" = i32x4_opcode_handlers.min_s;
pub const @"i32x4.min_u" = i32x4_opcode_handlers.min_u;
pub const @"i32x4.max_s" = i32x4_opcode_handlers.max_s;
pub const @"i32x4.max_u" = i32x4_opcode_handlers.max_u;

pub const @"i64x2.abs" = i64x2_opcode_handlers.abs;
pub const @"i64x2.neg" = i64x2_opcode_handlers.neg;
pub const @"i64x2.all_true" = i64x2_opcode_handlers.all_true;
pub const @"i64x2.bitmask" = i64x2_opcode_handlers.bitmask;

pub const @"i64x2.shl" = i64x2_opcode_handlers.shl;
pub const @"i64x2.shr_s" = i64x2_opcode_handlers.shr_s;
pub const @"i64x2.shr_u" = i64x2_opcode_handlers.shr_u;

pub const @"i64x2.add" = i64x2_opcode_handlers.add;
pub const @"i64x2.sub" = i64x2_opcode_handlers.sub;

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
