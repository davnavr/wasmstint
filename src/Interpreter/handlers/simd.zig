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

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-vrelop
pub fn defineRelOp(
    comptime interpretation: V128.Interpretation,
    comptime op: fn (
        c_1: interpretation.Type(),
        c_2: interpretation.Type(),
    ) @Vector(interpretation.laneCount(), bool),
) OpcodeHandler {
    return struct {
        const results_interpretation = interpretation.laneWidth().integerInterpretation(.signed);

        fn vRelOp(c_1: V128, c_2: V128) V128 {
            const results: @Vector(interpretation.laneCount(), i1) = @bitCast(
                @call(
                    .always_inline,
                    op,
                    .{ c_1.interpret(interpretation), c_2.interpret(interpretation) },
                ),
            );

            return V128.init(
                results_interpretation,
                // Sign-extension fills each line with all ones or all zeroes.
                results,
            );
        }

        const vRelOpHandler = defineBinOp(vRelOp);
    }.vRelOpHandler;
}

/// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#comparisons
fn laneWiseComparisonHandlers(comptime interpretation: V128.Interpretation) type {
    return struct {
        const Vec = interpretation.Type();
        const Results = @Vector(interpretation.laneCount(), bool);

        const operators = struct {
            fn eq(a: Vec, b: Vec) Results {
                return a == b;
            }

            fn ne(a: Vec, b: Vec) Results {
                return a != b;
            }

            fn lt(a: Vec, b: Vec) Results {
                return a < b;
            }

            fn gt(a: Vec, b: Vec) Results {
                return a > b;
            }

            fn le(a: Vec, b: Vec) Results {
                return a <= b;
            }

            fn ge(a: Vec, b: Vec) Results {
                return a >= b;
            }
        };

        const eq = defineRelOp(interpretation, operators.eq);
        const ne = defineRelOp(interpretation, operators.ne);
        const lt = defineRelOp(interpretation, operators.lt);
        const gt = defineRelOp(interpretation, operators.gt);
        const le = defineRelOp(interpretation, operators.le);
        const ge = defineRelOp(interpretation, operators.ge);
    };
}

pub const @"i8x16.eq" = laneWiseComparisonHandlers(.i8).eq;
pub const @"i8x16.ne" = laneWiseComparisonHandlers(.i8).ne;
pub const @"i8x16.lt_s" = laneWiseComparisonHandlers(.i8).lt;
pub const @"i8x16.lt_u" = laneWiseComparisonHandlers(.u8).lt;
pub const @"i8x16.gt_s" = laneWiseComparisonHandlers(.i8).gt;
pub const @"i8x16.gt_u" = laneWiseComparisonHandlers(.u8).gt;
pub const @"i8x16.le_s" = laneWiseComparisonHandlers(.i8).le;
pub const @"i8x16.le_u" = laneWiseComparisonHandlers(.u8).le;
pub const @"i8x16.ge_s" = laneWiseComparisonHandlers(.i8).ge;
pub const @"i8x16.ge_u" = laneWiseComparisonHandlers(.u8).ge;

pub const @"i16x8.eq" = laneWiseComparisonHandlers(.i16).eq;
pub const @"i16x8.ne" = laneWiseComparisonHandlers(.i16).ne;
pub const @"i16x8.lt_s" = laneWiseComparisonHandlers(.i16).lt;
pub const @"i16x8.lt_u" = laneWiseComparisonHandlers(.u16).lt;
pub const @"i16x8.gt_s" = laneWiseComparisonHandlers(.i16).gt;
pub const @"i16x8.gt_u" = laneWiseComparisonHandlers(.u16).gt;
pub const @"i16x8.le_s" = laneWiseComparisonHandlers(.i16).le;
pub const @"i16x8.le_u" = laneWiseComparisonHandlers(.u16).le;
pub const @"i16x8.ge_s" = laneWiseComparisonHandlers(.i16).ge;
pub const @"i16x8.ge_u" = laneWiseComparisonHandlers(.u16).ge;

pub const @"i32x4.eq" = laneWiseComparisonHandlers(.i32).eq;
pub const @"i32x4.ne" = laneWiseComparisonHandlers(.i32).ne;
pub const @"i32x4.lt_s" = laneWiseComparisonHandlers(.i32).lt;
pub const @"i32x4.lt_u" = laneWiseComparisonHandlers(.u32).lt;
pub const @"i32x4.gt_s" = laneWiseComparisonHandlers(.i32).gt;
pub const @"i32x4.gt_u" = laneWiseComparisonHandlers(.u32).gt;
pub const @"i32x4.le_s" = laneWiseComparisonHandlers(.i32).le;
pub const @"i32x4.le_u" = laneWiseComparisonHandlers(.u32).le;
pub const @"i32x4.ge_s" = laneWiseComparisonHandlers(.i32).ge;
pub const @"i32x4.ge_u" = laneWiseComparisonHandlers(.u32).ge;

pub const @"f32x4.eq" = laneWiseComparisonHandlers(.f32).eq;
pub const @"f32x4.ne" = laneWiseComparisonHandlers(.f32).ne;
pub const @"f32x4.lt" = laneWiseComparisonHandlers(.f32).lt;
pub const @"f32x4.gt" = laneWiseComparisonHandlers(.f32).gt;
pub const @"f32x4.le" = laneWiseComparisonHandlers(.f32).le;
pub const @"f32x4.ge" = laneWiseComparisonHandlers(.f32).ge;

pub const @"i64x2.eq" = laneWiseComparisonHandlers(.i64).eq;
pub const @"i64x2.ne" = laneWiseComparisonHandlers(.i64).ne;
pub const @"i64x2.lt_s" = laneWiseComparisonHandlers(.i64).lt;
pub const @"i64x2.lt_u" = laneWiseComparisonHandlers(.u64).lt;
pub const @"i64x2.gt_s" = laneWiseComparisonHandlers(.i64).gt;
pub const @"i64x2.gt_u" = laneWiseComparisonHandlers(.u64).gt;
pub const @"i64x2.le_s" = laneWiseComparisonHandlers(.i64).le;
pub const @"i64x2.le_u" = laneWiseComparisonHandlers(.u64).le;
pub const @"i64x2.ge_s" = laneWiseComparisonHandlers(.i64).ge;
pub const @"i64x2.ge_u" = laneWiseComparisonHandlers(.u64).ge;

pub const @"f64x2.eq" = laneWiseComparisonHandlers(.f64).eq;
pub const @"f64x2.ne" = laneWiseComparisonHandlers(.f64).ne;
pub const @"f64x2.lt" = laneWiseComparisonHandlers(.f64).lt;
pub const @"f64x2.gt" = laneWiseComparisonHandlers(.f64).gt;
pub const @"f64x2.le" = laneWiseComparisonHandlers(.f64).le;
pub const @"f64x2.ge" = laneWiseComparisonHandlers(.f64).ge;

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

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vcvtop
/// - https://webassembly.github.io/spec/core/exec/numerics.html#op-vcvtop
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-to-integer-extension
///
/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vextunop
/// - https://webassembly.github.io/spec/core/exec/numerics.html#op-vextunop
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#extended-integer-arithmetic
fn integerExtensionHandlers(
    /// Has lanes half the width of `To`.
    comptime From: type,
    comptime To: type,
) type {
    return struct {
        comptime {
            std.debug.assert(@typeInfo(From).int.bits * 2 == @typeInfo(To).int.bits);
            std.debug.assert(@typeInfo(From).int.signedness == @typeInfo(To).int.signedness);
        }

        const interpret_from = V128.Interpretation.fromLaneType(From);
        const from_lane_count = interpret_from.laneCount();
        const interpret_to = V128.Interpretation.fromLaneType(To);
        const to_lane_count = interpret_to.laneCount();

        comptime {
            std.debug.assert(to_lane_count * 2 == from_lane_count);
        }

        const operators = struct {
            fn addPairWise(v: V128) V128 {
                const inputs: @Vector(from_lane_count, From) = v.interpret(interpret_from);
                var result: @Vector(to_lane_count, To) = undefined;
                inline for (0..to_lane_count) |i| {
                    result[i] = @as(To, inputs[i * 2]) + @as(To, inputs[(i * 2) + 1]);
                }

                return V128.init(interpret_to, result);
            }

            fn extMulLow(a: V128, b: V128) V128 {
                return V128.init(interpret_to, extLow(a) * extLow(b));
            }

            fn extMulHigh(a: V128, b: V128) V128 {
                return V128.init(interpret_to, extHigh(a) * extHigh(b));
            }

            fn extend(lanes: @Vector(to_lane_count, From)) interpret_to.Type() {
                return lanes; // Does zero or sign extension automatically.
            }

            fn extLow(v: V128) interpret_to.Type() {
                return extend(std.simd.extract(v.interpret(interpret_from), 0, to_lane_count));
            }

            fn extendLow(v: V128) V128 {
                return V128.init(interpret_to, extLow(v));
            }

            fn extHigh(v: V128) interpret_to.Type() {
                return extend(
                    std.simd.extract(v.interpret(interpret_from), to_lane_count, to_lane_count),
                );
            }

            fn extendHigh(v: V128) V128 {
                return V128.init(interpret_to, extHigh(v));
            }
        };

        const addPairWise = defineUnaryOrConversionOp(operators.addPairWise);
        const extMulLow = defineBinOp(operators.extMulLow);
        const extMulHigh = defineBinOp(operators.extMulHigh);
        const extendLow = defineUnaryOrConversionOp(operators.extendLow);
        const extendHigh = defineUnaryOrConversionOp(operators.extendHigh);
    };
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

const i8x16_int_ops = integerOpcodeHandlers(@Vector(16, i8));
const i16x8_int_ops = integerOpcodeHandlers(@Vector(8, i16));
const i32x4_int_ops = integerOpcodeHandlers(@Vector(4, i32));
const i64x2_int_ops = integerOpcodeHandlers(@Vector(2, i64));

pub const @"i8x16.abs" = i8x16_int_ops.abs;
pub const @"i8x16.neg" = i8x16_int_ops.neg;
pub const @"i8x16.popcnt" = i8x16_int_ops.popcnt;
pub const @"i8x16.all_true" = i8x16_int_ops.all_true;
pub const @"i8x16.bitmask" = i8x16_int_ops.bitmask;
pub const @"i8x16.narrow_i16x8_s" = defineNarrowingOp(i16, i8);
pub const @"i8x16.narrow_i16x8_u" = defineNarrowingOp(i16, u8);

pub const @"i8x16.shl" = i8x16_int_ops.shl;
pub const @"i8x16.shr_s" = i8x16_int_ops.shr_s;
pub const @"i8x16.shr_u" = i8x16_int_ops.shr_u;

pub const @"i8x16.add" = i8x16_int_ops.add;
pub const @"i8x16.sub" = i8x16_int_ops.sub;

pub const @"i8x16.mul" = i8x16_int_ops.mul;
pub const @"i8x16.min_s" = i8x16_int_ops.min_s;
pub const @"i8x16.min_u" = i8x16_int_ops.min_u;
pub const @"i8x16.max_s" = i8x16_int_ops.max_s;
pub const @"i8x16.max_u" = i8x16_int_ops.max_u;
pub const @"i8x16.avgr_u" = i8x16_int_ops.avgr_u;

pub const @"i16x8.extadd_pairwise_i8x16_s" = integerExtensionHandlers(i8, i16).addPairWise;
pub const @"i16x8.extadd_pairwise_i8x16_u" = integerExtensionHandlers(u8, u16).addPairWise;
pub const @"i32x4.extadd_pairwise_i16x8_s" = integerExtensionHandlers(i16, i32).addPairWise;
pub const @"i32x4.extadd_pairwise_i16x8_u" = integerExtensionHandlers(u16, u32).addPairWise;
pub const @"i16x8.abs" = i16x8_int_ops.abs;
pub const @"i16x8.neg" = i16x8_int_ops.neg;
pub const @"i16x8.all_true" = i16x8_int_ops.all_true;
pub const @"i16x8.bitmask" = i16x8_int_ops.bitmask;
pub const @"i16x8.narrow_i32x4_s" = defineNarrowingOp(i32, i16);
pub const @"i16x8.narrow_i32x4_u" = defineNarrowingOp(i32, u16);
pub const @"i16x8.extend_low_i8x16_s" = integerExtensionHandlers(i8, i16).extendLow;
pub const @"i16x8.extend_low_i8x16_u" = integerExtensionHandlers(u8, u16).extendLow;
pub const @"i16x8.extend_high_i8x16_s" = integerExtensionHandlers(i8, i16).extendHigh;
pub const @"i16x8.extend_high_i8x16_u" = integerExtensionHandlers(u8, u16).extendHigh;
pub const @"i16x8.shl" = i16x8_int_ops.shl;
pub const @"i16x8.shr_s" = i16x8_int_ops.shr_s;
pub const @"i16x8.shr_u" = i16x8_int_ops.shr_u;

pub const @"i16x8.add" = i16x8_int_ops.add;
pub const @"i16x8.sub" = i16x8_int_ops.sub;

pub const @"i16x8.mul" = i16x8_int_ops.mul;
pub const @"i16x8.min_s" = i16x8_int_ops.min_s;
pub const @"i16x8.min_u" = i16x8_int_ops.min_u;
pub const @"i16x8.max_s" = i16x8_int_ops.max_s;
pub const @"i16x8.max_u" = i16x8_int_ops.max_u;
pub const @"i16x8.avgr_u" = i16x8_int_ops.avgr_u;
pub const @"i16x8.extmul_low_i8x16_s" = integerExtensionHandlers(i8, i16).extMulLow;
pub const @"i16x8.extmul_high_i8x16_s" = integerExtensionHandlers(i8, i16).extMulHigh;
pub const @"i16x8.extmul_low_i8x16_u" = integerExtensionHandlers(u8, u16).extMulLow;
pub const @"i16x8.extmul_high_i8x16_u" = integerExtensionHandlers(u8, u16).extMulHigh;

pub const @"i32x4.abs" = i32x4_int_ops.abs;
pub const @"i32x4.neg" = i32x4_int_ops.neg;
pub const @"i32x4.all_true" = i32x4_int_ops.all_true;
pub const @"i32x4.bitmask" = i32x4_int_ops.bitmask;
pub const @"i32x4.extend_low_i16x8_s" = integerExtensionHandlers(i16, i32).extendLow;
pub const @"i32x4.extend_low_i16x8_u" = integerExtensionHandlers(u16, u32).extendLow;
pub const @"i32x4.extend_high_i16x8_s" = integerExtensionHandlers(i16, i32).extendHigh;
pub const @"i32x4.extend_high_i16x8_u" = integerExtensionHandlers(u16, u32).extendHigh;
pub const @"i32x4.shl" = i32x4_int_ops.shl;
pub const @"i32x4.shr_s" = i32x4_int_ops.shr_s;
pub const @"i32x4.shr_u" = i32x4_int_ops.shr_u;

pub const @"i32x4.add" = i32x4_int_ops.add;
pub const @"i32x4.sub" = i32x4_int_ops.sub;

pub const @"i32x4.mul" = i32x4_int_ops.mul;
pub const @"i32x4.min_s" = i32x4_int_ops.min_s;
pub const @"i32x4.min_u" = i32x4_int_ops.min_u;
pub const @"i32x4.max_s" = i32x4_int_ops.max_s;
pub const @"i32x4.max_u" = i32x4_int_ops.max_u;
//pub const @"i32x4.dot_i16x8_s"
pub const @"i32x4.extmul_low_i16x8_s" = integerExtensionHandlers(i16, i32).extMulLow;
pub const @"i32x4.extmul_high_i16x8_s" = integerExtensionHandlers(i16, i32).extMulHigh;
pub const @"i32x4.extmul_low_i16x8_u" = integerExtensionHandlers(u16, u32).extMulLow;
pub const @"i32x4.extmul_high_i16x8_u" = integerExtensionHandlers(u16, u32).extMulHigh;

pub const @"i64x2.abs" = i64x2_int_ops.abs;
pub const @"i64x2.neg" = i64x2_int_ops.neg;
pub const @"i64x2.all_true" = i64x2_int_ops.all_true;
pub const @"i64x2.bitmask" = i64x2_int_ops.bitmask;
pub const @"i64x2.extend_low_i32x4_s" = integerExtensionHandlers(i32, i64).extendLow;
pub const @"i64x2.extend_low_i32x4_u" = integerExtensionHandlers(u32, u64).extendLow;
pub const @"i64x2.extend_high_i32x4_s" = integerExtensionHandlers(i32, i64).extendHigh;
pub const @"i64x2.extend_high_i32x4_u" = integerExtensionHandlers(u32, u64).extendHigh;
pub const @"i64x2.shl" = i64x2_int_ops.shl;
pub const @"i64x2.shr_s" = i64x2_int_ops.shr_s;
pub const @"i64x2.shr_u" = i64x2_int_ops.shr_u;

pub const @"i64x2.add" = i64x2_int_ops.add;
pub const @"i64x2.sub" = i64x2_int_ops.sub;
pub const @"i64x2.mul" = i64x2_int_ops.mul;

pub const @"i64x2.extmul_low_i32x4_s" = integerExtensionHandlers(i32, i64).extMulLow;
pub const @"i64x2.extmul_high_i32x4_s" = integerExtensionHandlers(i32, i64).extMulHigh;
pub const @"i64x2.extmul_low_i32x4_u" = integerExtensionHandlers(u32, u64).extMulLow;
pub const @"i64x2.extmul_high_i32x4_u" = integerExtensionHandlers(u32, u64).extMulHigh;

/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#floating-point-arithmetic
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#floating-point-min-and-max
fn floatOpcodeHandlers(comptime F: type) type {
    return struct {
        const interpretation = V128.Interpretation.fromLaneType(F);
        const Floats = interpretation.Type();
        const lane_count = interpretation.laneCount();
        const I = std.meta.Int(.unsigned, @typeInfo(F).float.bits);
        const Ints = @Vector(interpretation.laneCount(), I);

        // Copied from `handlers.zig`
        //const canonical_nan_bit: N = 1 << (std.math.floatMantissaBits(F) - 1);
        //const precise_int_limit = 1 << (std.math.floatMantissaBits(F) + 1);

        const operators = struct {
            fn neg(z: Floats) Floats {
                return -z;
            }

            fn sqrt(z: Floats) Floats {
                return @sqrt(z);
            }

            fn add(z_1: Floats, z_2: Floats) Floats {
                return z_1 + z_2;
            }

            fn sub(z_1: Floats, z_2: Floats) Floats {
                return z_1 - z_2;
            }

            fn mul(z_1: Floats, z_2: Floats) Floats {
                return z_1 * z_2;
            }

            fn div(z_1: Floats, z_2: Floats) Floats {
                return z_1 / z_2;
            }

            fn isNan(z: Floats) @Vector(lane_count, bool) {
                return z != z;
            }

            const pos_zeroes: Ints = @bitCast(@as(Floats, @splat(0.0)));
            const neg_zeroes: Ints = @bitCast(@as(Floats, @splat(-0.0)));

            fn min(z_1: Floats, z_2: Floats) Floats {
                const z_1_bits: Ints = @bitCast(z_1);
                const z_2_bits: Ints = @bitCast(z_2);
                return @select(
                    F,
                    isNan(z_1) | isNan(z_2),
                    // Pick a NaN
                    z_1 + z_2,
                    @select(
                        F,
                        ((z_1_bits == pos_zeroes) & (z_2_bits == neg_zeroes)) |
                            ((z_1_bits == neg_zeroes) & (z_2_bits == pos_zeroes)),
                        comptime @as(Floats, @bitCast(neg_zeroes)),
                        // https://llvm.org/docs/LangRef.html#llvm-minnum-intrinsic
                        @min(z_1, z_2),
                    ),
                );
            }

            fn max(z_1: Floats, z_2: Floats) Floats {
                const z_1_bits: Ints = @bitCast(z_1);
                const z_2_bits: Ints = @bitCast(z_2);
                return @select(
                    F,
                    isNan(z_1) | isNan(z_2),
                    // Pick a NaN
                    z_1 + z_2,
                    @select(
                        F,
                        ((z_1_bits == pos_zeroes) & (z_2_bits == neg_zeroes)) |
                            ((z_1_bits == neg_zeroes) & (z_2_bits == pos_zeroes)),
                        comptime @as(Floats, @bitCast(pos_zeroes)),
                        // https://llvm.org/docs/LangRef.html#llvm-maxnum-intrinsic
                        @max(z_1, z_2),
                    ),
                );
            }

            /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#pseudo-minimum
            /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-fpmin
            fn pmin(z_1: Floats, z_2: Floats) Floats {
                return @select(F, z_2 < z_1, z_2, z_1);
            }

            /// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#pseudo-maximum
            /// - https://webassembly.github.io/spec/core/exec/numerics.html#op-fpmax
            fn pmax(z_1: Floats, z_2: Floats) Floats {
                return @select(F, z_1 < z_2, z_2, z_1);
            }

            fn abs(z: Floats) Floats {
                return @abs(z);
            }
        };

        const abs = defineUnaryOp(interpretation, operators.abs);
        const neg = defineUnaryOp(interpretation, operators.neg);
        const sqrt = defineUnaryOp(interpretation, operators.sqrt);
        const add = defineLaneWiseBinOp(interpretation, operators.add);
        const sub = defineLaneWiseBinOp(interpretation, operators.sub);
        const mul = defineLaneWiseBinOp(interpretation, operators.mul);
        const div = defineLaneWiseBinOp(interpretation, operators.div);
        const min = defineLaneWiseBinOp(interpretation, operators.min);
        const max = defineLaneWiseBinOp(interpretation, operators.max);
        const pmin = defineLaneWiseBinOp(interpretation, operators.pmin);
        const pmax = defineLaneWiseBinOp(interpretation, operators.pmax);
    };
}

const f32x4_arith_ops = floatOpcodeHandlers(f32);
pub const @"f32x4.abs" = f32x4_arith_ops.abs;
pub const @"f32x4.neg" = f32x4_arith_ops.neg;
pub const @"f32x4.sqrt" = f32x4_arith_ops.sqrt;
pub const @"f32x4.add" = f32x4_arith_ops.add;
pub const @"f32x4.sub" = f32x4_arith_ops.sub;
pub const @"f32x4.mul" = f32x4_arith_ops.mul;
pub const @"f32x4.div" = f32x4_arith_ops.div;
pub const @"f32x4.min" = f32x4_arith_ops.min;
pub const @"f32x4.max" = f32x4_arith_ops.max;
pub const @"f32x4.pmin" = f32x4_arith_ops.pmin;
pub const @"f32x4.pmax" = f32x4_arith_ops.pmax;

const f64x2_arith_ops = floatOpcodeHandlers(f64);
pub const @"f64x2.abs" = f64x2_arith_ops.abs;
pub const @"f64x2.neg" = f64x2_arith_ops.neg;
pub const @"f64x2.sqrt" = f64x2_arith_ops.sqrt;
pub const @"f64x2.add" = f64x2_arith_ops.add;
pub const @"f64x2.sub" = f64x2_arith_ops.sub;
pub const @"f64x2.mul" = f64x2_arith_ops.mul;
pub const @"f64x2.div" = f64x2_arith_ops.div;
pub const @"f64x2.min" = f64x2_arith_ops.min;
pub const @"f64x2.max" = f64x2_arith_ops.max;
pub const @"f64x2.pmin" = f64x2_arith_ops.pmin;
pub const @"f64x2.pmax" = f64x2_arith_ops.pmax;

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
