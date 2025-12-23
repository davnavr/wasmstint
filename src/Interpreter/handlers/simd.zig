//! Implementation of instructions introduced in the
//! [fixed-width SIMD proposal](https://github.com/WebAssembly/simd).

inline fn trap(
    base_ip: Ip,
    comptime opcode: FDPrefixOpcode,
    eip: Eip,
    sp: Sp,
    stp: Stp,
    interp: *Interpreter,
    info: Interpreter.Trap,
) Transition {
    return Transition.trap(base_ip, .{ .fd = opcode }, eip, sp, stp, interp, info);
}

const load_store = struct {
    fn performLoad(
        instr: *Instr,
        vals: *Stack.Values,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        _: void,
        access: *[16]u8,
    ) Transition {
        vals.assertRemainingCountIs(0);
        vals.pushTyped(&.{.v128}, .{V128{ .u8x16 = access.* }});
        return dispatchNextOpcode(instr.*, vals.top, fuel, stp, locals, module, interp);
    }

    fn popVectorToStore(vals: *Stack.Values, interp: *Interpreter) V128 {
        _ = interp;
        return vals.popTyped(&.{.v128})[0];
    }

    fn performStore(
        instr: *Instr,
        vals: *Stack.Values,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        value: V128,
        access: *[16]u8,
    ) Transition {
        vals.assertRemainingCountIs(0);
        access.* = value.u8x16;
        return dispatchNextOpcode(instr.*, vals.top, fuel, stp, locals, module, interp);
    }
};

pub const @"v128.load" = handlers.linearMemoryAccessor(
    .@"16",
    .{ .fd = .@"v128.load" },
    .load,
    void,
    handlers.nopBeforeMemoryAccess,
    load_store.performLoad,
);

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vload-pack
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#load-and-extend
fn loadAndExtendHandler(
    comptime opcode: FDPrefixOpcode,
    /// Is half the width of `To`.
    comptime From: type,
    comptime To: type,
) OpcodeHandler {
    return struct {
        comptime {
            std.debug.assert(@typeInfo(From).int.bits * 2 == @typeInfo(To).int.bits);
            std.debug.assert(@typeInfo(From).int.signedness == @typeInfo(To).int.signedness);
        }

        const interpret_to = V128.Interpretation.fromLaneType(To);
        const to_lane_count = interpret_to.laneCount();
        const access_size = @sizeOf(From) * to_lane_count;
        const AccessBits = @Int(.unsigned, @as(u8, access_size) * 8);

        fn performExtendingLoad(
            instr: *Instr,
            vals: *Stack.Values,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            _: void,
            access: *[access_size]u8,
        ) Transition {
            vals.assertRemainingCountIs(0);
            const bits = std.mem.readInt(AccessBits, access, .little);
            const v: @Vector(to_lane_count, From) = @bitCast(bits);
            vals.pushTyped(
                &.{.v128},
                .{V128.init(interpret_to, v)}, // automatically sign/zero-extends
            );
            return dispatchNextOpcode(instr.*, vals.top, fuel, stp, locals, module, interp);
        }

        const extendingLoad = handlers.linearMemoryAccessor(
            .fromByteUnits(access_size),
            .{ .fd = opcode },
            .load,
            void,
            handlers.nopBeforeMemoryAccess,
            performExtendingLoad,
        );
    }.extendingLoad;
}

pub const @"v128.load8x8_s" = loadAndExtendHandler(.@"v128.load8x8_s", i8, i16);
pub const @"v128.load8x8_u" = loadAndExtendHandler(.@"v128.load8x8_u", u8, u16);
pub const @"v128.load16x4_s" = loadAndExtendHandler(.@"v128.load16x4_s", i16, i32);
pub const @"v128.load16x4_u" = loadAndExtendHandler(.@"v128.load16x4_u", u16, u32);
pub const @"v128.load32x2_s" = loadAndExtendHandler(.@"v128.load32x2_s", i32, i64);
pub const @"v128.load32x2_u" = loadAndExtendHandler(.@"v128.load32x2_u", u32, u64);

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vload-splat
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#load-and-splat
fn loadAndSplatHandler(comptime opcode: FDPrefixOpcode, comptime To: type) OpcodeHandler {
    return struct {
        const interpret_to = V128.Interpretation.fromLaneType(To);

        fn performLoadAndSplat(
            instr: *Instr,
            vals: *Stack.Values,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            _: void,
            access: *[@sizeOf(To)]u8,
        ) Transition {
            vals.assertRemainingCountIs(0);
            const loaded = std.mem.readInt(To, access, .little);
            vals.pushTyped(&.{.v128}, .{V128.init(interpret_to, @splat(loaded))});
            return dispatchNextOpcode(instr.*, vals.top, fuel, stp, locals, module, interp);
        }

        const loadAndSplat = handlers.linearMemoryAccessor(
            .fromByteUnits(@sizeOf(To)),
            .{ .fd = opcode },
            .load,
            void,
            handlers.nopBeforeMemoryAccess,
            performLoadAndSplat,
        );
    }.loadAndSplat;
}

pub const @"v128.load8_splat" = loadAndSplatHandler(.@"v128.load8_splat", u8);
pub const @"v128.load16_splat" = loadAndSplatHandler(.@"v128.load16_splat", u16);
pub const @"v128.load32_splat" = loadAndSplatHandler(.@"v128.load32_splat", u32);
pub const @"v128.load64_splat" = loadAndSplatHandler(.@"v128.load64_splat", u64);

pub const @"v128.store" = handlers.linearMemoryAccessor(
    .@"16",
    .{ .fd = .@"v128.store" },
    .store,
    V128,
    load_store.popVectorToStore,
    load_store.performStore,
);

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

pub fn @"i8x16.shuffle"(
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

    const indices: *const [16]V128.ShuffleIndex = @ptrCast(instr.readByteArray(16));
    const operands = vals.popTyped(&(.{.v128} ** 2));
    vals.assertRemainingCountIs(0);
    vals.pushArray(1)[0] = Value{
        .v128 = V128.@"i8x16.shuffle"(operands[0], operands[1], indices.*),
    };

    return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
}

pub const @"i8x16.swizzle" = defineBinOp(V128.@"i8x16.swizzle");

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vsplat
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#create-vector-with-identical-lanes
pub fn defineSplatHandler(
    comptime value: Value.Tag,
    comptime To: type,
) OpcodeHandler {
    return struct {
        const to_interpret = V128.Interpretation.fromLaneType(To);

        fn splat(
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

            const c = vals.popTyped(&.{value})[0];
            vals.assertRemainingCountIs(0);
            const scalar: To = switch (To) {
                i8, i16 => @truncate(c),
                i32, i64, f32, f64 => c,
                else => comptime unreachable,
            };
            vals.pushArray(1)[0] = Value{ .v128 = V128.init(to_interpret, @splat(scalar)) };

            const instr = Instr.init(ip, eip);
            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }
    }.splat;
}

pub const @"i8x16.splat" = defineSplatHandler(.i32, i8);
pub const @"i16x8.splat" = defineSplatHandler(.i32, i16);
pub const @"i32x4.splat" = defineSplatHandler(.i32, i32);
pub const @"i64x2.splat" = defineSplatHandler(.i64, i64);
pub const @"f32x4.splat" = defineSplatHandler(.f32, f32);
pub const @"f64x2.splat" = defineSplatHandler(.f64, f64);

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

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vextract-lane
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#extract-lane-as-a-scalar
fn extractLaneHandler(comptime From: type, comptime to: Value.Tag) OpcodeHandler {
    return struct {
        const interpret_from = V128.Interpretation.fromLaneType(From);

        fn extractLane(
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

            const lane = instr.readByte();
            const vector: [interpret_from.laneCount()]From = V128.interpret(
                vals.popTyped(&.{.v128})[0],
                interpret_from,
            );
            vals.assertRemainingCountIs(0);
            vals.pushArray(1)[0] = @unionInit(Value, @tagName(to), vector[lane]);

            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }
    }.extractLane;
}

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vreplace-lane
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#replace-lane-value
fn replaceLaneHandler(comptime T: type, comptime lane: Value.Tag) OpcodeHandler {
    return struct {
        const interpret_as = V128.Interpretation.fromLaneType(T);
        const needs_truncation = @typeInfo(T) == .int and
            @typeInfo(T).int.bits < @typeInfo(lane.Type()).int.bits;

        fn replaceLane(
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

            const lane_idx = instr.readByte();
            const operands = vals.popTyped(&.{ .v128, lane });
            vals.assertRemainingCountIs(0);
            var vector: [interpret_as.laneCount()]T = operands[0].interpret(interpret_as);
            const replacement = operands[1];
            vector[lane_idx] = if (needs_truncation) @truncate(replacement) else replacement;
            vals.pushArray(1)[0] = Value{ .v128 = V128.init(interpret_as, vector) };
            vals.assertRemainingCountIs(1);

            return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
        }
    }.replaceLane;
}

pub const @"i8x16.extract_lane_s" = extractLaneHandler(i8, .i32);
pub const @"i8x16.extract_lane_u" = extractLaneHandler(u8, .i32);
pub const @"i8x16.replace_lane" = replaceLaneHandler(i8, .i32);
pub const @"i16x8.extract_lane_s" = extractLaneHandler(i16, .i32);
pub const @"i16x8.extract_lane_u" = extractLaneHandler(u16, .i32);
pub const @"i16x8.replace_lane" = replaceLaneHandler(i16, .i32);
pub const @"i32x4.extract_lane" = extractLaneHandler(i32, .i32);
pub const @"i32x4.replace_lane" = replaceLaneHandler(i32, .i32);
pub const @"i64x2.extract_lane" = extractLaneHandler(i64, .i64);
pub const @"i64x2.replace_lane" = replaceLaneHandler(i64, .i64);
pub const @"f32x4.extract_lane" = extractLaneHandler(f32, .f32);
pub const @"f32x4.replace_lane" = replaceLaneHandler(f32, .f32);
pub const @"f64x2.extract_lane" = extractLaneHandler(f64, .f64);
pub const @"f64x2.replace_lane" = replaceLaneHandler(f64, .f64);

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

/// - https://webassembly.github.io/spec/core/exec/instructions.html#exec-vload-lane
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#load-lane
fn loadLaneHandler(
    comptime opcode: FDPrefixOpcode,
    comptime T: type,
) OpcodeHandler {
    return struct {
        const interpret = V128.Interpretation.fromLaneType(T);

        fn popVectorToReplaceLaneOf(vals: *Stack.Values, interp: *Interpreter) V128 {
            _ = interp;
            return vals.popTyped(&.{.v128})[0];
        }

        fn performLoadLane(
            instr: *Instr,
            vals: *Stack.Values,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            v: V128,
            access: *[@sizeOf(T)]u8,
        ) Transition {
            const idx = instr.readByte();
            vals.assertRemainingCountIs(0);
            const elem = std.mem.readInt(T, access, .little);
            var lanes: [interpret.laneCount()]T = v.interpret(interpret);
            lanes[idx] = elem;
            vals.pushTyped(&.{.v128}, .{V128.init(interpret, lanes)});
            return dispatchNextOpcode(instr.*, vals.top, fuel, stp, locals, module, interp);
        }

        const loadLane = handlers.linearMemoryAccessor(
            .fromByteUnits(@sizeOf(T)),
            .{ .fd = opcode },
            .store, // actually a load, this ensures an assertion checks for 2 values on the stack
            V128,
            popVectorToReplaceLaneOf,
            performLoadLane,
        );
    }.loadLane;
}

pub const @"v128.load8_lane" = loadLaneHandler(.@"v128.load8_lane", u8);
pub const @"v128.load16_lane" = loadLaneHandler(.@"v128.load16_lane", u16);
pub const @"v128.load32_lane" = loadLaneHandler(.@"v128.load32_lane", u32);
pub const @"v128.load64_lane" = loadLaneHandler(.@"v128.load64_lane", u64);

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

/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#single-precision-floating-point-to-integer-with-saturation
/// - https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#double-precision-floating-point-to-integer-with-saturation
fn floatToIntSaturating(
    comptime F: type,
    comptime I: type,
    floats: V128.Interpretation.fromLaneType(F).Type(),
) @Vector(V128.Interpretation.fromLaneType(F).laneCount(), I) {
    const float_interp = comptime V128.Interpretation.fromLaneType(F);
    const lane_count = comptime float_interp.laneCount();

    const zeroes: @Vector(lane_count, F) = comptime @splat(0);
    const unbounded_no_nan: @Vector(lane_count, F) = @select(F, floats != floats, zeroes, floats);
    var results: @Vector(lane_count, I) = undefined;
    inline for (0..lane_count) |i| {
        results[i] = std.math.lossyCast(I, unbounded_no_nan[i]); // no vector version available
    }
    return results;
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

    fn @"i32x4.trunc_sat_f32x4_s"(v: V128) V128 {
        return V128.init(.i32, floatToIntSaturating(f32, i32, v.f32x4));
    }

    fn @"i32x4.trunc_sat_f32x4_u"(v: V128) V128 {
        return V128.init(.u32, floatToIntSaturating(f32, u32, v.f32x4));
    }

    fn @"i32x4.trunc_sat_f64x2_s_zero"(v: V128) V128 {
        return V128.init(
            .i32,
            std.simd.join(
                floatToIntSaturating(f64, i32, v.f64x2),
                @as(@Vector(2, i32), @splat(0)),
            ),
        );
    }

    fn @"i32x4.trunc_sat_f64x2_u_zero"(v: V128) V128 {
        return V128.init(
            .u32,
            std.simd.join(
                floatToIntSaturating(f64, u32, v.f64x2),
                @as(@Vector(2, u32), @splat(0)),
            ),
        );
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
pub const @"i32x4.trunc_sat_f32x4_s" = defineUnaryOrConversionOp(conversions.@"i32x4.trunc_sat_f32x4_s");
pub const @"i32x4.trunc_sat_f32x4_u" = defineUnaryOrConversionOp(conversions.@"i32x4.trunc_sat_f32x4_u");
pub const @"i32x4.trunc_sat_f64x2_s_zero" = defineUnaryOrConversionOp(conversions.@"i32x4.trunc_sat_f64x2_s_zero");
pub const @"i32x4.trunc_sat_f64x2_u_zero" = defineUnaryOrConversionOp(conversions.@"i32x4.trunc_sat_f64x2_u_zero");
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

            fn add_sat_s(i_1: Signed, i_2: Signed) Signed {
                return i_1 +| i_2;
            }

            fn add_sat_u(i_1: Signed, i_2: Signed) Signed {
                return @bitCast(@as(Unsigned, @bitCast(i_1)) +| @as(Unsigned, @bitCast(i_2)));
            }

            fn sub(i_1: Signed, i_2: Signed) Signed {
                return i_1 -% i_2;
            }

            fn sub_sat_s(i_1: Signed, i_2: Signed) Signed {
                return i_1 -| i_2;
            }

            fn sub_sat_u(i_1: Signed, i_2: Signed) Signed {
                return @bitCast(@as(Unsigned, @bitCast(i_1)) -| @as(Unsigned, @bitCast(i_2)));
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
        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#saturating-integer-addition
        pub const add_sat_s = defineLaneWiseBinOp(interpretation, operators.add_sat_s);
        pub const add_sat_u = defineLaneWiseBinOp(interpretation, operators.add_sat_u);
        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#integer-subtraction
        pub const sub = defineLaneWiseBinOp(interpretation, operators.sub);
        /// https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md#saturating-integer-subtraction
        pub const sub_sat_s = defineLaneWiseBinOp(interpretation, operators.sub_sat_s);
        pub const sub_sat_u = defineLaneWiseBinOp(interpretation, operators.sub_sat_u);
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
pub const @"i8x16.add_sat_s" = i8x16_int_ops.add_sat_s;
pub const @"i8x16.add_sat_u" = i8x16_int_ops.add_sat_u;
pub const @"i8x16.sub" = i8x16_int_ops.sub;
pub const @"i8x16.sub_sat_s" = i8x16_int_ops.sub_sat_s;
pub const @"i8x16.sub_sat_u" = i8x16_int_ops.sub_sat_u;
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
pub const @"i16x8.q15mulr_sat_s" = defineBinOp(V128.@"i16x8.q15mulr_sat_s");
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
pub const @"i16x8.add_sat_s" = i16x8_int_ops.add_sat_s;
pub const @"i16x8.add_sat_u" = i16x8_int_ops.add_sat_u;
pub const @"i16x8.sub" = i16x8_int_ops.sub;
pub const @"i16x8.sub_sat_s" = i16x8_int_ops.sub_sat_s;
pub const @"i16x8.sub_sat_u" = i16x8_int_ops.sub_sat_u;
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
pub const @"i32x4.dot_i16x8_s" = defineBinOp(V128.@"i32x4.dot_i16x8_s");
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
const FDPrefixOpcode = @import("../../opcodes.zig").FDPrefixOpcode;
const runtime = @import("../../runtime.zig");
