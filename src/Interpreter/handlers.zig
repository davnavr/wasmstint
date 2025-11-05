//! Contains the implementations for the handlers of each WebAssembly opcode.

const Ip = Module.Code.Ip;
const Eip = *const Module.Code.End;
/// The value Stack Pointer.
const Sp = Stack.Top;
const Stp = SideTable.Ptr;

const cconv: std.builtin.CallingConvention = switch (builtin.zig_backend) {
    .stage2_x86_64 => if (false and std.builtin.CallingConvention.C == .x86_64_sysv)
        .{ .x86_64_sysv = .{} }
    else
        @compileError("use LLVM backend instead: https://github.com/ziglang/zig/issues/24044"),
    .other, // assume tail calls are present
    .stage2_llvm,
    => .auto,
    else => |bad| @compileError(@tagName(bad) ++ " backend might not support tail calls"),
};

// TODO(Zig): waiting for a calling convention w/o callee-saved registers
// - (i.e. `preserve_none` or `ghccc` in LLVM)
pub const OpcodeHandler = fn (
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    // `x86_64-windows` passes 4 parameters in registers
    locals: Locals,
    module: runtime.ModuleInst,
    // `x86_64` System V ABI passes 6 parameters in registers
    interp: *Interpreter,
    eip: Eip,
) callconv(cconv) Transition;

// const WrappedOpcodeHandler = fn (
//     i: *Instructions,
//     vals: *ValStack,
//     fuel: *Fuel,
//     stp: Stp,
//     locals: Locals,
//     interp: *Interpreter,
//     state: *State,
//     module: runtime.ModuleInst,
// ) StateTransition; // allow void return if handler doesn't trap

// fn wrappedOpcodeHandler(handler: WrappedOpcodeHandler) OpcodeHandler {
//     return struct {
//         fn wrapped(
//             ip: Ip,
//             sp: Sp,
//             fuel: *Fuel,
//             stp: Stp,
//             locals: Locals,
//             interp: *Interpreter,
//             eip: Eip,
//             state: *State,
//             module: runtime.ModuleInst,
//         ) StateTransition {}
//     }.wrapped;
// }

inline fn transition(
    interp: *Interpreter,
    update_wasm_frame_token: Transition.UpdateWasmFrameToken,
    new_state: @FieldType(Interpreter, "current_state"),
) Transition {
    interp.current_state = new_state;
    interp.version.increment();
    return Transition{
        .version = interp.version,
        .update_wasm_frame_token = update_wasm_frame_token,
    };
}

/// Asserts that `frame` corresponds to a WASM function.
fn updateWasmFrameState(
    frame: *Stack.Frame,
    instr: Instr,
    stp: Stp,
) Transition.UpdateWasmFrameToken {
    const code = frame.function.expanded().wasm.code().inner;
    frame.wasm.ip = instr.next;
    frame.wasm.stp = stp;
    if (builtin.mode == .Debug) {
        std.debug.assert(@intFromPtr(code.instructions_start) <= @intFromPtr(instr.next));
        std.debug.assert(@intFromPtr(code.instructions_end) == @intFromPtr(frame.wasm.eip));
    }
    std.debug.assert(@intFromPtr(instr.next) <= @intFromPtr(instr.end));
    std.debug.assert(@intFromPtr(frame.wasm.eip) == @intFromPtr(instr.end));
    return .wrote_ip_and_stp_to_the_current_stack_frame;
}

/// Is a `packed struct` to work around https://github.com/ziglang/zig/issues/18189
pub const Transition = packed struct(std.meta.Int(.unsigned, @bitSizeOf(Version))) {
    version: Version,
    update_wasm_frame_token: UpdateWasmFrameToken,

    const UpdateWasmFrameToken = enum(u0) { wrote_ip_and_stp_to_the_current_stack_frame };

    fn trap(
        trap_ip: Ip,
        eip: Eip,
        sp: Sp,
        stp: Stp,
        interp: *Interpreter,
        info: Trap,
    ) Transition {
        @branchHint(.unlikely);
        interp.stack_top = sp;
        const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;
        return transition(
            interp,
            // Host might want to observe IP of trapping instruction
            updateWasmFrameState(current_frame, Instr.init(trap_ip, eip), stp),
            .{ .trapped = .{ .source = .function_call, .trap = info } },
        );
    }

    fn interrupted(
        instr: Instr,
        sp: Sp,
        stp: Stp,
        interp: *Interpreter,
        cause: Interpreter.InterruptionCause,
    ) Transition {
        interp.stack_top = sp;
        const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;
        return transition(
            interp,
            updateWasmFrameState(current_frame, instr, stp),
            .{ .interrupted = .{ .cause = cause } },
        );
    }

    const TransitionToHost = enum { returning_to_host, calling_host };

    /// Assumes that all parameters are at the top of the value stack.
    fn awaitingHost(
        sp: Sp,
        interp: *Interpreter,
        callee_signature: *const Module.FuncType,
        status: TransitionToHost,
    ) Transition {
        const result_types = switch (status) {
            .returning_to_host => callee_signature.results(),
            .calling_host => &.{},
        };

        std.debug.assert( // stack underflow
            @intFromPtr(interp.stack.allocated.ptr) <= @intFromPtr(sp.ptr - result_types.len),
        );
        interp.stack_top = sp;
        return transition(
            interp,
            .wrote_ip_and_stp_to_the_current_stack_frame,
            .{ .awaiting_host = .{ .result_types = result_types } },
        );
    }

    fn callStackExhaustion(
        call_ip: Ip,
        eip: Eip,
        saved_sp: Stack.Saved,
        stp: Stp,
        interp: *Interpreter,
        callee: runtime.FuncAddr,
    ) Transition {
        saved_sp.checkIntegrity();
        interp.stack_top = saved_sp.saved_top;
        const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;
        return transition(
            interp,
            updateWasmFrameState(current_frame, Instr.init(call_ip, eip), stp),
            .{ .call_stack_exhaustion = .{ .callee = callee } },
        );
    }
};

pub const Locals = packed struct(usize) {
    ptr: [*]align(@sizeOf(Value)) Value,

    pub fn get(locals: Locals, stack: *Stack, idx: u32) *align(@sizeOf(Value)) Value {
        const locals_slice = if (builtin.mode == .Debug) checked: {
            const current_frame: *Stack.Frame = stack.frameAt(stack.current_frame).?;
            break :checked current_frame.localValues(stack);
        } else locals.ptr[0 .. idx + 1];

        std.debug.assert(@intFromPtr(locals.ptr) == @intFromPtr(locals_slice.ptr));
        return &locals_slice[idx];
    }
};

/// Moves return values to their appropriate place in the value stack.
///
/// Execution of the handlers for the `end` (only when it is last opcode of a function)
/// and `return` instructions ends up here.
///
/// To ensure the interpreter cannot overflow the native stack, opcode handlers must call this
/// function via `@call` with either `.always_tail` or `always_inline`.
fn returnFromWasm(
    ip: Ip,
    old_sp: Sp,
    fuel: *Fuel,
    old_stp: Stp,
    old_locals: Locals,
    old_module: runtime.ModuleInst,
    interp: *Interpreter,
    old_eip: Eip,
) Transition {
    _ = ip;
    _ = old_stp;
    _ = old_locals;

    const popped = interp.stack.popFrame(old_sp, .from_stack_top);
    if (builtin.mode == .Debug) {
        std.debug.assert( // module mismatch
            @intFromPtr(popped.info.callee.expanded().wasm.module.inner) ==
                @intFromPtr(old_module.inner),
        );
        std.debug.assert(@intFromPtr(popped.info.wasm.eip) == @intFromPtr(old_eip));
    }

    return_to_host: {
        if (interp.stack.call_depth == 0) {
            break :return_to_host;
        }

        const frame = interp.stack.frameAt(interp.stack.current_frame).?;
        switch (frame.function.expanded()) {
            .wasm => |wasm| {
                // std.log.debug("returning to WASM {f} with top {*}", .{ frame.function, popped.top.ptr });
                const new_locals = Locals{ .ptr = frame.localValues(&interp.stack).ptr };
                return Instr.init(frame.wasm.ip, frame.wasm.eip).dispatchNextOpcode(
                    popped.top,
                    fuel,
                    frame.wasm.stp,
                    new_locals,
                    wasm.module,
                    interp,
                );
            },
            .host => break :return_to_host,
        }

        comptime unreachable;
    }

    return Transition.awaitingHost(popped.top, interp, popped.signature, .returning_to_host);
}

/// Attempts to allocate a stack frame for the `target_function`, with arguments expected to be on
/// top of the value stack, and then resumes execution.
///
/// To ensure the interpreter cannot overflow the stack, opcode handlers must ensure this function
/// is called inline.
///
/// If enough stack space is not available, then the interpreter is interrupted and the IP is set to
/// `call_ip`, which is a pointer to the call instruction to restart.
inline fn invokeWithinWasm(
    old_instr: Instr,
    /// Pointer to the byte containing the call opcode.
    call_ip: Ip,
    /// Stores the stack before the `call` instruction was executed. Parameters to pass to the
    /// `callee` begin at the bottom at index `0`.
    ///
    /// Restored if a `.call_stack_exhausted` interrupt occurred.
    saved_sp: Stack.Saved,
    fuel: *Fuel,
    old_stp: Stp,
    interp: *Interpreter,
    callee: runtime.FuncAddr,
) Transition {
    var coz_begin = coz.begin("wasmstint.Interpreter.invokeWithinWasm");
    defer coz_begin.end();

    const signature = callee.signature();

    // Overlap trick to avoid copying arguments.
    const args: []align(@sizeOf(Value)) Value = @constCast(
        saved_sp.poppedValues()[0..signature.param_count],
    );
    const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;

    _ = updateWasmFrameState(current_frame, old_instr, old_stp);

    // std.debug.print(
    //     "WASM {f} WANTS TO CALL {f} (current depth = {}, args @ {*})\n",
    //     .{ current_frame.function, callee, interp.call_depth, args },
    // );

    const args_top = Stack.Top{ .ptr = args.ptr + args.len };
    const new_frame = interp.stack.pushFrameWithinCapacity(
        args_top,
        &interp.dummy_instantiate_flag,
        .preallocated,
        callee,
    ) catch |e| switch (e) {
        error.OutOfMemory => {
            // std.debug.print(
            //     "WASM CALL EXHAUSTED STACK (depth = {}, ver = {})\n",
            //     .{ interp.call_depth, interp.version.number },
            // );
            return Transition.callStackExhaustion(
                call_ip,
                old_instr.end,
                saved_sp,
                old_stp,
                interp,
                callee,
            );
        },
        error.ValidationNeeded => @panic("TODO: awaiting_validation"),
    };

    // std.debug.print(
    //     "CALLING {f} @ {*} (was called by {f})\n",
    //     .{ callee, new_frame.frame, current_frame.function },
    // );

    std.debug.assert(@intFromPtr(current_frame) != @intFromPtr(new_frame.frame));
    std.debug.assert(interp.stack.current_frame == new_frame.offset);
    std.debug.assert(@intFromPtr(old_instr.end) == @intFromPtr(current_frame.wasm.eip));

    const new_locals: []align(@sizeOf(Value)) Value = new_frame.frame.localValues(&interp.stack);
    std.debug.assert(@intFromPtr(new_locals.ptr) == @intFromPtr(args.ptr));
    std.debug.assert(args.len <= new_locals.len);

    switch (callee.expanded()) {
        .wasm => |wasm| {
            // std.debug.print(
            //     "AFTER CALL args={*}, sp={*}\n",
            //     .{ args.ptr, new_frame.top().ptr },
            // );
            return Instr.init(new_frame.frame.wasm.ip, new_frame.frame.wasm.eip).dispatchNextOpcode(
                new_frame.top(),
                fuel,
                new_frame.frame.wasm.stp,
                Locals{ .ptr = new_locals.ptr },
                wasm.module,
                interp,
            );
        },
        .host => |host| {
            // std.debug.print("GOING TO AWAIT HOST TRANSITION\n", .{});
            // std.debug.print(
            //     "old_vals = {*}, new_vals = {*}, args = {*}\n",
            //     .{ old_vals.stack.ptr, new_vals.stack.ptr, args.ptr },
            // );
            return Transition.awaitingHost(
                new_frame.top(),
                interp,
                &host.func.signature,
                .calling_host,
            );
        },
    }
}

const MemArg = struct {
    mem: *const runtime.MemInst,
    idx: Module.MemIdx,
    offset: u32,

    fn read(i: *Instr, module: runtime.ModuleInst) MemArg {
        // TODO: Spec probably only allows reading single byte here!
        // align, maximum is 16 bytes (1 << 4)
        _ = @as(u3, @intCast(i.readByte()));
        const mem_idx = Module.MemIdx.default;
        return .{
            .offset = @as(u32, i.readIdxRaw()),
            .mem = module.header().memAddr(mem_idx),
            .idx = mem_idx,
        };
    }

    fn trap(
        mem_arg: MemArg,
        address: usize,
        size: std.mem.Alignment,
    ) Trap {
        return Trap.init(
            .memory_access_out_of_bounds,
            .init(
                mem_arg.idx,
                .access,
                .{
                    .address = address + mem_arg.offset,
                    .size = size,
                    .maximum = mem_arg.mem.size,
                },
            ),
        );
    }
};

fn nopBeforeMemoryAccess(vals: *Stack.Values, interp: *Interpreter) void {
    _ = vals;
    _ = interp;
}

fn linearMemoryAccessor(
    /// How many bytes are read to and written from linear memory.
    ///
    /// Must be a positive power of two.
    comptime access_size: std.mem.Alignment,
    comptime prefix_len: u2,
    comptime kind: enum { load, store },
    comptime BeforeAccessData: type,
    comptime beforeAccess: fn (*Stack.Values, *Interpreter) BeforeAccessData,
    comptime handler: fn (
        *Instr,
        *Stack.Values,
        *Fuel,
        Stp,
        Locals,
        runtime.ModuleInst,
        *Interpreter,
        BeforeAccessData,
        *[access_size.toByteUnits()]u8,
    ) Transition,
) OpcodeHandler {
    return struct {
        comptime {
            std.debug.assert(builtin.cpu.arch.endian() == .little);
        }

        const access_size_bytes: comptime_int = access_size.toByteUnits();

        fn accessLinearMemory(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            var coz_begin = coz.begin("wasmstint.Interpreter.accessLinearMemory");
            defer coz_begin.end();

            const trap_ip: Ip = ip - 1 - prefix_len;
            var i = Instr.init(ip, eip);
            const vals_height = switch (kind) {
                .load => 1,
                .store => 2,
            };
            var vals = Stack.Values.init(sp, &interp.stack, vals_height, vals_height);

            const mem_arg = MemArg.read(&i, module);
            const before_access_data = @call(.always_inline, beforeAccess, .{ &vals, interp });
            const base_addr: u32 = @bitCast(vals.popTyped(&.{.i32}).@"0");

            // std.debug.print(
            //     " > access of size {} @ {}+{} ({X}+{X}) into memory size={}\n",
            //     .{
            //         access_size_bytes,
            //         base_addr,
            //         mem_arg.offset,
            //         base_addr,
            //         mem_arg.offset,
            //         mem_arg.mem.size,
            //     },
            // );

            const effective_addr = std.math.add(u32, base_addr, mem_arg.offset) catch {
                const info = mem_arg.trap(base_addr, access_size);
                return Transition.trap(trap_ip, eip, sp, stp, interp, info);
            };

            const end_addr = std.math.add(u32, effective_addr, access_size_bytes - 1) catch {
                const info = mem_arg.trap(base_addr, access_size);
                return Transition.trap(trap_ip, eip, sp, stp, interp, info);
            };

            return if (mem_arg.mem.size <= end_addr)
                Transition.trap(trap_ip, eip, sp, stp, interp, mem_arg.trap(base_addr, access_size))
            else
                @call(
                    .always_inline,
                    handler,
                    .{
                        &i,
                        &vals,
                        fuel,
                        stp,
                        locals,
                        module,
                        interp,
                        before_access_data,
                        mem_arg.mem.bytes()[effective_addr..][0..access_size_bytes],
                    },
                );
        }
    }.accessLinearMemory;
}

fn linearMemoryHandlers(comptime field: Value.Tag, comptime prefix_len: u2) type {
    return struct {
        comptime {
            std.debug.assert(builtin.cpu.arch.endian() == .little);
        }

        const T = field.Type();

        fn performLoad(
            instr: *Instr,
            vals: *Stack.Values,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            _: void,
            access: *[@sizeOf(T)]u8,
        ) Transition {
            vals.assertRemainingCountIs(0);
            vals.pushTyped(&.{field}, .{@as(T, @bitCast(access.*))});
            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }

        pub const load = linearMemoryAccessor(
            .fromByteUnits(@sizeOf(T)),
            prefix_len,
            .load,
            void,
            nopBeforeMemoryAccess,
            performLoad,
        );

        fn popValueToStore(vals: *Stack.Values, interp: *Interpreter) T {
            _ = interp;
            return vals.popTyped(&.{field}).@"0";
        }

        fn performStore(
            instr: *Instr,
            vals: *Stack.Values,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            value: T,
            access: *[@sizeOf(T)]u8,
        ) Transition {
            vals.assertRemainingCountIs(0);
            access.* = @bitCast(value);
            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }

        pub const store = linearMemoryAccessor(
            .fromByteUnits(@sizeOf(T)),
            prefix_len,
            .store,
            T,
            popValueToStore,
            performStore,
        );
    };
}

fn extendingLinearMemoryLoad(
    comptime field: Value.Tag,
    comptime S: type,
    comptime prefix_len: u2,
) OpcodeHandler {
    return struct {
        const T = field.Type();

        comptime {
            std.debug.assert(std.meta.hasUniqueRepresentation(S));
            std.debug.assert(@sizeOf(S) < @sizeOf(T));
        }

        fn handler(
            instr: *Instr,
            vals: *Stack.Values,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            _: void,
            access: *[@sizeOf(S)]u8,
        ) Transition {
            vals.assertRemainingCountIs(0);
            vals.pushTyped(&.{field}, .{@as(S, @bitCast(access.*))});
            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }

        pub const extendingLoad = linearMemoryAccessor(
            .fromByteUnits(@sizeOf(S)),
            prefix_len,
            .load,
            void,
            nopBeforeMemoryAccess,
            handler,
        );
    }.extendingLoad;
}

fn narrowingLinearMemoryStore(
    comptime field: Value.Tag,
    comptime access_size: std.mem.Alignment,
    comptime prefix_len: u2,
) OpcodeHandler {
    return struct {
        const T = field.Type();
        const S = std.meta.Int(.signed, access_size.toByteUnits() * 8);

        comptime {
            std.debug.assert(std.meta.hasUniqueRepresentation(S));
            std.debug.assert(@sizeOf(S) < @sizeOf(T));
        }

        fn popValueNarrowed(vals: *Stack.Values, interp: *Interpreter) S {
            _ = interp;
            return @truncate(vals.popTyped(&.{field}).@"0");
        }

        fn performNarrowingStore(
            instr: *Instr,
            vals: *Stack.Values,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            narrowed: S,
            access: *[@sizeOf(S)]u8,
        ) Transition {
            vals.assertRemainingCountIs(0);
            access.* = @bitCast(narrowed);
            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }

        pub const narrowingStore = linearMemoryAccessor(
            access_size,
            prefix_len,
            .store,
            S,
            popValueNarrowed,
            performNarrowingStore,
        );
    }.narrowingStore;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-binop
fn defineBinOp(
    comptime value_field: Value.Tag,
    comptime prefix_len: u2,
    /// Function that takes two operands as an input and returns the result of the operation.
    ///
    /// May return an error.
    comptime op: anytype,
    /// Function that takes an error returned by `op` and returns a `Trap`.
    comptime trap: anytype,
) OpcodeHandler {
    return struct {
        fn binOpHandler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            const trap_ip: Ip = ip - (1 - prefix_len);
            var instr = Instr.init(ip, eip);
            var vals = Stack.Values.init(sp, &interp.stack, 2, 2);

            const operands = vals.popTyped(&(.{value_field} ** 2));
            vals.assertRemainingCountIs(0);
            const c_2 = operands[1];
            const c_1 = operands[0];
            const result = @call(.always_inline, op, .{ c_1, c_2 }) catch |e| {
                const trap_info = @call(.auto, trap, .{e});
                return Transition.trap(trap_ip, eip, sp, stp, interp, trap_info);
            };

            vals.pushTyped(&.{value_field}, .{result});

            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }
    }.binOpHandler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-unop
fn defineUnOp(
    comptime value_field: Value.Tag,
    comptime op: fn (c_1: value_field.Type()) value_field.Type(),
) OpcodeHandler {
    return struct {
        fn unOpHandler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            var instr = Instr.init(ip, eip);
            var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

            const c_1 = vals.popTyped(&.{value_field}).@"0";
            vals.assertRemainingCountIs(0);
            const result = @call(.always_inline, op, .{c_1});
            vals.pushTyped(&.{value_field}, .{result});

            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }
    }.unOpHandler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-testop
fn defineTestOp(
    comptime value_field: Value.Tag,
    comptime op: fn (c_1: value_field.Type()) bool,
) OpcodeHandler {
    return struct {
        fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            var instr = Instr.init(ip, eip);
            var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

            const c_1 = vals.popTyped(&.{value_field}).@"0";
            vals.assertRemainingCountIs(0);
            const result = @call(.always_inline, op, .{c_1});
            vals.pushTyped(&.{.i32}, .{@intFromBool(result)});

            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }
    }.handler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-relop
fn defineRelOp(
    comptime value_field: Value.Tag,
    comptime op: fn (c_1: value_field.Type(), c_2: value_field.Type()) bool,
) OpcodeHandler {
    return struct {
        fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            var instr = Instr.init(ip, eip);
            var vals = Stack.Values.init(sp, &interp.stack, 2, 2);

            const operands = vals.popTyped(&(.{value_field} ** 2));
            vals.assertRemainingCountIs(0);
            const c_2 = operands[1];
            const c_1 = operands[0];
            const result = @call(.always_inline, op, .{ c_1, c_2 });
            vals.pushTyped(&.{.i32}, .{@intFromBool(result)});

            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }
    }.handler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-cvtop
fn defineConvOp(
    comptime src_tag: Value.Tag,
    comptime dst_tag: Value.Tag,
    comptime prefix_len: u2,
    /// `fn (t_1: src_tag.Type()) !dst_tag.Type()`
    comptime op: anytype,
    comptime trap: anytype,
) OpcodeHandler {
    return struct {
        fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            const trap_ip: Ip = ip - 1 - prefix_len;
            var instr = Instr.init(ip, eip);
            var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

            const t_1 = vals.popTyped(&.{src_tag}).@"0";
            vals.assertRemainingCountIs(0);
            const result = @call(.always_inline, op, .{t_1}) catch |e| {
                const info = @call(.auto, trap, .{e});
                return Transition.trap(trap_ip, eip, sp, stp, interp, info);
            };

            vals.pushTyped(&.{dst_tag}, .{result});

            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }
    }.handler;
}

pub fn trapIntegerOperation(e: error{ Overflow, DivisionByZero, NotANumber }) Trap {
    return switch (e) {
        error.Overflow => Trap.init(.integer_overflow, {}),
        error.DivisionByZero => Trap.init(.integer_division_by_zero, {}),
        error.NotANumber => Trap.init(.invalid_conversion_to_integer, {}),
    };
}

fn integerOpcodeHandlers(comptime Signed: type) type {
    return struct {
        const Unsigned = std.meta.Int(.unsigned, @typeInfo(Signed).int.bits);
        const value_field = @field(Value.Tag, @typeName(Signed));

        const operators = struct {
            fn eqz(i: Signed) bool {
                return i == 0;
            }

            fn eq(i_1: Signed, i_2: Signed) bool {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".eq) {0} (0x{0X}) == {1} (0x{1X})?\n", .{ i_1, i_2 });
                return i_1 == i_2;
            }

            fn ne(i_1: Signed, i_2: Signed) bool {
                return i_1 != i_2;
            }

            fn lt_s(i_1: Signed, i_2: Signed) bool {
                return i_1 < i_2;
            }

            fn lt_u(i_1: Signed, i_2: Signed) bool {
                return @as(Unsigned, @bitCast(i_1)) < @as(Unsigned, @bitCast(i_2));
            }

            fn gt_s(i_1: Signed, i_2: Signed) bool {
                return i_1 > i_2;
            }

            fn gt_u(i_1: Signed, i_2: Signed) bool {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".gt_u) {[0]X} (0x{[0]X}) > {[1]} ([{1}X])\n", .{ i_1, i_2 });
                return @as(Unsigned, @bitCast(i_1)) > @as(Unsigned, @bitCast(i_2));
            }

            fn le_s(i_1: Signed, i_2: Signed) bool {
                return i_1 <= i_2;
            }

            fn le_u(i_1: Signed, i_2: Signed) bool {
                return @as(Unsigned, @bitCast(i_1)) <= @as(Unsigned, @bitCast(i_2));
            }

            fn ge_s(i_1: Signed, i_2: Signed) bool {
                return i_1 >= i_2;
            }

            fn ge_u(i_1: Signed, i_2: Signed) bool {
                return @as(Unsigned, @bitCast(i_1)) >= @as(Unsigned, @bitCast(i_2));
            }

            fn clz(i: Signed) Signed {
                return @bitCast(@as(Unsigned, @clz(i)));
            }

            fn ctz(i: Signed) Signed {
                return @bitCast(@as(Unsigned, @ctz(i)));
            }

            fn popcnt(i: Signed) Signed {
                return @bitCast(@as(Unsigned, @popCount(i)));
            }

            fn add(i_1: Signed, i_2: Signed) !Signed {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".add) {0} (0x{0X}) + {1} (0x{1X})\n", .{ i_1, i_2 });
                return i_1 +% i_2;
            }

            fn sub(i_1: Signed, i_2: Signed) !Signed {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".sub) {0} (0x{0X}) - {1} (0x{1X})\n", .{ i_1, i_2 });
                return i_1 -% i_2;
            }

            fn mul(i_1: Signed, i_2: Signed) !Signed {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".mul) {0} (0x{0X}) * {1} (0x{1X})\n", .{ i_1, i_2 });
                return i_1 *% i_2;
            }

            fn div_s(j_1: Signed, j_2: Signed) error{ Overflow, DivisionByZero }!Signed {
                return std.math.divTrunc(Signed, j_1, j_2);
            }

            fn div_u(i_1: Signed, i_2: Signed) error{DivisionByZero}!Signed {
                return @bitCast(try std.math.divTrunc(Unsigned, @bitCast(i_1), @bitCast(i_2)));
            }

            fn rem_s(j_1: Signed, j_2: Signed) error{DivisionByZero}!Signed {
                return if (j_2 == 0)
                    error.DivisionByZero
                else if (j_1 == std.math.minInt(Signed) and j_2 == -1)
                    0
                else
                    j_1 - (j_2 * @divTrunc(j_1, j_2));
            }

            fn rem_u(i_1: Signed, i_2: Signed) error{DivisionByZero}!Signed {
                return @bitCast(try std.math.rem(Unsigned, @bitCast(i_1), @bitCast(i_2)));
            }

            fn @"and"(i_1: Signed, i_2: Signed) !Signed {
                return i_1 & i_2;
            }

            fn @"or"(i_1: Signed, i_2: Signed) !Signed {
                return i_1 | i_2;
            }

            fn xor(i_1: Signed, i_2: Signed) !Signed {
                return i_1 ^ i_2;
            }

            /// *k*
            inline fn bitShiftAmt(i_2: Signed) std.math.Log2Int(Signed) {
                return @intCast(@mod(i_2, @bitSizeOf(Signed)));
            }

            fn shl(i_1: Signed, i_2: Signed) !Signed {
                return i_1 << bitShiftAmt(i_2);
            }

            fn shr_s(i_1: Signed, i_2: Signed) !Signed {
                // Currently assumes Zig sign-extends when shifting right.
                return i_1 >> bitShiftAmt(i_2);
            }

            fn shr_u(i_1: Signed, i_2: Signed) !Signed {
                return @bitCast(@as(Unsigned, @bitCast(i_1)) >> bitShiftAmt(i_2));
            }

            fn rotl(i_1: Signed, i_2: Signed) !Signed {
                // Zig's function here handles the `bitShiftAmt()`/`@mod()`
                return @bitCast(std.math.rotl(Unsigned, @bitCast(i_1), i_2));
            }

            fn rotr(i_1: Signed, i_2: Signed) !Signed {
                // Zig's function here handles the `bitShiftAmt()`/`@mod()`
                return @bitCast(std.math.rotr(Unsigned, @bitCast(i_1), i_2));
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-trunc-s
            fn trunc_s(z: anytype) !Signed {
                if (std.math.isNan(z)) return error.NotANumber;

                // std.debug.print(
                //     "> ({[i]s}.trunc_{[f]s}_s) ({[f]s}.const {[z]d})\n",
                //     .{ .i = @typeName(Signed), .f = @typeName(@TypeOf(z)), .z = z },
                // );

                const tr = @trunc(z);
                return if (tr < @as(comptime_float, std.math.minInt(Signed)) or
                    @as(comptime_float, std.math.maxInt(Signed)) < tr)
                    error.Overflow
                else
                    std.math.cast(
                        Signed,
                        @as(
                            std.meta.Int(.signed, @typeInfo(Signed).int.bits + 1),
                            @intFromFloat(tr),
                        ),
                    ) orelse error.Overflow;
            }

            fn trunc_u(z: anytype) !Signed {
                if (std.math.isNan(z)) return error.NotANumber;

                const tr = @trunc(z);
                return if (tr < -0.0 or @as(comptime_float, std.math.maxInt(Unsigned)) < tr)
                    error.Overflow
                else
                    @bitCast(
                        std.math.cast(
                            Unsigned,
                            @as(
                                std.meta.Int(
                                    .unsigned,
                                    @typeInfo(Signed).int.bits + 1,
                                ),
                                @intFromFloat(tr),
                            ),
                        ) orelse return error.Overflow,
                    );
            }

            fn trunc_sat_s(z: anytype) !Signed {
                return std.math.lossyCast(Signed, z);
            }

            fn trunc_sat_u(z: anytype) !Signed {
                return @bitCast(std.math.lossyCast(Unsigned, z));
            }
        };

        fn @"const"(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            var instr = Instr.init(ip, eip);
            var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

            const n = instr.readIleb128(Signed);
            vals.pushTyped(&.{value_field}, .{n});

            // std.debug.print(
            //     " > (" ++ @typeName(Signed) ++ ".const (;{[0]};) 0x{[0]X}) ;; @ {[1]X} ; stp = {[2]*}\n",
            //     .{ n, @intFromPtr(ip - 1), sp.ptr },
            // );

            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }

        const eqz = defineTestOp(value_field, operators.eqz);
        const eq = defineRelOp(value_field, operators.eq);
        const ne = defineRelOp(value_field, operators.ne);
        const lt_s = defineRelOp(value_field, operators.lt_s);
        const lt_u = defineRelOp(value_field, operators.lt_u);
        const gt_s = defineRelOp(value_field, operators.gt_s);
        const gt_u = defineRelOp(value_field, operators.gt_u);
        const le_s = defineRelOp(value_field, operators.le_s);
        const le_u = defineRelOp(value_field, operators.le_u);
        const ge_s = defineRelOp(value_field, operators.ge_s);
        const ge_u = defineRelOp(value_field, operators.ge_u);

        const clz = defineUnOp(value_field, operators.clz);
        const ctz = defineUnOp(value_field, operators.ctz);
        const popcnt = defineUnOp(value_field, operators.popcnt);
        const add = defineBinOp(value_field, 0, operators.add, undefined);
        const sub = defineBinOp(value_field, 0, operators.sub, undefined);
        const mul = defineBinOp(value_field, 0, operators.mul, undefined);
        const div_s = defineBinOp(value_field, 0, operators.div_s, trapIntegerOperation);
        const div_u = defineBinOp(value_field, 0, operators.div_u, trapIntegerOperation);
        const rem_s = defineBinOp(value_field, 0, operators.rem_s, trapIntegerOperation);
        const rem_u = defineBinOp(value_field, 0, operators.rem_u, trapIntegerOperation);
        const @"and" = defineBinOp(value_field, 0, operators.@"and", undefined);
        const @"or" = defineBinOp(value_field, 0, operators.@"or", undefined);
        const xor = defineBinOp(value_field, 0, operators.xor, undefined);
        const shl = defineBinOp(value_field, 0, operators.shl, undefined);
        const shr_s = defineBinOp(value_field, 0, operators.shr_s, undefined);
        const shr_u = defineBinOp(value_field, 0, operators.shr_u, undefined);
        const rotl = defineBinOp(value_field, 0, operators.rotl, undefined);
        const rotr = defineBinOp(value_field, 0, operators.rotr, undefined);

        const trunc_f32_s = defineConvOp(.f32, value_field, 0, operators.trunc_s, trapIntegerOperation);
        const trunc_f32_u = defineConvOp(.f32, value_field, 0, operators.trunc_u, trapIntegerOperation);
        const trunc_f64_s = defineConvOp(.f64, value_field, 0, operators.trunc_s, trapIntegerOperation);
        const trunc_f64_u = defineConvOp(.f64, value_field, 0, operators.trunc_u, trapIntegerOperation);

        const trunc_sat_f32_s = defineConvOp(.f32, value_field, 0, operators.trunc_sat_s, trapIntegerOperation);
        const trunc_sat_f32_u = defineConvOp(.f32, value_field, 0, operators.trunc_sat_u, trapIntegerOperation);
        const trunc_sat_f64_s = defineConvOp(.f64, value_field, 0, operators.trunc_sat_s, trapIntegerOperation);
        const trunc_sat_f64_u = defineConvOp(.f64, value_field, 0, operators.trunc_sat_u, trapIntegerOperation);
    };
}

const i32_opcode_handlers = integerOpcodeHandlers(i32);
const i64_opcode_handlers = integerOpcodeHandlers(i64);

fn floatOpcodeHandlers(comptime F: type) type {
    return struct {
        const value_field = @field(Value.Tag, @typeName(F));
        const Bits = std.meta.Int(.unsigned, @typeInfo(F).float.bits);

        const canonical_nan_bit: Bits = 1 << (std.math.floatMantissaBits(F) - 1);

        const precise_int_limit = 1 << (std.math.floatMantissaBits(F) + 1);

        const operators = struct {
            fn convert_s(i: anytype) !F {
                comptime std.debug.assert(@typeInfo(@TypeOf(i)).int.signedness == .signed);
                return @floatFromInt(i);
            }

            fn convert_u(i: anytype) !F {
                comptime std.debug.assert(@typeInfo(@TypeOf(i)).int.signedness == .signed);
                const Unsigned = std.meta.Int(.unsigned, @typeInfo(@TypeOf(i)).int.bits);
                return @floatFromInt(@as(Unsigned, @bitCast(i)));
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-feq
            fn eq(z_1: F, z_2: F) bool {
                return z_1 == z_2;
            }

            fn ne(z_1: F, z_2: F) bool {
                return z_1 != z_2;
            }

            fn lt(z_1: F, z_2: F) bool {
                return z_1 < z_2;
            }

            fn gt(z_1: F, z_2: F) bool {
                return z_1 > z_2;
            }

            fn le(z_1: F, z_2: F) bool {
                return z_1 <= z_2;
            }

            fn ge(z_1: F, z_2: F) bool {
                return z_1 >= z_2;
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fabs
            fn abs(z: F) F {
                return @abs(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fneg
            fn neg(z: F) F {
                // const Int = std.meta.Int(.unsigned, @bitSizeOf(F));
                // return @bitCast(@as(Int, @bitCast(z)) ^ std.math.minInt(Int));
                return -z;
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fceil
            fn ceil(z: F) F {
                return @ceil(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-ffloor
            fn floor(z: F) F {
                // TODO: Consistent rounding behavior for `floor`
                // On `x86_64-linux`, uses `vroundss $0x11`
                // On `x86_64-windows`, uses `vroundss $0x9`
                // Correct rounding on windows on higher versions (e.g. x86-64-v2)
                return @floor(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-ftrunc
            fn trunc(z: F) F {
                return if (z <= -0.0) @ceil(z) else @floor(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fnearest
            fn nearest(z: F) F {
                // WASM requires rounds-to-nearest-ties-even

                // '@round' compiles to 'llvm.round.*', but what is needed is 'llvm.roundeven.*'
                // See also:
                // - https://github.com/ziglang/zig/issues/767
                // - https://github.com/ziglang/zig/issues/2535

                // Caution, might get error: "Invalid user of intrinsic instruction!"
                // extern fn @"llvm.roundeven.f32"(z: f32) callconv(.c) f32;
                // extern fn @"llvm.roundeven.f64"(z: f64) callconv(.c) f64;

                // Also seems to be available in C23, but that's too new:
                // extern "c" fn roundevenf(arg: f32);
                // extern "c" fn roundevenf(arg: f32);

                if (std.math.isNan(z)) {
                    return @bitCast(@as(Bits, @bitCast(z)) | canonical_nan_bit);
                } else if (std.math.isInf(z) or
                    std.math.isPositiveZero(z) or
                    std.math.isNegativeZero(z))
                {
                    return z;
                } else if (0 < z and z <= 0.5) {
                    return 0.0;
                } else if (-0.5 <= z and z < 0) {
                    return -0.0;
                }

                const left_int = @round(z);
                const right_int = @round(if (std.math.signbit(z)) z + 1.0 else z - 1.0);

                const left_dist = @abs(left_int - z);
                const right_dist = @abs(right_int - z);

                if (left_dist < right_dist) {
                    return left_int;
                } else if (right_dist < left_dist) {
                    return right_dist;
                } else if (-@as(F, precise_int_limit) < z and z < @as(F, precise_int_limit)) {
                    const RoundedInt = std.math.IntFittingRange(-precise_int_limit, precise_int_limit);

                    // Both candidates are the same distance from `z`, so pick the even one
                    const left_i: RoundedInt = @intFromFloat(left_int);
                    const right_i: RoundedInt = @intFromFloat(right_int);
                    std.debug.assert(left_i != right_i);

                    if (@rem(left_i, 2) == 0) {
                        std.debug.assert(@rem(right_i, 2) != 0);
                        return left_int;
                    } else {
                        return right_int;
                    }
                } else {
                    std.debug.assert(left_int == right_int);
                    return left_int;
                }
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fsqrt
            fn sqrt(z: F) F {
                return std.math.sqrt(z);
            }

            fn add(z_1: F, z_2: F) !F {
                return z_1 + z_2;
            }

            fn sub(z_1: F, z_2: F) !F {
                return z_1 - z_2;
            }

            fn mul(z_1: F, z_2: F) !F {
                return z_1 * z_2;
            }

            fn div(z_1: F, z_2: F) !F {
                return z_1 / z_2;
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fmin
            fn min(z_1: F, z_2: F) !F {
                return if (std.math.isNan(z_1) or std.math.isNan(z_2))
                    z_1 + z_2 // Pick a NaN
                else if ((std.math.isNegativeZero(z_1) and std.math.isPositiveZero(z_2)) or
                    (std.math.isPositiveZero(z_1) and std.math.isNegativeZero(z_2)))
                    -0.0
                else
                    // Zig currently maps `@min` to a call to `llvm.minnum`
                    @min(z_1, z_2);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fmax
            fn max(z_1: F, z_2: F) !F {
                return if (std.math.isNan(z_1) or std.math.isNan(z_2))
                    z_1 + z_2 // Pick a NaN
                else if ((std.math.isNegativeZero(z_1) and std.math.isPositiveZero(z_2)) or
                    (std.math.isPositiveZero(z_1) and std.math.isNegativeZero(z_2)))
                    0.0 // positive zero
                else
                    // Zig currently maps `@max` to a call to `llvm.maxnum`
                    @max(z_1, z_2);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fcopysign
            fn copysign(z_1: F, z_2: F) !F {
                return std.math.copysign(z_1, z_2);
            }
        };

        fn @"const"(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            var instr = Instr.init(ip, eip);
            var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

            const z = std.mem.readInt(
                std.meta.Int(.unsigned, @bitSizeOf(F)),
                instr.readByteArray(@sizeOf(F)),
                .little,
            );

            vals.pushTyped(&.{value_field}, .{@bitCast(z)});

            return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
        }

        const eq = defineRelOp(value_field, operators.eq);
        const ne = defineRelOp(value_field, operators.ne);
        const lt = defineRelOp(value_field, operators.lt);
        const gt = defineRelOp(value_field, operators.gt);
        const le = defineRelOp(value_field, operators.le);
        const ge = defineRelOp(value_field, operators.ge);

        const abs = defineUnOp(value_field, operators.abs);
        const neg = defineUnOp(value_field, operators.neg);
        const ceil = defineUnOp(value_field, operators.ceil);
        const floor = defineUnOp(value_field, operators.floor);
        const trunc = defineUnOp(value_field, operators.trunc);
        const nearest = defineUnOp(value_field, operators.nearest);
        const sqrt = defineUnOp(value_field, operators.sqrt);
        const add = defineBinOp(value_field, 0, operators.add, undefined);
        const sub = defineBinOp(value_field, 0, operators.sub, undefined);
        const mul = defineBinOp(value_field, 0, operators.mul, undefined);
        const div = defineBinOp(value_field, 0, operators.div, undefined);
        const min = defineBinOp(value_field, 0, operators.min, undefined);
        const max = defineBinOp(value_field, 0, operators.max, undefined);
        const copysign = defineBinOp(value_field, 0, operators.copysign, undefined);

        const convert_i32_s = defineConvOp(.i32, value_field, 0, operators.convert_s, undefined);
        const convert_i32_u = defineConvOp(.i32, value_field, 0, operators.convert_u, undefined);
        const convert_i64_s = defineConvOp(.i64, value_field, 0, operators.convert_s, undefined);
        const convert_i64_u = defineConvOp(.i64, value_field, 0, operators.convert_u, undefined);
    };
}

const f32_opcode_handlers = floatOpcodeHandlers(f32);
const f64_opcode_handlers = floatOpcodeHandlers(f64);

fn dispatchTableLength(comptime Opcode: type, comptime length_override: ?usize) comptime_int {
    var maximum = 0;
    for (@typeInfo(Opcode).@"enum".fields) |op| {
        maximum = @max(maximum, op.value);
    }

    const actual_len = maximum + 1;

    if (length_override) |manual_len| {
        std.debug.assert(actual_len <= manual_len);
        return manual_len;
    } else {
        return actual_len;
    }
}

fn dispatchTable(
    comptime Opcode: type,
    comptime invalid: OpcodeHandler,
    comptime length_override: ?usize,
) [dispatchTableLength(Opcode, length_override)]*const OpcodeHandler {
    var table = [_]*const OpcodeHandler{invalid} **
        dispatchTableLength(Opcode, length_override);

    for (@typeInfo(Opcode).@"enum".fields) |op| {
        if (@hasDecl(opcode_handlers, op.name)) {
            table[op.value] = @as(
                *const OpcodeHandler,
                @field(opcode_handlers, op.name),
            );
        }
    }

    return table;
}

fn prefixDispatchTable(comptime prefix: opcodes.ByteOpcode, comptime Opcode: type) type {
    return struct {
        fn panicInvalidInstruction(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            _ = sp;
            _ = fuel;
            _ = stp;
            _ = locals;
            _ = module;
            _ = interp;
            _ = eip;
            std.debug.panic(
                "invalid instruction 0x{X:0>2} ... 0x{X:0>2}",
                .{ @intFromEnum(prefix), (ip - 1)[0] },
            );
        }

        const invalid: OpcodeHandler = switch (builtin.mode) {
            .Debug, .ReleaseSafe => panicInvalidInstruction,
            .ReleaseFast, .ReleaseSmall => undefined,
        };

        const entries = dispatchTable(Opcode, invalid, null);

        pub fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            module: runtime.ModuleInst,
            interp: *Interpreter,
            eip: Eip,
        ) Transition {
            var instr = Instr.init(ip, eip);
            const next = entries[@intFromEnum(instr.readIdx(Opcode))];
            return @call(
                .always_tail,
                next,
                .{ instr.next, sp, fuel, stp, locals, module, interp, eip },
            );
        }
    };
}

const fc_prefixed_dispatch = prefixDispatchTable(.@"0xFC", opcodes.FCPrefixOpcode);

pub fn outOfFuelHandler(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
    eip: Eip,
) Transition {
    std.debug.assert(fuel.remaining == 0);
    _ = locals;
    _ = module;
    return Transition.interrupted(Instr.init(ip, eip), sp, stp, interp, .out_of_fuel);
}

const opcode_handlers = struct {
    fn panicInvalidInstruction(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        _ = sp;
        _ = fuel;
        _ = stp;
        _ = locals;
        _ = module;
        _ = interp;
        _ = eip;
        const bad_opcode: u8 = (ip - 1)[0];
        const opcode_name = name: {
            const tag = std.meta.intToEnum(opcodes.ByteOpcode, bad_opcode) catch
                break :name "unknown";

            break :name @tagName(tag);
        };

        std.debug.panic("invalid instruction 0x{X:0>2} ({s})", .{ bad_opcode, opcode_name });
    }

    const invalid: OpcodeHandler = switch (builtin.mode) {
        .Debug, .ReleaseSafe => panicInvalidInstruction,
        .ReleaseFast, .ReleaseSmall => undefined,
    };

    pub fn @"unreachable"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        _ = fuel;
        _ = locals;
        _ = module;

        const unreachable_ip: Ip = ip - 1;
        const is_validation_failure = @intFromPtr(unreachable_ip) ==
            @intFromPtr(Module.Code.validation_failed.instructions_start);
        const info = if (is_validation_failure) invalid: {
            @branchHint(.cold);

            const current_frame: *const Stack.Frame = interp.stack.currentFrame().?;
            const wasm_callee = current_frame.function.expanded().wasm;
            std.debug.assert(wasm_callee.code().isValidationFinished());

            break :invalid Trap.init(.lazy_validation_failure, .{ .function = wasm_callee.idx });
        } else Trap.init(.unreachable_code_reached, {});

        return Transition.trap(unreachable_ip, eip, sp, stp, interp, info);
    }

    pub fn nop(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        return Instr.init(ip, eip).dispatchNextOpcode(
            sp,
            fuel,
            stp,
            locals,
            module,
            interp,
        );
    }

    pub fn block(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        instr.skipBlockType();
        return instr.dispatchNextOpcode(
            sp,
            fuel,
            stp,
            locals,
            module,
            interp,
        );
    }

    pub const loop = block;

    pub fn @"if"(
        ip: Ip,
        old_sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(old_sp, &interp.stack, 1, 1);
        var side_table = SideTable.init(stp, &interp.stack);

        const c = vals.popTyped(&.{.i32}).@"0";

        // std.debug.print(" > (if) {}?\n", .{c != 0});

        const new_sp = if (c == 0) taken: {
            // No need to read LEB128 block type.
            break :taken side_table.takeBranch(&interp.stack, vals.top, ip - 1, &instr, 0);
        } else nope: {
            instr.skipBlockType();
            side_table.increment(&interp.stack);
            break :nope vals.top;
        };

        return instr.dispatchNextOpcode(new_sp, fuel, side_table.next, locals, module, interp);
    }

    pub fn @"else"(
        ip: Ip,
        old_sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var side_table = SideTable.init(stp, &interp.stack);
        const new_sp = side_table.takeBranch(&interp.stack, old_sp, ip - 1, &instr, 0);
        return instr.dispatchNextOpcode(new_sp, fuel, side_table.next, locals, module, interp);
    }

    pub fn end(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        defer coz.progessNamed("wasmstint.Interpreter.end");
        const end_ptr: Eip = @ptrCast(ip - 1);
        _ = end_ptr.*;
        return if (@intFromPtr(end_ptr) == @intFromPtr(eip))
            @call(
                .always_tail,
                returnFromWasm,
                .{ ip, sp, fuel, stp, locals, module, interp, eip },
            )
        else
            Instr.init(ip, eip).dispatchNextOpcode(sp, fuel, stp, locals, module, interp);
    }

    pub fn br(
        ip: Ip,
        old_sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var side_table = SideTable.init(stp, &interp.stack);

        // No need to read LEB128 branch target
        const br_ptr: Ip = ip - 1;
        std.debug.assert(br_ptr[0] == @intFromEnum(opcodes.ByteOpcode.br));
        const new_sp = side_table.takeBranch(&interp.stack, old_sp, br_ptr, &instr, 0);
        return instr.dispatchNextOpcode(new_sp, fuel, side_table.next, locals, module, interp);
    }

    pub fn br_if(
        ip: Ip,
        old_sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(old_sp, &interp.stack, 1, 1);
        var side_table = SideTable.init(stp, &interp.stack);

        const br_if_ip: Ip = ip - 1;
        std.debug.assert(br_if_ip[0] == @intFromEnum(opcodes.ByteOpcode.br_if));

        const c = vals.popTyped(&.{.i32}).@"0";
        // std.debug.print(" > (br_if) {}?\n", .{c != 0});
        const new_sp = if (c != 0) taken: {
            // No need to read LEB128 branch target
            break :taken side_table.takeBranch(&interp.stack, vals.top, br_if_ip, &instr, 0);
        } else fallthrough: {
            // branch target
            _ = instr.readIdxRaw();
            side_table.increment(&interp.stack);
            break :fallthrough vals.top;
        };

        return instr.dispatchNextOpcode(new_sp, fuel, side_table.next, locals, module, interp);
    }

    pub fn br_table(
        ip: Ip,
        old_sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const br_table_ip: Ip = ip - 1;
        std.debug.assert(br_table_ip[0] == @intFromEnum(opcodes.ByteOpcode.br_table));

        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(old_sp, &interp.stack, 1, 1);
        var side_table = SideTable.init(stp, &interp.stack);

        const label_count: u32 = instr.readIdxRaw();

        // No need to read LEB128 labels

        const n: u32 = @bitCast(vals.popTyped(&.{.i32}).@"0");
        const actual_target: u32 = @min(n, label_count);

        // std.debug.print(
        //     " > br_table (i32.const {}) ; {} labels ; goto {}\n",
        //     .{ n, label_count, actual_target },
        // );

        const new_sp = side_table.takeBranch(
            &interp.stack,
            vals.top,
            br_table_ip,
            &instr,
            actual_target,
        );

        return instr.dispatchNextOpcode(new_sp, fuel, stp, locals, module, interp);
    }

    pub const @"return" = returnFromWasm;

    pub fn call(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        _ = locals;
        const call_ip = ip - 1;
        std.debug.assert(call_ip[0] == @intFromEnum(opcodes.ByteOpcode.call));

        var instr = Instr.init(ip, eip);

        const func_idx = instr.readIdx(Module.FuncIdx);
        const callee = module.header().funcAddr(func_idx);
        const arg_count = callee.signature().param_count;
        const saved_sp = Stack.Saved.pop(
            Stack.Values.init(sp, &interp.stack, arg_count, arg_count),
            arg_count,
        );

        return invokeWithinWasm(instr, call_ip, saved_sp, fuel, stp, interp, callee);
    }

    pub fn call_indirect(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        _ = locals;
        const call_ip = ip - 1;
        std.debug.assert(call_ip[0] == @intFromEnum(opcodes.ByteOpcode.call_indirect));

        var instr = Instr.init(ip, eip);

        const current_module = module.header();
        const expected_signature = instr.readIdx(Module.TypeIdx).funcType(current_module.module);
        const table_idx = instr.readIdx(Module.TableIdx);

        const pop_count = 1 + expected_signature.param_count;
        const saved_sp = Stack.Saved.pop(
            Stack.Values.init(sp, &interp.stack, pop_count, pop_count),
            pop_count,
        );

        const elem_index_val: *align(@sizeOf(Value)) const Value =
            &saved_sp.poppedValues()[expected_signature.param_count];
        const elem_index: u32 = @bitCast(elem_index_val.i32);

        const table_addr = current_module.tableAddr(table_idx);
        std.debug.assert(table_addr.elem_type == .funcref);
        const table = table_addr.table;

        // std.debug.print(
        //     " > call_indirect (i32.const {} (; @ {X} ;)) ;; table.size = {}, call depth = {}\n",
        //     .{ elem_index, @intFromPtr(elem_index_val), table.len, interp.stack.call_depth },
        // );

        if (table.len <= elem_index) {
            const info = Trap.init(.table_access_out_of_bounds, .init(table_idx, .call_indirect));
            return Transition.trap(call_ip, eip, sp, stp, interp, info);
        }

        const callee = table.base.func_ref[0..table.len][elem_index].funcInst() orelse {
            const info = Trap.init(.indirect_call_to_null, .{ .index = elem_index });
            return Transition.trap(call_ip, eip, sp, stp, interp, info);
        };

        const actual_signature = callee.signature();
        if (!expected_signature.matches(actual_signature)) {
            const info = Trap.init(
                .indirect_call_signature_mismatch,
                .{ .expected = expected_signature, .actual = actual_signature },
            );

            return Transition.trap(call_ip, eip, sp, stp, interp, info);
        }

        // std.debug.print(" - calling {f}\n - sp = {*}\n", .{ callee, vals.stack.ptr });

        return invokeWithinWasm(instr, call_ip, saved_sp, fuel, stp, interp, callee);
    }

    pub fn drop(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

        const to_drop = &vals.popArray(1)[0];
        vals.assertRemainingCountIs(0);
        to_drop.* = undefined;

        // std.debug.print(" height after drop: {}\n", .{vals.items.len});

        return Instr.init(ip, eip).dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn select(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

        const popped = vals.popArray(2);
        vals.assertRemainingCountIs(1);
        const c = popped[1].i32;
        if (c == 0) {
            vals.topArray(1)[0] = popped[0];
        }

        @memset(popped, undefined);
        return Instr.init(ip, eip).dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"select t"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);

        const type_count: u32 = instr.readIdxRaw();
        std.debug.assert(type_count == 1); // as per implemented version of WASM standard

        for (0..type_count) |_| {
            instr.skipValType();
        }

        if (type_count == 1)
            return @call(
                switch (builtin.mode) {
                    .Debug, .ReleaseSmall => .always_tail,
                    .ReleaseSafe, .ReleaseFast => .always_inline,
                },
                select,
                .{ instr.next, sp, fuel, stp, locals, module, interp, eip },
            )
        else
            unreachable;
    }

    pub fn @"local.get"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

        const n: u16 = @intCast(instr.readIdxRaw());
        const src: *align(@sizeOf(Value)) const Value = locals.get(&interp.stack, n);

        // std.debug.print(" > before local.get {}, sp = {*}\n", .{ n, sp.ptr });
        vals.pushArray(1)[0] = src.*;

        // std.debug.print(" > (local.get {}) (i32.const {})\n", .{ n, value.i32 });

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"local.set"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

        const n: u16 = @intCast(instr.readIdxRaw());
        const dst: *align(@sizeOf(Value)) Value = locals.get(&interp.stack, n);
        const src: *align(@sizeOf(Value)) Value = &vals.popArray(1)[0];
        dst.* = src.*;
        src.* = undefined;
        vals.assertRemainingCountIs(0);

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"local.tee"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

        const n: u16 = @intCast(instr.readIdxRaw());
        locals.get(&interp.stack, n).* = vals.topArray(1)[0];
        vals.assertRemainingCountIs(1);

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"global.get"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        std.debug.assert((ip - 1)[0] == @intFromEnum(opcodes.ByteOpcode.@"global.get"));

        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

        const global_idx = instr.readIdx(Module.GlobalIdx);
        const global_addr = module.header().globalAddr(global_idx);

        vals.pushArray(1).* = .{switch (global_addr.global_type.val_type) {
            .v128 => unreachable, // TODO
            .externref => .{
                .externref = Value.ExternRef{
                    .addr = @as(
                        *const runtime.ExternAddr,
                        @ptrCast(@alignCast(@constCast(global_addr.value))),
                    ).*,
                },
            },
            inline else => |val_type| @unionInit(
                Value,
                @tagName(val_type),
                @as(
                    *const runtime.GlobalAddr.Pointee(val_type),
                    @ptrCast(@alignCast(@constCast(global_addr.value))),
                ).*,
            ),
        }};

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"global.set"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

        const global_idx = instr.readIdx(Module.GlobalIdx);
        const global_addr = module.header().globalAddr(global_idx);

        const popped: *align(@sizeOf(Value)) Value = &vals.popArray(1)[0];
        vals.assertRemainingCountIs(0);
        switch (global_addr.global_type.val_type) {
            .v128 => unreachable, // TODO
            .externref => {
                @as(
                    *runtime.ExternAddr,
                    @ptrCast(@alignCast(global_addr.value)),
                ).* = popped.externref.addr;
            },
            inline else => |val_type| {
                @as(
                    *runtime.GlobalAddr.Pointee(val_type),
                    @ptrCast(@alignCast(global_addr.value)),
                ).* = @field(popped, @tagName(val_type));
            },
        }

        popped.* = undefined;
        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-get
    pub fn @"table.get"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const table_get_ip: Ip = ip - 1;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

        const table_idx = instr.readIdx(Module.TableIdx);
        const table = module.header().tableAddr(table_idx).table;
        const stride = table.stride.toBytes();

        const operand: *align(@sizeOf(Value)) Value = &vals.topArray(1)[0];
        const idx: u32 = @bitCast(operand.i32);

        operand.* = undefined;
        const dst: []align(@sizeOf(Value)) u8 = std.mem.asBytes(operand);
        const src: []align(@sizeOf(*anyopaque)) u8 = table.elementSlice(idx) catch {
            const info = Trap.init(
                .table_access_out_of_bounds,
                .init(table_idx, .{ .@"table.get" = .{ .index = idx, .maximum = table.len } }),
            );

            return Transition.trap(table_get_ip, eip, vals.top, stp, interp, info);
        };

        @memcpy(dst[0..stride], src);
        @memset(dst[stride..], 0); // fill `ExternRef` padding

        std.debug.assert(vals.remaining == 1);
        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-set
    pub fn @"table.set"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const table_set_ip: Ip = ip - 1;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 2, 2);

        const table_idx = instr.readIdx(Module.TableIdx);
        const table = module.header().tableAddr(table_idx).table;

        const operands = vals.popArray(2);
        vals.assertRemainingCountIs(0);
        const ref: *align(@sizeOf(Value)) const Value = &operands[1];
        const idx: u32 = @bitCast(operands[0].i32);
        const dst: []align(@sizeOf(*anyopaque)) u8 = table.elementSlice(idx) catch {
            const info = Trap.init(
                .table_access_out_of_bounds,
                .init(table_idx, .{ .@"table.set" = .{ .index = idx, .maximum = table.len } }),
            );
            return Transition.trap(table_set_ip, eip, vals.top, stp, interp, info);
        };

        @memcpy(dst, std.mem.asBytes(ref)[0..table.stride.toBytes()]);

        operands.* = undefined;
        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub const @"i32.load" = linearMemoryHandlers(.i32, 0).load;
    pub const @"i64.load" = linearMemoryHandlers(.i64, 0).load;
    pub const @"f32.load" = linearMemoryHandlers(.f32, 0).load;
    pub const @"f64.load" = linearMemoryHandlers(.f64, 0).load;
    pub const @"i32.load8_s" = extendingLinearMemoryLoad(.i32, i8, 0);
    pub const @"i32.load8_u" = extendingLinearMemoryLoad(.i32, u8, 0);
    pub const @"i32.load16_s" = extendingLinearMemoryLoad(.i32, i16, 0);
    pub const @"i32.load16_u" = extendingLinearMemoryLoad(.i32, u16, 0);
    pub const @"i64.load8_s" = extendingLinearMemoryLoad(.i64, i8, 0);
    pub const @"i64.load8_u" = extendingLinearMemoryLoad(.i64, u8, 0);
    pub const @"i64.load16_s" = extendingLinearMemoryLoad(.i64, i16, 0);
    pub const @"i64.load16_u" = extendingLinearMemoryLoad(.i64, u16, 0);
    pub const @"i64.load32_s" = extendingLinearMemoryLoad(.i64, i32, 0);
    pub const @"i64.load32_u" = extendingLinearMemoryLoad(.i64, u32, 0);
    pub const @"i32.store" = linearMemoryHandlers(.i32, 0).store;
    pub const @"i64.store" = linearMemoryHandlers(.i64, 0).store;
    pub const @"f32.store" = linearMemoryHandlers(.f32, 0).store;
    pub const @"f64.store" = linearMemoryHandlers(.f64, 0).store;
    pub const @"i32.store8" = narrowingLinearMemoryStore(.i32, .@"1", 0);
    pub const @"i32.store16" = narrowingLinearMemoryStore(.i32, .@"2", 0);
    pub const @"i64.store8" = narrowingLinearMemoryStore(.i64, .@"1", 0);
    pub const @"i64.store16" = narrowingLinearMemoryStore(.i64, .@"2", 0);
    pub const @"i64.store32" = narrowingLinearMemoryStore(.i64, .@"4", 0);

    pub fn @"memory.size"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

        const mem_idx = instr.readIdx(Module.MemIdx);

        const size = module.header().memAddr(mem_idx).size / runtime.MemInst.page_size;
        vals.pushTyped(&.{.i32}, .{@bitCast(@as(u32, @intCast(size)))});

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"memory.grow"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

        const mem_idx = instr.readIdx(Module.MemIdx);
        const mem = module.header().memAddr(mem_idx);

        const operand: *align(@sizeOf(Value)) Value = &vals.topArray(1)[0];
        const delta: u32 = @bitCast(operand.i32);
        const grow_failed: i32 = -1;
        operand.* = .{ .i32 = grow_failed };

        done: {
            const delta_bytes = std.math.mul(u32, runtime.MemInst.page_size, delta) catch
                break :done;

            if (mem.limit - mem.size < delta_bytes) {
                break :done;
            } else if (mem.capacity - mem.size >= delta_bytes) {
                const new_size: u32 = @as(u32, @intCast(mem.size)) + delta_bytes;
                const old_size: u32 = @intCast(mem.size);
                mem.size = new_size;
                // TODO: Don't set to zero if `MemInst` implementation already knows its zero (e.g. OS pages)
                @memset(mem.bytes()[old_size..new_size], 0);
                operand.* = .{
                    .i32 = @bitCast(
                        @divExact(@as(u32, @intCast(old_size)), runtime.MemInst.page_size),
                    ),
                };
            } else return Transition.interrupted(instr, vals.top, stp, interp, .{
                .memory_grow = .{
                    .old_size = @intCast(mem.size),
                    .new_size = @as(u32, @intCast(mem.size)) + delta_bytes,
                    .memory = mem,
                    .result = operand,
                },
            });
        }

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub const @"i32.const" = i32_opcode_handlers.@"const";
    pub const @"i64.const" = i64_opcode_handlers.@"const";
    pub const @"f32.const" = f32_opcode_handlers.@"const";
    pub const @"f64.const" = f64_opcode_handlers.@"const";

    pub const @"i32.eqz" = i32_opcode_handlers.eqz;
    pub const @"i32.eq" = i32_opcode_handlers.eq;
    pub const @"i32.ne" = i32_opcode_handlers.ne;
    pub const @"i32.lt_s" = i32_opcode_handlers.lt_s;
    pub const @"i32.lt_u" = i32_opcode_handlers.lt_u;
    pub const @"i32.gt_s" = i32_opcode_handlers.gt_s;
    pub const @"i32.gt_u" = i32_opcode_handlers.gt_u;
    pub const @"i32.le_s" = i32_opcode_handlers.le_s;
    pub const @"i32.le_u" = i32_opcode_handlers.le_u;
    pub const @"i32.ge_s" = i32_opcode_handlers.ge_s;
    pub const @"i32.ge_u" = i32_opcode_handlers.ge_u;

    pub const @"i64.eqz" = i64_opcode_handlers.eqz;
    pub const @"i64.eq" = i64_opcode_handlers.eq;
    pub const @"i64.ne" = i64_opcode_handlers.ne;
    pub const @"i64.lt_s" = i64_opcode_handlers.lt_s;
    pub const @"i64.lt_u" = i64_opcode_handlers.lt_u;
    pub const @"i64.gt_s" = i64_opcode_handlers.gt_s;
    pub const @"i64.gt_u" = i64_opcode_handlers.gt_u;
    pub const @"i64.le_s" = i64_opcode_handlers.le_s;
    pub const @"i64.le_u" = i64_opcode_handlers.le_u;
    pub const @"i64.ge_s" = i64_opcode_handlers.ge_s;
    pub const @"i64.ge_u" = i64_opcode_handlers.ge_u;

    pub const @"f32.eq" = f32_opcode_handlers.eq;
    pub const @"f32.ne" = f32_opcode_handlers.ne;
    pub const @"f32.lt" = f32_opcode_handlers.lt;
    pub const @"f32.gt" = f32_opcode_handlers.gt;
    pub const @"f32.le" = f32_opcode_handlers.le;
    pub const @"f32.ge" = f32_opcode_handlers.ge;

    pub const @"f64.eq" = f64_opcode_handlers.eq;
    pub const @"f64.ne" = f64_opcode_handlers.ne;
    pub const @"f64.lt" = f64_opcode_handlers.lt;
    pub const @"f64.gt" = f64_opcode_handlers.gt;
    pub const @"f64.le" = f64_opcode_handlers.le;
    pub const @"f64.ge" = f64_opcode_handlers.ge;

    pub const @"i32.clz" = i32_opcode_handlers.clz;
    pub const @"i32.ctz" = i32_opcode_handlers.ctz;
    pub const @"i32.popcnt" = i32_opcode_handlers.popcnt;
    pub const @"i32.add" = i32_opcode_handlers.add;
    pub const @"i32.sub" = i32_opcode_handlers.sub;
    pub const @"i32.mul" = i32_opcode_handlers.mul;
    pub const @"i32.div_s" = i32_opcode_handlers.div_s;
    pub const @"i32.div_u" = i32_opcode_handlers.div_u;
    pub const @"i32.rem_s" = i32_opcode_handlers.rem_s;
    pub const @"i32.rem_u" = i32_opcode_handlers.rem_u;
    pub const @"i32.and" = i32_opcode_handlers.@"and";
    pub const @"i32.or" = i32_opcode_handlers.@"or";
    pub const @"i32.xor" = i32_opcode_handlers.xor;
    pub const @"i32.shl" = i32_opcode_handlers.shl;
    pub const @"i32.shr_s" = i32_opcode_handlers.shr_s;
    pub const @"i32.shr_u" = i32_opcode_handlers.shr_u;
    pub const @"i32.rotl" = i32_opcode_handlers.rotl;
    pub const @"i32.rotr" = i32_opcode_handlers.rotr;

    pub const @"i64.clz" = i64_opcode_handlers.clz;
    pub const @"i64.ctz" = i64_opcode_handlers.ctz;
    pub const @"i64.popcnt" = i64_opcode_handlers.popcnt;
    pub const @"i64.add" = i64_opcode_handlers.add;
    pub const @"i64.sub" = i64_opcode_handlers.sub;
    pub const @"i64.mul" = i64_opcode_handlers.mul;
    pub const @"i64.div_s" = i64_opcode_handlers.div_s;
    pub const @"i64.div_u" = i64_opcode_handlers.div_u;
    pub const @"i64.rem_s" = i64_opcode_handlers.rem_s;
    pub const @"i64.rem_u" = i64_opcode_handlers.rem_u;
    pub const @"i64.and" = i64_opcode_handlers.@"and";
    pub const @"i64.or" = i64_opcode_handlers.@"or";
    pub const @"i64.xor" = i64_opcode_handlers.xor;
    pub const @"i64.shl" = i64_opcode_handlers.shl;
    pub const @"i64.shr_s" = i64_opcode_handlers.shr_s;
    pub const @"i64.shr_u" = i64_opcode_handlers.shr_u;
    pub const @"i64.rotl" = i64_opcode_handlers.rotl;
    pub const @"i64.rotr" = i64_opcode_handlers.rotr;

    pub const @"f32.abs" = f32_opcode_handlers.abs;
    pub const @"f32.neg" = f32_opcode_handlers.neg;
    pub const @"f32.ceil" = f32_opcode_handlers.ceil;
    pub const @"f32.floor" = f32_opcode_handlers.floor;
    pub const @"f32.trunc" = f32_opcode_handlers.trunc;
    pub const @"f32.nearest" = f32_opcode_handlers.nearest;
    pub const @"f32.sqrt" = f32_opcode_handlers.sqrt;
    pub const @"f32.add" = f32_opcode_handlers.add;
    pub const @"f32.sub" = f32_opcode_handlers.sub;
    pub const @"f32.mul" = f32_opcode_handlers.mul;
    pub const @"f32.div" = f32_opcode_handlers.div;
    pub const @"f32.min" = f32_opcode_handlers.min;
    pub const @"f32.max" = f32_opcode_handlers.max;
    pub const @"f32.copysign" = f32_opcode_handlers.copysign;

    pub const @"f64.abs" = f64_opcode_handlers.abs;
    pub const @"f64.neg" = f64_opcode_handlers.neg;
    pub const @"f64.ceil" = f64_opcode_handlers.ceil;
    pub const @"f64.floor" = f64_opcode_handlers.floor;
    pub const @"f64.trunc" = f64_opcode_handlers.trunc;
    pub const @"f64.nearest" = f64_opcode_handlers.nearest;
    pub const @"f64.sqrt" = f64_opcode_handlers.sqrt;
    pub const @"f64.add" = f64_opcode_handlers.add;
    pub const @"f64.sub" = f64_opcode_handlers.sub;
    pub const @"f64.mul" = f64_opcode_handlers.mul;
    pub const @"f64.div" = f64_opcode_handlers.div;
    pub const @"f64.min" = f64_opcode_handlers.min;
    pub const @"f64.max" = f64_opcode_handlers.max;
    pub const @"f64.copysign" = f64_opcode_handlers.copysign;

    const conv_ops = struct {
        fn @"i32.wrap_i64"(i: i64) !i32 {
            return @truncate(i);
        }

        fn @"i64.extend_i32_s"(i: i32) !i64 {
            return i;
        }

        fn @"i64.extend_i32_u"(i: i32) !i64 {
            return @bitCast(@as(u64, @as(u32, @bitCast(i))));
        }

        fn @"f32.demote_f64"(z: f64) !f32 {
            return @floatCast(z);
        }

        fn @"f64.promote_f32"(z: f32) !f64 {
            return z;
        }
    };

    fn reinterpretOp(comptime Src: type, comptime Dst: type) (fn (Src) error{}!Dst) {
        return struct {
            fn op(src: Src) error{}!Dst {
                return @bitCast(src);
            }
        }.op;
    }

    pub const @"i32.wrap_i64" = defineConvOp(.i64, .i32, 0, conv_ops.@"i32.wrap_i64", undefined);
    pub const @"i32.trunc_f32_s" = i32_opcode_handlers.trunc_f32_s;
    pub const @"i32.trunc_f32_u" = i32_opcode_handlers.trunc_f32_u;
    pub const @"i32.trunc_f64_s" = i32_opcode_handlers.trunc_f64_s;
    pub const @"i32.trunc_f64_u" = i32_opcode_handlers.trunc_f64_u;
    pub const @"i64.extend_i32_s" = defineConvOp(.i32, .i64, 0, conv_ops.@"i64.extend_i32_s", undefined);
    pub const @"i64.extend_i32_u" = defineConvOp(.i32, .i64, 0, conv_ops.@"i64.extend_i32_u", undefined);
    pub const @"i64.trunc_f32_s" = i64_opcode_handlers.trunc_f32_s;
    pub const @"i64.trunc_f32_u" = i64_opcode_handlers.trunc_f32_u;
    pub const @"i64.trunc_f64_s" = i64_opcode_handlers.trunc_f64_s;
    pub const @"i64.trunc_f64_u" = i64_opcode_handlers.trunc_f64_u;
    pub const @"f32.convert_i32_s" = f32_opcode_handlers.convert_i32_s;
    pub const @"f32.convert_i32_u" = f32_opcode_handlers.convert_i32_u;
    pub const @"f32.convert_i64_s" = f32_opcode_handlers.convert_i64_s;
    pub const @"f32.convert_i64_u" = f32_opcode_handlers.convert_i64_u;
    pub const @"f32.demote_f64" = defineConvOp(.f64, .f32, 0, conv_ops.@"f32.demote_f64", undefined);
    pub const @"f64.convert_i32_s" = f64_opcode_handlers.convert_i32_s;
    pub const @"f64.convert_i32_u" = f64_opcode_handlers.convert_i32_u;
    pub const @"f64.convert_i64_s" = f64_opcode_handlers.convert_i64_s;
    pub const @"f64.convert_i64_u" = f64_opcode_handlers.convert_i64_u;
    pub const @"f64.promote_f32" = defineConvOp(.f32, .f64, 0, conv_ops.@"f64.promote_f32", undefined);
    pub const @"i32.reinterpret_f32" = defineConvOp(.f32, .i32, 0, reinterpretOp(f32, i32), undefined);
    pub const @"i64.reinterpret_f64" = defineConvOp(.f64, .i64, 0, reinterpretOp(f64, i64), undefined);
    pub const @"f32.reinterpret_i32" = defineConvOp(.i32, .f32, 0, reinterpretOp(i32, f32), undefined);
    pub const @"f64.reinterpret_i64" = defineConvOp(.i64, .f64, 0, reinterpretOp(i64, f64), undefined);

    fn intSignExtend(comptime I: type, comptime M: type) (fn (I) I) {
        std.debug.assert(@bitSizeOf(M) < @bitSizeOf(I));
        return struct {
            fn op(i: I) I {
                const j: I = @mod(i, @as(I, 1 << @bitSizeOf(M)));
                return @as(M, @truncate(j));
            }
        }.op;
    }

    pub const @"i32.extend8_s" = defineUnOp(.i32, intSignExtend(i32, i8));
    pub const @"i32.extend16_s" = defineUnOp(.i32, intSignExtend(i32, i16));
    pub const @"i64.extend8_s" = defineUnOp(.i64, intSignExtend(i64, i8));
    pub const @"i64.extend16_s" = defineUnOp(.i64, intSignExtend(i64, i16));
    pub const @"i64.extend32_s" = defineUnOp(.i64, intSignExtend(i64, i32));

    pub fn @"ref.null"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

        _ = instr.skipValType();
        vals.pushArray(1)[0] = std.mem.zeroes(Value);

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"ref.is_null"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 1, 1);

        const top: *align(@sizeOf(Value)) Value = &vals.topArray(1)[0];
        // Better codegen than `std.mem.allEqual` producing 16 `cmpb` on x86_64
        const is_null = @reduce(.Or, top.i64x2) == 0;
        // std.debug.print(
        //     "> ref.is_null [{f}] -> {}\n",
        //     .{ top.bytesFormatter(), is_null },
        // );

        top.* = .{ .i32 = @intFromBool(is_null) };

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"ref.func"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

        const func_idx = instr.readIdx(Module.FuncIdx);
        vals.pushTyped(&.{.funcref}, .{@bitCast(module.header().funcAddr(func_idx))});

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub const @"0xFC" = fc_prefixed_dispatch.handler;
    pub const @"i32.trunc_sat_f32_s" = i32_opcode_handlers.trunc_sat_f32_s;
    pub const @"i32.trunc_sat_f32_u" = i32_opcode_handlers.trunc_sat_f32_u;
    pub const @"i32.trunc_sat_f64_s" = i32_opcode_handlers.trunc_sat_f64_s;
    pub const @"i32.trunc_sat_f64_u" = i32_opcode_handlers.trunc_sat_f64_u;
    pub const @"i64.trunc_sat_f32_s" = i64_opcode_handlers.trunc_sat_f32_s;
    pub const @"i64.trunc_sat_f32_u" = i64_opcode_handlers.trunc_sat_f32_u;
    pub const @"i64.trunc_sat_f64_s" = i64_opcode_handlers.trunc_sat_f64_s;
    pub const @"i64.trunc_sat_f64_u" = i64_opcode_handlers.trunc_sat_f64_u;

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-init
    pub fn @"memory.init"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const memory_init_ip = ip - 2;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

        const data_idx = instr.readIdx(Module.DataIdx);
        const mem_idx = instr.readIdx(Module.MemIdx);
        const module_inst = module.header();
        const mem = module_inst.memAddr(mem_idx);

        const operands = vals.popTyped(&(.{.i32} ** 3));
        vals.assertRemainingCountIs(0);
        const n: u32 = @bitCast(operands[2]);
        const src_addr: u32 = @bitCast(operands[1]);
        const d: u32 = @bitCast(operands[0]);

        mem.init(module_inst.dataSegment(data_idx), n, src_addr, d) catch {
            const info = Trap.init(
                .memory_access_out_of_bounds,
                .init(mem_idx, .@"memory.init", {}),
            );
            return Transition.trap(memory_init_ip, eip, sp, stp, interp, info);
        };

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"data.drop"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        const data_idx = instr.readIdx(Module.DataIdx);
        module.header().dataSegmentDropFlag(data_idx).drop();
        return instr.dispatchNextOpcode(sp, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-copy
    pub fn @"memory.copy"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const memory_copy_ip = ip - 2;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

        const dst_idx = instr.readIdx(Module.MemIdx);
        const src_idx = instr.readIdx(Module.MemIdx);
        const module_inst = module.header();
        const dst_mem = module_inst.memAddr(dst_idx);
        const src_mem = module_inst.memAddr(src_idx);

        const operands = vals.popArray(3);
        vals.assertRemainingCountIs(0);
        const n: u32 = @bitCast(operands[2].i32);
        const src_addr: u32 = @bitCast(operands[1].i32);
        const d: u32 = @bitCast(operands[0].i32);
        @memset(operands, undefined);

        dst_mem.copy(src_mem, n, src_addr, d) catch {
            const info = Trap.init(
                .memory_access_out_of_bounds,
                .init(if (dst_mem.size < src_mem.size) dst_idx else src_idx, .@"memory.copy", {}),
            );
            return Transition.trap(memory_copy_ip, eip, sp, stp, interp, info);
        };

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-fill
    pub fn @"memory.fill"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const memory_fill_ip = ip - 2;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

        const mem_idx = instr.readIdx(Module.MemIdx);
        const mem = module.header().memAddr(mem_idx);

        const operands = vals.popArray(3);
        vals.assertRemainingCountIs(0);
        const n: u32 = @bitCast(operands[2].i32);
        const dupe: u8 = @truncate(@as(u32, @bitCast(operands[1].i32)));
        const d: u32 = @bitCast(operands[0].i32);
        @memset(operands, undefined);

        mem.fill(n, dupe, d) catch {
            const info = Trap.init(
                .memory_access_out_of_bounds,
                .init(mem_idx, .@"memory.fill", {}),
            );
            return Transition.trap(memory_fill_ip, eip, sp, stp, interp, info);
        };

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-init
    pub fn @"table.init"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const table_init_ip = ip - 2;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

        const elem_idx = instr.readIdx(Module.ElemIdx);
        const table_idx = instr.readIdx(Module.TableIdx);

        const operands = vals.popArray(3);
        vals.assertRemainingCountIs(0);
        const n: u32 = @bitCast(operands[2].i32);
        const src_idx: u32 = @bitCast(operands[1].i32);
        const d: u32 = @bitCast(operands[0].i32);
        @memset(operands, undefined);

        // std.debug.print(
        //     " > table.init {} elements from {} to {}, table length is {}\n",
        //     .{ n, src_idx, d, module.inner.tableAddr(table_idx).table.len },
        // );

        runtime.TableInst.init(table_idx, module, elem_idx, n, src_idx, d) catch {
            const info = Trap.init(.table_access_out_of_bounds, .init(table_idx, .@"table.init"));
            return Transition.trap(table_init_ip, eip, sp, stp, interp, info);
        };

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    pub fn @"elem.drop"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        const elem_idx = instr.readIdx(Module.ElemIdx);
        module.header().elemSegmentDropFlag(elem_idx).drop();
        return instr.dispatchNextOpcode(sp, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-copy
    pub fn @"table.copy"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const table_copy_ip = ip - 2;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

        const dst_idx = instr.readIdx(Module.TableIdx);
        const src_idx = instr.readIdx(Module.TableIdx);
        const module_inst = module.header();
        const dst_table = module_inst.tableAddr(dst_idx);
        const src_table = module_inst.tableAddr(src_idx);

        const operands = vals.popArray(3);
        vals.assertRemainingCountIs(0);
        const n: u32 = @bitCast(operands[2].i32);
        const src_addr: u32 = @bitCast(operands[1].i32);
        const d: u32 = @bitCast(operands[0].i32);
        @memset(operands, undefined);

        dst_table.table.copy(src_table.table, n, src_addr, d) catch {
            const info = Trap.init(
                .table_access_out_of_bounds,
                .init(
                    if (dst_table.table.len < src_table.table.len) dst_idx else src_idx,
                    .@"table.copy",
                ),
            );
            return Transition.trap(table_copy_ip, eip, sp, stp, interp, info);
        };

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-grow
    pub fn @"table.grow"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 2, 2);

        const table_idx = instr.readIdx(Module.TableIdx);
        const table_addr = module.header().tableAddr(table_idx);
        const table = table_addr.table;

        const delta: u32 = @bitCast(vals.popTyped(&.{.i32})[0]);
        const result_or_elem: *align(@sizeOf(Value)) Value = &vals.topArray(1)[0];
        vals.assertRemainingCountIs(1);

        const grow_failed: i32 = -1;

        const result: i32 = if (table.limit - table.len < delta)
            grow_failed
        else if (table.capacity - table.len >= delta) result: {
            const new_size: u32 = table.len + delta;
            const old_size: u32 = table.len;
            table.len = new_size;

            table.fillWithinCapacity(
                std.mem.asBytes(result_or_elem)[0..table.stride.toBytes()],
                old_size,
                new_size,
            );

            break :result @bitCast(old_size);
        } else return Transition.interrupted(instr, vals.top, stp, interp, .{
            .table_grow = .{
                .table = table_addr,
                .elem = result_or_elem,
                .old_len = table.len,
                .new_len = table.len + delta,
            },
        });

        result_or_elem.* = .{ .i32 = result };

        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-size
    pub fn @"table.size"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

        const table_idx = instr.readIdx(Module.TableIdx);
        vals.pushTyped(&.{.i32}, .{@bitCast(module.header().tableAddr(table_idx).table.len)});
        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-fill
    pub fn @"table.fill"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        module: runtime.ModuleInst,
        interp: *Interpreter,
        eip: Eip,
    ) Transition {
        const table_fill_ip = ip - 2;
        var instr = Instr.init(ip, eip);
        var vals = Stack.Values.init(sp, &interp.stack, 3, 3);

        const table_idx = instr.readIdx(Module.TableIdx);
        const table = module.header().tableAddr(table_idx).table;

        const operands = vals.popArray(3);
        vals.assertRemainingCountIs(0);
        const n: u32 = @bitCast(operands[2].i32);
        const dupe: *align(@sizeOf(Value)) const Value = &operands[1];
        const d: u32 = @bitCast(operands[0].i32);

        table.fill(n, std.mem.asBytes(dupe)[0..table.stride.toBytes()], d) catch {
            const info = Trap.init(.table_access_out_of_bounds, .init(table_idx, .@"table.fill"));
            return Transition.trap(table_fill_ip, eip, sp, stp, interp, info);
        };

        @memset(operands, undefined);
        return instr.dispatchNextOpcode(vals.top, fuel, stp, locals, module, interp);
    }
};

/// If the handler is not appearing in this table, make sure it is public first.
pub const byte_dispatch_table = dispatchTable(
    opcodes.ByteOpcode,
    opcode_handlers.invalid,
    256,
);

const std = @import("std");
const builtin = @import("builtin");
const opcodes = @import("../opcodes.zig");
const coz = @import("coz");
const Module = @import("../Module.zig");
const Stack = @import("Stack.zig");
const Instr = @import("Instr.zig");
const SideTable = @import("side_table.zig").SideTable;
const Interpreter = @import("../Interpreter.zig");
const Fuel = Interpreter.Fuel;
const Value = @import("value.zig").Value;
const Trap = @import("Trap.zig");
const Version = @import("version.zig").Version;
const runtime = @import("../runtime.zig");
