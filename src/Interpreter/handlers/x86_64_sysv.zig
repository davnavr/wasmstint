//! X86-64 assembly implementation of WebAssembly opcode handlers.

// TODO: restructure handlers
// handlers/zig
// handlers/portable.zig
// handlers/portable/simd.zig
// handlers/x86_64_sysv.zig

/// - %rax - `Ip`, `Transition`
/// - %rbx - `Stp`
/// - %rcx - `*Fuel`
/// - %rdx - `runtime.ModuleInst`
/// - %rsi - `Sp`
/// - %rdi - `common.Locals`
/// - %rsp - native stack pointer (reserved/unused)
/// - %rbp - native base pointer (reserved/unused)
/// - %r8 - `[*]const *runtime.MemInst`
/// - %r9 - `*Interpreter`
/// - %r10 - `Eip`
/// - %r11 - clobbered
/// - %r12 - `[*]const *const OpcodeHandler`
/// - %r13 - clobbered
/// - %r14 - clobbered
/// - %r15 - clobbered
///
/// - %xmm0-%xmm7 - clobbered
///
/// Partially inspired by the calling convention used in <https://doi.org/10.48550/arXiv.2205.01183>.
pub const OpcodeHandler = fn () callconv(.naked) Transition;

// Some functions are implemented in Zig, so this provides a stable calling convention that the
// inline assembly can use.
const sysvcc = std.builtin.CallingConvention{ .x86_64_sysv = .{} };

comptime {
    // TODO: Move these checks to generated Zig
    const ModuleInner = @typeInfo(@FieldType(Module, "inner")).pointer.child;
    std.debug.assert(@offsetOf(ModuleInner, "raw") == 0);
    std.debug.assert(@offsetOf(@FieldType(ModuleInner, "raw"), "types") == 0);
    std.debug.assert(@offsetOf(@FieldType(ModuleInner, "raw"), "global_types") == 80);
    std.debug.assert(@offsetOf(runtime.ModuleInst.Header, "tables") == 40);
    std.debug.assert(@offsetOf(runtime.ModuleInst.Header, "globals") == 48);
    std.debug.assert(@sizeOf(Module.GlobalType) == 2);
    std.debug.assert(@offsetOf(Module.GlobalType, "val_type") == 0);
    std.debug.assert(@offsetOf(runtime.TableInst, "base") == 0);
    std.debug.assert(@offsetOf(runtime.TableInst, "len") == 12);
}

const symbol_prefix = @import("options").symbol_prefix;

/// Sets up a stack frame for the assembly opcode handler, before invoking it.
///
/// Parameters are passed such that the trampoline has to move less parameters around to the
/// correct registers expected by `OpcodeHandler`s.
///
/// This also should allocate enough parameters on the stack to be usably for all
/// tail-callable functions defined here.
///
/// TODO: Ideally would use `.x86_64_regcall_v3_sysv`, but only LLVM backend supports it.
const opcodeHandlerTrampoline = @extern(
    *align(16) const fn (
        locals: common.Locals, // rdi
        sp: Sp, // rsi
        module: runtime.ModuleInst, // rdx,
        fuel: *const Interpreter.Fuel, // rcx
        memories: [*]const *runtime.MemInst, // r8
        interpreter: *Interpreter, // r9
        // These parameters are passed on the stack
        ip: Ip, // `rbp + 16` -> rax
        stp: Stp, // `rbp + 24` -> rbx
        eip: Eip, // `rbp + 32` -> r10
        handler: *const OpcodeHandler, // `rbp + 40`
        _: usize, // `rbp + 48`
    ) callconv(sysvcc) Transition,
    .{ .name = symbol_prefix ++ "opcodeHandlerTrampoline" },
);

pub inline fn callOpcodeHandler(
    handler: *const OpcodeHandler,
    instr: Instr,
    fuel: *Interpreter.Fuel,
    stp: Stp,
    locals: common.Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
) Transition {
    std.log.debug("IP={*}", .{instr.next}); // TODO: remove
    var transition = opcodeHandlerTrampoline(
        locals,
        interp.stack_top,
        module,
        fuel,
        module.header().mems,
        interp,
        instr.next,
        stp,
        instr.end,
        handler,
        undefined,
    );

    // Zig x86-64 backend does not support tail calls, and tail calls cannot be emulated with
    // inline `asm` due to the need to preserve callee-saved registers.
    while (builtin.zig_backend == .stage2_x86_64 and
        interp.current_state == .interrupted and
        interp.current_state.interrupted.cause == .out_of_fuel and
        fuel.remaining > 0)
    {
        const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;
        const wasm_func = current_frame.function.expanded().wasm;
        const new_module = wasm_func.module;
        var new_instr = Instr.init(current_frame.wasm.ip, current_frame.wasm.eip);
        const new_locals = common.Locals{ .ptr = current_frame.localValues(&interp.stack).ptr };
        const new_handler = new_instr.readNextOpcodeHandler(fuel, new_locals, new_module, interp);
        transition = opcodeHandlerTrampoline(
            new_locals,
            interp.stack_top,
            new_module,
            fuel,
            new_module.header().mems,
            interp,
            new_instr.next,
            current_frame.wasm.stp,
            new_instr.end,
            new_handler,
            undefined,
        );
    }

    return transition;
}

const invalidByteOpcode = @extern(
    *align(16) const OpcodeHandler,
    .{ .name = symbol_prefix ++ "invalidByteOpcode" },
);

fn panicInvalidByteOpcode(ip: Ip, eip: Eip) callconv(sysvcc) noreturn {
    @branchHint(.cold);
    const bad_ip = ip - 1;
    const bad_opcode: u8 = bad_ip[0];
    const opcode_name = name: {
        const tag = std.meta.intToEnum(opcodes.ByteOpcode, bad_opcode) catch
            break :name "unknown";

        break :name @tagName(tag);
    };

    std.debug.panic(
        "invalid instruction 0x{X:0>2} ({s}) @ {X}, EIP={X}",
        .{ bad_opcode, opcode_name, @intFromPtr(bad_ip), @intFromPtr(eip) },
    );
}

comptime {
    switch (builtin.mode) {
        .Debug, .ReleaseSafe => @export(
            &panicInvalidByteOpcode,
            .{ .name = symbol_prefix ++ "panicInvalidByteOpcode" },
        ),
        .ReleaseFast, .ReleaseSmall => {},
    }
}

/// Invokes `interruptOutOfFuel()`.
pub const outOfFuelHandler = @extern(
    *align(16) const OpcodeHandler,
    .{ .name = symbol_prefix ++ "outOfFuelHandler" },
);

fn interruptOutOfFuel(
    ip: Ip,
    eip: Eip,
    sp: Sp,
    stp: Stp,
    interp: *Interpreter,
) align(16) callconv(sysvcc) Transition {
    return Transition.interrupted(.init(ip, eip), sp, stp, interp, .out_of_fuel);
}

/// Parameters are arranged such that some registers already contain the correct value.
fn returnFromWasm(
    old_eip: Eip, // r10 -> rdi (only used in debug mode)
    old_sp: Sp, // stays in rsi
    old_module: runtime.ModuleInst, // stays in rdx (only used in debug mode)
    fuel: *Interpreter.Fuel, // stays in rcx
    _: usize, // r8 (unused)
    interp: *Interpreter, // stays in r9
    // Stack space for parameters, same as in `opcodeHandlerTrampoline`
    _: usize,
    _: usize,
    _: usize,
    _: usize,
    _: usize,
) callconv(sysvcc) Transition {
    const popped = interp.stack.popFrame(old_sp, .from_stack_top);
    if (builtin.mode == .Debug) {
        std.debug.assert( // module mismatch
            @intFromPtr(popped.info.callee.expanded().wasm.module.inner) ==
                @intFromPtr(old_module.inner),
        );
        const expected_eip = @intFromPtr(popped.info.wasm.eip);
        const actual_eip = @intFromPtr(old_eip);
        if (expected_eip != actual_eip) {
            std.debug.panic("expected EIP={X}, got {X}", .{ expected_eip, actual_eip });
        }
    }

    return_to_host: {
        if (interp.stack.call_depth == 0) {
            break :return_to_host;
        }

        const frame = interp.stack.frameAt(interp.stack.current_frame).?;
        switch (frame.function.expanded()) {
            .wasm => |wasm| {
                var instr = Instr.init(frame.wasm.ip, frame.wasm.eip);
                if (builtin.zig_backend == .stage2_x86_64) {
                    // trampoline continues execution
                    return Transition.interrupted(
                        instr,
                        popped.top,
                        frame.wasm.stp,
                        interp,
                        .out_of_fuel,
                    );
                } else {
                    const new_locals = common.Locals{
                        .ptr = frame.localValues(&interp.stack).ptr,
                    };
                    const handler = instr.readNextOpcodeHandler(
                        fuel,
                        new_locals,
                        wasm.module,
                        interp,
                    );

                    // ABI of the functions are the same, so this call is fine.
                    // Optimizer seems to emit a direct `jmp` despite function pointers here.
                    return @call(
                        .always_tail,
                        @as(@TypeOf(&returnFromWasm), @ptrCast(opcodeHandlerTrampoline)),
                        .{
                            @as(Eip, @ptrCast(new_locals.ptr)),
                            @as(Sp, @bitCast(popped.top)),
                            wasm.module,
                            fuel,
                            @as(usize, @intFromPtr(wasm.module.header().mems)),
                            interp,
                            @as(usize, @intFromPtr(instr.next)),
                            @as(usize, @intFromPtr(frame.wasm.stp)),
                            @as(usize, @intFromPtr(instr.end)),
                            @as(usize, @intFromPtr(handler)),
                            undefined,
                        },
                    );
                }
            },
            .host => break :return_to_host,
        }

        comptime unreachable;
    }

    return Transition.awaitingHost(
        popped.top,
        interp,
        popped.signature,
        .returning_to_host,
        .wrote_ip_and_stp_to_the_current_stack_frame, // no need to save, since this returns to host
    );
}

inline fn resumeAfterInvokeWithinWasm(
    old_instr: Instr,
    sp: Sp,
    fuel: *Interpreter.Fuel,
    stp: Stp,
    locals: common.Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
) Transition {
    if (builtin.zig_backend == .stage2_x86_64) {
        // trampoline continues execution
        return Transition.interrupted(old_instr, sp, stp, interp, .out_of_fuel);
    } else {
        var instr = old_instr;
        const handler = instr.readNextOpcodeHandler(fuel, locals, module, interp);
        // TODO: inlineLlvmTailCallToHandler()
        return @call(
            .always_tail,
            @as(@TypeOf(&invokeWithinWasm), @ptrCast(opcodeHandlerTrampoline)),
            .{
                locals,
                sp,
                module,
                fuel,
                module.header().mems,
                interp,
                instr.next,
                stp,
                instr.end,
                @intFromPtr(handler),
                undefined,
            },
        );
    }
}

// TODO: Don't need to pass `locals` or `memories`
fn invokeWithinWasm(
    locals: common.Locals, // rdi
    sp: Sp, // rsi
    module: runtime.ModuleInst, // rdx,
    fuel: *Interpreter.Fuel, // rcx
    memories: [*]const *runtime.MemInst, // r8
    interp: *Interpreter, // r9
    // These parameters are passed on the stack
    ip: Ip, // `rbp + 16`
    stp: Stp, // `rbp + 24`
    eip: Eip, // `rbp + 32`
    func_idx: usize, // `rbp + 40`
    call_ip: Ip, // `rbp + 48`
) callconv(sysvcc) Transition {
    switch (@as(opcodes.ByteOpcode, @enumFromInt(call_ip[0]))) {
        .call => {},
        else => |bad| switch (builtin.mode) {
            .Debug, .ReleaseSafe => std.debug.panic(
                "{t} (0x{X:0>2}) is not a valid call instruction",
                .{ bad, @intFromEnum(bad) },
            ),
            .ReleaseFast, .ReleaseSmall => unreachable,
        },
    }

    if (builtin.mode == .Debug) {
        std.debug.assert(@intFromPtr(module.header().memInsts().ptr) == @intFromPtr(memories));
        std.debug.assert( // bad locals ptr
            @intFromPtr(interp.stack.currentFrame().?.localValues(&interp.stack).ptr) ==
                @intFromPtr(locals.ptr),
        );
    }

    const callee = module.inner.funcInst(@enumFromInt(func_idx));
    const arg_count = callee.signature().param_count;
    const saved_sp = Stack.Saved.pop(
        Stack.Values.init(sp, &interp.stack, arg_count, arg_count),
        arg_count,
    );

    return common.invokeWithinWasm(
        Instr.init(ip, eip),
        call_ip,
        saved_sp,
        fuel,
        stp,
        interp,
        callee,
        resumeAfterInvokeWithinWasm,
    );
}

inline fn resumeAfterInvokeWithinWasmIndirect(
    old_instr: Instr,
    sp: Sp,
    fuel: *Interpreter.Fuel,
    stp: Stp,
    locals: common.Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
) Transition {
    if (builtin.zig_backend == .stage2_x86_64) {
        // trampoline continues execution
        return Transition.interrupted(old_instr, sp, stp, interp, .out_of_fuel);
    } else {
        var instr = old_instr;
        const handler = instr.readNextOpcodeHandler(fuel, locals, module, interp);
        // TODO: inlineLlvmTailCallToHandler()
        return @call(
            .always_tail,
            @as(@TypeOf(&invokeWithinWasm), @ptrCast(opcodeHandlerTrampoline)),
            .{
                @as(usize, @bitCast(locals)),
                sp,
                @as(runtime.FuncRef, @bitCast(module)),
                fuel,
                @as(*const Module.FuncType, @ptrCast(module.header().mems)),
                interp,
                instr.next,
                stp,
                instr.end,
                @intFromPtr(handler),
                undefined,
            },
        );
    }
}

fn invokeWithinWasmIndirect(
    call_ip: Ip, // rdi
    /// Does not have the `i32` index popped.
    sp: Sp, // rsi
    callee: runtime.FuncRef, // rdx,
    fuel: *Interpreter.Fuel, // rcx
    expected_signature: *const Module.FuncType, // r8
    interp: *Interpreter, // r9
    ip: Ip, // `rbp + 16`
    stp: Stp, // `rbp + 24`
    eip: Eip, // `rbp + 32`
    _: usize, // `rbp + 40`
    _: usize, // `rbp + 48`
) callconv(sysvcc) Transition {
    const pop_count = 1 + expected_signature.param_count;
    const saved_sp = Stack.Saved.pop(
        Stack.Values.init(sp, &interp.stack, pop_count, pop_count),
        pop_count,
    );

    const actual_signature = callee.signature();
    if (!expected_signature.matches(actual_signature)) {
        const info = Interpreter.Trap.init(
            .indirect_call_signature_mismatch,
            .{ .expected = expected_signature, .actual = actual_signature },
        );

        return Transition.trap(ip, .none, eip, sp, stp, interp, info);
    }

    return common.invokeWithinWasm(
        Instr.init(ip, eip),
        call_ip,
        saved_sp,
        fuel,
        stp,
        interp,
        callee.funcInst(),
        resumeAfterInvokeWithinWasmIndirect,
    );
}

fn memoryGrowReallocate(
    new_size: usize, // rdi
    /// `sp - 1` refers to `(i32.const -1)`, indicating growth failure.
    sp: Sp, // rsi
    ip: Ip, // rdx,
    eip: Eip, // rcx
    /// Pointer to memory to grow
    mem: *runtime.MemInst, // r8
    interp: *Interpreter, // r9
    // These parameters are passed on the stack
    stp: Stp, // `rbp + 16`
    _: usize, // `rbp + 24`
    _: usize, // `rbp + 32`
    _: usize, // `rbp + 40`
    _: usize, // `rbp + 48`
) callconv(sysvcc) Transition {
    const result = &(sp.ptr - 1)[0];
    std.debug.assert(result.i32 == -1);
    return Transition.interrupted(.init(ip, eip), sp, stp, interp, .{
        .memory_grow = .{
            .old_size = @intCast(mem.size),
            .new_size = new_size,
            .memory = mem,
            .result = result,
        },
    });
}

fn trapTableAccessOob(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    table_idx: usize, // r8
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    const info = Interpreter.Trap.init(
        .table_access_out_of_bounds,
        .init(@enumFromInt(table_idx), .call_indirect),
    );

    return Transition.trap(trap_ip, .none, eip, sp, stp, interp, info);
}

fn trapIndirectCallToNull(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    elem_idx: usize, // r8
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    const info = Interpreter.Trap.init(.indirect_call_to_null, .{ .index = @intCast(elem_idx) });
    return Transition.trap(trap_ip, .none, eip, sp, stp, interp, info);
}

fn trapIntegerDivisionByZero(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    _: usize, // r8 (unused)
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    return Transition.trapAt(trap_ip, eip, sp, stp, interp, .init(.integer_division_by_zero, {}));
}

fn trapIntegerOverflow(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    _: usize, // r8 (unused)
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    return Transition.trapAt(trap_ip, eip, sp, stp, interp, .init(.integer_overflow, {}));
}

fn trapMemoryAccessOutOfBounds(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    mem_idx: usize, // r8
    interp: *Interpreter, // stays in r9
    address: u32,
    size: u8,
    memory: *const runtime.MemInst,
) callconv(sysvcc) Transition {
    std.log.debug("address={X}, size={X}, memory={*}", .{ address, size, memory });
    return Transition.trapAt(
        trap_ip,
        eip,
        sp,
        stp,
        interp,
        .init(.memory_access_out_of_bounds, .init(
            @enumFromInt(mem_idx),
            .access,
            .{ .address = address, .size = @enumFromInt(size), .maximum = memory.size },
        )),
    );
}

const generated = @import("asm_generated");

pub const byte_dispatch_table align(64) = common.dispatchTable(
    opcodes.ByteOpcode,
    generated.handlers(*const OpcodeHandler),
    invalidByteOpcode,
    256,
);

comptime {
    for (&[_][]const u8{
        "interruptOutOfFuel",
        "returnFromWasm",
        "invokeWithinWasm",
        "invokeWithinWasmIndirect",
        "memoryGrowReallocate",
        "trapIntegerDivisionByZero",
        "trapIntegerOverflow",
        "trapMemoryAccessOutOfBounds",
        "trapTableAccessOob",
        "trapIndirectCallToNull",
        "byte_dispatch_table",
    }) |name| {
        @export(&@field(@This(), name), .{ .name = symbol_prefix ++ name });
    }
}

const std = @import("std");
const builtin = @import("builtin");
const opcodes = @import("../../opcodes.zig");

const Module = @import("../../Module.zig");
const Interpreter = @import("../../Interpreter.zig");
const runtime = @import("../../runtime.zig");

const Instr = @import("../Instr.zig");
const Stack = @import("../Stack.zig");

const common = @import("../handlers.zig");
const Transition = common.Transition;
const Ip = common.Ip;
const Eip = common.Eip;
const Sp = common.Sp;
const Stp = common.Stp;
