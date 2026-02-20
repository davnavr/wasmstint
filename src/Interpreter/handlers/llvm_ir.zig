//! FFI bridge to the implementation of WebAssembly opcode handlers written in LLVM IR.

/// Opcode handlers may use a calling convention not supported in Zig.
pub const OpcodeHandler = fn () callconv(.naked) Transition;

const symbol_prefix = @import("options").symbol_prefix;

const ffi_cc: CallingConvention = cc: {
    if (builtin.cpu.arch == .x86_64 and
        CallingConvention.c == .x86_64_sysv and
        builtin.zig_backend == .stage2_llvm)
    {
        break :cc .{ .x86_64_regcall_v3_sysv = .{} };
    }

    break :cc .c;
};

/// Sets up a stack frame for the assembly opcode handler, before invoking it.
const opcodeHandlerTrampoline = @extern(
    *const fn (
        locals: common.Locals,
        vsp: Sp,
        module: runtime.ModuleInst,
        fuel: *const Interpreter.Fuel,
        memories: [*]const *runtime.MemInst,
        ctx: *Interpreter,
        vip: Ip,
        stp: Stp,
        eip: Eip,
        handler: *const OpcodeHandler,
    ) callconv(ffi_cc) Transition,
    .{ .name = symbol_prefix ++ "opcodeHandlerTrampoline" },
);

pub inline fn callOpcodeHandler(
    handler: *const OpcodeHandler,
    instr: Instr,
    fuel: *Interpreter.Fuel,
    stp: Stp,
    locals: common.Locals,
    module: runtime.ModuleInst,
    ctx: *Interpreter,
) Transition {
    std.log.debug(
        "VIP={*}, EIP={*}, VSP={*}, LOC={*}, MODULE={*}",
        .{ instr.next, instr.end, ctx.stack_top.ptr, locals.ptr, module.inner },
    ); // TODO: remove this
    var transition = opcodeHandlerTrampoline(
        locals,
        ctx.stack_top,
        module,
        fuel,
        module.header().mems,
        ctx,
        instr.next,
        stp,
        instr.end,
        handler,
    );

    // Zig x86-64 backend does not support tail calls, and tail calls cannot be emulated with
    // inline `asm` due to the need to preserve callee-saved registers.
    while (builtin.zig_backend != .stage2_llvm and
        ctx.current_state == .interrupted and
        ctx.current_state.interrupted.cause == .out_of_fuel and
        fuel.remaining > 0)
    {
        const current_frame = ctx.stack.frameAt(ctx.stack.current_frame).?;
        const wasm_func = current_frame.function.expanded().wasm;
        const new_module = wasm_func.module;
        var new_instr = Instr.init(current_frame.wasm.ip, current_frame.wasm.eip);
        const new_locals = common.Locals{ .ptr = current_frame.localValues(&ctx.stack).ptr };
        const new_handler = new_instr.readNextOpcodeHandler(fuel, new_locals, new_module, ctx);
        transition = opcodeHandlerTrampoline(
            new_locals,
            ctx.stack_top,
            new_module,
            fuel,
            new_module.header().mems,
            ctx,
            new_instr.next,
            current_frame.wasm.stp,
            new_instr.end,
            new_handler,
        );
    }

    return transition;
}

pub const outOfFuelHandler = @extern(
    *const OpcodeHandler,
    .{ .name = symbol_prefix ++ "outOfFuelHandler" },
);

pub const byte_dispatch_table = @extern(
    *const [256]*const OpcodeHandler,
    .{ .name = symbol_prefix ++ "byte_dispatch_table" },
);

fn interruptOutOfFuel(
    vip: Ip,
    eip: Eip,
    sp: Sp,
    stp: Stp,
    ctx: *Interpreter,
) callconv(ffi_cc) Transition {
    return Transition.interrupted(.init(vip, eip), sp, stp, ctx, .out_of_fuel);
}

fn returnFromWasm(
    // Dummy parameters so LLVM can generate tail calls
    _: common.Locals,
    old_sp: Sp,
    old_module: runtime.ModuleInst,
    fuel: *Interpreter.Fuel,
    _: [*]const *runtime.MemInst,
    ctx: *Interpreter,
    _: Ip,
    _: Stp,
    old_eip: Eip,
    _: *const OpcodeHandler,
) callconv(ffi_cc) Transition {
    const popped = ctx.stack.popFrame(old_sp, .from_stack_top);
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
        if (ctx.stack.call_depth == 0) {
            break :return_to_host;
        }

        const frame = ctx.stack.frameAt(ctx.stack.current_frame).?;
        switch (frame.function.expanded()) {
            .wasm => |wasm| {
                var instr = Instr.init(frame.wasm.ip, frame.wasm.eip);
                if (builtin.zig_backend == .stage2_x86_64) {
                    // trampoline continues execution
                    return Transition.interrupted(
                        instr,
                        popped.top,
                        frame.wasm.stp,
                        ctx,
                        .out_of_fuel,
                    );
                } else {
                    const new_locals = common.Locals{
                        .ptr = frame.localValues(&ctx.stack).ptr,
                    };
                    const handler = instr.readNextOpcodeHandler(
                        fuel,
                        new_locals,
                        wasm.module,
                        ctx,
                    );

                    // ABI of the functions are the same, so this call is fine.
                    // Optimizer seems to emit a direct `jmp` despite function pointers here.
                    return @call(
                        .always_tail,
                        @as(@TypeOf(&returnFromWasm), @ptrCast(opcodeHandlerTrampoline)),
                        .{
                            new_locals.ptr,
                            popped.top,
                            wasm.module,
                            fuel,
                            wasm.module.header().mems,
                            ctx,
                            instr.next,
                            frame.wasm.stp,
                            instr.end,
                            handler,
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
        ctx,
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
        return @call(
            .always_tail,
            @as(@TypeOf(&invokeWithinWasm), @ptrCast(opcodeHandlerTrampoline)),
            .{
                locals,
                sp,
                module,
                fuel,
                @intFromPtr(module.header().mems),
                interp,
                instr.next,
                stp,
                instr.end,
                @as(*anyopaque, @ptrCast(@alignCast(handler))),
            },
        );
    }
}

fn invokeWithinWasm(
    locals_debug: common.Locals,
    vsp: Sp,
    module: runtime.ModuleInst,
    fuel: *Interpreter.Fuel,
    func_idx: usize,
    ctx: *Interpreter,
    vip: Ip,
    stp: Stp,
    eip: Eip,
    call_ip_int: *anyopaque,
) callconv(ffi_cc) Transition {
    const call_ip: Ip = @ptrCast(call_ip_int);
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
        std.debug.assert( // bad locals ptr
            @intFromPtr(ctx.stack.currentFrame().?.localValues(&ctx.stack).ptr) ==
                @intFromPtr(locals_debug.ptr),
        );
    }

    const callee = module.inner.funcInst(@enumFromInt(func_idx));
    const arg_count = callee.signature().param_count;
    const saved_sp = Stack.Saved.pop(
        Stack.Values.init(vsp, &ctx.stack, arg_count, arg_count),
        arg_count,
    );

    return common.invokeWithinWasm(
        Instr.init(vip, eip),
        call_ip,
        saved_sp,
        fuel,
        stp,
        ctx,
        callee,
        resumeAfterInvokeWithinWasm,
    );
}

fn trapWithNumericCode(
    trap_ip: Ip,
    sp: Sp,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    code: usize,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    const trap = switch (@as(Trap.Code, @enumFromInt(code))) {
        inline .unreachable_code_reached,
        .integer_division_by_zero,
        .integer_overflow,
        .invalid_conversion_to_integer,
        => |chosen| Trap.init(comptime chosen, {}),
        else => unreachable,
    };

    return Transition.trapAt(trap_ip, eip, sp, stp, ctx, trap);
}

fn trapMemoryAccessOutOfBounds(
    trap_ip: Ip,
    sp: Sp,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    memory: *const runtime.MemInst,
    mem_idx: usize,
    address: usize,
    offset: usize,
    size: usize,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    const oob_info = Trap.MemoryAccessOutOfBounds.init(@enumFromInt(mem_idx), .access, .{
        .address = address + offset,
        .size = @enumFromInt(size),
        .maximum = memory.size,
    });

    const trap_info = Trap.init(.memory_access_out_of_bounds, oob_info);
    return Transition.trapAt(trap_ip, eip, sp, stp, ctx, trap_info);
}

comptime {
    for (&[_][]const u8{
        "interruptOutOfFuel",
        "invokeWithinWasm",
        "returnFromWasm",
        "trapWithNumericCode",
        "trapMemoryAccessOutOfBounds",
    }) |name| {
        @export(&@field(@This(), name), .{ .name = symbol_prefix ++ name });
    }
}

fn panicInvalidByteOpcode(ip: Ip, eip: Eip) callconv(ffi_cc) noreturn {
    @branchHint(.cold);
    const bad_ip = ip - 1;
    const bad_opcode: u8 = bad_ip[0];
    const opcode_name = name: {
        const tag = std.enums.fromInt(opcodes.ByteOpcode, bad_opcode) orelse break :name "unknown";
        break :name @tagName(tag);
    };

    std.debug.panic(
        "invalid instruction 0x{X:0>2} ({s}) @ {X}, EIP={X}",
        .{ bad_opcode, opcode_name, @intFromPtr(bad_ip), @intFromPtr(eip) },
    );
}

comptime {
    if (builtin.mode != .ReleaseSmall) {
        for (&[_][]const u8{
            "panicInvalidByteOpcode",
            // "panicInvalidPrefixedOpcode",
        }) |name| {
            @export(&@field(@This(), name), .{ .name = symbol_prefix ++ name });
        }
    }
}

const std = @import("std");
const CallingConvention = std.builtin.CallingConvention;
const builtin = @import("builtin");

const opcodes = @import("opcodes");
const Interpreter = @import("../../Interpreter.zig");
const Trap = Interpreter.Trap;
const runtime = @import("../../runtime.zig");

const Instr = @import("../Instr.zig");
const Stack = @import("../Stack.zig");

const common = @import("../handlers.zig");
const Transition = common.Transition;
const Ip = common.Ip;
const Eip = common.Eip;
const Sp = common.Sp;
const Stp = common.Stp;
