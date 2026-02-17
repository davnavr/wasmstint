//! FFI bridge to the implementation of WebAssembly opcode handlers written in LLVM IR.

/// Opcode handlers may use a calling convention not supported in Zig.
pub const OpcodeHandler = fn () callconv(.naked) Transition;

const symbol_prefix = @import("options").symbol_prefix;

const calling_convention: CallingConvention = cc: {
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
        sp: Sp,
        module: runtime.ModuleInst,
        fuel: *const Interpreter.Fuel,
        memories: [*]const *runtime.MemInst,
        interpreter: *Interpreter,
        ip: Ip,
        stp: Stp,
        eip: Eip,
        handler: *const OpcodeHandler,
    ) callconv(calling_convention) Transition,
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
    );

    // Zig x86-64 backend does not support tail calls, and tail calls cannot be emulated with
    // inline `asm` due to the need to preserve callee-saved registers.
    while (builtin.zig_backend != .stage2_llvm and
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

const std = @import("std");
const CallingConvention = std.builtin.CallingConvention;
const builtin = @import("builtin");

const Interpreter = @import("../../Interpreter.zig");
const runtime = @import("../../runtime.zig");

const Instr = @import("../Instr.zig");
// const Stack = @import("../Stack.zig");

const common = @import("../handlers.zig");
const Transition = common.Transition;
const Ip = common.Ip;
const Eip = common.Eip;
const Sp = common.Sp;
const Stp = common.Stp;
