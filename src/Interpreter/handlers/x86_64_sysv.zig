//! X86-64 assembly implementation of WebAssembly opcode handlers.

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
const sysv_cc = std.builtin.CallingConvention{ .x86_64_sysv = .{} };

/// Sets up a stack frame for the assembly opcode handler, before invoking it.
///
/// Parameters are passed such that the trampoline has to move less parameters around to the
/// correct registers expected by `OpcodeHandler`s.
///
/// TODO: Ideally would use `.x86_64_regcall_v3_sysv`, but only LLVM backend supports it.
pub const opcodeHandlerTrampoline = @extern(
    *align(16) const fn (
        locals: common.Locals, // rdi
        sp: Sp, // rsi
        module: runtime.ModuleInst, // rdx,
        fuel: *const Interpreter.Fuel, // rcx
        memories: [*]const *runtime.MemInst, // r8
        interpreter: *Interpreter, // r9
        // These parameters are passed on the stack
        ip: Ip, // `rbp + 16`
        stp: Stp, // `rbp + 24`
        eip: Eip, // `rbp + 32`
        handler: *const OpcodeHandler, // `rbp + 40`
    ) callconv(sysv_cc) Transition,
    .{ .name = generated.symbol_prefix ++ "opcodeHandlerTrampoline" },
);

const invalidByteOpcode = @extern(
    *align(16) const OpcodeHandler,
    .{ .name = generated.symbol_prefix ++ "invalidByteOpcode" },
);

fn panicInvalidByteOpcode(ip: Ip, eip: Eip) callconv(sysv_cc) noreturn {
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
            .{ .name = generated.symbol_prefix ++ "panicInvalidByteOpcode" },
        ),
        .ReleaseFast, .ReleaseSmall => {},
    }
}

pub const outOfFuelHandler = @extern(
    *align(16) const OpcodeHandler,
    .{ .name = generated.symbol_prefix ++ "outOfFuelHandler" },
);

fn interruptOutOfFuel(
    ip: Ip,
    eip: Eip,
    sp: Sp,
    stp: Stp,
    interp: *Interpreter,
) align(16) callconv(sysv_cc) Transition {
    return Transition.interrupted(.init(ip, eip), sp, stp, interp, .out_of_fuel);
}

comptime {
    @export(&interruptOutOfFuel, .{ .name = generated.symbol_prefix ++ "interruptOutOfFuel" });
}

// TODO TODO: Don't forget to ensure layout of SideTableEntry is fine on .Debug mode

const generated = @import("x86_64_sysv");

pub const byte_dispatch_table align(64) = common.dispatchTable(
    opcodes.ByteOpcode,
    generated.handlers(*const OpcodeHandler),
    invalidByteOpcode,
    256,
);

comptime {
    @export(&byte_dispatch_table, .{ .name = generated.symbol_prefix ++ "byte_dispatch_table" });
}

const std = @import("std");
const builtin = @import("builtin");
const opcodes = @import("../../opcodes.zig");

const Interpreter = @import("../../Interpreter.zig");
const runtime = @import("../../runtime.zig");

const common = @import("../handlers.zig");
const Transition = common.Transition;
const Ip = common.Ip;
const Eip = common.Eip;
const Sp = common.Sp;
const Stp = common.Stp;
