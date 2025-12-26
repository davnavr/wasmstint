//! X86-64 assembly implementation of WebAssembly opcode handlers.

/// - %rax - `Ip`, `Transition`
/// - %rbx - `Stp`
/// - %rcx - `*Fuel`
/// - %rdx - `ModuleInst`
/// - %rsi - `Sp`
/// - %rdi - `Locals`
/// - %rsp - native stack pointer (reserved/unused)
/// - %rbp - native base pointer (reserved/unused)
/// - %r8 - `[*]const *runtime.MemInst`
/// - %r9 - `*Interpreter`
/// - %r10 - `Eip`
/// - %r11 - clobbered, or `*const OpcodeHandler` when calling the trampoline.
/// - %r12 - `[*]const *const OpcodeHandler`
/// - %r13 - clobbered
/// - %r14 - clobbered
/// - %r15 - clobbered
///
/// - %xmm0-%xmm7 - clobbered
///
/// Partially inspired by the calling convention used in <https://doi.org/10.48550/arXiv.2205.01183>.
pub const OpcodeHandler = fn () callconv(.naked) Transition;

/// Specifies the registers that are clobbered when calling an opcode handler.
pub const opcode_handler_clobbers = std.builtin.assembly.Clobbers{
    // Stack pointer and base pointer actually get saved, but a new frame is made before entering
    // any opcode handler.
    //.rsp = false,
    //.rbp = false,

    // GPRs
    .rax = true,
    .rcx = true,
    .rdx = true,
    .rbx = true,
    .rsi = true,
    .rdi = true,
    .r8 = true,
    .r9 = true,
    .r10 = true,
    .r11 = true,
    .r12 = true,
    .r13 = true,
    .r14 = true,
    .r15 = true,
};

/// Sets up a stack frame for the assembly opcode handlers.
///
/// - `%r11` contains the `*const OpcodeHandler` to jump to.
///
/// See `OpcodeHandler` for additional input and output registers.
pub fn opcodeHandlerTrampoline() callconv(.naked) Transition {
    // Naked since individual opcode handlers will have the function epilogue + `ret`.
    // Don't know if `volatile` is necessary here, or if clobbers are enough
    asm volatile (
        \\pushq %%rbp
        \\movq %%rsp, %%rbp
        \\movq %[dispatch:P], %%r12
        \\jmp *%%r11
        :
        : [dispatch] "X" (@as([*]const *const OpcodeHandler, &byte_dispatch_table)),
        : opcode_handler_clobbers);
}

// Some functions are implemented in Zig, so this provides a stable calling convention that the
// inline assembly can use.
const sysv_cc = std.builtin.CallingConvention{ .x86_64_sysv = .{} };

pub fn invalidByteOpcode() callconv(.naked) Transition {
    @branchHint(.cold);
    switch (builtin.mode) {
        .Debug, .ReleaseSafe => asm volatile (
            \\
            // Move IP to first argument
            \\movq %%rax, %%rdi
            // doesn't `jmp`, so stack trace is better
            \\callq %[panic:P]
            \\ud2
            :
            : [panic] "X" (&panicInvalidByteOpcode),
        ),
        .ReleaseFast, .ReleaseSmall => asm volatile ("ud2"),
    }
}

fn panicInvalidByteOpcode(ip: Ip) callconv(sysv_cc) noreturn {
    @branchHint(.cold);
    const bad_ip = ip - 1;
    const bad_opcode: u8 = bad_ip[0];
    const opcode_name = name: {
        const tag = std.meta.intToEnum(opcodes.ByteOpcode, bad_opcode) catch
            break :name "unknown";

        break :name @tagName(tag);
    };

    std.debug.panic(
        "invalid instruction 0x{X:0>2} ({s}) @ {X}",
        .{ bad_opcode, opcode_name, @intFromPtr(bad_ip) },
    );
}

pub fn outOfFuelHandler() align(16) callconv(.naked) Transition {
    asm volatile (
        \\
        // 1st argument
        \\movq %%rax, %%rdi
        // 3rd argument
        \\movq %%rsi, %%rdx
        // 2nd argument
        \\movq %%r10, %%rsi
        // 4th argument
        \\movq %%rbx, %%rcx
        // 5th argument
        \\movq %%r9, %%r8
        \\movq %%rbp, %%rsp
        \\popq %%rbp
        \\jmp %[oof:P]
        \\ud2
        :
        : [oof] "X" (&interruptOutOfFuel),
    );
}

fn interruptOutOfFuel(
    ip: Ip,
    eip: Eip,
    sp: Sp,
    stp: Stp,
    interp: *Interpreter,
) align(16) callconv(sysv_cc) Transition {
    return Transition.interrupted(.init(ip, eip), sp, stp, interp, .out_of_fuel);
}

pub const byte_dispatch_table = common.dispatchTable(
    opcodes.ByteOpcode,
    @This(),
    invalidByteOpcode,
    256,
);

const std = @import("std");
const builtin = @import("builtin");
const opcodes = @import("../../opcodes.zig");

const Interpreter = @import("../../Interpreter.zig");

const common = @import("../handlers.zig");
const Transition = common.Transition;
const Ip = common.Ip;
const Eip = common.Eip;
const Sp = common.Sp;
const Stp = common.Stp;
