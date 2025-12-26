//! X86-64 assembly implementation of WebAssembly opcode handlers.

/// - %rax - `Ip`, `Transition`
/// - %rbx - `Stp`
/// - %rcx - `*Fuel`
/// - %rdx - `runtime.ModuleInst`
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

    .xmm0 = true,
    .xmm1 = true,
    .xmm2 = true,
    .xmm3 = true,
    .xmm4 = true,
    .xmm5 = true,
    .xmm6 = true,
    .xmm7 = true,
};

/// Sets up a stack frame for the assembly opcode handlers.
///
/// - `%r11` contains the `*const OpcodeHandler` to jump to.
///
/// See `OpcodeHandler` for additional input and output registers.
pub const opcodeHandlerTrampoline = @extern(
    *align(16) const fn () callconv(.naked) Transition,
    .{ .name = generated.symbol_prefix ++ "opcodeHandlerTrampoline" },
);

// Both Zig and LLVM backends store the `&byte_dispatch_table` into a register first, clobbering
// the exising value.
// - Zig seems to ignore the clobber list, allocating into `rax`
// - LLVM seems to follow it, but since `rbp` is not listed, it allocates it into `ebp`
// Neither generate a symbol/label directly, so the ASM will have to do it.

//pub fn opcodeHandlerTrampoline() callconv(.naked) Transition {
//    // Naked since individual opcode handlers will have the function epilogue + `ret`.
//    // Don't know if `volatile` is necessary here, or if clobbers are enough
//    asm volatile (
//        \\pushq %%rbp
//        \\movq %%rsp, %%rbp
//        \\movq %[dispatch:P], %%r12
//        \\jmp *%%r11
//        \\ud2
//        :
//        // Could move directly into r12 here, but that would be placed before the `pushq`
//        : [dispatch] "X" (@as([*]const *const OpcodeHandler, &byte_dispatch_table)),
//        : opcode_handler_clobbers);
//}

// Some functions are implemented in Zig, so this provides a stable calling convention that the
// inline assembly can use.
const sysv_cc = std.builtin.CallingConvention{ .x86_64_sysv = .{} };

//fn invalidByteOpcode() callconv(.naked) Transition {
//    @branchHint(.cold);
//    switch (builtin.mode) {
//        .Debug, .ReleaseSafe => asm volatile (
//            \\
//            // Move IP to first argument
//            \\movq %%rax, %%rdi
//            \\movq %%r10, %%rsi
//            // doesn't `jmp`, so stack trace is better
//            \\call %[panic:P]
//            \\ud2
//            :
//            // Zig x86_64 backend writes this to `%rax`
//            : [panic] "X" (&panicInvalidByteOpcode),
//        ),
//        .ReleaseFast, .ReleaseSmall => asm volatile ("ud2"),
//    }
//}

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

//pub fn outOfFuelHandler() align(16) callconv(.naked) Transition {
//    asm volatile (
//        \\
//        // 1st argument
//        \\movq %%rax, %%rdi
//        // 3rd argument
//        \\movq %%rsi, %%rdx
//        // 2nd argument
//        \\movq %%r10, %%rsi
//        // 4th argument
//        \\movq %%rbx, %%rcx
//        // 5th argument
//        \\movq %%r9, %%r8
//        \\movq %%rbp, %%rsp
//        \\popq %%rbp
//        \\jmp %[oof:P]
//        \\ud2
//        :
//        // Zig x86_64 backend (probably) writes this to `%rax`
//        : [oof] "X" (&interruptOutOfFuel),
//    );
//}

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
