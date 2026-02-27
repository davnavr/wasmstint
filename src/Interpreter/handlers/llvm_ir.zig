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

// TODO: use inline asm to call this w/ x86_64_regcall_v3_sysv
/// Sets up a stack frame for the assembly opcode handler, before invoking it.
const opcodeHandlerTrampoline = @extern(
    *const fn (
        locals: common.Locals,
        vsp: Sp,
        module: runtime.ModuleInst,
        fuel: *const Interpreter.Fuel,
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
        "VIP={*}, EIP={*}, VSP={*}, LOC={*}, MODULE={*}, STP={*}",
        .{ instr.next, instr.end, ctx.stack_top.ptr, locals.ptr, module.inner, stp },
    ); // TODO: remove this
    return opcodeHandlerTrampoline(
        locals,
        ctx.stack_top,
        module,
        fuel,
        ctx,
        instr.next,
        stp,
        instr.end,
        handler,
    );
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

const UpdateState = extern union {
    transition: Transition,
    to_wasm: ToWasm,

    const ToWasm = extern struct {
        locals: common.Locals,
        vsp: Sp,
        module: runtime.ModuleInst,
        // fuel never changes
        // memories derived from `module`
        // ctx never changes
        // vip, stp, eip provided in return value
        // caller knows disp
    };
};

/// Returns `null` if control returned to the host (when the call stack is empty, or the caller was
/// a host function).
fn returnFromWasm(
    output: *UpdateState,
    old_vsp: Sp,
    ctx: *Interpreter,
    old_eip_debug: Eip,
) callconv(ffi_cc) ?*const Stack.Frame.Wasm {
    const popped = ctx.stack.popFrame(old_vsp, .from_stack_top);
    if (builtin.mode == .Debug) {
        const expected_eip = @intFromPtr(popped.info.wasm.eip);
        const actual_eip = @intFromPtr(old_eip_debug);
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
                output.* = .{
                    .to_wasm = .{
                        .locals = common.Locals{ .ptr = frame.localValues(&ctx.stack).ptr },
                        .vsp = popped.top,
                        .module = wasm.module,
                    },
                };
                return &frame.wasm;
            },
            .host => break :return_to_host,
        }

        comptime unreachable;
    }

    output.* = .{
        .transition = Transition.awaitingHost(
            popped.top,
            ctx,
            popped.signature,
            .returning_to_host,
            // no need to save, since this returns to host
            .wrote_ip_and_stp_to_the_current_stack_frame,
        ),
    };
    return null;
}

const InvokeWithinWasmCallback = struct {
    pub const Result = ?*const Stack.Frame.Wasm;

    state: *UpdateState,

    inline fn transitionIntoHost(out: InvokeWithinWasmCallback, transition: Transition) Result {
        out.state.* = .{ .transition = transition };
        return null;
    }

    pub const callStackExhaustion = transitionIntoHost;
    pub const intoHostFunction = transitionIntoHost;

    pub inline fn intoWasmFunction(
        out: InvokeWithinWasmCallback,
        new_frame: Stack.PushedFrame,
        _: *Interpreter.Fuel,
        locals: common.Locals,
        module: runtime.ModuleInst,
        _: *Interpreter,
    ) Result {
        out.state.* = .{
            .to_wasm = .{ .locals = locals, .vsp = new_frame.top(), .module = module },
        };
        return &new_frame.frame.wasm;
    }
};

fn invokeWithinWasm(
    output: *UpdateState,
    call_ip: Ip,
    vsp: Sp,
    module: runtime.ModuleInst,
    fuel: *Interpreter.Fuel,
    ctx: *Interpreter,
    vip: Ip,
    stp: Stp,
    eip: Eip,
    func_idx: usize,
) callconv(ffi_cc) ?*const Stack.Frame.Wasm {
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
        const current_frame = ctx.stack.currentFrame().?;
        const expected_eip = @intFromPtr(current_frame.wasm.eip);
        const actual_eip = @intFromPtr(eip);
        if (expected_eip != actual_eip) {
            std.debug.panic("expected EIP={X}, got {X}", .{ expected_eip, actual_eip });
        }
    }

    const callee = module.inner.funcInst(@enumFromInt(func_idx));
    const arg_count = callee.signature().param_count;
    const saved_sp = Stack.Saved.pop(
        Stack.Values.init(vsp, &ctx.stack, arg_count, arg_count),
        arg_count,
    );

    return common.invokeWithinWasmWithCallbacks(
        Instr.init(vip, eip),
        call_ip,
        saved_sp,
        fuel,
        stp,
        ctx,
        callee,
        InvokeWithinWasmCallback{ .state = output },
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
