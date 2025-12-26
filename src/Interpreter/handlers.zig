const portable = @import("handlers/portable.zig");
//const x86_64 = @import("handlers/x86_64.zig");

const implementation = portable;

/// Use `callOpcodeHandler()`
pub const OpcodeHandler = implementation.OpcodeHandler;
pub const outOfFuelHandler = implementation.outOfFuelHandler;
pub const byte_dispatch_table = implementation.byte_dispatch_table;

pub inline fn callOpcodeHandler(
    handler: *const OpcodeHandler,
    instr: Instr,
    fuel: *Interpreter.Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
) Transition {
    return handler(
        instr.next,
        interp.stack_top,
        fuel,
        stp,
        locals,
        module,
        interp,
        instr.end,
    );
}

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

pub const Ip = Module.Code.Ip;
pub const Eip = *const Module.Code.End;
/// The value Stack Pointer.
pub const Sp = Stack.Top;
pub const Stp = SideTable.Ptr;

pub inline fn transition(
    interp: *Interpreter,
    update_wasm_frame_token: Transition.UpdateWasmFrameToken,
    new_state: @FieldType(Interpreter, "current_state"),
) Transition {
    _ = update_wasm_frame_token;
    interp.current_state = new_state;
    interp.version.increment();
    return Transition{
        .version = interp.version,
    };
}

pub const OpcodePrefix = union(enum(u8)) {
    none = 0,
    fc: opcodes.FCPrefixOpcode = 0xFC,
    fd: opcodes.FDPrefixOpcode = 0xFD,
};

/// Calculates a pointer to the first byte of the instruction based on a pointer to the first byte
/// after it's opcode.
pub fn calculateTrapIp(base_ip: Ip, comptime prefix: OpcodePrefix) Ip {
    var ip = base_ip - 1;
    switch (prefix) {
        .none => return ip,
        inline .fc, .fd => |opcode| {
            var decoded: u32 = ip[0];
            for (0..4) |_| {
                ip -= 1;
                std.debug.assert(decoded <= @intFromEnum(opcode)); // please check expected opcode
                if (decoded == @intFromEnum(opcode)) {
                    @branchHint(.likely);
                    break;
                }

                decoded <<= 7;
                decoded |= (0x7F & ip[0]);
            } else unreachable;

            std.debug.assert(ip[0] == comptime @intFromEnum(prefix));
            return ip;
        },
    }
}

test calculateTrapIp {
    {
        const bytes = [_:0x0B]u8{ 0xAA, 0xFD, 0x6B, 0xAA };
        try std.testing.expectEqual(
            &bytes[1],
            &calculateTrapIp(bytes[3..], .{ .fd = .@"i8x16.shl" })[0],
        );
    }
    {
        // WASM spec seems to allow over-long instruction opcodes
        const bytes = [_:0x0B]u8{ 0xAA, 0xFD, 0xEB, 0x00, 0xAA };
        try std.testing.expectEqual(
            &bytes[1],
            &calculateTrapIp(bytes[4..], .{ .fd = .@"i8x16.shl" })[0],
        );
    }
    {
        const bytes = [_:0x0B]u8{ 0xAA, 0xFD, 0x0C, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xAA };
        try std.testing.expectEqual(
            &bytes[1],
            &calculateTrapIp(bytes[3..], .{ .fd = .@"v128.const" })[0],
        );
    }
}

/// Asserts that `frame` corresponds to a WASM function.
pub fn updateWasmFrameState(
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
pub const Transition = packed struct {
    version: Version,
    // Can't use `u0` here
    // TODO(Zig): https://github.com/ziglang/zig/issues/25846
    //update_wasm_frame_token: UpdateWasmFrameToken,

    const UpdateWasmFrameToken = enum(u0) {
        wrote_ip_and_stp_to_the_current_stack_frame,
    };

    pub fn trap(
        base_ip: Ip,
        comptime opcode_prefix: OpcodePrefix,
        eip: Eip,
        sp: Sp,
        stp: Stp,
        interp: *Interpreter,
        info: Trap,
    ) Transition {
        @branchHint(.unlikely);
        const trap_ip = calculateTrapIp(base_ip, opcode_prefix);
        interp.stack_top = sp;
        const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;
        return transition(
            interp,
            // Host might want to observe IP of trapping instruction
            updateWasmFrameState(current_frame, Instr.init(trap_ip, eip), stp),
            .{ .trapped = .{ .source = .function_call, .trap = info } },
        );
    }

    pub fn interrupted(
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
    pub fn awaitingHost(
        sp: Sp,
        interp: *Interpreter,
        callee_signature: *const Module.FuncType,
        status: TransitionToHost,
        update_wasm_frame_token: UpdateWasmFrameToken,
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
            update_wasm_frame_token,
            .{ .awaiting_host = .{ .result_types = result_types } },
        );
    }

    pub fn callStackExhaustion(
        call_ip: Ip,
        eip: Eip,
        saved_sp: Stack.Saved,
        stp: Stp,
        interp: *Interpreter,
        callee: runtime.FuncInst,
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

const std = @import("std");
const builtin = @import("builtin");

const Instr = @import("Instr.zig");
const Interpreter = @import("../Interpreter.zig");
const Stack = @import("Stack.zig");
const Trap = @import("Trap.zig");
const Value = @import("value.zig").Value;
const Version = @import("version.zig").Version;

const opcodes = @import("../opcodes.zig");
const runtime = @import("../runtime.zig");
const Module = @import("../Module.zig");
const SideTable = @import("side_table.zig").SideTable;
