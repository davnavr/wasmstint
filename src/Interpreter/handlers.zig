const portable = @import("handlers/portable.zig");
const x86_64_sysv = @import("handlers/x86_64_sysv.zig");

const use_assembly: bool = @import("options").use_assembly_interpreter;

const implementation = if (use_assembly)
    switch (builtin.cpu.arch) {
        .x86_64 => if (!std.Target.x86.featureSetHas(builtin.cpu.features, .sse2))
            @compileError("SSE2 is required to use the x86-64 assembly interpreter")
        else if (builtin.os.tag == .linux)
            x86_64_sysv
        else
            @compileError("x86-64 assembly interpreter implementation cannot be used on " ++
                @tagName(builtin.os.tag)),
        else => |bad| @compileError("no assembly interpreter implementation for " ++
            @tagName(bad)),
    }
else
    portable;

/// Use `callOpcodeHandler()`
pub const OpcodeHandler = implementation.OpcodeHandler;
pub const outOfFuelHandler = implementation.outOfFuelHandler;
pub const byte_dispatch_table = &implementation.byte_dispatch_table;
pub const callOpcodeHandler = implementation.callOpcodeHandler;

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

fn dispatchTableLength(comptime Opcode: type, comptime manual_len: usize) comptime_int {
    var maximum = 0;
    for (@typeInfo(Opcode).@"enum".fields) |op| {
        maximum = @max(maximum, op.value);
    }

    const actual_len = maximum + 1;
    std.debug.assert(actual_len <= manual_len);

    return switch (builtin.mode) {
        .ReleaseSafe => manual_len, // optimization should remove bounds checks
        .Debug, .ReleaseFast, .ReleaseSmall => actual_len,
    };
}

/// If the handler is not appearing in this table, make sure it is public first.
pub fn dispatchTable(
    comptime Opcode: type,
    /// Namespace containing the opcode handler functions.
    ///
    /// Opcode handler functions should be marked `pub`.
    comptime handler_namespace: type,
    /// Must not be `undefined`, as this seems to cause a crash in the Zig compiler.
    comptime invalid: *const OpcodeHandler,
    comptime manual_length: usize,
) [dispatchTableLength(Opcode, manual_length)]*const OpcodeHandler {
    var table: [dispatchTableLength(Opcode, manual_length)]*const OpcodeHandler = @splat(invalid);
    for (std.enums.values(Opcode)) |op| {
        const name = @tagName(op);
        // TODO: Remove this when x64 asm impl is done
        if (!use_assembly or @hasDecl(handler_namespace, name)) {
            table[@intFromEnum(op)] = @as(*const OpcodeHandler, @field(handler_namespace, name));
        }
    }
    return table;
}

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

/// Attempts to allocate a stack frame for the `target_function`, with arguments expected to be on
/// top of the value stack, and then resumes execution.
///
/// To ensure the interpreter cannot overflow the stack, opcode handlers must ensure this function
/// is called inline.
///
/// If enough stack space is not available, then the interpreter is interrupted and the IP is set to
/// `call_ip`, which is a pointer to the call instruction to restart.
pub inline fn invokeWithinWasm(
    old_instr: Instr,
    /// Pointer to the byte containing the call opcode.
    call_ip: Ip,
    /// Stores the stack before the `call` instruction was executed. Parameters to pass to the
    /// `callee` begin at the bottom at index `0`.
    ///
    /// Restored if a `.call_stack_exhausted` interrupt occurred.
    saved_sp: Stack.Saved,
    fuel: *Interpreter.Fuel,
    old_stp: Stp,
    interp: *Interpreter,
    callee: runtime.FuncInst,
    comptime dispatchNextOpcode: fn (
        Instr,
        Stack.Top,
        *Interpreter.Fuel,
        Stp,
        Locals,
        runtime.ModuleInst,
        *Interpreter,
    ) callconv(.@"inline") Transition,
) Transition {
    var coz_begin = coz.begin("wasmstint.Interpreter.invokeWithinWasm");
    defer coz_begin.end();

    const signature = callee.signature();

    // Overlap trick to avoid copying arguments.
    const args: []align(@sizeOf(Value)) Value = @constCast(
        saved_sp.poppedValues()[0..signature.param_count],
    );
    const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;

    const saved_token = updateWasmFrameState(current_frame, old_instr, old_stp);
    // std.debug.print(
    //     "WASM {f} WANTS TO CALL {f} (call_depth = {}, args @ {*}, fuel = {})\n",
    //     .{ current_frame.function, callee, interp.stack.call_depth, args, fuel.remaining },
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

    // std.log.debug(
    //     "CALLING {f} @ {*} called by {f}",
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
            return dispatchNextOpcode(
                Instr.init(new_frame.frame.wasm.ip, new_frame.frame.wasm.eip),
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
            // std.log.debug(
            //     "new_frame.top() = {*}, args = {*}",
            //     .{ new_frame.top().ptr, args.ptr },
            // );
            return Transition.awaitingHost(
                new_frame.top(),
                interp,
                &host.signature,
                .calling_host,
                saved_token,
            );
        },
    }
}

/// Is a `packed struct` to work around https://github.com/ziglang/zig/issues/18189
pub const Transition = packed struct(u32) {
    version: Version,
    // Can't use `u0` here
    // TODO(Zig): https://github.com/ziglang/zig/issues/25846
    //update_wasm_frame_token: UpdateWasmFrameToken,

    const UpdateWasmFrameToken = enum(u0) {
        wrote_ip_and_stp_to_the_current_stack_frame,
    };

    pub fn trapAt(
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
        return trapAt(calculateTrapIp(base_ip, opcode_prefix), eip, sp, stp, interp, info);
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
const coz = @import("coz");

const Instr = @import("Instr.zig");
const Interpreter = @import("../Interpreter.zig");
const Stack = @import("Stack.zig");
const Trap = @import("Trap.zig");
const Value = @import("value.zig").Value;
const Version = @import("version.zig").Version;

const opcodes = @import("opcodes");
const runtime = @import("../runtime.zig");
const Module = @import("../Module.zig");
const SideTable = @import("side_table.zig").SideTable;
