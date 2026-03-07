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
    func_idx: u32,
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

fn invokeWithinWasmIndirect(
    output: *UpdateState,
    call_ip: Ip,
    /// Does not have the `i32` index popped.
    vsp: Sp,
    callee: runtime.FuncRef,
    fuel: *Interpreter.Fuel,
    ctx: *Interpreter,
    vip: Ip,
    stp: Stp,
    eip: Eip,
    expected_signature: *const Module.FuncType,
) callconv(ffi_cc) ?*const Stack.Frame.Wasm {
    switch (@as(opcodes.ByteOpcode, @enumFromInt(call_ip[0]))) {
        .call_indirect => {},
        else => |bad| switch (builtin.mode) {
            .Debug, .ReleaseSafe => std.debug.panic(
                "{t} (0x{X:0>2}) is not a valid indirect call instruction",
                .{ bad, @intFromEnum(bad) },
            ),
            .ReleaseFast, .ReleaseSmall => unreachable,
        },
    }

    const pop_count = 1 + expected_signature.param_count;
    const saved_sp = Stack.Saved.pop(
        Stack.Values.init(vsp, &ctx.stack, pop_count, pop_count),
        pop_count,
    );

    const actual_signature = callee.signature();
    if (!expected_signature.matches(actual_signature)) {
        const info = Interpreter.Trap.init(
            .indirect_call_signature_mismatch,
            .{ .expected = expected_signature, .actual = actual_signature },
        );

        output.* = .{ .transition = Transition.trap(vip, .none, eip, vsp, stp, ctx, info) };
        return null;
    }

    return common.invokeWithinWasmWithCallbacks(
        Instr.init(vip, eip),
        call_ip,
        saved_sp,
        fuel,
        stp,
        ctx,
        callee.funcInst(),
        InvokeWithinWasmCallback{ .state = output },
    );
}

fn finishInvokeWithinWasm(
    output: *UpdateState,
    ctx: *Interpreter,
    callee: runtime.FuncInst,
    new_frame: *const Stack.PushedFrame,
) ?*Stack.Frame.Wasm {
    switch (callee.expanded()) {
        .wasm => |wasm| {
            output.* = .{
                .to_wasm = .{
                    .locals = .{ .ptr = new_frame.frame.localValues(&ctx.stack).ptr },
                    .vsp = new_frame.top(),
                    .module = wasm.module,
                },
            };
            return &new_frame.frame.wasm;
        },
        .host => |host| {
            output.* = .{
                .transition = Transition.awaitingHost(
                    new_frame.top(),
                    ctx,
                    &host.signature,
                    .calling_host,
                    .wrote_ip_and_stp_to_the_current_stack_frame,
                ),
            };
            return null;
        },
    }
}

fn tailCallWithinWasm(
    output: *UpdateState,
    call_ip: Ip,
    vsp: Sp,
    module: runtime.ModuleInst,
    ctx: *Interpreter,
    stp: Stp,
    eip: Eip,
    func_idx: u32,
) callconv(ffi_cc) ?*const Stack.Frame.Wasm {
    switch (@as(opcodes.ByteOpcode, @enumFromInt(call_ip[0]))) {
        .return_call => {},
        else => |bad| switch (builtin.mode) {
            .Debug, .ReleaseSafe => std.debug.panic(
                "{t} (0x{X:0>2}) is not a valid tail call instruction",
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

    const new_frame = common.replaceTopStackFrame(saved_sp, 0, ctx, callee) catch |e| switch (e) {
        // Not enough room for new stack frame
        error.OutOfMemory => {
            const oom = Transition.callStackExhaustion(call_ip, eip, saved_sp, stp, ctx, callee);
            output.* = .{ .transition = oom };
            return null;
        },
    };

    return finishInvokeWithinWasm(output, ctx, callee, &new_frame);
}

fn tailCallWithinWasmIndirect(
    output: *UpdateState,
    call_ip: Ip,
    /// Does not have the `i32` index popped.
    vsp: Sp,
    callee: runtime.FuncRef,
    ctx: *Interpreter,
    vip: Ip,
    stp: Stp,
    eip: Eip,
    expected_signature: *const Module.FuncType,
) callconv(ffi_cc) ?*const Stack.Frame.Wasm {
    switch (@as(opcodes.ByteOpcode, @enumFromInt(call_ip[0]))) {
        .return_call_indirect => {},
        else => |bad| switch (builtin.mode) {
            .Debug, .ReleaseSafe => std.debug.panic(
                "{t} (0x{X:0>2}) is not a valid indirect tail call instruction",
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

    const pop_count = 1 + expected_signature.param_count;
    const saved_sp = Stack.Saved.pop(
        Stack.Values.init(vsp, &ctx.stack, pop_count, pop_count),
        pop_count,
    );

    const actual_signature = callee.signature();
    if (!expected_signature.matches(actual_signature)) {
        const info = Interpreter.Trap.init(
            .indirect_call_signature_mismatch,
            .{ .expected = expected_signature, .actual = actual_signature },
        );

        output.* = .{ .transition = Transition.trap(vip, .none, eip, vsp, stp, ctx, info) };
        return null;
    }

    const func = callee.funcInst();
    const new_frame = common.replaceTopStackFrame(saved_sp, 1, ctx, func) catch |e| switch (e) {
        // Not enough room for new stack frame
        error.OutOfMemory => {
            const oom = Transition.callStackExhaustion(call_ip, eip, saved_sp, stp, ctx, func);
            output.* = .{ .transition = oom };
            return null;
        },
    };

    return finishInvokeWithinWasm(output, ctx, func, &new_frame);
}

// TODO: Common comptime helper for invoke helper functions (common code between normal and non-tail call versions)

fn memoryGrowReallocate(
    new_size: usize,
    /// `vsp - 1` refers to `(i32.const -1)`, indicating growth failure.
    vsp: Sp,
    vip: Ip,
    eip: Eip,
    /// Pointer to memory to grow
    mem: *runtime.MemInst,
    ctx: *Interpreter,
    stp: Stp,
) callconv(ffi_cc) Transition {
    const result = &(vsp.ptr - 1)[0];
    std.debug.assert(result.i32 == -1);
    return Transition.interrupted(.init(vip, eip), vsp, stp, ctx, .{
        .memory_grow = .{
            .old_size = mem.size,
            .new_size = new_size,
            .memory = mem,
            .result = result,
        },
    });
}

fn tableGrowReallocate(
    new_len: u32,
    /// `vsp - 1` is the element to replicate, and where the `i32` result is stored.
    vsp: Sp,
    vip: Ip,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    table: *runtime.TableInst,
) callconv(ffi_cc) Transition {
    return Transition.interrupted(.init(vip, eip), vsp, stp, ctx, .{
        .table_grow = .{
            .old_len = table.len,
            .new_len = @intCast(new_len),
            .table = table,
            .elem = &(vsp.ptr - 1)[0],
        },
    });
}

const TableInitStatus = enum(usize) {
    success = 0,
    out_of_bounds = 1,
};

fn tableInit(
    /// Number of elements to initialize.
    n: u32,
    src_idx: u32,
    dst_idx: u32,
    /// The 3 operands to `table.init` are already popped.
    vsp: Sp,
    module: runtime.ModuleInst,
    table_idx_raw: u32,
    elem_idx_raw: u32,
) callconv(ffi_cc) TableInitStatus {
    const table_idx: Module.TableIdx = @enumFromInt(table_idx_raw);
    const buffer_len = module.header().module.elementSegments()[elem_idx_raw].header.elem_max_stack;
    const buffer = vsp.ptr[0..buffer_len];
    @memset(buffer, undefined);
    runtime.TableInst.init(
        table_idx,
        module,
        @enumFromInt(elem_idx_raw),
        n,
        src_idx,
        dst_idx,
        buffer,
    ) catch |e| switch (e) {
        error.TableAccessOutOfBounds => return .out_of_bounds,
    };

    return .success;
}

fn constructFuncRef(
    func_index: i32,
    module: runtime.ModuleInst,
) callconv(ffi_cc) runtime.FuncRef.Nullable {
    return @as(
        runtime.FuncRef.Nullable,
        @bitCast(module.inner.funcRef(@enumFromInt(func_index))),
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

fn trapMemoryFillOutOfBounds(
    vip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    mem_idx: usize,
    ctx: *Interpreter,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    return Transition.trap(
        vip,
        .{ .fc = .@"memory.fill" },
        eip,
        vsp,
        stp,
        ctx,
        .init(.memory_access_out_of_bounds, .init(@enumFromInt(mem_idx), .@"memory.fill", {})),
    );
}

fn trapMemoryInitOutOfBounds(
    vip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    mem_idx: usize,
    data_idx: usize,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    _ = @as(Module.DataIdx, @enumFromInt(data_idx));
    return Transition.trap(
        vip,
        .{ .fc = .@"memory.init" },
        eip,
        vsp,
        stp,
        ctx,
        .init(.memory_access_out_of_bounds, .init(@enumFromInt(mem_idx), .@"memory.init", {})),
    );
}

fn trapMemoryCopyOutOfBounds(
    vip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    interp: *Interpreter,
    src_mem: usize,
    dst_mem: usize,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    std.debug.assert(src_mem == dst_mem);
    return Transition.trap(
        vip,
        .{ .fc = .@"memory.copy" },
        eip,
        vsp,
        stp,
        interp,
        .init(.memory_access_out_of_bounds, .init(@enumFromInt(src_mem), .@"memory.copy", {})),
    );
}

fn trapTableAccessOutOfBounds(
    trap_ip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    table: *const runtime.TableInst,
    index: u32,
    info_bits: u8,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    const Info = packed struct(u8) {
        table: Module.TableIdx,
        cause: enum(u1) { @"table.get" = 0, @"table.set" = 1 },
    };

    const access_info: Info = @bitCast(info_bits);
    const trap_info = Trap.init(
        .table_access_out_of_bounds,
        Trap.TableAccessOutOfBounds.init(access_info.table, switch (access_info.cause) {
            inline else => |trap_cause| @unionInit(
                Trap.TableAccessOutOfBounds.Cause,
                @tagName(trap_cause),
                .{ .index = index, .maximum = table.len },
            ),
        }),
    );

    return Transition.trapAt(
        trap_ip,
        eip,
        vsp,
        stp,
        ctx,
        trap_info,
    );
}

fn trapTableCopyOutOfBounds(
    vip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    src_table_idx: u32,
    dst_table_idx: u32,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    _ = dst_table_idx;
    const info = Trap.init(
        .table_access_out_of_bounds,
        // Include both indices eventually
        Trap.TableAccessOutOfBounds.init(@enumFromInt(src_table_idx), .@"table.copy"),
    );

    return Transition.trap(vip, .{ .fc = .@"table.copy" }, eip, vsp, stp, ctx, info);
}

fn trapTableFillOutOfBounds(
    trap_ip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    table_idx: u32,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    const oob_info = Trap.TableAccessOutOfBounds.init(@enumFromInt(table_idx), .@"table.fill");
    const info = Trap.init(.table_access_out_of_bounds, oob_info);
    return Transition.trap(trap_ip, .{ .fc = .@"table.fill" }, eip, vsp, stp, ctx, info);
}

fn trapTableInitOutOfBounds(
    trap_ip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    ctx: *Interpreter,
    table_idx: u32,
    data_idx: u32,
) callconv(ffi_cc) Transition {
    @branchHint(.cold);
    _ = data_idx;
    const info = Trap.init(.table_access_out_of_bounds, .init(@enumFromInt(table_idx), .@"table.init"));
    return Transition.trap(trap_ip, .{ .fc = .@"table.init" }, eip, vsp, stp, ctx, info);
}

fn trapCallIndirectAccessOob(
    trap_ip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    table_idx: usize,
    ctx: *Interpreter,
) callconv(ffi_cc) Transition {
    const oob_info = Trap.TableAccessOutOfBounds.init(@enumFromInt(table_idx), .call_indirect);
    const info = Interpreter.Trap.init(.table_access_out_of_bounds, oob_info);
    return Transition.trap(trap_ip, .none, eip, vsp, stp, ctx, info);
}

fn trapIndirectCallToNull(
    trap_ip: Ip,
    vsp: Sp,
    eip: Eip,
    stp: Stp,
    elem_idx: usize,
    ctx: *Interpreter,
) callconv(ffi_cc) Transition {
    const info = Interpreter.Trap.init(.indirect_call_to_null, .{ .index = @intCast(elem_idx) });
    return Transition.trap(trap_ip, .none, eip, vsp, stp, ctx, info);
}

comptime {
    for (&[_][]const u8{
        "interruptOutOfFuel",
        "invokeWithinWasm",
        "invokeWithinWasmIndirect",
        "returnFromWasm",
        "tailCallWithinWasm",
        "tailCallWithinWasmIndirect",
        "memoryGrowReallocate",
        "tableGrowReallocate",
        "tableInit",
        "constructFuncRef",
        "trapWithNumericCode",
        "trapMemoryAccessOutOfBounds",
        "trapMemoryFillOutOfBounds",
        "trapMemoryInitOutOfBounds",
        "trapMemoryCopyOutOfBounds",
        "trapTableAccessOutOfBounds",
        "trapTableCopyOutOfBounds",
        "trapTableFillOutOfBounds",
        "trapTableInitOutOfBounds",
        "trapCallIndirectAccessOob",
        "trapIndirectCallToNull",
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

const FmtOpcodeBytes = struct {
    bytes: []const u8,

    pub fn format(f: FmtOpcodeBytes, out: *std.Io.Writer) std.Io.Writer.Error!void {
        for (0.., f.bytes) |i, b| {
            if (i == 0) {
                try out.writeAll("0x");
            } else {
                try out.writeByte(' ');
            }

            try out.writeAll(&std.fmt.bytesToHex([1]u8{b}, .upper));
        }
    }
};

const FmtInvalidPrefixedOpcodeName = struct {
    name: ?[]const u8,

    pub fn format(f: FmtInvalidPrefixedOpcodeName, out: *std.Io.Writer) std.Io.Writer.Error!void {
        if (f.name) |name| {
            try out.writeAll(name);
            try out.writeByte(',');
        }
    }
};

fn panicInvalidPrefixedOpcode(
    /// Points to first byte after the opcode bytes.
    ip: Ip,
    eip: Eip,
    prefix: usize,
) callconv(ffi_cc) noreturn {
    @branchHint(.cold);
    const prefix_byte: u8 = @intCast(prefix);
    var decoded: u32 = 0;
    const first_opcode_byte, const name: ?[]const u8 = result: {
        for (1..5) |i| {
            const ptr = ip - i;
            decoded = @shlExact(decoded, 7) | @as(u32, ptr[0] & 0x7F);
            const opcode_name = name: switch (prefix_byte) {
                0xFC => @tagName(
                    std.enums.fromInt(opcodes.FCPrefixOpcode, decoded) orelse break :name null,
                ),
                0xFD => @tagName(
                    std.enums.fromInt(opcodes.FDPrefixOpcode, decoded) orelse break :name null,
                ),
                else => unreachable,
            };

            const maybe_prefix = ptr - 1;
            if (maybe_prefix[0] == prefix_byte and (i == 4 or opcode_name != null)) {
                break :result .{ maybe_prefix, opcode_name };
            }
        }

        unreachable;
    };

    std.debug.panic(
        "invalid instruction {[bytes]f} ({[name]f} {[value]d}) @ {[ip]X}, EIP={[eip]X}",
        .{
            .bytes = FmtOpcodeBytes{ .bytes = first_opcode_byte[0 .. ip - first_opcode_byte] },
            .name = FmtInvalidPrefixedOpcodeName{ .name = name },
            .value = decoded,
            .ip = @intFromPtr(first_opcode_byte),
            .eip = @intFromPtr(eip),
        },
    );
}

comptime {
    if (builtin.mode != .ReleaseSmall) {
        for (&[_][]const u8{ "panicInvalidByteOpcode", "panicInvalidPrefixedOpcode" }) |name| {
            @export(&@field(@This(), name), .{ .name = symbol_prefix ++ name });
        }
    }
}

const std = @import("std");
const CallingConvention = std.builtin.CallingConvention;
const builtin = @import("builtin");

const opcodes = @import("opcodes");
const Module = @import("../../Module.zig");

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
