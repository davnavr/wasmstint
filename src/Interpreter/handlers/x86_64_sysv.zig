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
    std.debug.assert(@offsetOf(@FieldType(ModuleInner, "raw"), "datas_ptrs") == 232);
    std.debug.assert(@offsetOf(@FieldType(ModuleInner, "raw"), "datas_lens") == 240);
    std.debug.assert(@offsetOf(runtime.ModuleInst.Header, "tables") == 40);
    std.debug.assert(@offsetOf(runtime.ModuleInst.Header, "globals") == 48);
    std.debug.assert(@offsetOf(runtime.ModuleInst.Header, "datas_drop_mask") == 56);
    std.debug.assert(@offsetOf(runtime.ModuleInst.Header, "elems_drop_mask") == 64);
    std.debug.assert(@sizeOf(Module.GlobalType) == 2);
    std.debug.assert(@offsetOf(Module.GlobalType, "val_type") == 0);
    std.debug.assert(@offsetOf(runtime.TableInst, "base") == 0);
    std.debug.assert(@offsetOf(runtime.TableInst, "len") == 12);
    std.debug.assert(@offsetOf(runtime.TableInst, "capacity") == 16);
    std.debug.assert(@offsetOf(runtime.TableInst, "limit") == 20);
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
    *const OpcodeHandler,
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

fn panicInvalidPrefixedOpcode(ip: Ip, eip: Eip, prefix_ip: Ip) callconv(sysvcc) noreturn {
    @branchHint(.cold);
    const opcode_bytes = prefix_ip[0 .. ip - prefix_ip];

    const FormatInvalidInstruction = struct {
        opcode_bytes: []const u8,

        pub fn format(f: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const prefix_byte = f.opcode_bytes[0];
            for (0.., f.opcode_bytes) |i, b| {
                if (i > 0) {
                    try writer.writeByte(' ');
                }

                try writer.print("{X:0>2}", .{b});
            }

            const numeric_opcode = opcode: {
                var numeric_value: u32 = 0;
                var leb_bytes = f.opcode_bytes[1..];
                for (0..5) |i| {
                    const byte = if (leb_bytes.len == 0) return else leb_bytes[0];
                    leb_bytes = leb_bytes[1..];
                    numeric_value |= std.math.shlExact(
                        u32,
                        byte & 0x7F,
                        @as(u5, @intCast(i)) * 7,
                    ) catch return;
                    if (byte & 0x80 == 0) {
                        break :opcode numeric_value;
                    }
                }

                return;
            };

            try writer.print(" #{d}", .{numeric_opcode});

            const name: ?[]const u8 = name: switch (prefix_byte) {
                0xFC => @tagName(
                    std.meta.intToEnum(opcodes.FCPrefixOpcode, numeric_opcode) catch
                        break :name null,
                ),
                0xFD => @tagName(
                    std.meta.intToEnum(opcodes.FDPrefixOpcode, numeric_opcode) catch
                        break :name null,
                ),
                else => null,
            };

            if (name) |known| {
                try writer.print(" ({s})", .{known});
            }
        }
    };

    std.debug.panic(
        "invalid instruction {f} @ {X}, EIP={X}",
        .{
            FormatInvalidInstruction{ .opcode_bytes = opcode_bytes },
            @intFromPtr(prefix_ip),
            @intFromPtr(eip),
        },
    );
}

comptime {
    switch (builtin.mode) {
        .Debug, .ReleaseSafe => for (&[_][]const u8{
            "panicInvalidByteOpcode",
            "panicInvalidPrefixedOpcode",
        }) |name| {
            @export(&@field(@This(), name), .{ .name = symbol_prefix ++ name });
        },
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
            @as(@TypeOf(&invokeWithinWasmIndirect), @ptrCast(opcodeHandlerTrampoline)),
            .{
                @as(Ip, @ptrCast(locals.ptr)),
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

const ConstructedFuncRef = extern struct {
    func: runtime.FuncRef.Nullable, // rax
    current_module: runtime.ModuleInst, // stays in rdx
};

fn constructFuncRef(
    func_index: usize, // rdi
    _: usize, // rsi
    module: runtime.ModuleInst, // stays in rdx
) callconv(sysvcc) ConstructedFuncRef {
    const func_idx: Module.FuncIdx = @enumFromInt(func_index);
    return .{
        .func = @as(runtime.FuncRef.Nullable, @bitCast(module.inner.funcRef(func_idx))),
        .current_module = module,
    };
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

fn tableGrowReallocate(
    new_len: u32, // rdi
    /// `sp[0]` is the element to replicate.
    ///
    /// `sp - 1` refers to `(i32.const -1)`, indicating growth failure.
    sp: Sp, // rsi
    ip: Ip, // rdx,
    eip: Eip, // rcx
    table: *runtime.TableInst, // r8
    interp: *Interpreter, // r9
    // These parameters are passed on the stack
    stp: Stp, // `rbp + 16`
    _: usize, // `rbp + 24`,
    _: usize, // `rbp + 32`
    _: usize, // `rbp + 40`
    _: usize, // `rbp + 48`
) callconv(sysvcc) Transition {
    const result = &(sp.ptr - 1)[0];
    std.debug.assert(result.i32 == -1);
    return Transition.interrupted(.init(ip, eip), sp, stp, interp, .{
        .table_grow = .{
            .old_len = table.len,
            .new_len = @intCast(new_len),
            .table = table,
            .elem = &sp.ptr[0],
        },
    });
}

const TableInitIndices = packed struct(u64) {
    table: u32,
    elem: u32,
};

fn tableInit(
    indices: TableInitIndices, // rdi
    sp: Sp, // rsi
    module: runtime.ModuleInst, // rdx,
    fuel: *Interpreter.Fuel, // rcx
    next_ip: Ip, // rax -> r8
    interp: *Interpreter, // r9
    // These parameters are passed on the stack
    /// Needs to allow passing `Ip` on tail call.
    unaligned_stp: [*]align(1) const Module.Code.SideTableEntry, // rbx -> `rbp + 16`
    eip: Eip, // r10 -> `rbp + 24`
    trap_ip: Ip, // `rbp + 32`
    _: usize, // `rbp + 40`
    _: usize, // `rbp + 48`
) callconv(sysvcc) Transition {
    const stp: Stp = @alignCast(unaligned_stp);
    const current_frame = interp.stack.frameAt(interp.stack.current_frame).?;
    if (builtin.mode == .Debug) {
        const expected_eip = @intFromPtr(current_frame.wasm.eip);
        if (expected_eip != @intFromPtr(eip)) {
            std.debug.panic("expected EIP 0x{X}, got 0x{X}", .{ expected_eip, @intFromPtr(eip) });
        }
        std.debug.assert(@intFromPtr(trap_ip) < @intFromPtr(next_ip));
        std.debug.assert(@intFromPtr(next_ip) <= @intFromPtr(eip));
        std.debug.assert( // bad module ptr
            @intFromPtr(current_frame.function.expanded().wasm.module.inner) ==
                @intFromPtr(module.inner),
        );
    }

    // Just copies what the portable interpreter does
    var vals = Stack.Values.init(
        sp,
        &interp.stack,
        3,
        @max(3, module.header().module.elementSegments()[indices.elem].header.elem_max_stack),
    );

    const operands = vals.popArray(3);
    vals.assertRemainingCountIs(0);
    const n: u32 = @bitCast(operands[2].i32);
    const src_idx: u32 = @bitCast(operands[1].i32);
    const d: u32 = @bitCast(operands[0].i32);
    @memset(operands, undefined);

    const table_idx: Module.TableIdx = @enumFromInt(indices.table);
    runtime.TableInst.init(
        table_idx,
        module,
        @enumFromInt(indices.elem),
        n,
        src_idx,
        d,
        vals.unallocated(&interp.stack),
    ) catch |e| switch (e) {
        error.TableAccessOutOfBounds => {
            const info = Interpreter.Trap.init(
                .table_access_out_of_bounds,
                .init(table_idx, .@"table.init"),
            );
            return Transition.trap(trap_ip, .{ .fc = .@"table.init" }, eip, vals.top, stp, interp, info);
        },
    };

    var instr = Instr.init(next_ip, eip);
    if (builtin.zig_backend == .stage2_x86_64) {
        // trampoline continues execution
        return Transition.interrupted(instr, vals.top, stp, interp, .out_of_fuel);
    } else {
        const locals = common.Locals{ .ptr = current_frame.localValues(&interp.stack).ptr };
        const handler = instr.readNextOpcodeHandler(fuel, locals, module, interp);
        // TODO: inlineLlvmTailCallToHandler()
        return @call(
            .always_tail,
            @as(@TypeOf(&tableInit), @ptrCast(opcodeHandlerTrampoline)),
            .{
                @as(TableInitIndices, @bitCast(locals)),
                vals.top,
                module,
                fuel,
                @as(Ip, @ptrCast(module.header().mems)),
                interp,
                @as([*]align(1) const Module.Code.SideTableEntry, @ptrCast(@alignCast(instr.next))),
                @as(Eip, @ptrCast(stp)),
                @as(Ip, @ptrFromInt(@intFromPtr(instr.end))),
                @intFromPtr(handler),
                undefined,
            },
        );
    }
}

fn trapUnreachable(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    _: usize, // r8 (unused)
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    return Transition.trapAt(trap_ip, eip, sp, stp, interp, .init(.unreachable_code_reached, {}));
}

fn trapCallIndirectAccessOob(
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

fn trapInvalidConversionToInteger(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    _: usize, // r8 (unused)
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    return Transition.trapAt(trap_ip, eip, sp, stp, interp, .init(.invalid_conversion_to_integer, {}));
}

fn trapMemoryAccessOutOfBounds(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    mem_idx: usize, // r8
    interp: *Interpreter, // stays in r9
    // These parameters are passed on the stack
    address: u32, // rbp + 16
    size: u8, // rbp + 24
    memory: *const runtime.MemInst, // rbp + 32
) callconv(sysvcc) Transition {
    @branchHint(.cold);
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

fn trapMemoryInitOutOfBounds(
    ip: Ip, // rax -> rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    mem_idx: usize, // r8
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    @branchHint(.cold);
    return Transition.trap(
        ip,
        .{ .fc = .@"memory.init" },
        eip,
        sp,
        stp,
        interp,
        .init(.memory_access_out_of_bounds, .init(@enumFromInt(mem_idx), .@"memory.init", {})),
    );
}

fn trapMemoryCopyOutOfBounds(
    ip: Ip, // rax -> rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    mem_idx: usize, // r8
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    @branchHint(.cold);
    return Transition.trap(
        ip,
        .{ .fc = .@"memory.copy" },
        eip,
        sp,
        stp,
        interp,
        .init(.memory_access_out_of_bounds, .init(@enumFromInt(mem_idx), .@"memory.copy", {})),
    );
}

fn trapMemoryFillOutOfBounds(
    ip: Ip, // rax -> rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    mem_idx: usize, // r8
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    @branchHint(.cold);
    return Transition.trap(
        ip,
        .{ .fc = .@"memory.fill" },
        eip,
        sp,
        stp,
        interp,
        .init(.memory_access_out_of_bounds, .init(@enumFromInt(mem_idx), .@"memory.fill", {})),
    );
}

fn trapTableAccessOutOfBounds(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    table_idx: usize, // r8
    interp: *Interpreter, // stays in r9
    // These parameters are passed on the stack
    index: u32, // rbp + 16
    cause: enum(usize) { @"table.get" = 0, @"table.set" = 1 }, // rbp + 24
    table: *const runtime.TableInst, // rbp + 32
) callconv(sysvcc) Transition {
    @branchHint(.cold);
    return Transition.trapAt(
        trap_ip,
        eip,
        sp,
        stp,
        interp,
        .init(.table_access_out_of_bounds, .init(@enumFromInt(table_idx), switch (cause) {
            inline else => |trap_cause| @unionInit(
                Interpreter.Trap.TableAccessOutOfBounds.Cause,
                @tagName(trap_cause),
                .{ .index = index, .maximum = table.len },
            ),
        })),
    );
}

fn trapTableCopyOutOfBounds(
    ip: Ip, // rax -> rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    table_idx: usize, // r8
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    @branchHint(.cold);
    const info = Interpreter.Trap.init(
        .table_access_out_of_bounds,
        .init(@enumFromInt(table_idx), .@"table.copy"),
    );
    return Transition.trap(ip, .{ .fc = .@"table.copy" }, eip, sp, stp, interp, info);
}

fn trapTableFillOutOfBounds(
    trap_ip: Ip, // rdi
    sp: Sp, // stays in rsi
    eip: Eip, // r10 -> rdx
    stp: Stp, // rbx -> rcx
    table_idx: usize, // r8
    interp: *Interpreter, // stays in r9
) callconv(sysvcc) Transition {
    @branchHint(.cold);
    return Transition.trap(trap_ip, .{ .fc = .@"table.fill" }, eip, sp, stp, interp, .init(
        .table_access_out_of_bounds,
        .init(@enumFromInt(table_idx), .@"table.fill"),
    ));
}

const generated = @import("asm_generated");
const generated_handlers = generated.handlers(*const OpcodeHandler);

pub const byte_dispatch_table align(64) = common.dispatchTable(
    opcodes.ByteOpcode,
    generated_handlers,
    invalidByteOpcode,
    256,
);

const invalidPrefixedOpcode: *const OpcodeHandler = switch (builtin.mode) {
    .Debug, .ReleaseSafe => @extern(
        *align(16) const OpcodeHandler,
        .{ .name = symbol_prefix ++ "invalidPrefixedOpcode" },
    ),
    .ReleaseFast, .ReleaseSmall => invalidByteOpcode,
};

pub const fc_prefix_dispatch_table align(64) = common.dispatchTable(
    opcodes.FCPrefixOpcode,
    generated_handlers,
    invalidPrefixedOpcode,
    std.math.maxInt(u5),
);

comptime {
    for (&[_][]const u8{
        "interruptOutOfFuel",
        "returnFromWasm",
        "invokeWithinWasm",
        "invokeWithinWasmIndirect",
        "constructFuncRef",
        "memoryGrowReallocate",
        "tableGrowReallocate",
        "tableInit",
        "trapUnreachable",
        "trapIntegerDivisionByZero",
        "trapIntegerOverflow",
        "trapInvalidConversionToInteger",
        "trapMemoryAccessOutOfBounds",
        "trapMemoryInitOutOfBounds",
        "trapMemoryCopyOutOfBounds",
        "trapMemoryFillOutOfBounds",
        "trapTableAccessOutOfBounds",
        "trapTableCopyOutOfBounds",
        "trapTableFillOutOfBounds",
        "trapCallIndirectAccessOob",
        "trapIndirectCallToNull",
        "byte_dispatch_table",
        "fc_prefix_dispatch_table",
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
