//! Generates an assembly `.s` file and a `.zig` file containing `extern fn` definitions
//! to individual opcode handlers.

const stack_space_padding = 8;

pub fn main() !void {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.ioBasic();

    var arena = ArenaAllocator.init(std.heap.page_allocator);
    var scratch = ArenaAllocator.init(std.heap.page_allocator);

    var cli_args = try std.process.ArgIterator.initWithAllocator(scratch.allocator());
    _ = cli_args.next().?;

    const cwd = std.Io.Dir.cwd();
    const name_prefix = try std.mem.concat(
        arena.allocator(),
        u8,
        &.{ "wasmstint-", cli_args.next().?, ".handlers." },
    );
    const optimize = std.meta.stringToEnum(std.builtin.OptimizeMode, cli_args.next().?).?;

    const file_flags = std.Io.File.CreateFlags{ .exclusive = true };
    const asm_file = try cwd.createFile(io, cli_args.next().?, file_flags);
    const zig_file = try cwd.createFile(io, cli_args.next().?, file_flags);

    _ = scratch.reset(.retain_capacity);

    const writer_buf_size = std.heap.pageSize() * 2;
    var asm_writer = std.fs.File.adaptFromNewApi(asm_file).writerStreaming(
        try std.heap.page_allocator.alloc(u8, writer_buf_size),
    );
    var zig_writer = std.fs.File.adaptFromNewApi(zig_file).writerStreaming(
        try std.heap.page_allocator.alloc(u8, writer_buf_size),
    );

    var ctx = Context{
        .name_prefix = name_prefix,
        .scratch = &scratch,
        .optimize = optimize,
        .asm_out = &asm_writer.interface,
        .zig_out = &zig_writer.interface,
    };

    try ctx.asm_out.writeAll(
        \\# WASM opcodes implemented in x86-64 assembly, used in the wasmstint interpreter
        \\#
        \\# This file is generated.
        \\
        \\.intel_syntax noprefix
        \\
    );

    try ctx.zig_out.print(
        "//! This file is generated.\n\n" ++
            "pub const symbol_prefix = \"{s}\";\n\n",
        .{name_prefix},
    );

    {
        // TODO: Could detect if build script uses LLVM backend, meaning RegCall calling
        // convention could be used instead of System V
        try ctx.asm_out.print(
            \\
            \\.global "{[prefix]s}{[name]s}"
            \\.align 64
            \\"{[prefix]s}{[name]s}": # System V calling convention
            \\
        , .{ .prefix = ctx.name_prefix, .name = "opcodeHandlerTrampoline" });
        try ctx.asm_out.writeAll(
            \\    push rbp
            \\    mov rbp, rsp
            \\    # System V calling convention callee-saved registers
            \\
        );
        // TODO: Why not save 4 of the registers in the stack space for parameters?
        for (Reg64.system_v_saved_registers) |save| {
            try ctx.asm_out.print(
                \\    push {t}
                \\
            , .{save});
        }
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    sub rsp, {[stack_space_padding]d}
            \\    # Move parameters to correct registers
            \\    mov {[ip]t}, qword ptr [rbp + 16]
            \\    mov {[stp]t}, qword ptr [rbp + 24]
            \\    mov {[eip]t}, qword ptr [rbp + 32]
            \\
        , .{
            .stack_space_padding = stack_space_padding,
            .ip = Reg64.vip,
            .stp = Reg64.stp,
            .eip = Reg64.eip,
        }));
        try ctx.asm_out.print(
            \\    lea {[dispatch]t}, "{[prefix]s}byte_dispatch_table"
            \\    jmp qword ptr [rbp + 40]
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix, .dispatch = Reg64.disp });
    }
    {
        try ctx.asm_out.print(
            \\
            \\.global "{[prefix]s}{[name]s}"
            \\
        , .{ .prefix = ctx.name_prefix, .name = "invalidByteOpcode" });
        switch (optimize) {
            .Debug, .ReleaseSafe => try ctx.asm_out.print(
                \\.align 16
                \\"{[prefix]s}{[name]s}":
                \\    mov rdi, {[vip]t} #1
                \\    mov rsi, {[eip]t} #2
                \\    # doesn't `jmp`, so stack trace is better
                \\    call "{[prefix]s}panicInvalidByteOpcode"
                \\    ud2
                \\
            , .{
                .prefix = ctx.name_prefix,
                .name = "invalidByteOpcode",
                .vip = Reg64.vip,
                .eip = Reg64.eip,
            }),
            .ReleaseFast, .ReleaseSmall => try ctx.asm_out.print(
                \\"{[prefix]s}{[name]s}":
                \\    ud2
                \\
            , .{ .prefix = ctx.name_prefix, .name = "invalidByteOpcode" }),
        }
    }
    {
        try ctx.asm_out.print(
            \\
            \\.global "{[prefix]s}{[name]s}"
            \\.align 16
            \\"{[prefix]s}{[name]s}":
            \\    mov rdi, {[vip]t} # 1st argument
            \\    mov rdx, {[vsp]t} # 3rd argument
            \\    mov rsi, {[eip]t} # 2nd argument
            \\    mov rcx, {[stp]t} # 4th argument
            \\    mov r8, {[interp]t} # 5th argument
            \\    # Perform a tail call
            \\
        , .{
            .prefix = ctx.name_prefix,
            .name = "outOfFuelHandler",
            .vip = Reg64.vip,
            .eip = Reg64.eip,
            .vsp = Reg64.vsp,
            .stp = Reg64.stp,
            .interp = Reg64.interp,
        });
        // This will make the called function restore the registers
        // Seems to be no way to avoid doing this even, if a tail call doesn't occur here
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}interruptOutOfFuel"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix });
    }

    try ctx.zig_out.writeAll(
        \\/// Generates references to the individual opcode handlers in the generated assembly."
        \\/// TODO: Organize wasmstint into modules so this doesn't need to be a function
        \\/// TODO: Write comptime checks for layout of runtime structures
        \\pub fn handlers(comptime OpcodeHandler: type) type {
        \\    return struct {
    );

    try defineAllOpcodeHandlers(&ctx);

    try ctx.zig_out.writeAll(
        \\    };
        \\}
        \\
    );
    try ctx.asm_out.flush();
    try ctx.zig_out.flush();
}

fn defineAllOpcodeHandlers(ctx: *Context) !void {
    {
        try ctx.defineOpcodeHandler("nop", .@"16");
        try ctx.jmpToNextHandler(.r11);
    }
    {
        try ctx.asm_out.writeAll("\n");
        try ctx.defineOpcodeHandlerWithAliases(&.{ "block", "loop" }, .@"32");
        const block_type = try ctx.skipBlockType(.r11);
        try ctx.jmpToNextHandler(.r13);
        try block_type.writeSlowPath(ctx);
    }

    {
        try ctx.defineOpcodeHandler("end", .@"32");
        // Could detect ReleaseSafe/ReleaseFast, and inline the call to `return` opcode handler
        try ctx.asm_out.print(
            \\    # Note that IP + 1 == EIP would indicate end of function
            \\    cmp {[vip]t}, {[eip]t}
            \\    ja "{[prefix]s}return" # Slow path is returning from the function
            \\
        , .{ .vip = Reg64.vip, .eip = Reg64.eip, .prefix = ctx.name_prefix });
        try ctx.jmpToNextHandler(.r13);
    }
    {
        try ctx.defineOpcodeHandler("br", .@"32");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    # Skip reading label idx
            \\    lea r15, [{[vip]t} - 1] # save ip to br byte
            \\
        , .{ .vip = Reg64.vip }));
        const branch = try ctx.takeBranch();
        try ctx.jmpToNextHandler(.r11);
        try branch.writeSlowPath(ctx);
    }
    // br_if
    {
        try ctx.defineOpcodeHandler("br_table", .@"32");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    lea r15, [{[vip]t} - 1] # save ip to br_table byte
            \\
        , .{ .vip = Reg64.vip }));
        const label_count = try ctx.decodeUlebIdx(.r11, .r13, .r14, "label-count");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    # No need to actually read the labels
            \\    mov r13d, dword ptr [{[vsp]t} - 16]
            \\    sub {[vsp]t}, 16
            \\    cmp r11d, r13d 
            \\    cmovb r13d, r11d # prevent exceeding label count
            \\    shl r13d, 3
            \\    add {[stp]t}, r13
            \\
        , .{ .vsp = Reg64.vsp, .stp = Reg64.stp }));
        const branch = try ctx.takeBranch();
        try ctx.jmpToNextHandler(.r11);
        try label_count.writeSlowPath(ctx);
        try branch.writeSlowPath(ctx);
    }

    {
        try ctx.defineOpcodeHandler("return", .@"32");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    # No need to save every register, since this is returning
            \\    mov rdi, {[eip]t} # Most parameters are already in the correct place
            \\
        , .{ .eip = Reg64.eip }));
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}returnFromWasm"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix });
        ctx.skip_oof_handler -= 1;
    }

    {
        try ctx.defineOpcodeHandler("local.get", .@"64");
        const idx_decode = try ctx.decodeUlebIdx(.r13, .r14, .r15, "idx");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    shl r13, 4
            \\    movaps xmm0, xmmword ptr [{[locals]t} + r13]
            \\    movaps xmmword ptr [{[vsp]t}], xmm0
            \\    add {[vsp]t}, 16
            \\
        , .{ .locals = Reg64.locals, .vsp = Reg64.vsp }));
        try ctx.jmpToNextHandler(.r11);
        try idx_decode.writeSlowPath(ctx);
    }
    {
        try ctx.defineOpcodeHandler("local.set", .@"64");
        const idx_decode = try ctx.decodeUlebIdx(.r13, .r14, .r15, "idx");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    shl r13, 4
            \\    movaps xmm0, xmmword ptr [{[vsp]t} - 16]
            \\    sub {[vsp]t}, 16
            \\    movaps xmmword ptr [{[locals]t} + r13], xmm0
            \\
        , .{ .locals = Reg64.locals, .vsp = Reg64.vsp }));
        try ctx.jmpToNextHandler(.r11);
        try idx_decode.writeSlowPath(ctx);
    }

    for (&[_]struct { []const u8, std.mem.Alignment, []const u8, RegSize }{
        .{ "i32.load", .@"4", "mov", .dword },
        .{ "f32.load", .@"4", "mov", .dword }, // ReleaseSmall could deduplicate w/ i32.load
        .{ "i32.load8_u", .@"1", "movzx", .byte },
        .{ "i32.load8_s", .@"1", "movsx", .byte },
        .{ "i32.load16_s", .@"2", "movsx", .word },
        .{ "i32.load16_u", .@"2", "movzx", .word },
    }) |info| {
        const name, const access_size, const instr, const addr_size = info;
        try ctx.defineOpcodeHandler(name, .@"64");
        const access = try ctx.linearMemoryAccess(0, access_size);
        try ctx.asm_out.print(
            \\    {[instr]s} r13d, {[size]t} ptr [r13 + r15]
            \\    mov dword ptr [{[vsp]t} - 16], r13d
            \\
        , .{ .vsp = Reg64.vsp, .instr = instr, .size = addr_size });
        try access.finish(ctx);
    }

    for (&[_]struct { []const u8, std.mem.Alignment, []const u8, RegSize }{
        .{ "i64.load", .@"8", "mov", .qword },
        .{ "f64.load", .@"8", "mov", .qword }, // ReleaseSmall could deduplicate w/ i64.load
        .{ "i64.load8_u", .@"1", "movzx", .byte },
        .{ "i64.load8_s", .@"1", "movsx", .byte },
        .{ "i64.load16_s", .@"2", "movsx", .word },
        .{ "i64.load16_u", .@"2", "movzx", .word },
        .{ "i64.load32_s", .@"4", "movsxd", .dword },
    }) |info| {
        const name, const access_size, const instr, const addr_size = info;
        try ctx.defineOpcodeHandler(name, .@"64");
        const access = try ctx.linearMemoryAccess(0, access_size);
        try ctx.asm_out.print(
            \\    {[instr]s} r13, {[size]t} ptr [r13 + r15]
            \\    mov qword ptr [{[vsp]t} - 16], r13
            \\
        , .{ .vsp = Reg64.vsp, .instr = instr, .size = addr_size });
        try access.finish(ctx);
    }

    {
        try ctx.defineOpcodeHandler("i64.load32_u", .@"64");
        const access = try ctx.linearMemoryAccess(0, .@"4");
        try ctx.asm_out.print(
            \\    mov r13d, dword ptr [r13 + r15]
            \\    mov qword ptr [{[vsp]t} - 16], r13
            \\
        , .{ .vsp = Reg64.vsp });
        try access.finish(ctx);
    }

    for (&[_]struct { []const u8, std.mem.Alignment, RegSize, []const u8, RegSize }{
        .{ "i32.store", .@"4", .dword, "mov", .dword },
        .{ "f32.store", .@"4", .dword, "mov", .dword }, // ReleaseSmall could deduplicate w/ i32.store
    }) |info| {
        const name, const access_size, const load_size, const instr, const store_size = info;
        try ctx.defineOpcodeHandler(name, .@"64");
        const access = try ctx.linearMemoryAccess(1, access_size);
        try ctx.asm_out.print(
            \\    mov {[load_reg]s}, {[load_size]t} ptr [{[vsp]t} - 16] 
            \\    {[instr]s} {[store_size]t} ptr [r13 + r15], {[store_reg]s}
            \\    sub {[vsp]t}, 16 # TODO: Shouldn't this be 32?
            \\
        , .{
            .vsp = Reg64.vsp,
            .load_reg = Reg64.r14.nameResized(load_size),
            .load_size = load_size,
            .instr = instr,
            .store_reg = Reg64.r14.nameResized(store_size),
            .store_size = store_size,
        });
        try access.finish(ctx);
    }

    for (&[_]struct { []const u8, u5, Context.IntType, u7 }{
        .{ "i32.const", 5, .i32, 32 },
        .{ "i64.const", 10, .i64, 64 },
    }) |info| {
        const name, const max_byte_len, const int_type, const bit_size = info;
        try ctx.defineOpcodeHandler(name, .@"64");
        const finished = try Label.init(ctx, "finished");
        var continuation_buf: [9]Label = undefined;
        const continuation = continuation_buf[0..(max_byte_len - 1)];
        for (continuation, 0..) |*cont_label, i| {
            var cont_label_name_buf: [7]u8 = undefined;
            cont_label.* = try Label.init(
                ctx,
                std.fmt.bufPrint(&cont_label_name_buf, "byte-{d}", .{1 + i}) catch unreachable,
            );
        }

        const r11 = int_type.register(.r11);
        const r13 = int_type.register(.r13);
        const r14 = int_type.register(.r14);

        // Fast path is single-byte constant
        try ctx.asm_out.print(
            \\    movzx {[r11]s}, byte ptr [{[vip]t}]
            \\    inc {[vip]t}
            \\    test r11b, 0x80
            \\    jnz {[two_bytes]f}
            \\    shl {[r11]s}, {[shift]d}
            \\    sar {[r11]s}, {[shift]d}
            \\
        , .{
            .r11 = r11,
            .vip = Reg64.vip,
            .shift = bit_size - 7,
            .two_bytes = continuation[0],
        });

        // This falls through to the actual storing of the constant
        try ctx.asm_out.print(
            \\{[label]f}:
            \\    mov {[store_size]t} ptr [{[vsp]t}], {[r11]s}
            \\    add {[vsp]t}, 16
            \\
        , .{
            .label = finished,
            .store_size = switch (int_type) {
                .i32 => RegSize.dword,
                .i64 => RegSize.qword,
            },
            .vsp = Reg64.vsp,
            .r11 = r11,
        });
        try ctx.jmpToNextHandler(.r11);

        for (continuation[0 .. continuation.len - 1], 0..) |label, i| {
            try ctx.asm_out.print(
                \\.align 16
                \\{[label]f}:
                \\    movzx {[r14]s}, byte ptr [{[vip]t}]
                \\    mov {[r13]s}, {[r14]s}
                \\    inc {[vip]t}
                \\    and r13b, 0x7F
                \\    shl {[r13]s}, {[byte_shift]d}
                \\    or {[r11]s}, {[r13]s}
                \\    test r14b, 0x80
                \\    je {[next]f}
                \\    shl {[r11]s}, {[final_shift]d}
                \\    sar {[r11]s}, {[final_shift]d}
                \\    jmp {[finished]f}
                \\    ud2
                \\
            , .{
                .label = label,
                .r11 = r11,
                .r13 = r13,
                .r14 = r14,
                .vip = Reg64.vip,
                .next = continuation[i + 1],
                .byte_shift = 7 * (i + 1),
                .final_shift = @as(usize, bit_size) - (7 * (i + 2)),
                .finished = finished,
            });
        }

        try ctx.asm_out.print(
            \\.align 8
            \\{[label]f}:
            \\    movzx {[r13]s}, byte ptr [{[vip]t}]
            \\    inc {[vip]t}
            \\    shl {[r13]s}, {[final_shift]d}
            \\    or {[r11]s}, {[r13]s}
            \\    jmp {[finished]f}
            \\    ud2
            \\
        , .{
            .label = continuation[continuation.len - 1],
            .r11 = r11,
            .r13 = r13,
            .vip = Reg64.vip,
            .final_shift = bit_size - (7 * continuation.len),
            .finished = finished,
        });
    }

    {
        try ctx.defineOpcodeHandler("f32.const", .@"64");
        try ctx.asm_out.print(
            \\    mov r13d, dword ptr [{[vip]t}] # unaligned
            \\    add {[vip]t}, 4
            \\    mov dword ptr [{[vsp]t}], r13d
            \\    add {[vsp]t}, 16
            \\
        , .{ .vip = Reg64.vip, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);
    }
    {
        try ctx.defineOpcodeHandler("f64.const", .@"64");
        try ctx.asm_out.print(
            \\    mov r13, qword ptr [{[vip]t}] # unaligned
            \\    add {[vip]t}, 8
            \\    mov qword ptr [{[vsp]t}], r13
            \\    add {[vsp]t}, 16
            \\
        , .{ .vip = Reg64.vip, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);
    }

    try ctx.defineIntegerOpcodeHandlers(.i32);
    try ctx.defineIntegerOpcodeHandlers(.i64);

    // Write handlers for traps
    try ctx.asm_out.writeAll(".align 32\n");
    for (&[_][]const u8{
        Context.trap_integer_divide_by_zero,
        Context.trap_integer_overflow,
    }) |name| {
        try ctx.asm_out.print(
            \\ # r12 is clobbered
            \\"{[prefix]s}jmp.{[name]s}":
            \\    lea rdi, [r14 - 1] # vip
            \\    mov rdx, {[eip]t}
            \\    mov rcx, {[stp]t}
            \\
        , .{ .prefix = ctx.name_prefix, .name = name, .eip = Reg64.eip, .stp = Reg64.stp });
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}{[name]s}"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix, .name = name });
    }
}

const Reg64 = enum {
    rax,
    rcx,
    rdx,
    rbx,
    rsi,
    rdi,
    // rsp,
    // rbp,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,

    const vip = Reg64.rax;
    const stp = Reg64.rbx;
    const fuel = Reg64.rcx;
    const module = Reg64.rdx;
    const vsp = Reg64.rsi;
    const locals = Reg64.rdi;
    const mems = Reg64.r8;
    const interp = Reg64.r9;
    const eip = Reg64.r10;

    const disp = Reg64.r12;

    /// Specifies the order the registers are `push`ed onto the stack.
    const system_v_saved_registers = [5]Reg64{ .r15, .r14, .r13, .r12, .rbx };

    fn toReg32(reg: Reg64) Reg32 {
        switch (reg) {
            inline .rax,
            .rbx,
            .rcx,
            .rdx,
            .rsi,
            .rdi,
            => |r| {
                const name = comptime name: {
                    const src_name = @tagName(r);
                    var name: [src_name.len]u8 = undefined;
                    name[0] = 'e';
                    @memcpy(name[1..], src_name[1..]);
                    break :name name;
                };
                return @field(Reg32, &name);
            },
            inline .r8,
            .r9,
            .r10,
            .r11,
            .r12,
            .r13,
            .r14,
            .r15,
            => |r| return @field(Reg32, @tagName(r) ++ "d"),
        }
    }

    fn toReg8(reg: Reg64) Reg8 {
        return reg.toReg32().toReg8();
    }

    fn nameResized(reg: Reg64, size: RegSize) []const u8 {
        return switch (size) {
            .qword => @tagName(reg),
            .dword => @tagName(reg.toReg32()),
            .word => unreachable,
            .byte => @tagName(reg.toReg8()),
        };
    }
};

const Reg32 = enum {
    eax,
    ebx,
    ecx,
    edx,
    esi,
    edi,
    //esp,
    //ebp,
    r8d,
    r9d,
    r10d,
    r11d,
    r12d,
    r13d,
    r14d,
    r15d,

    fn toReg8(reg: Reg32) Reg8 {
        switch (reg) {
            inline .eax, .ebx, .ecx, .edx => |r| return @field(Reg8, &[2]u8{ @tagName(r)[1], 'l' }),
            .esi => return .sil,
            .edi => return .dil,
            inline .r8d,
            .r9d,
            .r10d,
            .r11d,
            .r12d,
            .r13d,
            .r14d,
            .r15d,
            => |r| {
                const name = comptime @tagName(r);
                return @field(Reg8, name[0..(name.len - 1)] ++ "b");
            },
        }
    }
};

const RegSize = enum {
    qword,
    dword,
    word,
    byte,
};

/// Low 8-bits
const Reg8 = enum {
    al,
    bl,
    cl,
    dl,
    sil,
    dil,
    //spl,
    //bpl
    r8b,
    r9b,
    r10b,
    r11b,
    r12b,
    r13b,
    r14b,
    r15b,
};

const TempReg = enum {
    r11,
    r13,
    r14,
    r15,

    fn toReg32(reg: TempReg) Reg32 {
        return switch (reg) {
            inline else => |r| @field(Reg32, @tagName(r) ++ "d"),
        };
    }
};

// const XmmReg = enum {
//     xmm0,
//     xmm1,
//     xmm2,
//     xmm3,
//     xmm4,
//     xmm5,
//     xmm6,
//     xmm7,
// };

const Label = struct {
    name: []const u8,

    fn init(ctx: *Context, name: []const u8) !Label {
        return Label{
            .name = try ctx.concat(&.{ "\"", ctx.opcode_name, ".", name, "\"" }),
        };
    }

    fn initWithSuffix(ctx: *Context, name: []const u8, suffix: []const u8) !Label {
        return Label{
            .name = try ctx.concat(&.{ "\"", ctx.opcode_name, ".", name, "-", suffix, "\"" }),
        };
    }

    pub fn format(label: Label, writer: *Writer) Writer.Error!void {
        try writer.writeAll(label.name);
    }
};

const Context = struct {
    name_prefix: []const u8,
    opcode_name: []const u8 = undefined,
    optimize: std.builtin.OptimizeMode,
    scratch: *ArenaAllocator,
    asm_out: *Writer,
    zig_out: *Writer,
    skip_oof_handler: u32 = 0,

    fn popSystemVSavedRegisters(ctx: *Context) !void {
        try ctx.asm_out.writeAll("    # Restore System V saved registers\n");
        const restore_count = Reg64.system_v_saved_registers.len;
        for (0..restore_count) |i| {
            try ctx.asm_out.print(
                "    pop {t}\n",
                .{Reg64.system_v_saved_registers[restore_count - 1 - i]},
            );
        }
    }

    fn concat(ctx: *Context, strings: []const []const u8) ![]const u8 {
        return try std.mem.concat(ctx.scratch.allocator(), u8, strings);
    }

    const trap_integer_divide_by_zero = "trapIntegerDivisionByZero";
    const trap_integer_overflow = "trapIntegerOverflow";

    fn defineOpcodeHandlerWithAliases(ctx: *Context, names: []const []const u8, align_to: std.mem.Alignment) !void {
        _ = ctx.scratch.reset(.retain_capacity);
        const first_name = names[0];
        ctx.opcode_name = try ctx.concat(&.{ ctx.name_prefix, first_name });
        std.debug.assert(ctx.skip_oof_handler == 0);
        ctx.skip_oof_handler = 1;
        try ctx.asm_out.print(
            \\
            \\.align {[align_to]d}
            \\
        ,
            .{ .align_to = align_to.toByteUnits() },
        );

        for (names) |n| {
            const args = .{ .prefix = ctx.name_prefix, .name = n };
            try ctx.zig_out.print(
                \\        pub const @"{[name]s}" = @extern(OpcodeHandler, .{{ .name = "{[prefix]s}{[name]s}" }});
                \\
            , args);
            try ctx.asm_out.print(
                \\.global "{[prefix]s}{[name]s}"
                \\"{[prefix]s}{[name]s}":
                \\
            , args);
        }
    }

    fn defineOpcodeHandler(ctx: *Context, name: []const u8, align_to: std.mem.Alignment) !void {
        try ctx.defineOpcodeHandlerWithAliases(&.{name}, align_to);
    }

    const DecodeUlebIdx = struct {
        slow_path: Label,
        fast_path: Label,
        result: Reg32,
        byte: Reg32,
        acc: Reg32,

        fn writeSlowPath(decode: DecodeUlebIdx, ctx: *Context) !void {
            try ctx.asm_out.print(
                \\.align 16
                \\{[label]f}:
                \\    and {[result]t}, 0x7F
                \\
            , .{
                .label = decode.slow_path,
                .result = decode.result,
            });
            // A loop would probably work better here, but clobbering another register is annoying
            for (1..4) |i| {
                try ctx.asm_out.print(
                    \\    movzx {[byte]t}, byte ptr [{[ip]t}]
                    \\    inc {[ip]t}
                    \\    mov {[acc]t}, {[byte]t} 
                    \\    and {[acc]t}, 0x7F
                    \\    shl {[acc]t}, {[shift_by]d}
                    \\    or {[result]t}, {[acc]t}
                    \\    test {[byte]t}, 0x80 # TODO: test against byte register
                    \\    jz {[fast_path]f}
                    \\
                , .{
                    .result = decode.result,
                    .byte = decode.byte,
                    .acc = decode.acc,
                    .shift_by = i * 7,
                    .ip = Reg64.vip,
                    .fast_path = decode.fast_path,
                });
            }

            // Assume max length (5 bytes) ULEB128
            try ctx.asm_out.print(
                \\    movzx {[byte]t}, byte ptr [{[ip]t}]
                \\    inc {[ip]t}
                \\    mov {[acc]t}, {[byte]t} 
                \\    and {[acc]t}, 0x7F
                \\    shl {[acc]t}, 28
                \\    or {[result]t}, {[acc]t}
                \\    jmp {[fast_path]f}
                \\    ud2
                \\
            , .{
                .result = decode.result,
                .byte = decode.byte,
                .acc = decode.acc,
                .ip = Reg64.vip,
                .fast_path = decode.fast_path,
            });
        }
    };

    const OpcodeNamePrefix = struct {
        buf: []u8,
        prefix_len: usize,

        fn init(prefix: []const u8, buf: []u8) OpcodeNamePrefix {
            @memcpy(buf[0..prefix.len], prefix);
            return .{ .buf = buf, .prefix_len = prefix.len };
        }

        fn name(prefix: *const OpcodeNamePrefix, s: []const u8) []const u8 {
            const final_len = prefix.prefix_len + s.len;
            @memcpy(prefix.buf[prefix.prefix_len..final_len], s);
            return prefix.buf[0..final_len];
        }
    };

    const IntType = enum {
        i32,
        i64,

        fn register(ty: IntType, reg: Reg64) []const u8 {
            return switch (ty) {
                .i32 => @tagName(reg.toReg32()),
                .i64 => @tagName(reg),
            };
        }
    };

    fn defineIntegerOpcodeHandlers(ctx: *Context, int_type: IntType) !void {
        var opcode_name_buf: [16]u8 = undefined;
        var opcode_name = OpcodeNamePrefix.init(@tagName(int_type), &opcode_name_buf);
        const r13 = int_type.register(.r13);
        const r14 = int_type.register(.r14);
        const r15 = int_type.register(.r15);
        const size: RegSize = switch (int_type) {
            .i32 => .dword,
            .i64 => .qword,
        };
        {
            try ctx.defineOpcodeHandler(opcode_name.name(".eqz"), .@"64");
            try ctx.asm_out.print(
                \\    mov {[r13]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    xor r14d, r14d
                \\    test {[r13]s}, {[r13]s}
                \\    setz r14b
                \\    mov {[size]t} ptr [{[vsp]t} - 16], {[r14]s}
                \\
            , .{ .r13 = r13, .r14 = r14, .size = size, .vsp = Reg64.vsp });
            try ctx.jmpToNextHandler(.r11);
        }

        for (&[_][2][]const u8{
            .{ ".eq", "sete" },
            .{ ".ne", "setne" },
            .{ ".lt_s", "setl" },
            .{ ".lt_u", "setb" },
            .{ ".gt_s", "setg" },
            .{ ".gt_u", "seta" },
            .{ ".le_s", "setle" },
            .{ ".le_u", "setbe" },
            .{ ".ge_s", "setge" },
            .{ ".ge_u", "setae" },
        }) |info| {
            try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
            try ctx.asm_out.print(
                \\    mov {[r13]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    mov {[r14]s}, {[size]t} ptr [{[vsp]t} - 32]
                \\    xor r15d, r15d
                \\    cmp {[r14]s}, {[r13]s}
                \\    {[set_instr]s} r15b
                \\    mov {[size]t} ptr [{[vsp]t} - 32], {[r15]s}
                \\    sub {[vsp]t}, 16
                \\
            , .{
                .r13 = r13,
                .r14 = r14,
                .r15 = r15,
                .size = size,
                .vsp = Reg64.vsp,
                .set_instr = info[1],
            });
            try ctx.jmpToNextHandler(.r11);
        }

        for (&[_][2][]const u8{
            .{ ".clz", "lzcnt" },
            .{ ".ctz", "tzcnt" },
            .{ ".popcnt", "popcnt" },
        }) |info| {
            try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
            try ctx.asm_out.print(
                \\    {[instr]s} {[r13]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    mov {[size]t} ptr [{[vsp]t} - 16], {[r13]s}
                \\
            , .{ .r13 = r13, .size = size, .instr = info[1], .vsp = Reg64.vsp });
            try ctx.jmpToNextHandler(.r11);
        }

        {
            try ctx.defineOpcodeHandler(opcode_name.name(".add"), .@"64");
            try ctx.asm_out.print(
                \\    mov {[r13]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    add {[size]t} ptr [{[vsp]t} - 32], {[r13]s}
                \\    sub {[vsp]t}, 16
                \\
            , .{ .r13 = r13, .size = size, .vsp = Reg64.vsp });
            try ctx.jmpToNextHandler(.r11);
        }
        {
            try ctx.defineOpcodeHandler(opcode_name.name(".sub"), .@"64");
            try ctx.asm_out.print(
                \\    mov {[r13]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    sub {[size]t} ptr [{[vsp]t} - 32], {[r13]s}
                \\    sub {[vsp]t}, 16
                \\
            , .{ .r13 = r13, .size = size, .vsp = Reg64.vsp });
            try ctx.jmpToNextHandler(.r11);
        }
        {
            try ctx.defineOpcodeHandler(opcode_name.name(".mul"), .@"64");
            try ctx.asm_out.print(
                \\    mov {[r13]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    imul {[r13]s}, {[size]t} ptr [{[vsp]t} - 32]
                \\    mov {[size]t} ptr [{[vsp]t} - 32], {[r13]s}
                \\    sub {[vsp]t}, 16
                \\
            , .{ .r13 = r13, .size = size, .vsp = Reg64.vsp });
            try ctx.jmpToNextHandler(.r11);
        }

        const rax = int_type.register(.rax);
        const rdx = int_type.register(.rdx);
        const r12 = int_type.register(.r12);
        for (&[_]struct { []const u8, enum { div, rem }, enum { signed, unsigned } }{
            .{ ".div_s", .div, .signed },
            .{ ".div_u", .div, .unsigned },
            .{ ".rem_s", .rem, .signed },
            .{ ".rem_u", .rem, .unsigned },
        }) |info| {
            _, const kind, const signedness = info;
            try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
            // Integer division on X86-64 only works with eax/rax as the dividend
            try ctx.asm_out.print(
                \\    mov r14, {[vip]t} # save IP
                \\    mov r15, {[module]t} # save module
                \\    mov {[r13]s}, {[size]t} ptr [{[vsp]t} - 16] # divisor aka denominator
                \\    mov {[rax]s}, {[size]t} ptr [{[vsp]t} - 32] # dividend aka numerator
                \\    test {[r13]s}, {[r13]s} # check for division by zero
                \\    jz "{[prefix]s}jmp.{[trap_zero]s}"
                \\
            , .{
                .r13 = r13,
                .rax = rax,
                .size = size,
                .vip = Reg64.vip,
                .vsp = Reg64.vsp,
                .module = Reg64.module,
                .prefix = ctx.name_prefix,
                .trap_zero = Context.trap_integer_divide_by_zero,
            });

            var signed_rem_overflow: Label = undefined;
            switch (signedness) {
                .signed => {
                    try ctx.asm_out.print(
                        \\    mov {[rdx]s}, {[rax]s}
                        \\    xor {[rdx]s}, {[r13]s} # overflow check ({[min_int]s} ^ {[neg_one]s})
                        \\
                    , .{
                        .rdx = rdx,
                        .rax = rax,
                        .r13 = r13,
                        .min_int = switch (int_type) {
                            .i32 => "0x8000_0000",
                            .i64 => "0x8000_0000_0000_0000",
                        },
                        .neg_one = switch (int_type) {
                            .i32 => "0xFFFF_FFFF",
                            .i64 => "0xFFFF_FFFF_FFFF_FFFF",
                        },
                    });

                    switch (int_type) {
                        .i32 => try ctx.asm_out.writeAll(
                            \\    xor edx, 0x7FFFFFFF
                            \\
                        ),
                        .i64 => try ctx.asm_out.writeAll(
                            \\    movabs r11, 0x7FFFFFFFFFFFFFFF
                            \\    xor rdx, r11
                            \\
                        ),
                    }

                    switch (kind) {
                        .div => try ctx.asm_out.print(
                            \\    je "{[prefix]s}jmp.{[trap_overflow]s}"
                            \\
                        , .{
                            .prefix = ctx.name_prefix,
                            .trap_overflow = Context.trap_integer_overflow,
                        }),
                        .rem => {
                            signed_rem_overflow = try Label.init(ctx, "overflow");
                            try ctx.asm_out.print(
                                \\    jz {[overflow]f}
                                \\    mov {[r12]s}, {[rax]s} # clobbers dispatch table register
                                \\
                            , .{ .overflow = signed_rem_overflow, .r12 = r12, .rax = rax });
                        },
                    }

                    switch (int_type) {
                        .i32 => try ctx.asm_out.writeAll(
                            \\    cdq # clobbers edx
                            \\    idiv r13d
                            \\
                        ),
                        .i64 => try ctx.asm_out.writeAll(
                            \\    cqo # clobbers rdx
                            \\    idiv r13
                            \\
                        ),
                    }

                    if (kind == .rem) {
                        try ctx.asm_out.print(
                            \\    imul {[rax]s}, {[r13]s}
                            \\    sub {[r12]s}, {[rax]s}
                            \\
                        , .{ .rax = rax, .r12 = r12, .r13 = r13 });
                    }
                },
                .unsigned => try ctx.asm_out.print(
                    \\    xor {[rdx]s}, {[rdx]s}
                    \\    div {[r13]s}
                    \\
                , .{ .rdx = rdx, .r13 = r13 }),
            }

            try ctx.asm_out.print(
                \\    mov {[size]t} ptr [{[vsp]t} - 32], {[result]s}
                \\    sub {[vsp]t}, 16
                \\    mov {[vip]t}, r14 # restore IP
                \\    mov {[module]t}, r15 # restore module
                \\
            , .{
                .result = switch (kind) {
                    .div => rax,
                    .rem => switch (signedness) {
                        .signed => r12,
                        .unsigned => rdx,
                    },
                },
                .size = size,
                .vip = Reg64.vip,
                .vsp = Reg64.vsp,
                .module = Reg64.module,
            });
            if (kind == .rem and signedness == .signed) {
                // Restores r12
                try ctx.asm_out.print(
                    \\    lea {[dispatch]t}, "{[prefix]s}byte_dispatch_table"
                    \\
                , .{ .prefix = ctx.name_prefix, .dispatch = Reg64.disp });
                ctx.skip_oof_handler += 1;
            }
            try ctx.jmpToNextHandler(.r11);

            if (kind == .rem and signedness == .signed) {
                try ctx.asm_out.print(
                    \\.align 16
                    \\{[label]f}:
                    \\    mov {[size]t} ptr [{[vsp]t} - 32], {[rdx]s}
                    \\    sub {[vsp]t}, 16
                    \\    mov {[vip]t}, r14 # restore IP
                    \\    mov {[module]t}, r15 # restore module
                    \\
                , .{
                    .size = size,
                    .rdx = rdx,
                    .label = signed_rem_overflow,
                    .vip = Reg64.vip,
                    .vsp = Reg64.vsp,
                    .module = Reg64.module,
                });
                try ctx.jmpToNextHandler(.r11);
            }
        }

        for (&[_][]const u8{ ".and", ".or", ".xor" }) |name| {
            try ctx.defineOpcodeHandler(opcode_name.name(name), .@"64");
            try ctx.asm_out.print(
                \\    mov {[r13]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    {[instr]s} {[size]t} ptr [{[vsp]t} - 32], {[r13]s} 
                \\    sub {[vsp]t}, 16
                \\
            , .{ .r13 = r13, .size = size, .vsp = Reg64.vsp, .instr = name[1..] });
            try ctx.jmpToNextHandler(.r11);
        }

        // Shift/Rotate instructions clobber fuel register (rcx)
        const rcx = int_type.register(.rcx);
        for (&[_][2][]const u8{
            .{ ".shl", "shl" },
            .{ ".shr_s", "sar" },
            .{ ".shr_u", "shr" },
            .{ ".rotl", "rol" },
            .{ ".rotr", "ror" },
        }) |info| {
            try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
            try ctx.asm_out.print(
                \\    mov r13, {[fuel]t}
                \\    mov {[rcx]s}, {[size]t} ptr [{[vsp]t} - 16]
                \\    {[instr]s} {[size]t} ptr [{[vsp]t} - 32], cl
                \\    sub {[vsp]t}, 16
                \\    mov {[fuel]t}, r13
                \\
            , .{
                .rcx = rcx,
                .size = size,
                .instr = info[1],
                .fuel = Reg64.fuel,
                .vsp = Reg64.vsp,
            });
            try ctx.jmpToNextHandler(.r11);
        }

        for (&[_]struct { []const u8, RegSize }{
            .{ ".extend8_s", .byte },
            .{ ".extend16_s", .word },
        }) |info| {
            try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"32");
            try ctx.asm_out.print(
                \\    movsx {[r13]s}, {[src_size]t} ptr [{[vsp]t} - 16]
                \\    mov {[dst_size]t} ptr [{[vsp]t} - 16], {[r13]s}
                \\
            , .{ .r13 = r13, .src_size = info[1], .dst_size = size, .vsp = Reg64.vsp });
            try ctx.jmpToNextHandler(.r11);
        }

        if (int_type == .i64) {
            try ctx.defineOpcodeHandler("i64.extend32_s", .@"32");
            try ctx.asm_out.print(
                \\    movsxd r13, dword ptr [{[vsp]t} - 16]
                \\    mov qword ptr [{[vsp]t} - 16], r13
                \\
            , .{ .vsp = Reg64.vsp });
            try ctx.jmpToNextHandler(.r11);
        }
    }

    fn decodeUlebIdx(
        ctx: *Context,
        comptime result: TempReg,
        clobber_0: TempReg,
        clobber_1: TempReg,
        name: []const u8,
    ) !DecodeUlebIdx {
        const fast_path = try Label.initWithSuffix(ctx, name, "fast");
        const slow_path = try Label.initWithSuffix(ctx, name, "slow");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    movzx {[temp]t}, byte ptr [{[ip]t}]
            \\    inc {[ip]t}
            \\    test {[temp]t}, 0x80  # TODO: test against byte register
            \\
        , .{ .temp = result, .ip = Reg64.vip }));
        try ctx.asm_out.print("    jnz {f}\n", .{slow_path});
        try ctx.asm_out.print("{f}:\n", .{fast_path});
        return DecodeUlebIdx{
            .slow_path = slow_path,
            .fast_path = fast_path,
            .result = result.toReg32(),
            .byte = clobber_0.toReg32(),
            .acc = clobber_1.toReg32(),
        };
    }

    const SkipBlockType = struct {
        type_idx: Label,
        fast_path: Label,
        clobber: Reg32,

        fn writeSlowPath(skip: SkipBlockType, ctx: *Context) !void {
            try ctx.asm_out.print(
                \\.align 16
                \\{[skip_type_idx]f}:
                \\    movzx {[temp]t}, byte ptr [{[vip]t}]
                \\    inc {[vip]t}
                \\    test {[temp_b]t}, 0x80
                \\    jz {[fast_path]f}
                \\    jmp {[skip_type_idx]f}
                \\    ud2
                \\
            , .{
                .temp = skip.clobber,
                .temp_b = skip.clobber.toReg8(),
                .vip = Reg64.vip,
                .skip_type_idx = skip.type_idx,
                .fast_path = skip.fast_path,
            });
        }
    };

    fn skipBlockType(ctx: *Context, clobber: TempReg) !SkipBlockType {
        const skip_type_idx = try Label.init(ctx, "skip-type-idx");
        const fast_path = try Label.init(ctx, "after-block-type");
        const clobber_32 = clobber.toReg32();
        try ctx.asm_out.print(
            \\    movzx {[temp]t}, byte ptr [{[vip]t}]
            \\    inc {[vip]t}
            \\    test {[temp_b]t}, 0x80
            \\    jnz {[skip_type_idx]f}
            \\{[fast_path]f}:
            \\
        , .{
            .temp = clobber,
            .temp_b = clobber_32.toReg8(),
            .vip = Reg64.vip,
            .skip_type_idx = skip_type_idx,
            .fast_path = fast_path,
        });
        return .{ .type_idx = skip_type_idx, .fast_path = fast_path, .clobber = clobber_32 };
    }

    const LinearMemoryAccess = struct {
        align_decode: DecodeUlebIdx,
        offset_decode: DecodeUlebIdx,
        oob: Label,
        size: std.mem.Alignment,

        fn finish(acc: *const LinearMemoryAccess, ctx: *Context) !void {
            try ctx.jmpToNextHandler(.r11);
            try ctx.asm_out.print(
                \\.align 16
                \\{[label]f}:
                \\    lea rdi, [{[vip]t} - 1]
                \\    mov rdx, {[eip]t}
                \\    mov rcx, {[stp]t}
                \\    mov r8, 0 # memidx
                \\    # These parameters will be moved onto the stack
                \\    mov r11d, r13d # address
                \\    mov r10, r14 # *MemInst
                \\
            , .{ .label = acc.oob, .vip = Reg64.vip, .eip = Reg64.eip, .stp = Reg64.stp });
            try ctx.popSystemVSavedRegisters();
            try ctx.asm_out.print(
                \\    mov rsp, rbp
                \\    pop rbp
                \\    # System V stack parameters, trampoline parameters ensure enough space
                \\    mov dword ptr [rsp + 8], r11d # address
                \\    mov dword ptr [rsp + 16], {[size]d} # size
                \\    mov qword ptr [rsp + 24], r10 # *MemInst
                \\    jmp "{[prefix]s}trapMemoryAccessOutOfBounds"
                \\    ud2
                \\
            , .{ .size = @intFromEnum(acc.size), .prefix = ctx.name_prefix });

            // TODO: Helper functions for align/offset decode
            try acc.align_decode.writeSlowPath(ctx);
            try acc.offset_decode.writeSlowPath(ctx);
        }
    };

    fn linearMemoryAccess(
        ctx: *Context,
        /// Offset from value stack pointer to `i32` memory offset.
        offset_loc: u1,
        size: std.mem.Alignment,
    ) !LinearMemoryAccess {
        const oob = try Label.init(ctx, "oob");
        const align_decode = try ctx.decodeUlebIdx(.r13, .r14, .r15, "align");
        const offset_decode = try ctx.decodeUlebIdx(.r13, .r14, .r15, "offset");
        try ctx.asm_out.print(
            \\    mov r14, qword ptr [{[mems]t}] # Pointer to MemInst
            \\    mov r15, qword ptr [r14] # Base pointer
            \\    add r13d, dword ptr [{[vsp]t} - {[offset]d}] # offset
            \\    jc {[oob]f} # target address overflowed
            \\    lea r11, [r13 + {[access_size]d}]
            \\    cmp r11, qword ptr [r14 + {[size_field]d}]
            \\    ja {[oob]f} # exceeded memory bounds
            \\    # Actually perform the access
            \\
        , .{
            .mems = Reg64.mems,
            .vsp = Reg64.vsp,
            .size_field = 8,
            .access_size = size.toByteUnits(),
            .oob = oob,
            .offset = 16 * (@as(u6, offset_loc) + 1),
        });
        return .{
            .oob = oob,
            .align_decode = align_decode,
            .offset_decode = offset_decode,
            .size = size,
        };
    }

    const TakeBranch = struct {
        begin: Label,
        finish: Label,

        fn writeSlowPath(branch: *const TakeBranch, ctx: *Context) !void {
            // TODO: See if AVX is enabled to use ymm registers
            try ctx.asm_out.print(
                \\.align 16
                \\{[begin_label]f}:
                \\    add {[vsp]t}, 16
                \\    lea r13, [r14 + 16]  # pointer for results destination
                \\
            , .{ .begin_label = branch.begin, .vsp = Reg64.vsp });

            const loop_start = try Label.init(ctx, "copy-results-loop");
            try ctx.asm_out.print(
                \\{[loop_start]f}:
                \\
            , .{ .loop_start = loop_start });

            const unroll_count: usize = switch (ctx.optimize) {
                .Debug, .ReleaseSmall => 1,
                .ReleaseSafe, .ReleaseFast => 4,
            };
            for (0..unroll_count) |_| {
                try ctx.asm_out.print(
                    \\    movaps xmm0, xmmword ptr [{[vsp]t}]
                    \\    movaps xmmword ptr [r13], xmm0
                    \\    add {[vsp]t}, 16
                    \\    add r13, 16
                    \\    cmp r13, r15
                    \\    je {[finish]f}
                    \\
                , .{ .vsp = Reg64.vsp, .finish = branch.finish });
            }

            try ctx.asm_out.print(
                \\    jmp {[loop_start]f}
                \\    ud2
                \\
            , .{ .loop_start = loop_start });
        }
    };

    /// Branch to take is stored in `Reg64.stp`.
    ///
    /// IP to first byte of branch instruction is stored at `r15`.
    fn takeBranch(ctx: *Context) !TakeBranch {
        const cpy_many_results = try Label.init(ctx, "copy-results");
        const finish_cpy_results = try Label.init(ctx, "adjust-stp");
        try ctx.asm_out.print(
            \\    movsxd r11, dword ptr [{[stp]t}] # delta_ip
            \\    lea {[vip]t}, [r15 + r11]
            \\    movzx r11, byte ptr [{[stp]t} + {[copy_count_off]d}] # copy_count
            \\    shl r11, 4
            \\    movzx r13, byte ptr [{[stp]t} + {[pop_count_off]d}] # pop_count
            \\    shl r13, 4
            \\    mov r14, {[vsp]t}
            \\    sub r14, r13 # base pointer for results destination
            \\    test r11, r11
            \\    jz {[finish_cpy_results]f}
            \\    mov r15, {[vsp]t} # copying stops at this address
            \\    sub {[vsp]t}, r11 # base pointer for results source
            \\    movaps xmm0, xmmword ptr [{[vsp]t}] # copy single result
            \\    movaps xmmword ptr [r14], xmm0
            \\    cmp r13, 0x20
            \\    jae {[cpy_many_results]f} # clobbers r13
            \\{[finish_cpy_results]f}:
            \\    lea {[vsp]t}, [r14 + r11]
            \\    movsx r11, word ptr [{[stp]t} + {[delta_stp_off]d}] # delta_stp
            \\    shl r11, 3
            \\    add {[stp]t}, r11
            \\
        , .{
            .vip = Reg64.vip,
            .vsp = Reg64.vsp,
            .stp = Reg64.stp,
            .delta_stp_off = 4,
            .copy_count_off = 6,
            .pop_count_off = 7,
            .cpy_many_results = cpy_many_results,
            .finish_cpy_results = finish_cpy_results,
        });
        return .{ .begin = cpy_many_results, .finish = finish_cpy_results };
    }

    fn jmpToNextHandler(ctx: *Context, comptime temp: TempReg) !void {
        // TODO: Store fuel directly instead of via pointer, include fuel in return value
        // ^ needs Zig to support multiple results in inline assembly, or making a RegCall/SysV
        // compliant ASM function that returns in two registers
        const out_of_fuel = try Label.init(ctx, "out-of-fuel");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    movzx {[temp]t}, byte ptr [{[ip]t}] # Start reading next opcode byte
            \\    sub qword ptr [{[fuel]t}], 1 # Fuel check
            \\
        , .{ .ip = Reg64.vip, .temp = temp, .fuel = Reg64.fuel }));
        try ctx.asm_out.print("    jb {f}\n", .{out_of_fuel});
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    # Jump to handler
            \\    inc {[ip]t}
            \\    mov {[temp]t}, qword ptr [{[disp]t} + {[temp]t} * 8]
            \\    jmp {[temp]t}
            \\    ud2
            \\
        , .{ .ip = Reg64.vip, .temp = temp, .disp = Reg64.disp }));
        ctx.skip_oof_handler -= 1;
        if (ctx.skip_oof_handler == 0) {
            try ctx.asm_out.print(
                \\{[oof]f}:
                \\    jmp "{[prefix]s}outOfFuelHandler"
                \\    ud2
                \\
            , .{ .oof = out_of_fuel, .prefix = ctx.name_prefix });
        }
    }
};

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const Writer = std.Io.Writer;
