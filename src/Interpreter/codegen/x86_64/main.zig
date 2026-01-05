//! Generates an assembly `.s` file and a `.zig` file containing `extern fn` definitions
//! to individual opcode handlers.

pub fn main() noreturn {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.ioBasic();

    var arena = ArenaAllocator.init(std.heap.page_allocator); // never reset
    var scratch = ArenaAllocator.init(std.heap.page_allocator);

    var cli_args = std.process.ArgIterator.initWithAllocator(scratch.allocator()) catch
        @panic("oom");
    _ = cli_args.next().?;

    const symbol_prefix = arena.allocator().dupe(u8, cli_args.next().?) catch @panic("oom");
    const optimize = std.meta.stringToEnum(std.builtin.OptimizeMode, cli_args.next().?).?;

    const cwd = std.Io.Dir.cwd();
    const file_flags = std.Io.File.CreateFlags{ .exclusive = true };
    const asm_file = file: {
        const path = cli_args.next().?;
        break :file cwd.createFile(io, path, file_flags) catch |e|
            std.debug.panic("cannot open {s}: {t}", .{ path, e });
    };
    const zig_file = file: {
        const path = cli_args.next().?;
        break :file cwd.createFile(io, path, file_flags) catch |e|
            std.debug.panic("cannot open {s}: {t}", .{ path, e });
    };

    _ = scratch.reset(.retain_capacity);

    const writer_buf_size = std.heap.pageSize() * 2;
    var asm_writer = Assembler.init(
        std.fs.File.adaptFromNewApi(asm_file).writerStreaming(
            std.heap.page_allocator.alloc(u8, writer_buf_size) catch @panic("oom"),
        ),
        symbol_prefix,
        scratch,
    );
    var zig_writer = ZigWriter.init(
        std.fs.File.adaptFromNewApi(zig_file).writerStreaming(
            std.heap.page_allocator.alloc(u8, writer_buf_size) catch @panic("oom"),
        ),
        symbol_prefix,
    );

    defineSupportRoutines(&asm_writer, optimize);
    defineControlOpcodeHandlers(&asm_writer, &zig_writer, optimize);
    // defineCallOpcodeHandlers(&asm_writer, &zig_writer);
    // defineParametericOpcodeHandlers(&asm_writer, &zig_writer);
    defineLocalOpcodeHandlers(&asm_writer, &zig_writer);

    asm_writer.finish();
    zig_writer.finish();
    std.process.exit(0);
}

fn defineSupportRoutines(
    as: *Assembler,
    optimize: std.builtin.OptimizeMode,
) void {
    {
        const system_v_callee_saved = Assembler.Gpr.Tag.system_v_callee_saved;
        // TODO: Could detect if build script uses LLVM backend, meaning RegCall calling
        // convention could be used instead of System V
        const trampoline = as.startFunction("opcodeHandlerTrampoline", .@"64");
        as.writeComment("System V calling convention");
        as.push(.{ .gpr = .rbp }, "");
        as.mov(.{ .gpr = .rbp }, .{ .gpr = .rsp }, "");
        as.writeComment("move parameters to correct registers and save callee-save registers");

        const entry_preserved_registers = comptime std.EnumSet(Assembler.Gpr.Tag).initMany(
            &(system_v_callee_saved ++ Assembler.Gpr.Tag.system_v_parameters),
        );
        as.markInitialized(entry_preserved_registers);
        as.preventClobbering(entry_preserved_registers.unionWith(.initMany(&.{ .stack, .base })));

        const temp = Assembler.Operand{ .gpr = .r13 };
        const handler = Assembler.Gpr.r14;
        for (
            system_v_callee_saved[0..4],
            &[_]Assembler.Gpr{ .vip, .stp, .eip, handler },
            &[_][]const u8{ "vip", "stp", "eip", "opcode handler" },
            0..,
        ) |saved_tag, param, comment, i| {
            as.allowClobbering(.initMany(&.{ param.tag, saved_tag }));
            const saved = Assembler.Operand{ .gpr = .qword(saved_tag) };
            const slot = Assembler.Operand.paramFromRbp(i, .qword);
            if (saved.gpr == param) {
                as.mov(temp, saved, "swap callee saved");
                as.mov(.{ .gpr = param }, slot, comment);
                as.mov(slot, temp, "callee-saved");
            } else {
                as.mov(.{ .gpr = param }, slot, comment);
                as.mov(slot, saved, "callee-saved");
            }
        }

        as.mov(
            .paramFromRbp(4, .qword),
            .{ .gpr = .qword(system_v_callee_saved[4]) },
            "callee-saved",
        );

        as.lea(.disp, .{ .symbol = .byte_dispatch_table }, "");
        as.jmp(.{ .gpr = handler }, "jump to opcode handler");
        as.ud2();
        trampoline.end(as);
    }
    {
        const handler = as.startFunction(
            Assembler.Symbol.out_of_fuel_handler.nameUnprefixed(),
            .@"16",
        );

        const state_params = [_]Assembler.Gpr{ .vip, .vsp, .eip, .stp, .interp };
        as.markInitialized(Assembler.Gpr.sliceToTagSet(&state_params));

        for (
            &[_]Assembler.Gpr{ .rdi, .rdx, .rsi, .rcx, .r8 },
            &state_params,
            &[_]u3{ 1, 3, 2, 4, 5 },
        ) |param, src, n| {
            std.debug.assert(param.tag != src.tag);
            var comment_buf = "argument #n".*;
            comment_buf[comment_buf.len - 1] = n;
            as.mov(.{ .gpr = param }, .{ .gpr = src }, &comment_buf);
            as.preventClobbering(.initOne(param.tag));
        }

        as.writeComment("perform a tail call");
        // This will make the called function restore the registers
        // Seems to be no way to avoid doing this, even if a normal `call` is used instead
        as.restoreSystemVSavedRegisters();
        as.mov(.{ .gpr = .rsp }, .{ .gpr = .rbp }, "");
        as.pop(.{ .gpr = .rbp }, "");
        as.jmp(.{ .symbol = .interrupt_out_of_fuel }, "");
        as.ud2();
        handler.end(as);
    }
    {
        const handler = as.startFunction("invalidByteOpcode", switch (optimize) {
            .Debug, .ReleaseSafe => .@"16",
            .ReleaseFast, .ReleaseSmall => .@"1",
        });
        switch (optimize) {
            .Debug, .ReleaseSafe => {
                as.markInitialized(Assembler.Gpr.sliceToTagSet(&Assembler.Gpr.interpreter_state));
                as.mov(.{ .gpr = Assembler.Gpr.system_v_parameters[0] }, .{ .gpr = .vip }, "1");
                as.mov(.{ .gpr = Assembler.Gpr.system_v_parameters[1] }, .{ .gpr = .eip }, "2");
                as.writeComment("doesn't jmp so stack trace is better");
                as.instr("call", &.{.{ .symbol = .initPrefixed("panicInvalidByteOpcode") }}, "");
            },
            .ReleaseFast, .ReleaseSmall => {},
        }
        as.ud2();
        handler.end(as);
    }
}

const DecodeUlebIdx = struct {
    slow_path: Assembler.Label,
    fast_path: Assembler.Label,
    result: Assembler.Gpr64,
    byte: Assembler.Gpr64,
    accumulator: Assembler.Gpr64,

    fn fastPath(
        as: *Assembler,
        result: Assembler.Gpr64,
        /// `clobbers[1]` is only cloberred in the slow path.
        clobbers: [2]Assembler.Gpr64,
        name: []const u8,
    ) DecodeUlebIdx {
        var fast_path = as.label(&.{ "index_", name, "_done" });
        const slow_path = as.label(&.{ "index_", name, "_slow" });
        const byte, const accumulator = clobbers;

        as.movzx(result.toGpr(), .{ .mem = .{ .size = .byte, .base = .vip } }, "first byte");
        as.inc(.{ .gpr = .vip }, "");
        as.@"test"(
            .{ .gpr = result.toGpr().withSize(.byte) },
            .{ .raw = "0x80" },
            "check for multi-byte",
        );
        as.jcc(.nz, .{ .label = &fast_path }, "");
        fast_path.place(as);

        return DecodeUlebIdx{
            .slow_path = slow_path,
            .fast_path = fast_path,
            .result = result,
            .byte = byte,
            .accumulator = accumulator,
        };
    }

    fn writeSlowPath(decode: *DecodeUlebIdx, as: *Assembler) void {
        as.p2align(.@"16");
        decode.slow_path.place(as);
        as.@"and"(.gpr64(decode.result), .{ .raw = "0x7F" }, "keep lower 7 bits");
        as.writeComment("a loop would probably work better here");
        const byte = decode.byte.toGpr();
        const accumulator = Assembler.Operand.gpr64(decode.accumulator);
        for (1..4) |i| {
            var comment_buf = "length is _ bytes".*;
            comment_buf[comment_buf.len - 1] = '1' + @as(u8, @intCast(i));
            as.movzx(byte, .{ .mem = .{ .size = .byte, .base = .vip } }, &comment_buf);
            as.inc(.{ .gpr = .vip }, "vip");
            as.mov(accumulator, .gpr64(decode.byte), "");
            as.@"and"(accumulator, .{ .raw = "0x7F" }, "");
            as.shl(accumulator, .{ .amount = @as(u6, @intCast(i)) * 7 }, "");
            as.@"or"(.gpr64(decode.result), accumulator, "");
            as.@"test"(.{ .gpr = byte.withSize(.byte) }, .{ .raw = "0x80" }, "check for continuation");
            as.jcc(.z, .{ .label = &decode.fast_path }, "");
        }

        // Assume max length (5 bytes) ULEB128
        as.movzx(
            decode.byte.toGpr(),
            .{ .mem = .{ .size = .byte, .base = .vip } },
            "length is maximum of 5 bytes",
        );
        as.inc(.{ .gpr = .vip }, "vip");
        as.mov(accumulator, .gpr64(decode.byte), "");
        as.@"and"(accumulator, .{ .raw = "0x7F" }, "");
        as.shl(accumulator, .{ .amount = 28 }, "");
        as.@"or"(.gpr64(decode.result), accumulator, "");
        as.jmp(.{ .label = &decode.fast_path }, "");
        as.ud2();

        decode.* = undefined;
    }
};

const SkipUlebIdx = struct {
    skip_idx: Assembler.Label,
    fast_path: Assembler.Label,
    byte: Assembler.Gpr64,

    fn writeDecodeByte(skip: *const SkipUlebIdx, as: *Assembler, first_comment: []const u8) void {
        as.movzx(
            skip.byte.toGpr(),
            .{ .mem = .{ .size = .byte, .base = .vip } },
            first_comment,
        );
        as.inc(.{ .gpr = .vip }, "vip");
        as.@"test"(
            .{ .gpr = skip.byte.toGpr().withSize(.byte) },
            .{ .raw = "0x80" },
            "check for longer index",
        );
    }

    fn fastPath(as: *Assembler, clobber: Assembler.Gpr64, name: []const u8) SkipUlebIdx {
        var skip = SkipUlebIdx{
            .skip_idx = as.label(&.{ "skip_idx_", name }),
            .fast_path = as.label(&.{ "after_idx_", name }),
            .byte = clobber,
        };
        skip.writeDecodeByte(as, "first byte of index");
        as.jcc(.nz, .{ .label = &skip.skip_idx }, "");
        skip.fast_path.place(as);
        return skip;
    }

    fn writeSlowPath(skip: *SkipUlebIdx, as: *Assembler) void {
        as.p2align(.@"16");
        skip.skip_idx.place(as);
        skip.writeDecodeByte(as, "next byte of index");
        as.jcc(.z, .{ .label = &skip.fast_path }, "check for end");
        as.jmp(.{ .label = &skip.skip_idx }, "loop");
        as.ud2();
        skip.* = undefined;
    }
};

const TakeBranch = struct {
    cpy_many_results: Assembler.Label,
    finish: Assembler.Label,

    const pop_count = Assembler.Gpr.r13;
    const starting_results_dst = Assembler.Gpr.r14;
    const stop_copying_at = Assembler.Gpr.r15;

    /// Branch to take is stored in `Reg64.stp`.
    ///
    /// The IP to the first byte of the branch instruction is stored in `r15`.
    fn fastPath(as: *Assembler) TakeBranch {
        const cpy_many_results = as.label(&.{"branch_copy_results"});
        var finish_cpy_results = as.label(&.{"branch_adjust_stp"});

        as.allowClobbering(.initOne(Assembler.Gpr.stp.tag));

        const saved_ip = stop_copying_at;
        as.preventClobbering(.initOne(saved_ip.tag));

        const delta_ip = Assembler.Gpr.r11;
        as.movsxd(delta_ip, .{ .mem = .{ .size = .dword, .base = .stp } }, "delta_ip");
        as.lea(.vip, .{ .mem = .{ .base = saved_ip, .index = delta_ip } }, "set IP to target");

        const copy_count = delta_ip;
        as.movzx(
            delta_ip,
            .{ .mem = .{ .size = .byte, .base = .stp, .disp = .{ .literal = 6 } } },
            "copy_count",
        );
        as.shl(.{ .gpr = copy_count }, .{ .amount = 4 }, "in units of 16-byte values");
        as.preventClobbering(.initOne(copy_count.tag));

        as.movzx(
            pop_count,
            .{ .mem = .{ .size = .byte, .base = .stp, .disp = .{ .literal = 7 } } },
            "pop_count",
        );
        as.shl(.{ .gpr = pop_count }, .{ .amount = 4 }, "in units of 16-byte values");
        as.preventClobbering(.initOne(pop_count.tag));
        as.mov(.{ .gpr = starting_results_dst }, .{ .gpr = .vsp }, "copy VSP");
        as.sub(
            .{ .gpr = starting_results_dst },
            .{ .gpr = pop_count },
            "base pointer for results destination",
        );
        as.allowClobberingStrict(.initOne(copy_count.tag));
        as.@"test"(.{ .gpr = copy_count }, .{ .gpr = copy_count }, "check for results to copy");
        as.jcc(.z, .{ .label = &finish_cpy_results }, "");

        as.allowClobberingStrict(.initOne(saved_ip.tag));
        as.mov(
            .{ .gpr = stop_copying_at },
            .{ .mem = .{ .base = .vsp } },
            "copying stops at this address",
        );
        as.sub(.{ .gpr = .vsp }, .{ .gpr = copy_count }, "base pointer for results source");
        as.movaps(
            .{ .xmm = .xmm0 },
            .{ .mem = .{ .size = .xmmword, .base = .vsp } },
            "copy single result",
        );
        as.movaps(
            .{ .mem = .{ .size = .xmmword, .base = starting_results_dst } },
            .{ .xmm = .xmm0 },
            "",
        );
        as.allowClobberingStrict(.initOne(pop_count.tag));
        as.cmp(.{ .gpr = pop_count }, .{ .raw = "0x20" }, "check for more results");
        as.jcc(.ae, .{ .label = &cpy_many_results }, "clobbers pop count");

        finish_cpy_results.place(as);
        as.lea(
            .vsp,
            .{ .mem = .{ .base = starting_results_dst, .index = copy_count } },
            "adjust VSP to point after results",
        );
        const delta_stp = copy_count;
        as.movsx(
            delta_stp,
            .{ .mem = .{ .size = .word, .base = .stp, .disp = .{ .literal = 4 } } },
            "delta_stp",
        );
        as.shl(.{ .gpr = delta_stp }, .{ .amount = 3 }, "side table entries are 8 bytes each");
        as.add(.{ .gpr = .stp }, .{ .gpr = delta_stp }, "adjust STP");
        as.preventClobbering(.initOne(Assembler.Gpr.stp.tag));
        return .{ .cpy_many_results = cpy_many_results, .finish = finish_cpy_results };
    }

    fn writeSlowPath(
        branch: *TakeBranch,
        as: *Assembler,
        optimize: std.builtin.OptimizeMode,
    ) void {
        as.allowClobbering(.initOne(pop_count.tag));
        as.allowClobbering(.initMany(&.{ starting_results_dst.tag, stop_copying_at.tag }));

        // TODO: See if AVX is enabled to use ymm registers

        as.p2align(.@"16");
        branch.cpy_many_results.place(as);
        as.add(.{ .gpr = .vsp }, .{ .raw = "0x10" }, "# one result already copied");
        const results_dst = pop_count;
        as.lea(
            results_dst,
            .{ .mem = .{ .base = starting_results_dst, .disp = .{ .literal = 0x10 } } },
            "pointer to results destination",
        );

        var loop_start = as.label(&.{"copy_results_loop"});
        loop_start.place(as);

        const unroll_count: usize = switch (optimize) {
            .Debug, .ReleaseSmall => 1,
            .ReleaseSafe, .ReleaseFast => 4,
        };
        for (0..unroll_count) |_| {
            as.movaps(.{ .xmm = .xmm0 }, .{ .mem = .{ .size = .xmmword, .base = .vsp } }, "");
            as.movaps(
                .{ .mem = .{ .size = .xmmword, .base = results_dst } },
                .{ .xmm = .xmm0 },
                "",
            );
            as.add(.{ .gpr = .vsp }, .{ .raw = "0x10" }, "");
            as.add(.{ .gpr = results_dst }, .{ .raw = "0x10" }, "");
            as.cmp(.{ .gpr = results_dst }, .{ .gpr = stop_copying_at }, "check if done");
            as.jcc(.e, .{ .label = &branch.finish }, "");
        }

        as.jmp(.{ .label = &loop_start }, "");
        as.ud2();
    }
};

fn defineControlOpcodeHandlers(
    as: *Assembler,
    zig: *ZigWriter,
    optimize: std.builtin.OptimizeMode,
) void {
    {
        var nop = as.defineOpcodeHandler(zig, "nop", .@"16");
        nop.jmpToNextHandler(as, .r11);
        nop.end(as);
    }
    {
        var block = as.defineOpcodeHandler(zig, "block", .@"32");
        zig.defineOpcodeHandlerAlias("block", "loop");
        var block_type = SkipUlebIdx.fastPath(as, .r11, "type");
        block.jmpToNextHandler(as, .r13);
        block_type.writeSlowPath(as);
        block.end(as);
    }
    {
        var @"if" = as.defineOpcodeHandler(zig, "if", .@"32");
        var false_branch = as.label(&.{"false"});
        const condition = Assembler.Gpr.r13d;
        as.mov(
            .{ .gpr = condition },
            .{ .mem = .{ .size = .dword, .base = .vsp, .disp = .{ .literal = -0x10 } } },
            "load condition from top of stack",
        );
        as.sub(.{ .gpr = .vsp }, .{ .raw = "0x10" }, "condition was popped");
        as.@"test"(.{ .gpr = condition }, .{ .gpr = condition }, "");
        as.jcc(.z, .{ .label = &false_branch }, "");
        var block_type = SkipUlebIdx.fastPath(as, .r11, "type");
        as.allowClobbering(.initOne(Assembler.Gpr.stp.tag));
        as.add(.{ .gpr = .stp }, .{ .u8 = 8 }, "increment STP");
        as.preventClobbering(.initOne(Assembler.Gpr.stp.tag));
        @"if".jmpToNextHandler(as, .r13);
        block_type.writeSlowPath(as);

        false_branch.place(as);
        as.writeComment("no need to read the block type");
        const saved_ip = Assembler.Gpr.r15;
        as.lea(
            saved_ip,
            .{ .mem = .{ .base = .vip, .disp = .{ .literal = -1 } } },
            "save ip to if byte",
        );
        var branch = TakeBranch.fastPath(as);
        @"if".jmpToNextHandler(as, .r11);
        branch.writeSlowPath(as, optimize);
        @"if".end(as);
    }
    if (true) {
        return;
    }
    const ctx = void;
    {
        try ctx.defineOpcodeHandler("else", .@"32");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    # end of true branch of if, jump to end
            \\    lea r15, [{[vip]t} - 1] # save ip to else byte
            \\
        , .{ .vip = Reg64.vip }));
        const branch = try ctx.takeBranch();
        try ctx.jmpToNextHandler(.r11);
        try branch.writeSlowPath(ctx);
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
    {
        try ctx.defineOpcodeHandler("br_if", .@"32");
        const false_branch = try Label.init(ctx, "false");
        try ctx.asm_out.print(
            \\    mov r13d, dword ptr [{[vsp]t} - 0x10]
            \\    sub {[vsp]t}, 0x10 # pop condition
            \\    test r13d, r13d
            \\    jz {[false]f}
            \\    lea r15, [{[vip]t} - 1] # save ip to br_if byte
            \\
        , .{ .vsp = Reg64.vsp, .vip = Reg64.vip, .false = false_branch });
        const branch = try ctx.takeBranch();
        ctx.skip_oof_handler += 1;
        try ctx.jmpToNextHandler(.r11);
        try branch.writeSlowPath(ctx);

        try ctx.asm_out.print(
            \\.align 16
            \\{[false]f}:
            \\
        , .{ .false = false_branch });
        const label_idx = try ctx.decodeUlebIdx(.r11, .r13, .r14, "label-idx"); // TODO: Helper to SKIP uleb128 indices
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    inc {[stp]t} # stp
            \\
        , .{ .stp = Reg64.stp }));
        try ctx.jmpToNextHandler(.r11);
        try label_idx.writeSlowPath(ctx);
    }
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
}

// fn defineCallOpcodeHandlers
// fn defineParametericOpcodeHandlers

fn defineLocalOpcodeHandlers(as: *Assembler, zig: *ZigWriter) void {
    const LocalOpcode = enum {
        @"local.get",
        @"local.set",
        @"local.tee",
    };
    for (std.enums.values(LocalOpcode)) |opcode| {
        var get = as.defineOpcodeHandler(zig, @tagName(opcode), .@"64");
        const local_idx = Assembler.Gpr64.r13;
        var idx_decode = DecodeUlebIdx.fastPath(as, local_idx, .{ .r14, .r15 }, "local");
        as.shl(.gpr64(local_idx), .{ .amount = 4 }, "offset to local, 16-bytes each");
        as.preventClobbering(.initOne(local_idx.toGpr().tag));
        switch (opcode) {
            .@"local.get" => {
                as.movaps(
                    .{ .xmm = .xmm0 },
                    .{ .mem = .{ .size = .xmmword, .base = .locals, .index = local_idx.toGpr() } },
                    "load value from locals",
                );
                as.movaps(
                    .{ .mem = .{ .size = .xmmword, .base = .vsp } },
                    .{ .xmm = .xmm0 },
                    "store into value stack",
                );
                as.add(.{ .gpr = .vsp }, .{ .raw = "0x10" }, "vsp");
            },
            .@"local.set", .@"local.tee" => {
                as.movaps(
                    .{ .xmm = .xmm0 },
                    .{ .mem = .{ .size = .xmmword, .base = .vsp, .disp = .{ .literal = -0x10 } } },
                    "load value to copy from value stack",
                );
                if (opcode == .@"local.set") {
                    as.sub(.{ .gpr = .vsp }, .{ .raw = "0x10" }, "vsp");
                }
                as.movaps(
                    .{ .mem = .{ .size = .xmmword, .base = .locals, .index = local_idx.toGpr() } },
                    .{ .xmm = .xmm0 },
                    "store into locals",
                );
                if (opcode == .@"local.tee") {
                    as.writeComment("argument is still at the top of the value stack");
                }
            },
        }
        as.allowClobberingStrict(.initOne(local_idx.toGpr().tag));
        get.jmpToNextHandler(as, .r11);
        idx_decode.writeSlowPath(as);
        get.end(as);
    }
}

fn defineAllOpcodeHandlers(ctx: *Context) !void {
    try defineCallOpcodeHandlers(ctx);
    try defineParametericOpcodeHandlers(ctx);
    // try defineLocalOpcodeHandlers(ctx);
    try defineGlobalOpcodeHandlers(ctx);
    try defineMemoryLoadOpcodeHandlers(ctx);
    try defineMemoryStoreOpcodeHandlers(ctx);
    try defineMemoryManagementOpcodeHandlers(ctx);
    try defineConstOpcodeHandlers(ctx);
    try defineIntegerOpcodeHandlers(ctx, .i32);
    try defineIntegerOpcodeHandlers(ctx, .i64);
    try defineFloatOpcodeHandlers(ctx, .f32);
    try defineFloatOpcodeHandlers(ctx, .f64);

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

fn defineCallOpcodeHandlers(ctx: *Context) !void {
    {
        try ctx.defineOpcodeHandler("call", .@"32");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    lea r15, [{[vip]t} - 1] # save ip to call byte
            \\
        , .{ .vip = Reg64.vip }));
        const idx_decode = try ctx.decodeUlebIdx(.r11, .r13, .r14, "idx");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    mov qword ptr [rbp + 16], {[vip]t} # ip
            \\    mov qword ptr [rbp + 24], {[stp]t} # stp
            \\    mov qword ptr [rbp + 32], {[eip]t} # eip
            \\    mov qword ptr [rbp + 40], r11 # func_idx
            \\    mov qword ptr [rbp + 48], r15 # call_ip
            \\
        , .{ .stp = Reg64.stp, .eip = Reg64.eip, .vip = Reg64.vip }));
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}invokeWithinWasm"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix });
        try idx_decode.writeSlowPath(ctx);
        ctx.skip_oof_handler -= 1;
    }
    {
        try ctx.defineOpcodeHandler("call_indirect", .@"32");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    lea rdi, [{[vip]t} - 1] # save ip to call_indirect byte, clobbers locals
            \\    # clobber mems
            \\
        , .{ .vip = Reg64.vip }));
        const type_idx_decode = try ctx.decodeUlebIdx(.r8, .r13, .r14, "type");
        const table_idx_decode = try ctx.decodeUlebIdx(.r13, .r14, .r15, "table");
        const oob = try Label.init(ctx, "oob");
        const null_elem = try Label.init(ctx, "null_elem");
        try ctx.asm_out.print(
            \\    # load expected signature
            \\    mov r11, qword ptr [{[module]t} + {[module_info_off]d}] # ptr to info
            \\    mov r11, qword ptr [r11 + {[info_types_off]d}] # ptr to func types
            \\    shl r8, 4 # size of func type is two qwords
            \\    lea r8, qword ptr [r11 + r8] # ptr to func type, clobbers type idx
            \\    # load funcref from table
            \\    mov r14d, dword ptr [{[vsp]t} - 0x10] # element index
            \\    mov rdx, qword ptr [{[module]t} + {[module_tables_off]d}] # ptr to module's tables, clobbers module
            \\    mov rdx, qword ptr [rdx + r13 * 8] # ptr to table
            \\    cmp r14d, dword ptr [rdx + {[table_len_off]d}] # bounds check
            \\    ja {[oob]f}
            \\    mov rdx, qword ptr [rdx] # ptr to elems, clobbers ptr to table
            \\    mov rdx, qword ptr [rdx + r14 * 8] # funcref, clobbers ptr to elems
            \\    test rdx, rdx # check for null
            \\    jz {[null_elem]f}
            \\    mov qword ptr [rbp + 16], {[vip]t} # ip
            \\    mov qword ptr [rbp + 24], {[stp]t} # stp
            \\    mov qword ptr [rbp + 32], {[eip]t} # eip
            \\
        , .{
            .vsp = Reg64.vsp,
            .module = Reg64.module,
            .module_info_off = 8,
            .info_types_off = 0, // Assumes offset of RawInner in Module.Inner is 0
            .module_tables_off = 40,
            .table_len_off = 12,
            .oob = oob,
            .null_elem = null_elem,
            .vip = Reg64.vip,
            .stp = Reg64.stp,
            .eip = Reg64.eip,
        });
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}invokeWithinWasmIndirect"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix });
        try type_idx_decode.writeSlowPath(ctx);
        try table_idx_decode.writeSlowPath(ctx);
        ctx.skip_oof_handler -= 1;

        try ctx.asm_out.print(
            \\.align 16
            \\{[oob]f}:
            \\    # rdi has trap_ip
            \\    mov rdx, {[eip]t}
            \\    mov rcx, {[stp]t}
            \\    mov r8, r13 # table index
            \\
        , .{ .oob = oob, .eip = Reg64.eip, .stp = Reg64.stp });
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}trapTableAccessOob"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix });

        try ctx.asm_out.print(
            \\.align 16
            \\{[null_elem]f}:
            \\    # rdi has trap_ip
            \\    mov rdx, {[eip]t}
            \\    mov rcx, {[stp]t}
            \\    mov r8, r14 # elem index
            \\
        , .{ .null_elem = null_elem, .eip = Reg64.eip, .stp = Reg64.stp });
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}trapIndirectCallToNull"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix });
    }
}

fn defineParametericOpcodeHandlers(ctx: *Context) !void {
    {
        try ctx.defineOpcodeHandler("drop", .@"16");
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    sub {[vsp]t}, 16
            \\
        , .{ .vsp = Reg64.vsp }));
        try ctx.jmpToNextHandler(.r11);
    }
    // TODO: "select t" handler to fallthrough to "select" handler
    {
        try ctx.defineOpcodeHandler("select", .@"16");
        const true_label = try Label.init(ctx, "true");
        // select without type requires numeric or vector type, so this must
        // assume vector (xmmword) to be safe
        try ctx.asm_out.print(
            \\    xor r14, r14
            \\    mov r13d, dword ptr [{[vsp]t} - 0x10]
            \\    test r13d, r13d
            \\    jnz {[true]f}
            \\    movaps xmm0, xmmword ptr [{[vsp]t} - 0x20]
            \\    movaps xmmword ptr [{[vsp]t} - 0x30], xmm0
            \\    {[true]f}:
            \\    sub {[vsp]t}, 0x20
            \\
        , .{ .vsp = Reg64.vsp, .true = true_label });
        try ctx.jmpToNextHandler(.r11);
    }
}

fn defineGlobalOpcodeHandlers(ctx: *Context) !void {
    {
        try ctx.defineOpcodeHandler("global.get", .@"64");
        const jump_table = try Label.init(ctx, "jump-table");
        const load_4 = try Label.init(ctx, "load-4");
        const load_8 = try Label.init(ctx, "load-8");
        const load_16 = try Label.init(ctx, "load-16");
        const idx_decode = try ctx.decodeUlebIdx(.r11, .r13, .r14, "idx");
        try ctx.asm_out.print(
            \\    mov r13, qword ptr [{[module]t} + {[module_info_off]d}] # ptr to info
            \\    mov r13, qword ptr [r13 + {[info_types_off]d}] # ptr to global types
            \\    xor r14, r14
            \\    mov r14b, byte ptr [r13 + r11 * {[global_type_size]d}] # global type
            \\    # r14b contains valtype byte
            \\    sub r14b, 0x6F # index into jump table
            \\    mov r15, qword ptr [{[module]t} + {[module_globals_off]d}] # ptr to globals
            \\    mov r15, qword ptr [r15 + r11*8] # ptr to value
            \\    jmp qword ptr [{[jump_table]f} + r14*8]
            \\    ud2
            \\
        , .{
            .module = Reg64.module,
            .module_info_off = 8,
            .module_globals_off = 48,
            .info_types_off = 80, // Assumes offset of RawInner in Module.Inner is 0
            .global_type_size = 2,
            .jump_table = jump_table,
        });
        try idx_decode.writeSlowPath(ctx);

        ctx.skip_oof_handler += 2;

        try ctx.asm_out.print(
            \\.align 8
            \\{[load_4]f}:
            \\    mov r11d, dword ptr [r15] # get value to load
            \\    mov dword ptr [{[vsp]t}], r11d
            \\    add {[vsp]t}, 0x10
            \\
        , .{ .load_4 = load_4, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);

        try ctx.asm_out.print(
            \\.align 16
            \\{[load_8]f}:
            \\    mov r11, qword ptr [r15] # get value to load
            \\    mov qword ptr [{[vsp]t}], r11
            \\    add {[vsp]t}, 0x10
            \\
        , .{ .load_8 = load_8, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);

        try ctx.asm_out.print(
            \\.align 32
            \\{[load_16]f}:
            \\    movaps xmm0, xmmword ptr [r15] # get value to load
            \\    movaps xmmword ptr [{[vsp]t}], xmm0
            \\    add {[vsp]t}, 0x10
            \\
        , .{ .load_16 = load_16, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);

        try ctx.asm_out.print(
            \\.section .rodata
            \\.align 64
            \\{[label]f}:
            \\    .quad {[load_8]f} # externref
            \\    .quad {[load_8]f} # funcref
            \\
        , .{ .label = jump_table, .load_8 = load_8 });
        for (0..10) |_| {
            try ctx.asm_out.writeAll(
                \\    .quad 0xAAAAAAAAAAAAAAAA
                \\
            );
        }
        try ctx.asm_out.print(
            \\    .quad {[load_16]f} # v128
            \\    .quad {[load_8]f} # f64
            \\    .quad {[load_4]f} # f32
            \\    .quad {[load_8]f} # i64
            \\    .quad {[load_4]f} # i32
            \\.text
            \\
        , .{ .load_4 = load_4, .load_8 = load_8, .load_16 = load_16 });
    }
    {
        try ctx.defineOpcodeHandler("global.set", .@"64");
        const jump_table = try Label.init(ctx, "jump-table");
        const store_4 = try Label.init(ctx, "store-4");
        const store_8 = try Label.init(ctx, "store-8");
        const store_16 = try Label.init(ctx, "store-16");
        const idx_decode = try ctx.decodeUlebIdx(.r11, .r13, .r14, "idx");
        try ctx.asm_out.print(
            \\    mov r13, qword ptr [{[module]t} + {[module_info_off]d}] # ptr to info
            \\    mov r13, qword ptr [r13 + {[info_types_off]d}] # ptr to global types
            \\    xor r14, r14
            \\    mov r14b, byte ptr [r13 + r11 * {[global_type_size]d}] # global type
            \\    # r14b contains valtype byte
            \\    # i32       = 7F
            \\    # i64       = 7E
            \\    # f32       = 7D
            \\    # f64       = 7C
            \\    # v128      = 7B
            \\    #             71..7A
            \\    # funcref   = 70
            \\    # externref = 6F
            \\    sub r14b, 0x6F # index into jump table
            \\    mov r15, qword ptr [{[module]t} + {[module_globals_off]d}] # ptr to globals
            \\    mov r15, qword ptr [r15 + r11*8] # ptr to value
            \\    jmp qword ptr [{[jump_table]f} + r14*8]
            \\    ud2
            \\
        , .{
            .module = Reg64.module,
            .module_info_off = 8,
            .module_globals_off = 48,
            .info_types_off = 80, // Assumes offset of RawInner in Module.Inner is 0
            .global_type_size = 2,
            .jump_table = jump_table,
        });
        try idx_decode.writeSlowPath(ctx);

        ctx.skip_oof_handler += 2;

        try ctx.asm_out.print(
            \\.align 8
            \\{[store_4]f}:
            \\    mov r11d, dword ptr [{[vsp]t} - 0x10] # get value to store
            \\    mov dword ptr [r15], r11d
            \\    sub {[vsp]t}, 0x10
            \\
        , .{ .store_4 = store_4, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);

        try ctx.asm_out.print(
            \\.align 16
            \\{[store_8]f}:
            \\    mov r11, qword ptr [{[vsp]t} - 0x10] # get value to store
            \\    mov qword ptr [r15], r11
            \\    sub {[vsp]t}, 0x10
            \\
        , .{ .store_8 = store_8, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);

        try ctx.asm_out.print(
            \\.align 32
            \\{[store_16]f}:
            \\    movaps xmm0, xmmword ptr [{[vsp]t} - 0x10] # get value to store
            \\    movaps xmmword ptr [r15], xmm0
            \\    sub {[vsp]t}, 0x10
            \\
        , .{ .store_16 = store_16, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);

        try ctx.asm_out.print(
            \\.section .rodata
            \\.align 64
            \\{[label]f}:
            \\    .quad {[store_8]f} # externref
            \\    .quad {[store_8]f} # funcref
            \\
        , .{ .label = jump_table, .store_8 = store_8 });
        for (0..10) |_| {
            try ctx.asm_out.writeAll(
                \\    .quad 0xAAAAAAAAAAAAAAAA
                \\
            );
        }
        try ctx.asm_out.print(
            \\    .quad {[store_16]f} # v128
            \\    .quad {[store_8]f} # f64
            \\    .quad {[store_4]f} # f32
            \\    .quad {[store_8]f} # i64
            \\    .quad {[store_4]f} # i32
            \\.text
            \\
        , .{ .store_4 = store_4, .store_8 = store_8, .store_16 = store_16 });
    }
}

fn defineMemoryLoadOpcodeHandlers(ctx: *Context) !void {
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
}

fn defineMemoryStoreOpcodeHandlers(ctx: *Context) !void {
    for (&[_]struct { []const u8, std.mem.Alignment, RegSize, []const u8, RegSize }{
        .{ "i32.store", .@"4", .dword, "mov", .dword },
        .{ "f32.store", .@"4", .dword, "mov", .dword }, // ReleaseSmall could deduplicate w/ i32.store
        .{ "i32.store8", .@"1", .dword, "mov", .byte },
        .{ "i32.store16", .@"2", .dword, "mov", .word },
        .{ "i64.store", .@"8", .qword, "mov", .qword },
        .{ "f64.store", .@"8", .qword, "mov", .qword }, // ReleaseSmall could deduplicate w/ i64.store
        .{ "i64.store8", .@"1", .qword, "mov", .byte },
        .{ "i64.store16", .@"2", .qword, "mov", .word },
        .{ "i64.store32", .@"4", .qword, "mov", .dword },
    }) |info| {
        const name, const access_size, const load_size, const instr, const store_size = info;
        try ctx.defineOpcodeHandler(name, .@"64");
        const access = try ctx.linearMemoryAccess(1, access_size);
        try ctx.asm_out.print(
            \\    mov {[load_reg]s}, {[load_size]t} ptr [{[vsp]t} - 16] 
            \\    {[instr]s} {[store_size]t} ptr [r13 + r15], {[store_reg]s}
            \\    sub {[vsp]t}, 32
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
}

fn defineMemoryManagementOpcodeHandlers(ctx: *Context) !void {
    // memory.size
    {
        try ctx.defineOpcodeHandler("memory.grow", .@"64");
        const mem_idx_decode = try ctx.decodeUlebIdx(.r11, .r13, .r14, "idx");
        const fail = try Label.init(ctx, "fail");
        const within_capacity = try Label.init(ctx, "within-capacity");
        try ctx.asm_out.print(
            \\    mov r13d, dword ptr [{[vsp]t} - 0x10] # delta, in pages
            \\    shl r13d, 16 # go from page size to bytes
            \\    # ^ assumes 32-bit memories/indices
            \\    jc {[fail]f}
            \\    mov r11, [{[mems]t} + r11*8] # ptr to memory, clobbers memidx
            \\    mov r14, qword ptr [r11 + {[mem_size_off]d}] # memory size
            \\    add r13, r14 # memory size + delta = desired size
            \\    cmp r13, qword ptr [r11 + {[mem_limit_off]d}] # check against limit 
            \\    ja {[fail]f}
            \\    cmp r13, qword ptr [r11 + {[mem_cap_off]d}] # check against capacity
            \\    jna {[within_capacity]f}
            \\    mov dword ptr [{[vsp]t} - 0x10], -1 # assume growth failure
            \\    # Setup parameters
            \\    mov rdi, r13 #1 clobbers locals
            \\    #2 vsp is already in rsi
            \\    mov rdx, {[vip]t} #3 clobbers module
            \\    mov rcx, {[eip]t} #4 clobbers fuel
            \\    mov r8, r11 #5 clobbers mems
            \\    #6 is already in r9
            \\    mov qword ptr [rbp + 16], {[stp]t} # stp
            \\
        , .{
            .vsp = Reg64.vsp,
            .vip = Reg64.vip,
            .eip = Reg64.eip,
            .stp = Reg64.stp,
            .mems = Reg64.mems,
            .fail = fail,
            .within_capacity = within_capacity,
            // .mem_base_off = 0,
            .mem_size_off = 8,
            .mem_cap_off = 16,
            .mem_limit_off = 24,
        });
        try ctx.popSystemVSavedRegisters();
        try ctx.asm_out.print(
            \\    mov rsp, rbp
            \\    pop rbp
            \\    jmp "{[prefix]s}memoryGrowReallocate"
            \\    ud2
            \\
        , .{ .prefix = ctx.name_prefix });

        const to_next = try Label.init(ctx, "next-opcode");
        try ctx.asm_out.print(
            \\.align 16
            \\{[within_capacity]f}:
            \\    # TODO: only fill with zeroes if allocator says it doesn't fill w/ zeroes
            \\    # OS pages are zeroed
            \\    # Assuming 65536 page size, could memset with rep stosb (apparently not as good on AMD)
            \\    mov dword ptr [{[vsp]t} - 0x10], r14d # store old size
            \\    mov qword ptr [r11 + {[mem_size_off]d}], r13 # store new size
            \\{[to_next]f}:
            \\
        , .{
            .within_capacity = within_capacity,
            .to_next = to_next,
            .vsp = Reg64.vsp,
            .mem_size_off = 8,
        });
        try ctx.jmpToNextHandler(.r11);
        try ctx.asm_out.print(
            \\{[fail]f}:
            \\    mov dword ptr [{[vsp]t} - 0x10], -1
            \\    jmp {[to_next]f}
            \\
        , .{ .fail = fail, .vsp = Reg64.vsp, .to_next = to_next });
        try mem_idx_decode.writeSlowPath(ctx);
    }
}

fn defineConstOpcodeHandlers(ctx: *Context) !void {
    for (&[_]struct { []const u8, u5, IntType, u7 }{
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
                \\
            , .{ .label = label });
            if (i == 0) {
                try ctx.asm_out.writeAll(
                    \\    and r11b, 0x7F
                    \\
                );
            }

            try ctx.asm_out.print(
                \\    movzx {[r14]s}, byte ptr [{[vip]t}]
                \\    mov {[r13]s}, {[r14]s}
                \\    inc {[vip]t}
                \\    and r13b, 0x7F
                \\    shl {[r13]s}, {[byte_shift]d}
                \\    or {[r11]s}, {[r13]s}
                \\    test r14b, 0x80
                \\    jnz {[next]f}
                \\    shl {[r11]s}, {[final_shift]d}
                \\    sar {[r11]s}, {[final_shift]d}
                \\    jmp {[finished]f}
                \\    ud2
                \\
            , .{
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
}

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
            \\    cmp {[r14]s}, {[r13]s} # TODO: 2nd operand of cmp can be memory
            \\    {[set_instr]s} r15b
            \\    mov {[size]t} ptr [{[vsp]t} - 32], {[r15]s} # TODO: Oops, this should be a dword
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

const FloatType = enum {
    f32,
    f64,

    fn regSize(ty: FloatType) RegSize {
        return switch (ty) {
            .f32 => .dword,
            .f64 => .qword,
        };
    }
};

fn defineFloatOpcodeHandlers(ctx: *Context, float_type: FloatType) !void {
    var opcode_name_buf: [16]u8 = undefined;
    var opcode_name = OpcodeNamePrefix.init(@tagName(float_type), &opcode_name_buf);
    const size = float_type.regSize();
    const float_suffix: u8 = switch (float_type) {
        .f32 => 's',
        .f64 => 'd',
    };
    const int_suffix: u8 = switch (float_type) {
        .f32 => 'd',
        .f64 => 'q',
    };
    const r13 = Reg64.r13.nameResized(size);
    const r14 = Reg64.r14.nameResized(size);
    const sign_bit = switch (float_type) {
        .f32 => "0x8000" ++ "0000",
        .f64 => "0x8000" ++ "0000" ++ "0000" ++ "0000",
    };
    const non_sign_mask = switch (float_type) {
        .f32 => "0x7FFF" ++ "FFFF",
        .f64 => "0x7FFF" ++ "FFFF" ++ "FFFF" ++ "FFFF",
    };
    const canonical_nan_mask = switch (float_type) {
        .f32 => "0xFFC0" ++ "0000",
        .f64 => "0xFFF8" ++ "0000" ++ "0000" ++ "0000",
    };
    const canonical_nan_bit = switch (float_type) {
        .f32 => "0x0040" ++ "0000",
        .f64 => "0x0008" ++ "0000" ++ "0000" ++ "0000",
    };

    // Zig/LLVM uses vmovs(s|d) when targeting x86_64_v3

    for (&[_][2][]const u8{
        .{ ".eq", "cmpeqs" },
        .{ ".ne", "cmpneqs" },
    }) |info| {
        try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
        try ctx.asm_out.print(
            \\    movs{[float_suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x10]
            \\    xor r13, r13
            \\    {[instr]s}{[float_suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x20]
            \\    mov{[int_suffix]c} {[r13]s}, xmm0
            \\    and {[r13]s}, 1
            \\    mov {[size]t} ptr [{[vsp]t} - 0x20], {[r13]s}
            \\    sub {[vsp]t}, 16
            \\
        , .{
            .float_suffix = float_suffix,
            .int_suffix = int_suffix,
            .r13 = r13,
            .size = size,
            .vsp = Reg64.vsp,
            .instr = info[1],
        });
        try ctx.jmpToNextHandler(.r11);
    }

    // Zig/LLVM uses vucomis(s|d) when targeting x86_64_v3
    for (&[_]struct { []const u8, []const u8, u1 }{
        .{ ".lt", "seta", 0 },
        .{ ".le", "setae", 0 },
        .{ ".gt", "seta", 1 },
        .{ ".ge", "setae", 1 },
    }) |info| {
        const name, const set_instr, const order = info;
        try ctx.defineOpcodeHandler(opcode_name.name(name), .@"64");
        try ctx.asm_out.print(
            \\    movs{[suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x{[op_1]X}]
            \\    xor r15, r15
            \\    ucomis{[suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x{[op_2]X}]
            \\    {[set_instr]s} r15b
            \\    mov dword ptr [{[vsp]t} - 0x20], r15d
            \\    sub {[vsp]t}, 16
            \\
        , .{
            .suffix = float_suffix,
            .size = size,
            .vsp = Reg64.vsp,
            .set_instr = set_instr,
            .op_1 = @as(u8, switch (order) {
                0 => 0x10,
                1 => 0x20,
            }),
            .op_2 = @as(u8, switch (order) {
                0 => 0x20,
                1 => 0x10,
            }),
        });
        try ctx.jmpToNextHandler(.r11);
    }

    {
        try ctx.defineOpcodeHandler(opcode_name.name(".abs"), .@"32");
        try ctx.asm_out.print(
            \\    mov {[r13]s}, {[mask]s}
            \\    and {[size]t} ptr [{[vsp]t} - 16], {[r13]s} # clear sign bit
            \\
        , .{ .r13 = r13, .size = size, .vsp = Reg64.vsp, .mask = non_sign_mask });
        try ctx.jmpToNextHandler(.r11);
    }
    {
        try ctx.defineOpcodeHandler(opcode_name.name(".neg"), .@"32");
        try ctx.asm_out.print(
            \\    mov {[r13]s}, {[mask]s}
            \\    xor {[size]t} ptr [{[vsp]t} - 16], {[r13]s} # clear sign bit
            \\
        , .{ .r13 = r13, .size = size, .vsp = Reg64.vsp, .mask = sign_bit });
        try ctx.jmpToNextHandler(.r11);
    }

    // When only SSE2 is available, LLVM calls libc functions via @PLT
    for (&[_]struct { []const u8, u2 }{
        .{ ".ceil", 0b10 }, // ceilf/ceill
        .{ ".floor", 0b01 }, // floorf/floorl
        .{ ".trunc", 0b11 }, // trunc/truncl?
        .{ ".nearest", 0b00 }, // roundevenf/roundeevenl
    }) |info| {
        try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
        try ctx.asm_out.print(
            \\    rounds{[suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x10], 0x{[rounding_mode]X} # TODO: Requires SSE4.1
            \\    movs{[suffix]c} {[size]t} ptr [{[vsp]t} - 0x10], xmm0
            \\
        , .{
            .suffix = float_suffix,
            .size = size,
            .vsp = Reg64.vsp,
            .rounding_mode = 0b1000 | @as(u8, info[1]),
        });
        try ctx.jmpToNextHandler(.r11);
    }

    for (&[_][2][]const u8{
        .{ ".sqrt", "sqrts" },
    }) |info| {
        try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
        try ctx.asm_out.print(
            \\    {[instr]s}{[suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x10]
            \\    movs{[suffix]c} {[size]t} ptr [{[vsp]t} - 0x10], xmm0
            \\
        , .{ .instr = info[1], .suffix = float_suffix, .size = size, .vsp = Reg64.vsp });
        try ctx.jmpToNextHandler(.r11);
    }

    for (&[_][2][]const u8{
        .{ ".add", "adds" },
        .{ ".sub", "subs" },
        .{ ".mul", "muls" },
        .{ ".div", "divs" },
    }) |info| {
        try ctx.defineOpcodeHandler(opcode_name.name(info[0]), .@"64");
        try ctx.asm_out.print(
            \\    movs{[suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x20]
            \\    {[instr]s}{[suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x10]
            \\    movs{[suffix]c} {[size]t} ptr [{[vsp]t} - 0x20], xmm0
            \\    sub {[vsp]t}, 16
            \\
        , .{ .suffix = float_suffix, .size = size, .vsp = Reg64.vsp, .instr = info[1] });
        try ctx.jmpToNextHandler(.r11);
    }

    {
        // Cranelift and Wizard implement `f32.min` with two `minss`
        // - https://github.com/llvm/llvm-project/pull/170069
        // - https://github.com/rust-lang/rust/issues/91079
        try ctx.defineOpcodeHandler(opcode_name.name(".min"), .@"64");
        try ctx.asm_out.print(
            \\    mov{[int_suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x10] # first
            \\    mov{[int_suffix]c} xmm1, {[size]t} ptr [{[vsp]t} - 0x20] # second
            \\    movaps xmm2, xmm0
            \\    movaps xmm3, xmm1
            \\    movaps xmm4, xmm0
            \\    mins{[float_suffix]c} xmm2, xmm1
            \\    mins{[float_suffix]c} xmm3, xmm0
            \\    orp{[float_suffix]c} xmm2, xmm3 # handles non-NaN case correctly
            //
            \\    mov {[r13]s}, {[canonical_nan_mask]s}
            \\    mov{[int_suffix]c} xmm3, {[r13]s} # canonical NaN mask
            //
            \\    cmpords{[float_suffix]c} xmm4, xmm1 # all 1's if NaN was NOT present
            \\    # mask of all 1's if no NaN, canonical_nan_mask if there is NaN
            \\    orp{[float_suffix]c} xmm3, xmm4
            \\    andp{[float_suffix]c} xmm2, xmm3 # If NaN, mask away non-canonical NaN bits
            //
            \\    mov {[r13]s}, {[canonical_nan_bit]s}
            \\    mov{[int_suffix]c} xmm3, {[r13]s} # canonical NaN bit
            \\    andnp{[float_suffix]c} xmm4, xmm3 # canonical NaN bit if NaN is present
            \\    # If NaNs are present, set the canonical NaN bit
            \\    orp{[float_suffix]c} xmm2, xmm4
            //
            \\    mov{[int_suffix]c} {[size]t} ptr [{[vsp]t} - 0x20], xmm2 # write result
            \\    sub {[vsp]t}, 0x10 # vsp
            \\
        , .{
            .r13 = r13,
            .canonical_nan_mask = canonical_nan_mask,
            .canonical_nan_bit = canonical_nan_bit,
            .int_suffix = int_suffix,
            .float_suffix = float_suffix,
            .size = size,
            .vsp = Reg64.vsp,
        });
        try ctx.jmpToNextHandler(.r11);
    }
    {
        try ctx.defineOpcodeHandler(opcode_name.name(".max"), .@"64");
        try ctx.asm_out.print(
            \\    mov{[int_suffix]c} xmm0, {[size]t} ptr [{[vsp]t} - 0x10] # first
            \\    mov{[int_suffix]c} xmm1, {[size]t} ptr [{[vsp]t} - 0x20] # second
            \\    movaps xmm2, xmm0
            \\    movaps xmm3, xmm1
            \\    movaps xmm4, xmm0
            \\    maxs{[float_suffix]c} xmm2, xmm1
            \\    maxs{[float_suffix]c} xmm3, xmm0
            \\    orp{[float_suffix]c} xmm2, xmm3 # almost handles non-NaN case correctly, sign may be wrong
            //
            \\    mov {[r13]s}, {[sign_bit]s}
            \\    mov{[int_suffix]c} xmm3, {[r13]s} # sign bit
            \\    movaps xmm5, xmm3
            \\    andnp{[float_suffix]c} xmm3, xmm2 # remove sign bit
            //
            \\    andp{[float_suffix]c} xmm4, xmm5 # sign of first input
            \\    andp{[float_suffix]c} xmm5, xmm1 # sign of second input
            \\    andp{[float_suffix]c} xmm4, xmm5 # final sign
            \\    orp{[float_suffix]c} xmm3, xmm4 # apply correct sign bit
            //
            \\    mov {[r13]s}, {[canonical_nan_mask]s}
            \\    mov{[int_suffix]c} xmm2, {[r13]s} # canonical NaN mask
            //
            \\    movaps xmm4, xmm0
            \\    cmpords{[float_suffix]c} xmm4, xmm1 # all 1's if NaN was NOT present
            \\    # mask of all 1's if no NaN, canonical_nan_mask if there is NaN
            \\    orp{[float_suffix]c} xmm2, xmm4
            \\    andp{[float_suffix]c} xmm3, xmm2 # If NaN, mask away non-canonical NaN bits
            //
            \\    mov {[r13]s}, {[canonical_nan_bit]s}
            \\    mov{[int_suffix]c} xmm2, {[r13]s} # canonical NaN bit
            \\    andnp{[float_suffix]c} xmm4, xmm2 # canonical NaN bit if NaN is present
            \\    # If NaNs are present, set the canonical NaN bit
            \\    orp{[float_suffix]c} xmm3, xmm4
            //
            \\    mov{[int_suffix]c} {[size]t} ptr [{[vsp]t} - 0x20], xmm3 # write result
            \\    sub {[vsp]t}, 0x10 # vsp
            \\
        , .{
            .r13 = r13,
            .sign_bit = sign_bit,
            .canonical_nan_mask = canonical_nan_mask,
            .canonical_nan_bit = canonical_nan_bit,
            .int_suffix = int_suffix,
            .float_suffix = float_suffix,
            .size = size,
            .vsp = Reg64.vsp,
        });
        try ctx.jmpToNextHandler(.r11);
    }
    {
        try ctx.defineOpcodeHandler(opcode_name.name(".copysign"), .@"64");
        // Could use ANDN from BMI1 here
        try ctx.asm_out.print(
            \\    mov {[r13]s}, {[sign_bit]s} # sign bit
            \\    mov {[r14]s}, {[r13]s}
            \\    not {[r14]s} # non-sign mask
            \\    and {[r13]s}, {[size]t} ptr [{[vsp]t} - 0x10] # get sign
            \\    and {[r14]s}, {[size]t} ptr [{[vsp]t} - 0x20] # get other bits
            \\    or {[r13]s}, {[r14]s} # combine them
            \\    mov {[size]t} ptr [{[vsp]t} - 0x20], {[r13]s}
            \\    sub {[vsp]t}, 0x10
            \\
        , .{
            .r13 = r13,
            .r14 = r14,
            .sign_bit = sign_bit,
            .vsp = Reg64.vsp,
            .size = size,
        });
        try ctx.jmpToNextHandler(.r11);
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

    fn toReg16(reg: Reg64) Reg16 {
        return reg.toReg32().toReg16();
    }

    fn toReg8(reg: Reg64) Reg8 {
        return reg.toReg32().toReg8();
    }

    fn nameResized(reg: Reg64, size: RegSize) []const u8 {
        return switch (size) {
            .qword => @tagName(reg),
            .dword => @tagName(reg.toReg32()),
            .word => @tagName(reg.toReg16()),
            .byte => @tagName(reg.toReg8()),
        };
    }
};

const Reg16 = enum {
    ax,
    bx,
    cx,
    dx,
    si,
    di,
    //sp,
    //bp,
    r8w,
    r9w,
    r10w,
    r11w,
    r12w,
    r13w,
    r14w,
    r15w,
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
            inline .eax, .ebx, .ecx, .edx => |r| return @field(
                Reg8,
                &[2]u8{ @tagName(r)[1], 'l' },
            ),
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

    fn toReg16(reg: Reg32) Reg16 {
        switch (reg) {
            inline .eax,
            .ebx,
            .ecx,
            .edx,
            .esi,
            .edi,
            => |r| return @field(Reg16, @tagName(r)[1..]),
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
                return @field(Reg16, name[0..(name.len - 1)] ++ "w");
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

    fn toReg8(reg: TempReg) Reg8 {
        return reg.toReg32().toReg8();
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
            .name = try ctx.concat(&.{ "\".L", ctx.opcode_name, ".", name, "\"" }),
        };
    }

    fn initWithSuffix(ctx: *Context, name: []const u8, suffix: []const u8) !Label {
        return Label{
            .name = try ctx.concat(&.{ "\".L", ctx.opcode_name, ".", name, "-", suffix, "\"" }),
        };
    }

    pub fn format(label: Label, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(label.name);
    }
};

const Context = struct {
    name_prefix: []const u8,
    opcode_name: []const u8 = undefined,
    optimize: std.builtin.OptimizeMode,
    scratch: *std.heap.ArenaAllocator,
    asm_out: *std.Io.Writer,
    zig_out: *std.Io.Writer,
    skip_oof_handler: u32 = 0,

    fn popSystemVSavedRegisters(ctx: *Context) !void {
        try ctx.asm_out.writeAll(std.fmt.comptimePrint(
            \\    # Restore System V saved registers
            \\    add rsp, {[stack_space_padding]d}
            \\
        , .{ .stack_space_padding = 8 }));
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

    fn defineOpcodeHandlerWithAliases(
        ctx: *Context,
        names: []const []const u8,
        align_to: std.mem.Alignment,
    ) !void {
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
                \\.type "{[prefix]s}{[name]s}", @function
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

        fn writeSlowPath(decode: @This(), ctx: *Context) !void {
            _ = decode;
            _ = ctx;
            unreachable;
        }
    };

    fn decodeUlebIdx(
        ctx: *Context,
        result: Reg64,
        clobber_0: TempReg,
        clobber_1: TempReg,
        name: []const u8,
    ) !@This().DecodeUlebIdx {
        _ = ctx;
        _ = result;
        _ = clobber_0;
        _ = clobber_1;
        _ = name;
        unreachable;
    }

    const LinearMemoryAccess = struct {
        align_decode: @This().DecodeUlebIdx,
        offset_decode: @This().DecodeUlebIdx,
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

    fn jmpToNextHandler(ctx: *Context, comptime temp: TempReg) !void {
        const out_of_fuel = try Label.init(ctx, "out-of-fuel");
        _ = temp;
        // try ctx.asm_out.writeAll(std.fmt.comptimePrint(
        //     \\    movzx {[temp]t}, byte ptr [{[ip]t}] # Start reading next opcode byte
        //     \\    sub qword ptr [{[fuel]t}], 1 # Fuel check
        //     \\
        // , .{ .ip = Reg64.vip, .temp = temp, .fuel = Reg64.fuel }));
        // try ctx.asm_out.print("    jb {f}\n", .{out_of_fuel});
        // try ctx.asm_out.writeAll(std.fmt.comptimePrint(
        //     // \\    # Jump to handler
        //     // \\    inc {[ip]t}
        //     \\    mov {[temp]t}, qword ptr [{[disp]t} + {[temp]t} * 8]
        //     \\    jmp {[temp]t}
        //     \\    ud2
        //     \\
        // , .{ .ip = Reg64.vip, .temp = temp, .disp = Reg64.disp }));
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
const Assembler = @import("Assembler.zig");
const ZigWriter = @import("ZigWriter");
