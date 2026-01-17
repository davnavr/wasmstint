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
    var asm_writer = AsmWriter.init(
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
    defineControlOpcodeHandlers(&asm_writer, &zig_writer);
    defineCallOpcodeHandlers(&asm_writer, &zig_writer);
    defineParametericOpcodeHandlers(&asm_writer, &zig_writer, optimize);
    defineLocalOpcodeHandlers(&asm_writer, &zig_writer);
    defineGlobalOpcodeHandlers(&asm_writer, &zig_writer);
    defineTableAccessOpcodeHandlers(&asm_writer, &zig_writer);
    defineMemoryLoadOpcodeHandlers(&asm_writer, &zig_writer);
    defineMemoryStoreOpcodeHandlers(&asm_writer, &zig_writer);
    defineMemoryManagementOpcodeHandlers(&asm_writer, &zig_writer);
    defineConstOpcodeHandlers(&asm_writer, &zig_writer);
    defineIntegerOpcodeHandlers(&asm_writer, &zig_writer, .i32);
    defineIntegerOpcodeHandlers(&asm_writer, &zig_writer, .i64);
    defineFloatOpcodeHandlers(&asm_writer, &zig_writer, .f32);
    defineFloatOpcodeHandlers(&asm_writer, &zig_writer, .f64);
    defineNumericConversionOpcodeHandlers(&asm_writer, &zig_writer);
    defineReferenceOpcodeHandlers(&asm_writer, &zig_writer);
    definePrefixOpcodeHandlers(&asm_writer, &zig_writer, optimize);
    defineBulkMemoryOpcodeHandlers(&asm_writer, &zig_writer);

    asm_writer.finish();
    zig_writer.finish();
    std.process.exit(0);
}

fn defineSupportRoutines(as: *AsmWriter, optimize: std.builtin.OptimizeMode) void {
    {
        // TODO: Could detect if build script uses LLVM backend, meaning RegCall calling
        // convention could be used instead of System V
        var trampoline = as.startFunction("opcodeHandlerTrampoline", .@"64");
        as.writeInstrs(&.{
            "# System V calling convention",
            "push rbp",
            ".cfi_def_cfa_offset 16",
            ".cfi_offset rbp, -16",
            "mov rbp, rsp",
            ".cfi_def_cfa_register rbp",
        });
        as.pushSystemVSavedRegisters();
        as.printInstrs(&.{
            "# Stack is NOT 16-byte aligned, as required by the calling convention, at this point",
            "mov {[vip]f}, {[stack_0]f} #6 VIP",
            "mov {[stp]f}, {[stack_1]f} #7 STP",
            "mov {[eip]f}, {[stack_2]f} #8 EIP",
            "mov r15, {[stack_3]f} #9 opcode handler",

            "# jump to next handler",
            "lea {[dispatch]f}, {[symbol_prefix]s}byte_dispatch_table",
            "jmp r15",
            "ud2",
        }, .{
            .vip = Gpr.vip,
            .stack_0 = SystemVParam{ .index = 6 },
            .stp = Gpr.stp,
            .stack_1 = SystemVParam{ .index = 7 },
            .eip = Gpr.eip,
            .stack_2 = SystemVParam{ .index = 8 },
            .stack_3 = SystemVParam{ .index = 9 },
            .dispatch = Gpr.disp,
            .symbol_prefix = as.symbol_prefix,
        });
        trampoline.end(as);
    }
    {
        var invalid = as.startFunction("invalidByteOpcode", switch (optimize) {
            .Debug, .ReleaseSafe => .@"16",
            .ReleaseFast, .ReleaseSmall => .@"1",
        });
        AsmWriter.OpcodeHandler.writeStartingCfiDirectives(as);
        switch (optimize) {
            .Debug, .ReleaseSafe => as.printInstrs(&.{
                "mov {[param_0]f}, {[vip]f} #0 VIP",
                "mov {[param_1]f}, {[eip]f} #1 EIP",
                "# doesn't `jmp`, so stack trace is better",
                "call {[symbol_prefix]s}panicInvalidByteOpcode",
            }, .{
                .param_0 = SystemVParam{ .index = 0 },
                .vip = Gpr.vip,
                .param_1 = SystemVParam{ .index = 1 },
                .eip = Gpr.eip,
                .symbol_prefix = as.symbol_prefix,
            }),
            .ReleaseFast, .ReleaseSmall => {},
        }
        as.writeInstrs(&.{"ud2"});
        invalid.end(as);
    }
    {
        var oof = as.startFunction("outOfFuelHandler", .@"16");
        AsmWriter.OpcodeHandler.writeStartingCfiDirectives(as);
        for (
            &[_]Gpr{ .vip, .vsp, .eip, .stp, .interp },
            &[_]u8{ 0, 2, 1, 3, 4 },
        ) |arg, idx| {
            as.printInstrs(
                &.{"mov {[param]f}, {[src]f} # argument {[n]d}"},
                .{ .param = SystemVParam{ .index = idx }, .src = arg, .n = idx },
            );
        }
        as.writeInstrs(&.{"# perform a tail call"});
        // This will make the called function restore the registers
        // Seems to be no way to avoid doing this, even if a normal `call` is used here
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[symbol_prefix]s}interruptOutOfFuel",
            "ud2",
        }, .{ .symbol_prefix = as.symbol_prefix });
        oof.end(as);
    }
    switch (optimize) {
        .Debug, .ReleaseSafe => {
            var invalid = as.startFunction("invalidPrefixedOpcode", .@"16");
            AsmWriter.OpcodeHandler.writeStartingCfiDirectives(as);
            for (0.., &[3]Gpr{ .vip, .eip, .prefix_opcode_base_ip }) |idx, param| {
                as.printInstrs(
                    &.{"mov {[param]f}, {[src]f} # argument {[n]d}"},
                    .{ .param = SystemVParam{ .index = @intCast(idx) }, .src = param, .n = idx },
                );
            }
            as.printInstrs(&.{
                "# doesn't `jmp`, so stack trace is better",
                "call {[symbol_prefix]s}panicInvalidPrefixedOpcode",
                "ud2",
            }, .{ .symbol_prefix = as.symbol_prefix });
            invalid.end(as);
        },
        .ReleaseFast, .ReleaseSmall => {},
    }
}

const DecodeUlebIdx = struct {
    done: AsmWriter.Label,
    slow_path: AsmWriter.Label,
    result: Gpr,
    byte: Gpr,
    accumulator: Gpr,

    fn fastPath(
        as: *AsmWriter,
        result: Gpr,
        clobbers: [2]Gpr,
        name: []const u8,
    ) DecodeUlebIdx {
        var decode = DecodeUlebIdx{
            .done = as.label(&.{ "index_", name, "_done" }),
            .slow_path = as.label(&.{ "index_", name, "_slow" }),
            .result = result,
            .byte = clobbers[0],
            .accumulator = clobbers[1],
        };
        as.printInstrs(&.{
            "movzx {[result]f}, byte ptr [{[vip]f}] # first byte",
            "inc {[vip]f}",
            "test {[result_l]f}, 0x80 # check for longer index",
            "jnz {[slow_path]f}",
        }, .{
            .result = result,
            .result_l = result.withSize(.byte),
            .vip = Gpr.vip,
            .slow_path = decode.slow_path,
        });
        decode.done.place(as);
        return decode;
    }

    fn writeSlowPath(decode: *DecodeUlebIdx, as: *AsmWriter) void {
        as.write(".p2align 4\n");
        decode.slow_path.place(as);
        as.printInstrs(&.{"and {[result]f}, 0x7F # keep lower 7 bits"}, .{
            .result = decode.result,
        });
        // A loop would probably work better here, but clobbering another register is annoying
        for (1..4) |i| {
            as.printInstrs(&.{
                "movzx {[byte]f}, byte ptr [{[vip]f}] # length is {[len]d} bytes",
                "inc {[vip]f}",
                "mov {[acc]f}, {[byte]f}",
                "and {[acc]f}, 0x7F",
                "shl {[acc]f}, {[shift_by]d}",
                "or {[result]f}, {[acc]f}",
                "test {[byte_l]f}, 0x80 # check for continuation",
                "jz {[done]f}",
            }, .{
                .len = i + 1,
                .result = decode.result,
                .byte = decode.byte,
                .byte_l = decode.byte.withSize(.byte),
                .acc = decode.accumulator,
                .shift_by = i * 7,
                .vip = Gpr.vip,
                .done = decode.done,
            });
        }

        // Assume max length (5 bytes) ULEB128
        as.printInstrs(&.{
            "movzx {[byte]f}, byte ptr [{[vip]f}] # length is maximum of 5 bytes",
            "inc {[vip]f}",
            "mov {[acc]f}, {[byte]f} ",
            // "and {[acc]f}, 0x7F", // final byte, no need to mask
            "shl {[acc]f}, 28",
            "or {[result]f}, {[acc]f}",
            "jmp {[done]f}",
            "ud2",
        }, .{
            .result = decode.result,
            .byte = decode.byte,
            .acc = decode.accumulator,
            .vip = Gpr.vip,
            .done = decode.done,
        });
    }
};

const SkipUlebIdx = struct {
    skip_type_idx: AsmWriter.Label,
    finished: AsmWriter.Label,
    byte: Gpr,

    fn writeDecodeByte(skip: *const SkipUlebIdx, as: *AsmWriter, first_comment: []const u8) void {
        as.printInstrs(&.{
            "movzx {[byte]f}, byte ptr [{[vip]f}] # {[first_comment]s}",
            "inc {[vip]f} # vip",
            "test {[byte_lo]f}, 0x80 # check for longer index",
        }, .{
            .byte = skip.byte,
            .byte_lo = skip.byte.withSize(.byte),
            .first_comment = first_comment,
            .vip = Gpr.vip,
        });
    }

    fn fastPath(as: *AsmWriter, clobber: Gpr, name: []const u8) SkipUlebIdx {
        var skip = SkipUlebIdx{
            .skip_type_idx = as.label(&.{ "skip_idx_", name }),
            .finished = as.label(&.{ "after_idx_", name }),
            .byte = clobber,
        };

        skip.writeDecodeByte(as, "first byte of index");
        as.printInstrs(&.{"jnz {f}"}, .{skip.skip_type_idx});
        skip.finished.place(as);
        return skip;
    }

    fn writeSlowPath(skip: *SkipUlebIdx, as: *AsmWriter) void {
        as.write(".p2align 4\n");
        skip.skip_type_idx.place(as);
        skip.writeDecodeByte(as, "next byte of index");
        as.printInstrs(&.{
            "jz {[finished]f}",
            "jmp {[loop]f}",
            "ud2",
        }, .{ .finished = skip.finished, .loop = skip.skip_type_idx });
        skip.* = undefined;
    }
};

const TakeBranch = struct {
    copy_results: AsmWriter.Label,
    finish: AsmWriter.Label,

    fn fastPath(as: *AsmWriter) TakeBranch {
        var take = TakeBranch{
            .copy_results = as.label(&.{"copy_results"}),
            .finish = as.label(&.{"adjust_stp"}),
        };
        as.printInstrs(&.{
            "movsxd r11, dword ptr [{[stp]f}] # delta_ip",
            "lea {[vip]f}, [r15 + r11]",
            "movzx r11, byte ptr [{[stp]f} + {[copy_count_off]d}] # copy_count",
            "shl r11, 4",
            "movzx r13, byte ptr [{[stp]f} + {[pop_count_off]d}] # pop_count",
            "shl r13, 4",
            "mov r14, {[vsp]f}",
            "sub r14, r13 # base pointer for results destination",
            "test r11, r11",
            "jz {[finish]f}",
            "mov r15, {[vsp]f} # copying stops at this address",
            "sub {[vsp]f}, r11 # base pointer for results source",
            "movaps xmm0, xmmword ptr [{[vsp]f}] # copy single result",
            "movaps xmmword ptr [r14], xmm0",
            "cmp r13, 0x20",
            "jae {[copy_results]f} # clobbers r13",
        }, .{
            .stp = Gpr.stp,
            .vsp = Gpr.vsp,
            .vip = Gpr.vip,
            .copy_count_off = 6,
            .pop_count_off = 7,
            .finish = take.finish,
            .copy_results = take.copy_results,
        });
        take.finish.place(as);
        as.printInstrs(&.{
            "lea {[vsp]f}, [r14 + r11]",
            "movsx r11, word ptr [{[stp]f} + {[delta_stp_off]d}] # delta_stp",
            "shl r11, 3",
            "add {[stp]f}, r11",
        }, .{ .delta_stp_off = 4, .vsp = Gpr.vsp, .stp = Gpr.stp });
        return take;
    }

    fn writeSlowPath(take: *TakeBranch, as: *AsmWriter) void {
        as.write(".p2align 4\n");
        take.copy_results.place(as);
        as.printInstrs(&.{
            "lea {[vsp]f}, [{[vsp]f} + 0x10 # one result was already copied",
            "lea r13, [r14 + 0x10] # pointer to results destination",
        }, .{ .vsp = Gpr.vsp });

        var loop_start = as.label(&.{"copy_results_loop"});
        loop_start.place(as);
        as.printInstrs(&.{
            "# assumes small number of results, so this just copies one at a time",
            "movaps xmm0, xmmword ptr [{[vsp]f}]",
            "movaps xmmword ptr [r13], xmm0",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
            "add r13, 0x10",
            "cmp r13, r15 # check if done",
            "je {[finish]f}",
            "jmp {[loop_start]f}",
            "ud2",
        }, .{ .vsp = Gpr.vsp, .finish = take.finish, .loop_start = loop_start });
        take.* = undefined;
    }
};

fn defineControlOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var handler = as.defineOpcodeHandler(zig, "unreachable", .@"16");
        as.printInstrs(&.{
            "lea rdi, [{[vip]f} - 1] #0 IP to opcode byte",
        }, .{ .vip = Gpr.vip });
        inline for (
            1..,
            Gpr.system_v_parameters[1..],
            [5]?[]const u8{ "vsp", "eip", "stp", null, "interp" },
        ) |i, dst, arg| {
            if (arg) |reg| {
                const src: Gpr = @field(Gpr, reg);
                if (dst.tag == src.tag) {
                    as.printInstrs(&.{"#{d} {s} is already in {f}"}, .{ i, reg, dst });
                } else {
                    as.printInstrs(
                        &.{"mov {[dst]f}, {[src]f} #{[i]d} " ++ reg},
                        .{ .i = i, .dst = dst, .src = src },
                    );
                }
            } else {
                as.printInstrs(&.{"#{d} {f} is unused"}, .{ i, dst });
            }
        }
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapUnreachable",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        handler.end(as);
    }
    {
        var nop = as.defineOpcodeHandler(zig, "nop", .@"16");
        nop.jmpToNextHandler(as);
        nop.end(as);
    }
    {
        var block = as.defineOpcodeHandler(zig, "block", .@"32");
        zig.defineOpcodeHandlerAlias("block", "loop");
        var block_type = SkipUlebIdx.fastPath(as, .r11, "type");
        block.jmpToNextHandler(as);
        block_type.writeSlowPath(as);
        block.end(as);
    }
    {
        var @"if" = as.defineOpcodeHandler(zig, "if", .@"32");
        var false_branch = as.label(&.{"false"});
        as.printInstrs(&.{
            "mov r13d, dword ptr [{[vsp]f} - 0x10] # load condition from top of stack",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # condition was popped",
            "test r13d, r13d",
            "jz {[false_branch]f}",
        }, .{
            .vsp = Gpr.vsp,
            .false_branch = false_branch,
        });
        var block_type = SkipUlebIdx.fastPath(as, .r11, "type");
        as.printInstrs(&.{"lea {[stp]f}, [{[stp]f} + 8] # increment STP"}, .{ .stp = Gpr.stp });
        @"if".jmpToNextHandler(as);

        false_branch.place(as);
        as.printInstrs(&.{
            "# no need to read the block type",
            "lea r15, [{[vip]f} - 1] # save ip to if byte",
        }, .{ .vip = Gpr.vip });
        var branch = TakeBranch.fastPath(as);
        @"if".jmpToNextHandler(as);
        branch.writeSlowPath(as);
        block_type.writeSlowPath(as);
        @"if".end(as);
    }
    {
        var @"else" = as.defineOpcodeHandler(zig, "else", .@"32");
        as.printInstrs(&.{
            "# end of true branch of if, jump to end",
            "lea r15, [{[vip]f} - 1] # save ip to else byte",
        }, .{ .vip = Gpr.vip });
        var branch = TakeBranch.fastPath(as);
        @"else".jmpToNextHandler(as);
        branch.writeSlowPath(as);
        @"else".end(as);
    }
    {
        var end = as.defineOpcodeHandler(zig, "end", .@"32");
        // Could detect ReleaseSafe/ReleaseFast, and inline the call to `return` opcode handler
        as.printInstrs(&.{
            "# IP - 1 == EIP indicates end of function",
            "cmp {[vip]f}, {[eip]f}",
            "ja {[prefix]s}return # Slow path is returning from the function",
        }, .{ .vip = Gpr.vip, .eip = Gpr.eip, .prefix = as.symbol_prefix });
        end.jmpToNextHandler(as);
        end.end(as);
    }
    {
        var br = as.defineOpcodeHandler(zig, "br", .@"32");
        as.printInstrs(&.{
            "# skip reading label idx",
            "lea r15, [{[vip]f} - 1] # save ip to br byte",
        }, .{ .vip = Gpr.vip });
        var branch = TakeBranch.fastPath(as);
        br.jmpToNextHandler(as);
        branch.writeSlowPath(as);
        br.end(as);
    }
    {
        var br_if = as.defineOpcodeHandler(zig, "br_if", .@"32");
        var false_branch = as.label(&.{"false"});
        as.printInstrs(&.{
            "mov r13d, dword ptr [{[vsp]f} - 0x10] # load condition",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # pop condition",
            "test r13d, r13d",
            "jz {[false]f}",
            "lea r15, [{[vip]f} - 1] # save ip to br_if byte",
        }, .{ .vsp = Gpr.vsp, .vip = Gpr.vip, .false = false_branch });
        var branch = TakeBranch.fastPath(as);
        br_if.jmpToNextHandler(as);
        branch.writeSlowPath(as);

        as.write(".p2align 4\n");
        false_branch.place(as);
        var skip_label_idx = SkipUlebIdx.fastPath(as, .r11, "label");
        as.printInstrs(&.{"lea {[stp]f}, [{[stp]f} + 8] # increment stp"}, .{ .stp = Gpr.stp });
        br_if.jmpToNextHandler(as);
        skip_label_idx.writeSlowPath(as);
        br_if.end(as);
    }
    {
        var br_table = as.defineOpcodeHandler(zig, "br_table", .@"32");
        as.printInstrs(&.{
            "lea r15, [{[vip]f} - 1] # save ip to br_table byte",
        }, .{ .vip = Gpr.vip });
        var label_count = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "label_count");
        as.printInstrs(&.{
            "# no need to actually read the labels",
            "mov r13d, dword ptr [{[vsp]f} - 0x10] # load index from value stack",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # VSP",
            "cmp r11d, r13d",
            "cmovb r13d, r11d # prevent exceeding label count",
            "shl r13d, 3 # side table entries are 8 bytes in size",
            "add {[stp]f}, r13",
        }, .{ .vsp = Gpr.vsp, .stp = Gpr.stp });
        var branch = TakeBranch.fastPath(as);
        br_table.jmpToNextHandler(as);
        branch.writeSlowPath(as);
        label_count.writeSlowPath(as);
        br_table.end(as);
    }
    {
        var @"return" = as.defineOpcodeHandler(zig, "return", .@"32");
        as.printInstrs(&.{
            "# no need to save every register, since this is returning",
            "mov {[param_0]f}, {[eip]f} #0 EIP",
            "# other parameters are already in the correct place",
        }, .{ .eip = Gpr.eip, .param_0 = SystemVParam{ .index = 0 } });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}returnFromWasm",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        @"return".end(as);
    }
}

fn defineCallOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var call = as.defineOpcodeHandler(zig, "call", .@"32");
        as.printInstrs(&.{
            "lea r15, [{[vip]f} - 1] # save VIP to call byte",
            "# stack parameters",
        }, .{ .vip = Gpr.vip });
        var idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "func");
        for (
            Gpr.system_v_parameters.len..,
            &[5]Gpr{ .vip, .stp, .eip, .r11, .r15 },
            &[5][]const u8{ "VIP", "STP", "EIP", "function index", "call VIP" },
        ) |i, src, comment| {
            as.printInstrs(&.{"mov {[dst]f}, {[src]f} #{[i]d} {[comment]s}"}, .{
                .dst = SystemVParam{ .index = @intCast(i) },
                .src = src,
                .i = i,
                .comment = comment,
            });
        }
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}invokeWithinWasm # call into Zig",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        idx_decode.writeSlowPath(as);
        call.end(as);
    }
    {
        var call_indirect = as.defineOpcodeHandler(zig, "call_indirect", .@"32");
        as.printInstrs(&.{
            "lea rdi, [{[vip]f} - 1] #0 save ip to call_indirect byte, clobbers locals",
            "# clobbers mems",
        }, .{ .vip = Gpr.vip });
        var type_idx_decode = DecodeUlebIdx.fastPath(as, .r8, .{ .r13, .r14 }, "type");
        var table_idx_decode = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "table");
        var oob = as.label(&.{"oob"});
        var null_elem = as.label(&.{"null_elem"});
        as.printInstrs(&.{
            "# load expected signature",
            "mov r11, qword ptr [{[module]f} + {[module_info_off]d}] # ptr to info",
            "mov r11, qword ptr [r11 + {[info_types_off]d}] # ptr to func types",
            "shl r8, 4 # size of func type is two qwords",
            "lea r8, qword ptr [r11 + r8] # ptr to func type, clobbers type idx",
            "# load funcref from table",
            "mov r14d, dword ptr [{[vsp]f} - 0x10] # element index",
            "mov rdx, qword ptr [{[module]f} + {[module_tables_off]d}]" ++
                " # ptr to module's tables, clobbers module",
            "mov rdx, qword ptr [rdx + r13 * 8] # ptr to table",
            "cmp r14d, dword ptr [rdx + {[table_len_off]d}] # bounds check",
            "jae {[oob]f}",
            "mov rdx, qword ptr [rdx] # ptr to elems, clobbers ptr to table",
            "mov rdx, qword ptr [rdx + r14 * 8] # funcref, clobbers ptr to elems",
            "test rdx, rdx # check for null",
            "jz {[null_elem]f}",
        }, .{
            .vsp = Gpr.vsp,
            .module = Gpr.module,
            .module_info_off = 8,
            .info_types_off = 0, // Assumes offset of RawInner in Module.Inner is 0
            .module_tables_off = 40,
            .table_len_off = 12,
            .oob = oob,
            .null_elem = null_elem,
        });
        for (
            Gpr.system_v_parameters.len..,
            &[3]Gpr{ .vip, .stp, .eip },
            &[3][]const u8{ "VIP", "STP", "EIP" },
        ) |i, src, comment| {
            as.printInstrs(&.{"mov {[dst]f}, {[src]f} #{[i]d} {[comment]s}"}, .{
                .dst = SystemVParam{ .index = @intCast(i) },
                .src = src,
                .i = i,
                .comment = comment,
            });
        }
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}invokeWithinWasmIndirect",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        type_idx_decode.writeSlowPath(as);
        table_idx_decode.writeSlowPath(as);

        as.write(".p2align 4\n");
        oob.place(as);
        as.printInstrs(&.{
            "#0 rdi has trap_ip",
            "mov rdx, {[eip]f} #2 EIP",
            "mov rcx, {[stp]f} #3 STP",
            "mov r8, r13 #4 table index",
        }, .{ .eip = Gpr.eip, .stp = Gpr.stp });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapCallIndirectAccessOob",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });

        as.write(".p2align 4\n");
        null_elem.place(as);
        as.printInstrs(&.{
            "#0 rdi has trap_ip",
            "mov rdx, {[eip]f} #2 EIP",
            "mov rcx, {[stp]f} #3 STP",
            "mov r8, r14 #4 elem index",
        }, .{ .eip = Gpr.eip, .stp = Gpr.stp });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapIndirectCallToNull",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        call_indirect.end(as);
    }
}

fn writeSelectHandler(as: *AsmWriter) void {
    as.printInstrs(&.{
        "xor r14d, r14d",
        "mov r13d, dword ptr [{[vsp]f} - 0x10] # load condition",
        "test r13d, r13d",
        "setz r14b # set r14 to 1 if condition is false",
        "shl r14d, 4 # set r14 to 0x10 if condition is false",
        "movaps xmm0, xmmword ptr [{[vsp]f} - 0x30 + r14] # load selected value",
        "movaps xmmword ptr [{[vsp]f} - 0x30], xmm0 # move selected value to correct place",
        "lea {[vsp]f}, [{[vsp]f} - 0x20] # vsp",
    }, .{ .vsp = Gpr.vsp });
}

fn defineParametericOpcodeHandlers(
    as: *AsmWriter,
    zig: *ZigWriter,
    optimize: std.builtin.OptimizeMode,
) void {
    {
        var drop = as.defineOpcodeHandler(zig, "drop", .@"16");
        as.printInstrs(&.{"lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp"}, .{ .vsp = Gpr.vsp });
        drop.jmpToNextHandler(as);
        drop.end(as);
    }
    {
        var select_t = AsmWriter.OpcodeHandler{
            .function = as.startFunction("select_t", .@"16"),
            .out_of_fuel = as.label(&.{"out_of_fuel"}),
        };
        AsmWriter.OpcodeHandler.writeStartingCfiDirectives(as);
        zig.defineOpcodeHandlerAlias("select_t", "select t");
        var type_count = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "count");
        var bad_type_count: AsmWriter.Label = undefined;
        const has_type_count_check = switch (optimize) {
            .Debug, .ReleaseSafe => true,
            .ReleaseFast, .ReleaseSmall => false,
        };

        if (has_type_count_check) {
            bad_type_count = as.label(&.{"type_count_check"});
            as.printInstrs(&.{
                "test r11, r11",
                "cmp r11, 1",
                "jne {[bad_type_count]f}",
            }, .{ .bad_type_count = bad_type_count });
        }

        as.printInstrs(&.{
            "inc {[vip]f} # skip val type",
        }, .{ .vip = Gpr.vip });
        writeSelectHandler(as);
        select_t.jmpToNextHandler(as);

        type_count.writeSlowPath(as);

        if (has_type_count_check) {
            bad_type_count.place(as);
            as.writeInstrs(&.{"ud2 # invalid type count for select t"});
        }

        select_t.end(as);
    }
    {
        var select = as.defineOpcodeHandler(zig, "select", .@"16");
        // select without type requires numeric or vector type, so this must
        // assume xmmword-sized values to be safe
        writeSelectHandler(as);
        select.jmpToNextHandler(as);
        select.end(as);
    }
}

fn defineLocalOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    const LocalOpcode = enum {
        @"local.get",
        @"local.set",
        @"local.tee",
    };

    for (std.enums.values(LocalOpcode)) |opcode_name| {
        var op = as.defineOpcodeHandler(zig, @tagName(opcode_name), .@"64");
        var idx_decode = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "local");
        as.writeInstrs(&.{"shl r13, 4 # offset to local"});
        switch (opcode_name) {
            .@"local.get" => as.printInstrs(&.{
                "movaps xmm0, xmmword ptr [{[locals]f} + r13] # load value from locals",
                "movaps xmmword ptr [{[vsp]f}], xmm0 # store into value stack",
                "lea {[vsp]f}, [{[vsp]f} + 0x10] # push value that was stored",
            }, .{ .locals = Gpr.locals, .vsp = Gpr.vsp }),
            .@"local.set", .@"local.tee" => {
                as.printInstrs(&.{
                    "movaps xmm0, xmmword ptr [{[vsp]f} - 0x10] # load from value stack",
                }, .{ .vsp = Gpr.vsp });
                if (opcode_name == .@"local.set") {
                    as.printInstrs(&.{"lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp"}, .{ .vsp = Gpr.vsp });
                }
                as.printInstrs(&.{
                    "movaps xmmword ptr [{[locals]f} + r13], xmm0 # store into locals",
                }, .{ .locals = Gpr.locals });
                if (opcode_name == .@"local.tee") {
                    as.writeInstrs(&.{"# argument is still at the top of the value stack"});
                }
            },
        }
        op.jmpToNextHandler(as);
        idx_decode.writeSlowPath(as);
        op.end(as);
    }
}

fn defineGlobalOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var get = as.defineOpcodeHandler(zig, "global.get", .@"64");
        var jump_table = as.label(&.{"jump_table"});
        var load_4 = as.label(&.{"load_4"});
        var load_8 = as.label(&.{"load_8"});
        var load_16 = as.label(&.{"load_16"});
        var idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "global");
        as.printInstrs(&.{
            "mov r13, qword ptr [{[module]f} + {[module_info_off]d}] # ptr to info",
            "mov r13, qword ptr [r13 + {[info_types_off]d}] # ptr to global types",
            "xor r14d, r14d",
            "mov r14b, byte ptr [r13 + r11 * {[global_type_size]d}] # global type",
            "# r14b contains valtype byte",
            "sub r14b, 0x6F # index into jump table",
            "mov r15, qword ptr [{[module]f} + {[module_globals_off]d}] # ptr to globals",
            "mov r15, qword ptr [r15 + r11*8] # ptr to value",
            "jmp qword ptr [{[jump_table]f} + r14*8]",
            "ud2",
        }, .{
            .module = Gpr.module,
            .module_info_off = 8,
            .module_globals_off = 48,
            .info_types_off = 80, // Assumes offset of RawInner in Module.Inner is 0
            .global_type_size = 2,
            .jump_table = jump_table,
        });
        idx_decode.writeSlowPath(as);

        as.write(".p2align 4\n");
        load_4.place(as);
        as.printInstrs(&.{
            "mov r11d, dword ptr [r15] # get value to load",
            "mov dword ptr [{[vsp]f}], r11d",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
        }, .{ .vsp = Gpr.vsp });
        get.jmpToNextHandler(as);

        as.write(".p2align 4\n");
        load_8.place(as);
        as.printInstrs(&.{
            "mov r11, qword ptr [r15] # get value to load",
            "mov qword ptr [{[vsp]f}], r11",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
        }, .{ .vsp = Gpr.vsp });
        get.jmpToNextHandler(as);

        as.write(".p2align 5\n");
        load_16.place(as);
        as.printInstrs(&.{
            "movaps xmm0, xmmword ptr [r15] # get value to load",
            "movaps xmmword ptr [{[vsp]f}], xmm0",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
        }, .{ .vsp = Gpr.vsp });
        get.jmpToNextHandler(as);

        as.write(
            \\.section .rodata
            \\.p2align 6
            \\
        );
        jump_table.place(as);
        as.printInstrs(&(.{
            ".quad {[load_8]f} # externref",
            ".quad {[load_8]f} # funcref",
        } ++ (.{".quad 0"} ** 10) ++ .{
            ".quad {[load_16]f} # v128",
            ".quad {[load_8]f} # f64",
            ".quad {[load_4]f} # f32",
            ".quad {[load_8]f} # i64",
            ".quad {[load_4]f} # i32",
        }), .{ .load_4 = load_4, .load_8 = load_8, .load_16 = load_16 });
        as.write(".text\n");
        get.end(as);
    }
    {
        var set = as.defineOpcodeHandler(zig, "global.set", .@"64");
        var jump_table = as.label(&.{"jump_table"});
        var store_4 = as.label(&.{"store_4"});
        var store_8 = as.label(&.{"store_8"});
        var store_16 = as.label(&.{"store_16"});
        var idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "global");
        as.printInstrs(&.{
            "mov r13, qword ptr [{[module]f} + {[module_info_off]d}] # ptr to info",
            "mov r13, qword ptr [r13 + {[info_types_off]d}] # ptr to global types",
            "xor r14d, r14d",
            "mov r14b, byte ptr [r13 + r11 * {[global_type_size]d}] # global type",
            "# r14b contains valtype byte",
            "# i32       = 7F",
            "# i64       = 7E",
            "# f32       = 7D",
            "# f64       = 7C",
            "# v128      = 7B",
            "#             71..7A",
            "# funcref   = 70",
            "# externref = 6F",
            "sub r14b, 0x6F # index into jump table",
            "mov r15, qword ptr [{[module]f} + {[module_globals_off]d}] # ptr to globals",
            "mov r15, qword ptr [r15 + r11*8] # ptr to value",
            "jmp qword ptr [{[jump_table]f} + r14*8]",
            "ud2",
        }, .{
            .module = Gpr.module,
            .module_info_off = 8,
            .module_globals_off = 48,
            .info_types_off = 80, // Assumes offset of RawInner in Module.Inner is 0
            .global_type_size = 2,
            .jump_table = jump_table,
        });
        idx_decode.writeSlowPath(as);

        as.write(".p2align 4\n");
        store_4.place(as);
        as.printInstrs(&.{
            "mov r11d, dword ptr [{[vsp]f} - 0x10] # get value to store",
            "mov dword ptr [r15], r11d",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .vsp = Gpr.vsp });
        set.jmpToNextHandler(as);

        as.write(".p2align 4\n");
        store_8.place(as);
        as.printInstrs(&.{
            "mov r11, qword ptr [{[vsp]f} - 0x10] # get value to store",
            "mov qword ptr [r15], r11",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .vsp = Gpr.vsp });
        set.jmpToNextHandler(as);

        as.write(".p2align 5\n");
        store_16.place(as);
        as.printInstrs(&.{
            "movaps xmm0, xmmword ptr [{[vsp]f} - 0x10] # get value to store",
            "movaps xmmword ptr [r15], xmm0",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .vsp = Gpr.vsp });
        set.jmpToNextHandler(as);

        as.write(
            \\.section .rodata
            \\.p2align 6
            \\
        );
        jump_table.place(as);
        as.printInstrs(&(.{
            ".quad {[store_8]f} # externref",
            ".quad {[store_8]f} # funcref",
        } ++ (.{".quad 0"} ** 10) ++ .{
            ".quad {[store_16]f} # v128",
            ".quad {[store_8]f} # f64",
            ".quad {[store_4]f} # f32",
            ".quad {[store_8]f} # i64",
            ".quad {[store_4]f} # i32",
        }), .{ .store_4 = store_4, .store_8 = store_8, .store_16 = store_16 });
        as.write(".text\n");
        set.end(as);
    }
}

fn defineTableAccessOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var get = as.defineOpcodeHandler(zig, "table.get", .@"32");
        var table_idx = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "table");
        var oob = as.label(&.{"oob"});
        as.printInstrs(&.{
            "mov r11d, dword ptr [{[vsp]f} - 0x10] # index of element",
            "mov r14, qword ptr [{[module]f} + {[module_tables_off]d}] # ptr to module's tables",
            "mov r14, qword ptr [r14 + r13*8] # ptr to target table",
            "cmp r11d, dword ptr [r14 + {[table_len_off]d}] # bounds check",
            "mov r15, qword ptr [r14] # table base pointer",
            "jae {[oob]f}",
            "mov r11, qword ptr [r15 + r11*8] # load element, clobbers index of element",
            "mov qword ptr [{[vsp]f} - 0x10], r11",
        }, .{
            .vsp = Gpr.vsp,
            .module = Gpr.module,
            .module_tables_off = 40,
            .table_len_off = 12,
            .oob = oob,
        });
        get.jmpToNextHandler(as);

        table_idx.writeSlowPath(as);

        oob.place(as);
        as.printInstrs(&.{
            "lea {[param_0]f}, [{[vip]f} - 1] #0 VIP",
            "#1 VSP in rsi",
            "mov {[param_2]f}, {[eip]f} #2 EIP",
            "mov {[param_3]f}, {[stp]f} #3 STP",
            "mov {[param_4]f}, r13 #4 table index",
            "#5 interp in r9",
            "mov {[param_6]f}, r11d #6 index to access",
            "mov {[param_7]f}, 0 #7 cause enum",
            "mov {[param_8]f}, r14 #8 *TableInst",
        }, .{
            .param_0 = SystemVParam{ .index = 0 },
            .vip = Gpr.vip,
            .param_2 = SystemVParam{ .index = 2 },
            .eip = Gpr.eip,
            .param_3 = SystemVParam{ .index = 3 },
            .stp = Gpr.stp,
            .param_4 = SystemVParam{ .index = 4 },
            .param_6 = SystemVParam{ .index = 6, .size = .dword },
            .param_7 = SystemVParam{ .index = 7 },
            .param_8 = SystemVParam{ .index = 8 },
        });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapTableAccessOutOfBounds",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });

        get.end(as);
    }
    {
        var set = as.defineOpcodeHandler(zig, "table.set", .@"32");
        var table_idx = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "table");
        var oob = as.label(&.{"oob"});
        as.printInstrs(&.{
            "mov r11d, dword ptr [{[vsp]f} - 0x20] # index of element to set",
            "mov r14, qword ptr [{[module]f} + {[module_tables_off]d}] # ptr to module's tables",
            "mov r14, qword ptr [r14 + r13*8] # ptr to target table",
            "cmp r11d, dword ptr [r14 + {[table_len_off]d}] # bounds check",
            "mov r15, qword ptr [r14] # table base pointer",
            "jae {[oob]f}",
            "mov r13, qword ptr [{[vsp]f} - 0x10] # element, clobbers index of table",
            "lea {[vsp]f}, [{[vsp]f} - 0x20] # vsp",
            "mov qword ptr [r15 + r11*8], r13 # store element",
        }, .{
            .vsp = Gpr.vsp,
            .module = Gpr.module,
            .module_tables_off = 40,
            .table_len_off = 12,
            .oob = oob,
        });
        set.jmpToNextHandler(as);

        table_idx.writeSlowPath(as);

        oob.place(as);
        as.printInstrs(&.{
            "lea {[param_0]f}, [{[vip]f} - 1] #0 VIP",
            "#1 VSP in rsi",
            "mov {[param_2]f}, {[eip]f} #2 EIP",
            "mov {[param_3]f}, {[stp]f} #3 STP",
            "mov {[param_4]f}, r13 #4 table index",
            "#5 interp in r9",
            "mov {[param_6]f}, r11d #6 index to access",
            "mov {[param_7]f}, 1 #7 cause enum",
            "mov {[param_8]f}, r14 #8 *TableInst",
        }, .{
            .param_0 = SystemVParam{ .index = 0 },
            .vip = Gpr.vip,
            .param_2 = SystemVParam{ .index = 2 },
            .eip = Gpr.eip,
            .param_3 = SystemVParam{ .index = 3 },
            .stp = Gpr.stp,
            .param_4 = SystemVParam{ .index = 4 },
            .param_6 = SystemVParam{ .index = 6, .size = .dword },
            .param_7 = SystemVParam{ .index = 7 },
            .param_8 = SystemVParam{ .index = 8 },
        });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapTableAccessOutOfBounds",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });

        set.end(as);
    }
}

const LinearMemoryAccess = struct {
    align_skip: SkipUlebIdx,
    offset_decode: DecodeUlebIdx,
    oob: AsmWriter.Label,
    size: std.mem.Alignment,

    /// Pointer to memory base is stored in `r15`, while offset into to memory is stored in `r13d`.
    fn start(
        as: *AsmWriter,
        /// Offset from value stack pointer to `i32` memory offset.
        offset: enum { @"0x10", @"0x20" },
        size: std.mem.Alignment,
    ) LinearMemoryAccess {
        const oob = as.label(&.{"oob"});
        const align_skip = SkipUlebIdx.fastPath(as, .r13, "align");
        const offset_decode = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "offset");
        as.printInstrs(&.{
            "mov r14, qword ptr [{[mems]f}] # Pointer to MemInst",
            "mov r15, qword ptr [r14] # Base pointer",
            "add r13d, dword ptr [{[vsp]f} - {[offset]t}] # offset",
            "jc {[oob]f} # target address overflowed",
            "lea r11, [r13 + {[access_size]d}]",
            "cmp r11, qword ptr [r14 + {[size_field_off]d}]",
            "ja {[oob]f} # exceeded memory bounds",
            "# Actually perform the access",
        }, .{
            .mems = Gpr.mems,
            .vsp = Gpr.vsp,
            .size_field_off = 8,
            .access_size = size.toByteUnits(),
            .oob = oob,
            .offset = offset,
        });
        return .{
            .oob = oob,
            .align_skip = align_skip,
            .offset_decode = offset_decode,
            .size = size,
        };
    }

    /// At this point `rsp` must refer to the saved `rbp` (it must be equal to `rbp`).
    fn end(access: *LinearMemoryAccess, op: *AsmWriter.OpcodeHandler, as: *AsmWriter) void {
        op.jmpToNextHandler(as);
        access.align_skip.writeSlowPath(as);
        access.offset_decode.writeSlowPath(as);

        as.write(".p2align 4\n");
        access.oob.place(as);
        as.printInstrs(&.{
            "lea {[param_0]f}, [{[vip]f} - 1] #0 VIP",
            "#1 VSP in rsi",
            "mov {[param_2]f}, {[eip]f} #2 EIP",
            "mov {[param_3]f}, {[stp]f} #3 STP",
            "mov {[param_4]f}, 0 #4 memory index",
            "#5 interp in r9",
            "mov {[param_6]f}, r13d #6 address",
            "mov {[param_7]f}, {[size]d} #7 size",
            "mov {[param_8]f}, r14 #8 *MemInst",
        }, .{
            .param_0 = SystemVParam{ .index = 0 },
            .vip = Gpr.vip,
            .param_2 = SystemVParam{ .index = 2 },
            .eip = Gpr.eip,
            .param_3 = SystemVParam{ .index = 3 },
            .stp = Gpr.stp,
            .param_4 = SystemVParam{ .index = 4 },
            .param_6 = SystemVParam{ .index = 6, .size = .dword },
            .size = @intFromEnum(access.size),
            .param_7 = SystemVParam{ .index = 7, .size = .dword },
            .param_8 = SystemVParam{ .index = 8 },
        });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapMemoryAccessOutOfBounds",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        access.* = undefined;
        op.end(as);
    }
};

fn defineMemoryLoadOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    for (&[_]struct { []const u8, std.mem.Alignment, []const u8, Gpr.Size }{
        .{ "i32.load", .@"4", "mov", .dword },
        .{ "f32.load", .@"4", "mov", .dword }, // ReleaseSmall could deduplicate w/ i32.load
        .{ "i32.load8_u", .@"1", "movzx", .byte },
        .{ "i32.load8_s", .@"1", "movsx", .byte },
        .{ "i32.load16_s", .@"2", "movsx", .word },
        .{ "i32.load16_u", .@"2", "movzx", .word },
    }) |info| {
        const name, const access_size, const instr, const addr_size = info;
        var load = as.defineOpcodeHandler(zig, name, .@"64");
        var access = LinearMemoryAccess.start(as, .@"0x10", access_size);
        as.printInstrs(&.{
            "{[instr]s} r13d, {[size]t} ptr [r13 + r15]",
            "mov dword ptr [{[vsp]f} - 16], r13d",
        }, .{ .vsp = Gpr.vsp, .instr = instr, .size = addr_size });
        access.end(&load, as);
    }

    for (&[_]struct { []const u8, std.mem.Alignment, []const u8, Gpr.Size }{
        .{ "i64.load", .@"8", "mov", .qword },
        .{ "f64.load", .@"8", "mov", .qword }, // ReleaseSmall could deduplicate w/ i64.load
        .{ "i64.load8_u", .@"1", "movzx", .byte },
        .{ "i64.load8_s", .@"1", "movsx", .byte },
        .{ "i64.load16_s", .@"2", "movsx", .word },
        .{ "i64.load16_u", .@"2", "movzx", .word },
        .{ "i64.load32_s", .@"4", "movsxd", .dword },
    }) |info| {
        const name, const access_size, const instr, const addr_size = info;
        var load = as.defineOpcodeHandler(zig, name, .@"64");
        var access = LinearMemoryAccess.start(as, .@"0x10", access_size);
        as.printInstrs(&.{
            "{[instr]s} r13, {[size]t} ptr [r13 + r15] # load from memory",
            "mov qword ptr [{[vsp]f} - 16], r13 # write loaded value",
        }, .{ .vsp = Gpr.vsp, .instr = instr, .size = addr_size });
        access.end(&load, as);
    }

    {
        var load = as.defineOpcodeHandler(zig, "i64.load32_u", .@"64");
        var access = LinearMemoryAccess.start(as, .@"0x10", .@"4");
        as.printInstrs(&.{
            "mov r13d, dword ptr [r13 + r15] # load from memory",
            "mov qword ptr [{[vsp]f} - 0x10], r13 # write loaded value",
        }, .{ .vsp = Gpr.vsp });
        access.end(&load, as);
    }
}

fn defineMemoryStoreOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    for (&[_]struct { []const u8, std.mem.Alignment, Gpr.Size, []const u8, Gpr.Size }{
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
        var store = as.defineOpcodeHandler(zig, name, .@"64");
        var access = LinearMemoryAccess.start(as, .@"0x20", access_size);
        as.printInstrs(&.{
            "mov {[load_reg]f}, {[load_size]t} ptr [{[vsp]f} - 0x10] # get value to store ",
            "{[instr]s} {[store_size]t} ptr [r13 + r15], {[store_reg]f}" ++
                " # write into linear memory",
            "lea {[vsp]f}, [{[vsp]f} - 0x20] # vsp",
        }, .{
            .vsp = Gpr.vsp,
            .load_reg = Gpr.r14.withSize(load_size),
            .load_size = load_size,
            .instr = instr,
            .store_reg = Gpr.r14.withSize(store_size),
            .store_size = store_size,
        });
        access.end(&store, as);
    }
}

fn defineMemoryManagementOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var memory_size = as.defineOpcodeHandler(zig, "memory.size", .@"32");
        var mem_idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "memory");
        as.printInstrs(&.{
            "mov r13, qword ptr [{[mems]f} + r11*8] # pointer to MemInst",
            "mov r13, qword ptr [r13 + {[mem_size_off]d}] # memory size",
            "shr r13d, 16 # go bytes to page size",
            "mov dword ptr [{[vsp]f}], r13d",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # pushed onto stack",
        }, .{ .mems = Gpr.mems, .mem_size_off = 8, .vsp = Gpr.vsp });
        memory_size.jmpToNextHandler(as);
        mem_idx_decode.writeSlowPath(as);
        memory_size.end(as);
    }
    {
        var memory_grow = as.defineOpcodeHandler(zig, "memory.grow", .@"64");
        var mem_idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "memory");
        var fail = as.label(&.{"fail"});
        var within_capacity = as.label(&.{"within_capacity"});
        as.printInstrs(&.{
            "mov r13d, dword ptr [{[vsp]f} - 0x10] # delta, in pages",
            "shl r13d, 16 # go from page size to bytes",
            "# ^ assumes 32-bit memories/indices",
            "jc {[fail]f}",
            "mov r11, [{[mems]f} + r11*8] # ptr to memory, clobbers memidx",
            "mov r14, qword ptr [r11 + {[mem_size_off]d}] # memory size",
            "add r13, r14 # memory size + delta = desired size",
            "cmp r13, qword ptr [r11 + {[mem_limit_off]d}] # check against limit",
            "ja {[fail]f}",
            "cmp r13, qword ptr [r11 + {[mem_cap_off]d}] # check against capacity",
            "jna {[within_capacity]f}",
            "mov dword ptr [{[vsp]f} - 0x10], -1 # assume growth failure",
            "# Setup parameters",
            "mov rdi, r13 #0 clobbers locals",
            "#1 vsp is already in rsi",
            "mov rdx, {[vip]f} #2 clobbers module",
            "mov rcx, {[eip]f} #3 clobbers fuel",
            "mov r8, r11 #4 clobbers mems",
            "#5 interp is already in r9",
            "mov {[param_6]f}, {[stp]f} #6 STP",
        }, .{
            .vsp = Gpr.vsp,
            .vip = Gpr.vip,
            .eip = Gpr.eip,
            .mems = Gpr.mems,
            .stp = Gpr.stp,
            .fail = fail,
            .within_capacity = within_capacity,
            // .mem_base_off = 0,
            .mem_size_off = 8,
            .mem_cap_off = 16,
            .mem_limit_off = 24,
            .param_6 = SystemVParam{ .index = 6 },
        });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}memoryGrowReallocate",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });

        var to_next = as.label(&.{"next_opcode"});
        as.write(".p2align 4\n");
        within_capacity.place(as);
        as.printInstrs(&.{
            "# TODO: only fill with zeroes if allocator says it doesn't fill w/ zeroes",
            "# OS pages are zeroed",
            "# Assuming 65536 page size, could memset with rep stosb" ++
                " (apparently not as good on AMD)",
            "shr r14d, 16 # from pages to bytes",
            "mov dword ptr [{[vsp]f} - 0x10], r14d # store old size",
            "mov qword ptr [r11 + {[mem_size_off]d}], r13 # store new size",
        }, .{ .vsp = Gpr.vsp, .mem_size_off = 8 });
        to_next.place(as);
        memory_grow.jmpToNextHandler(as);

        fail.place(as);
        as.printInstrs(&.{
            "mov dword ptr [{[vsp]f} - 0x10], -1 # write error value",
            "jmp {[to_next]f}",
        }, .{ .vsp = Gpr.vsp, .to_next = to_next });
        mem_idx_decode.writeSlowPath(as);
        memory_grow.end(as);
    }
}

fn defineConstOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    for (&[_]struct { []const u8, u5, IntType, u7 }{
        .{ "i32.const", 5, .i32, 32 },
        .{ "i64.const", 10, .i64, 64 },
    }) |info| {
        const name, const max_byte_len, const int_type, const bit_size = info;
        var op = as.defineOpcodeHandler(zig, name, .@"64");
        var finished = as.label(&.{"finished"});
        var continuation_buf: [9]AsmWriter.Label = undefined;
        const continuation = continuation_buf[0..(max_byte_len - 1)];
        for (continuation, 0..) |*cont_label, i| {
            var cont_label_name_buf: [7]u8 = undefined;
            cont_label.* = as.label(&.{
                std.fmt.bufPrint(&cont_label_name_buf, "byte_{d}_", .{1 + i}) catch unreachable,
            });
        }

        const r11 = Gpr.r11.withSize(int_type.size());
        const r13 = Gpr.r13.withSize(int_type.size());
        const r14 = Gpr.r14.withSize(int_type.size());

        // Fast path is single-byte constant
        as.printInstrs(&.{
            "movzx {[r11]f}, byte ptr [{[vip]f}] # read first byte",
            "inc {[vip]f} # vip",
            "test r11b, 0x80 # check for continuation",
            "jnz {[two_bytes]f}",
            "shl {[r11]f}, {[shift]d} # sign-extend",
            "sar {[r11]f}, {[shift]d}",
        }, .{
            .r11 = r11,
            .vip = Gpr.vip,
            .shift = bit_size - 7,
            .two_bytes = continuation[0],
        });

        // This falls through to the actual storing of the constant
        finished.place(as);
        as.printInstrs(&.{
            "mov {[store_size]t} ptr [{[vsp]f}], {[r11]f}",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
        }, .{
            .store_size = switch (int_type) {
                .i32 => Gpr.Size.dword,
                .i64 => Gpr.Size.qword,
            },
            .vsp = Gpr.vsp,
            .r11 = r11,
        });
        op.jmpToNextHandler(as);

        for (continuation[0 .. continuation.len - 1], 0..) |*label, i| {
            as.write(".p2align 4\n");
            label.place(as);
            if (i == 0) {
                as.writeInstrs(&.{"and r11b, 0x7F # keep lower 7 bits from first byte"});
            }

            as.printInstrs(&.{
                "movzx {[r14]f}, byte ptr [{[vip]f}] # byte {[byte_n]d}",
                "mov {[r13]f}, {[r14]f}",
                "inc {[vip]f}",
                "and r13b, 0x7F",
                "shl {[r13]f}, {[byte_shift]d}",
                "or {[r11]f}, {[r13]f}",
                "test r14b, 0x80",
                "jnz {[next]f}",
                "shl {[r11]f}, {[final_shift]d}",
                "sar {[r11]f}, {[final_shift]d}",
                "jmp {[finished]f}",
                "ud2",
            }, .{
                .byte_n = i + 2,
                .r11 = r11,
                .r13 = r13,
                .r14 = r14,
                .vip = Gpr.vip,
                .next = continuation[i + 1],
                .byte_shift = 7 * (i + 1),
                .final_shift = @as(usize, bit_size) - (7 * (i + 2)),
                .finished = finished,
            });
        }

        as.write(".p2align 3\n");
        continuation[continuation.len - 1].place(as);
        as.printInstrs(&.{
            "movzx {[r13]f}, byte ptr [{[vip]f}] # byte {[max_byte_len]d} (last)",
            "inc {[vip]f} # vip",
            "shl {[r13]f}, {[final_shift]d}",
            "or {[r11]f}, {[r13]f}",
            "jmp {[finished]f}",
            "ud2",
        }, .{
            .max_byte_len = max_byte_len,
            .r11 = r11,
            .r13 = r13,
            .vip = Gpr.vip,
            .final_shift = 7 * continuation.len,
            .finished = finished,
        });
        op.end(as);
    }

    {
        var op = as.defineOpcodeHandler(zig, "f32.const", .@"64");
        as.printInstrs(&.{
            "mov r13d, dword ptr [{[vip]f}] # unaligned",
            "add {[vip]f}, 4",
            "mov dword ptr [{[vsp]f}], r13d",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
        }, .{ .vip = Gpr.vip, .vsp = Gpr.vsp });
        op.jmpToNextHandler(as);
        op.end(as);
    }
    {
        var op = as.defineOpcodeHandler(zig, "f64.const", .@"64");
        as.printInstrs(&.{
            "mov r13, qword ptr [{[vip]f}] # unaligned",
            "add {[vip]f}, 8",
            "mov qword ptr [{[vsp]f}], r13",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
        }, .{ .vip = Gpr.vip, .vsp = Gpr.vsp });
        op.jmpToNextHandler(as);
        op.end(as);
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

    fn size(int_type: IntType) AsmWriter.Gpr.Size {
        return switch (int_type) {
            .i32 => .dword,
            .i64 => .qword,
        };
    }
};

/// IP to first byte after opcode is stored in `r14`.
///
/// Assumes that the saved `rbp` is on top of the stack
///
/// TODO: deduplicate these handlers
fn numericOperationTrapJmp(as: *AsmWriter, handler: []const u8) void {
    as.printInstrs(&.{
        "lea {[param_0]f}, [r14 - 1] #0 VIP",
        "#1 VSP already in rsi",
        "mov {[param_2]f}, {[eip]f} #2 EIP",
        "mov {[param_3]f}, {[stp]f} #3 STP",
        "#5 r9 already contains interpreter",
    }, .{
        .eip = Gpr.eip,
        .stp = Gpr.stp,
        .param_0 = SystemVParam{ .index = 0 },
        .param_2 = SystemVParam{ .index = 2 },
        .param_3 = SystemVParam{ .index = 3 },
    });
    as.popSystemVSavedRegisters();
    as.printInstrs(&.{
        "pop rbp",
        ".cfi_def_cfa rsp, 8",
        "jmp {[prefix]s}{[name]s}",
        "ud2",
    }, .{ .prefix = as.symbol_prefix, .name = handler });
}

fn defineIntegerOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter, int_type: IntType) void {
    var opcode_name_buf: [16]u8 = undefined;
    var opcode_name = OpcodeNamePrefix.init(@tagName(int_type), &opcode_name_buf);

    const size = int_type.size();
    const r13 = Gpr.r13.withSize(size);
    const r14 = Gpr.r14.withSize(size);
    {
        var eqz = as.defineOpcodeHandler(zig, opcode_name.name(".eqz"), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10] # load value to compare from VSP",
            "xor r14d, r14d",
            "test {[r13]f}, {[r13]f}",
            "setz r14b",
            "mov {[size]t} ptr [{[vsp]f} - 0x10], {[r14]f} # store result",
        }, .{ .r13 = r13, .r14 = r14, .size = size, .vsp = Gpr.vsp });
        eqz.jmpToNextHandler(as);
        eqz.end(as);
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
        var cmp = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x20] # second operand",
            "xor r14d, r14d",
            "cmp {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "{[set_instr]s} r14b",
            "mov dword ptr [{[vsp]f} - 0x20], r14d # store result of comparison",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp, .set_instr = info[1] });
        cmp.jmpToNextHandler(as);
        cmp.end(as);
    }

    for (&[_][2][]const u8{
        .{ ".clz", "lzcnt" },
        .{ ".ctz", "tzcnt" },
        .{ ".popcnt", "popcnt" },
    }) |info| {
        var op = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        as.printInstrs(&.{
            "{[instr]s} {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "mov {[size]t} ptr [{[vsp]f} - 0x10], {[r13]f}",
        }, .{ .r13 = r13, .size = size, .instr = info[1], .vsp = Gpr.vsp });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    {
        var add = as.defineOpcodeHandler(zig, opcode_name.name(".add"), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "add {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f}",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp });
        add.jmpToNextHandler(as);
        add.end(as);
    }
    {
        var sub = as.defineOpcodeHandler(zig, opcode_name.name(".sub"), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "sub {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f}",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp });
        sub.jmpToNextHandler(as);
        sub.end(as);
    }
    {
        var mul = as.defineOpcodeHandler(zig, opcode_name.name(".mul"), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "imul {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x20]",
            "mov {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f}",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp });
        mul.jmpToNextHandler(as);
        mul.end(as);
    }

    const rax = Gpr.rax.withSize(size);
    const rdx = Gpr.rdx.withSize(size);
    const r12 = Gpr.r12.withSize(size);
    for (&[_]struct { []const u8, enum { div, rem }, enum { signed, unsigned } }{
        .{ ".div_s", .div, .signed },
        .{ ".div_u", .div, .unsigned },
        .{ ".rem_s", .rem, .signed },
        .{ ".rem_u", .rem, .unsigned },
    }) |info| {
        _, const kind, const signedness = info;
        var op = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        // Integer division on X86-64 only works with eax/rax as the dividend
        var div_by_zero = as.label(&.{"div_by_zero"});
        as.printInstrs(&.{
            "mov r14, {[vip]f} # save IP",
            "mov r15, {[module]f} # save module",
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10] # divisor aka denominator",
            "mov {[rax]f}, {[size]t} ptr [{[vsp]f} - 0x20] # dividend aka numerator",
            "test {[r13]f}, {[r13]f} # check for division by zero",
            "jz {[div_by_zero]f}",
        }, .{
            .r13 = r13,
            .rax = rax,
            .size = size,
            .vip = Gpr.vip,
            .vsp = Gpr.vsp,
            .module = Gpr.module,
            .div_by_zero = div_by_zero,
        });

        var signed_overflow: AsmWriter.Label = undefined;
        switch (signedness) {
            .signed => {
                as.printInstrs(&.{
                    "mov {[rdx]f}, {[rax]f}",
                    "xor {[rdx]f}, {[r13]f} # overflow check ({[min_int]s} ^ {[neg_one]s})",
                }, .{
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

                as.writeInstrs(switch (int_type) {
                    .i32 => &.{"xor edx, 0x7FFF" ++ "FFFF"},
                    .i64 => &.{
                        "movabs r11, 0x7FFF" ++ "FFFF" ++ "FFFF" ++ "FFFF",
                        "xor rdx, r11",
                    },
                });

                signed_overflow = as.label(&.{"overflow"});
                switch (kind) {
                    .div => as.printInstrs(&.{"je {[trap_overflow]f}"}, .{
                        .trap_overflow = signed_overflow,
                    }),
                    .rem => {
                        as.printInstrs(&.{
                            "jz {[overflow]f}",
                            "mov {[r12]f}, {[rax]f} # clobbers dispatch table register",
                        }, .{ .overflow = signed_overflow, .r12 = r12, .rax = rax });
                    },
                }

                as.writeInstrs(switch (int_type) {
                    .i32 => &.{
                        "cdq # clobbers edx",
                        "idiv r13d",
                    },
                    .i64 => &.{
                        "cqo # clobbers rdx",
                        "idiv r13",
                    },
                });

                if (kind == .rem) {
                    as.printInstrs(&.{
                        "imul {[rax]f}, {[r13]f}",
                        "sub {[r12]f}, {[rax]f}",
                    }, .{ .rax = rax, .r12 = r12, .r13 = r13 });
                }
            },
            .unsigned => as.printInstrs(&.{
                "xor {[rdx]f}, {[rdx]f}",
                "div {[r13]f}",
            }, .{ .rdx = rdx, .r13 = r13 }),
        }

        as.printInstrs(&.{
            "mov {[size]t} ptr [{[vsp]f} - 0x20], {[result]f} # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
            "mov {[vip]f}, r14 # restore IP",
            "mov {[module]f}, r15 # restore module",
        }, .{
            .result = switch (kind) {
                .div => rax,
                .rem => switch (signedness) {
                    .signed => r12,
                    .unsigned => rdx,
                },
            },
            .size = size,
            .vip = Gpr.vip,
            .vsp = Gpr.vsp,
            .module = Gpr.module,
        });
        if (kind == .rem and signedness == .signed) {
            as.printInstrs(
                &.{"lea {[dispatch]f}, {[prefix]s}byte_dispatch_table # restore dispatch table"},
                .{ .prefix = as.symbol_prefix, .dispatch = Gpr.disp },
            );
        }
        op.jmpToNextHandler(as);

        if (signedness == .signed) {
            as.write(".p2align 4\n");
            signed_overflow.place(as);
            switch (kind) {
                .rem => {
                    as.printInstrs(&.{
                        "mov {[size]t} ptr [{[vsp]f} - 0x20], {[rdx]f}",
                        "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
                        "mov {[vip]f}, r14 # restore IP",
                        "mov {[module]f}, r15 # restore module",
                    }, .{
                        .size = size,
                        .rdx = rdx,
                        .vip = Gpr.vip,
                        .vsp = Gpr.vsp,
                        .module = Gpr.module,
                    });
                    op.jmpToNextHandler(as);
                },
                .div => numericOperationTrapJmp(as, "trapIntegerOverflow"),
            }
        }

        div_by_zero.place(as);
        numericOperationTrapJmp(as, "trapIntegerDivisionByZero");

        op.end(as);
    }

    for (&[_][]const u8{ ".and", ".or", ".xor" }) |name| {
        var op = as.defineOpcodeHandler(zig, opcode_name.name(name), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "{[instr]s} {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f}",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # VSP",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp, .instr = name[1..] });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    // Shift/Rotate instructions clobber fuel register (rcx)
    const rcx = Gpr.rcx.withSize(size);
    for (&[_][2][]const u8{
        .{ ".shl", "shl" },
        .{ ".shr_s", "sar" },
        .{ ".shr_u", "shr" },
        .{ ".rotl", "rol" },
        .{ ".rotr", "ror" },
    }) |info| {
        var op = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        as.printInstrs(&.{
            "mov r13, {[fuel]f} # save fuel",
            "mov {[rcx]f}, {[size]t} ptr [{[vsp]f} - 0x10] # shift amount",
            "# TODO: could use BMI2 shift without flags here",
            "{[instr]s} {[size]t} ptr [{[vsp]f} - 0x20], cl",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # VSP",
            "mov {[fuel]f}, r13 # restore fuel",
        }, .{
            .rcx = rcx,
            .size = size,
            .instr = info[1],
            .fuel = Gpr.fuel,
            .vsp = Gpr.vsp,
        });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_]struct { []const u8, Gpr.Size }{
        .{ ".extend8_s", .byte },
        .{ ".extend16_s", .word },
    }) |info| {
        var extend = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"32");
        as.printInstrs(&.{
            "movsx {[r13]f}, {[src_size]t} ptr [{[vsp]f} - 0x10]",
            "mov {[dst_size]t} ptr [{[vsp]f} - 0x10], {[r13]f} # store sign-extended result",
        }, .{ .r13 = r13, .src_size = info[1], .dst_size = size, .vsp = Gpr.vsp });
        extend.jmpToNextHandler(as);
        extend.end(as);
    }

    if (int_type == .i64) {
        var extend = as.defineOpcodeHandler(zig, "i64.extend32_s", .@"32");
        as.printInstrs(&.{
            "movsxd r13, dword ptr [{[vsp]f} - 0x10]",
            "mov qword ptr [{[vsp]f} - 0x10], r13 # store sign-extended result",
        }, .{ .vsp = Gpr.vsp });
        extend.jmpToNextHandler(as);
        extend.end(as);
    }
}

const FloatType = enum {
    f32,
    f64,

    fn size(float_type: FloatType) Gpr.Size {
        return switch (float_type) {
            .f32 => .dword,
            .f64 => .qword,
        };
    }
};

fn defineFloatOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter, float_type: FloatType) void {
    var opcode_name_buf: [19]u8 = undefined;
    var opcode_name = OpcodeNamePrefix.init(@tagName(float_type), &opcode_name_buf);
    const size = float_type.size();
    const float_suffix: u8 = switch (float_type) {
        .f32 => 's',
        .f64 => 'd',
    };
    const int_suffix: u8 = switch (float_type) {
        .f32 => 'd',
        .f64 => 'q',
    };
    const r13 = Gpr.r13.withSize(size);
    const r14 = Gpr.r14.withSize(size);
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
        var cmp = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        as.printInstrs(&.{
            "movs{[float_suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x10] # load operand 2",
            "{[instr]s}{[float_suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x20] # load operand 1",
            "mov{[int_suffix]c} {[r13]f}, xmm0 # all 1's if true",
            "and {[r13]f}, 1",
            "mov {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f} # write result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{
            .float_suffix = float_suffix,
            .int_suffix = int_suffix,
            .r13 = r13,
            .size = size,
            .vsp = Gpr.vsp,
            .instr = info[1],
        });
        cmp.jmpToNextHandler(as);
        cmp.end(as);
    }

    // Zig/LLVM uses vucomis(s|d) when targeting x86_64_v3
    for (&[_]struct { []const u8, []const u8, u1 }{
        .{ ".lt", "seta", 0 },
        .{ ".le", "setae", 0 },
        .{ ".gt", "seta", 1 },
        .{ ".ge", "setae", 1 },
    }) |info| {
        const name, const set_instr, const order = info;
        var cmp = as.defineOpcodeHandler(zig, opcode_name.name(name), .@"64");
        as.printInstrs(&.{
            "movs{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - {[op_1]s}] # operand 2",
            "xor r15d, r15d",
            "ucomis{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - {[op_2]s}] # operand 1",
            "{[set_instr]s} r15b",
            "mov dword ptr [{[vsp]f} - 0x20], r15d # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{
            .suffix = float_suffix,
            .size = size,
            .vsp = Gpr.vsp,
            .set_instr = set_instr,
            .op_1 = switch (order) {
                0 => "0x10",
                1 => "0x20",
            },
            .op_2 = switch (order) {
                0 => "0x20",
                1 => "0x10",
            },
        });
        cmp.jmpToNextHandler(as);
        cmp.end(as);
    }

    {
        var abs = as.defineOpcodeHandler(zig, opcode_name.name(".abs"), .@"32");
        as.printInstrs(&.{
            "mov {[r13]f}, {[mask]s}",
            "and {[size]t} ptr [{[vsp]f} - 0x10], {[r13]f} # clear sign bit",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp, .mask = non_sign_mask });
        abs.jmpToNextHandler(as);
        abs.end(as);
    }
    {
        var neg = as.defineOpcodeHandler(zig, opcode_name.name(".neg"), .@"32");
        as.printInstrs(&.{
            "mov {[r13]f}, {[mask]s}",
            "xor {[size]t} ptr [{[vsp]f} - 0x10], {[r13]f} # clear sign bit",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp, .mask = sign_bit });
        neg.jmpToNextHandler(as);
        neg.end(as);
    }

    // When only SSE2 is available, LLVM calls libc functions via @PLT
    for (&[_]struct { []const u8, u2 }{
        .{ ".ceil", 0b10 }, // ceilf/ceill
        .{ ".floor", 0b01 }, // floorf/floorl
        .{ ".trunc", 0b11 }, // trunc/truncl?
        .{ ".nearest", 0b00 }, // roundevenf/roundeevenl
    }) |info| {
        var op = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        as.printInstrs(&.{
            "rounds{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x10], 0x{[rounding_mode]X}" ++
                " # TODO: Requires SSE4.1",
            "movs{[suffix]c} {[size]t} ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{
            .suffix = float_suffix,
            .size = size,
            .vsp = Gpr.vsp,
            .rounding_mode = 0b1000 | @as(u8, info[1]),
        });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_][2][]const u8{
        .{ ".sqrt", "sqrts" },
    }) |info| {
        var op = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        as.printInstrs(&.{
            "{[instr]s}{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x10]",
            "movs{[suffix]c} {[size]t} ptr [{[vsp]f} - 0x10], xmm0 # store result",
        }, .{ .instr = info[1], .suffix = float_suffix, .size = size, .vsp = Gpr.vsp });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    for (&[_][2][]const u8{
        .{ ".add", "adds" },
        .{ ".sub", "subs" },
        .{ ".mul", "muls" },
        .{ ".div", "divs" },
    }) |info| {
        var op = as.defineOpcodeHandler(zig, opcode_name.name(info[0]), .@"64");
        as.printInstrs(&.{
            "movs{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x20] # operand 2",
            "{[instr]s}{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x10]",
            "movs{[suffix]c} {[size]t} ptr [{[vsp]f} - 0x20], xmm0 # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{ .suffix = float_suffix, .size = size, .vsp = Gpr.vsp, .instr = info[1] });
        op.jmpToNextHandler(as);
        op.end(as);
    }

    {
        // Cranelift and Wizard implement `f32.min` with two `minss`
        // - https://github.com/llvm/llvm-project/pull/170069
        // - https://github.com/rust-lang/rust/issues/91079
        var min = as.defineOpcodeHandler(zig, opcode_name.name(".min"), .@"64");
        as.printInstrs(&.{
            "mov{[int_suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x10] # first",
            "mov{[int_suffix]c} xmm1, {[size]t} ptr [{[vsp]f} - 0x20] # second",
            "movaps xmm2, xmm0",
            "movaps xmm3, xmm1",
            "movaps xmm4, xmm0",
            "mins{[float_suffix]c} xmm2, xmm1",
            "mins{[float_suffix]c} xmm3, xmm0",
            "orp{[float_suffix]c} xmm2, xmm3 # handles non-NaN case correctly",

            "mov {[r13]f}, {[canonical_nan_mask]s}",
            "mov{[int_suffix]c} xmm3, {[r13]f} # canonical NaN mask",

            "cmpords{[float_suffix]c} xmm4, xmm1 # all 1's if NaN was NOT present",
            "# mask of all 1's if no NaN, canonical_nan_mask if there is NaN",
            "orp{[float_suffix]c} xmm3, xmm4",
            "andp{[float_suffix]c} xmm2, xmm3 # If NaN, mask away non-canonical NaN bits",

            "mov {[r13]f}, {[canonical_nan_bit]s}",
            "mov{[int_suffix]c} xmm3, {[r13]f} # canonical NaN bit",
            "andnp{[float_suffix]c} xmm4, xmm3 # canonical NaN bit if NaN is present",
            "# If NaNs are present, set the canonical NaN bit",
            "orp{[float_suffix]c} xmm2, xmm4",

            "mov{[int_suffix]c} {[size]t} ptr [{[vsp]f} - 0x20], xmm2 # write result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{
            .r13 = r13,
            .canonical_nan_mask = canonical_nan_mask,
            .canonical_nan_bit = canonical_nan_bit,
            .int_suffix = int_suffix,
            .float_suffix = float_suffix,
            .size = size,
            .vsp = Gpr.vsp,
        });
        min.jmpToNextHandler(as);
        min.end(as);
    }
    {
        var max = as.defineOpcodeHandler(zig, opcode_name.name(".max"), .@"64");
        as.printInstrs(&.{
            "mov{[int_suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x10] # first",
            "mov{[int_suffix]c} xmm1, {[size]t} ptr [{[vsp]f} - 0x20] # second",
            "movaps xmm2, xmm0",
            "movaps xmm3, xmm1",
            "movaps xmm4, xmm0",
            "maxs{[float_suffix]c} xmm2, xmm1",
            "maxs{[float_suffix]c} xmm3, xmm0",
            "orp{[float_suffix]c} xmm2, xmm3" ++
                " # almost handles non-NaN case correctly, sign may be wrong",

            "mov {[r13]f}, {[sign_bit]s}",
            "mov{[int_suffix]c} xmm3, {[r13]f} # sign bit",
            "movaps xmm5, xmm3",
            "andnp{[float_suffix]c} xmm3, xmm2 # remove sign bit",

            "andp{[float_suffix]c} xmm4, xmm5 # sign of first input",
            "andp{[float_suffix]c} xmm5, xmm1 # sign of second input",
            "andp{[float_suffix]c} xmm4, xmm5 # final sign",
            "orp{[float_suffix]c} xmm3, xmm4 # apply correct sign bit",

            "mov {[r13]f}, {[canonical_nan_mask]s}",
            "mov{[int_suffix]c} xmm2, {[r13]f} # canonical NaN mask",

            "movaps xmm4, xmm0",
            "cmpords{[float_suffix]c} xmm4, xmm1 # all 1's if NaN was NOT present",
            "# mask of all 1's if no NaN, canonical_nan_mask if there is NaN",
            "orp{[float_suffix]c} xmm2, xmm4",
            "andp{[float_suffix]c} xmm3, xmm2 # If NaN, mask away non-canonical NaN bits",

            "mov {[r13]f}, {[canonical_nan_bit]s}",
            "mov{[int_suffix]c} xmm2, {[r13]f} # canonical NaN bit",
            "andnp{[float_suffix]c} xmm4, xmm2 # canonical NaN bit if NaN is present",
            "# If NaNs are present, set the canonical NaN bit",
            "orp{[float_suffix]c} xmm3, xmm4",

            "mov{[int_suffix]c} {[size]t} ptr [{[vsp]f} - 0x20], xmm3 # write result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{
            .r13 = r13,
            .sign_bit = sign_bit,
            .canonical_nan_mask = canonical_nan_mask,
            .canonical_nan_bit = canonical_nan_bit,
            .int_suffix = int_suffix,
            .float_suffix = float_suffix,
            .size = size,
            .vsp = Gpr.vsp,
        });
        max.jmpToNextHandler(as);
        max.end(as);
    }
    {
        var copysign = as.defineOpcodeHandler(zig, opcode_name.name(".copysign"), .@"64");
        // Could use ANDN from BMI1 here
        as.printInstrs(&.{
            "mov {[r13]f}, {[sign_bit]s} # sign bit",
            "mov {[r14]f}, {[r13]f}",
            "not {[r14]f} # non-sign mask",
            "and {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10] # get sign",
            "and {[r14]f}, {[size]t} ptr [{[vsp]f} - 0x20] # get other bits",
            "or {[r13]f}, {[r14]f} # combine them",
            "mov {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f} # store result",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # vsp",
        }, .{
            .r13 = r13,
            .r14 = r14,
            .sign_bit = sign_bit,
            .vsp = Gpr.vsp,
            .size = size,
        });
        copysign.jmpToNextHandler(as);
        copysign.end(as);
    }
}

fn defineNumericConversionOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var wrap = as.defineOpcodeHandler(zig, "i32.wrap_i64", .@"16");
        as.writeInstrs(&.{"# truncate i64 to i32, high qword is unobserved"});
        wrap.jmpToNextHandler(as);
        wrap.end(as);
    }

    const IntToFloat = struct {
        name: []const u8,
        // Bounds based on what Zig uses to panic on Debug/ReleaseSafe for `@floatFromInt`
        lower_bound: []const u8,
        upper_bound: []const u8,
        subtract: ?[]const u8 = null,
        float_suffix: u8,
        int_suffix: u8,
        temp_size: Gpr.Size,
        result_size: Gpr.Size,
    };

    for (&[_]IntToFloat{
        .{
            .name = "i32.trunc_f32_s",
            .lower_bound = "0xCF00" ++ "0001",
            .upper_bound = "0x4F00" ++ "0000",
            .float_suffix = 's',
            .int_suffix = 'd',
            .temp_size = .dword,
            .result_size = .dword,
        },
        .{
            // VCVTTSS2USI requires AVX512F
            .name = "i32.trunc_f32_u",
            .lower_bound = "0xBF80" ++ "0000",
            .upper_bound = "0x4F80" ++ "0000",
            .float_suffix = 's',
            .int_suffix = 'd',
            .temp_size = .dword,
            .result_size = .qword,
        },
        .{
            .name = "i32.trunc_f64_s",
            .lower_bound = "0xC1E0" ++ "0000" ++ "0020" ++ "0000",
            .upper_bound = "0x41E0" ++ "0000" ++ "0000" ++ "0000",
            .float_suffix = 'd',
            .int_suffix = 'q',
            .temp_size = .qword,
            .result_size = .qword,
        },
        .{
            .name = "i32.trunc_f64_u",
            .lower_bound = "0xBFF0" ++ "0000" ++ "0000" ++ "0000",
            .upper_bound = "0x41F0" ++ "0000" ++ "0000" ++ "0000",
            .float_suffix = 'd',
            .int_suffix = 'q',
            .temp_size = .qword,
            .result_size = .qword,
        },
        .{
            .name = "i64.trunc_f32_s",
            .lower_bound = "0xDF00" ++ "0001",
            .upper_bound = "0x5F00" ++ "0000",
            .float_suffix = 's',
            .int_suffix = 'd',
            .temp_size = .dword,
            .result_size = .qword,
        },
        .{
            .name = "i64.trunc_f32_u",
            .lower_bound = "0xBF80" ++ "0000",
            .upper_bound = "0x5F80" ++ "0000",
            .subtract = "0x5F00" ++ "0000",
            .float_suffix = 's',
            .int_suffix = 'd',
            .temp_size = .dword,
            .result_size = .qword,
        },
        .{
            .name = "i64.trunc_f64_s",
            .lower_bound = "0xC3E0" ++ "0000" ++ "0000" ++ "0001",
            .upper_bound = "0x43E0" ++ "0000" ++ "0000" ++ "0000",
            .float_suffix = 'd',
            .int_suffix = 'q',
            .temp_size = .qword,
            .result_size = .qword,
        },
        .{
            .name = "i64.trunc_f64_u",
            .lower_bound = "0xBFF0" ++ "0000" ++ "0000" ++ "0000",
            .upper_bound = "0x43F0" ++ "0000" ++ "0000" ++ "0000",
            .subtract = "0x43E0" ++ "0000" ++ "0000" ++ "0000",
            .float_suffix = 'd',
            .int_suffix = 'q',
            .temp_size = .qword,
            .result_size = .qword,
        },
    }) |info| {
        var trunc = as.defineOpcodeHandler(zig, info.name, .@"16");
        var nan = as.label(&.{"nan"});
        var overflow = as.label(&.{"overflow"});
        const temp = Gpr.r11.withSize(info.temp_size);
        const result = Gpr.r11.withSize(info.result_size);
        as.printInstrs(&.{
            "mov r14, {[vip]f} # save IP in case of trap",
            "movs{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x10] # load float value",
            "mov {[temp]f}, {[lower_bound]s} # lower bound",
            "mov{[movd_suffix]c} xmm1, {[temp]f} # load lower bound",
            "ucomis{[suffix]c} xmm1, xmm0",
            "jae [{[overflow]f}]",
            "jz [{[nan]f}] # nan check must come after bounds check",
            "mov {[temp]f}, {[upper_bound]s} # upper bound",
            "mov{[movd_suffix]c} xmm1, {[temp]f} # load upper bound",
            "ucomis{[suffix]c} xmm0, xmm1",
            "jae [{[overflow]f}]",
            "cvtts{[suffix]c}2si {[result]f}, xmm0",
        }, .{
            .vip = Gpr.vip,
            .vsp = Gpr.vsp,
            .size = info.temp_size,
            .suffix = info.float_suffix,
            .movd_suffix = info.int_suffix,
            .temp = temp,
            .result = result,
            .lower_bound = info.lower_bound,
            .upper_bound = info.upper_bound,
            .nan = nan,
            .overflow = overflow,
        });
        if (info.subtract) |subtract| {
            as.printInstrs(&.{
                "# Thanks Zig+LLVM!",
                "mov r13, r11",
                "mov r14, {[subtract]s}",
                "movq xmm1, r14",
                "subs{[suffix]c} xmm0, xmm1",
                "cvtts{[suffix]c}2si r14, xmm0",
                "sar r13, 63 # sign-extend result?",
                "and r14, r13",
                "or r11, r14",
            }, .{
                .subtract = subtract,
                .suffix = info.float_suffix,
            });
        }
        as.printInstrs(&.{
            "mov {[result_size]t} ptr [{[vsp]f} - 0x10], {[result]f}",
        }, .{ .result_size = info.result_size, .vsp = Gpr.vsp, .result = result });
        trunc.jmpToNextHandler(as);
        as.write(".p2align 4\n");
        overflow.place(as);
        numericOperationTrapJmp(as, "trapIntegerOverflow");
        nan.place(as);
        numericOperationTrapJmp(as, "trapInvalidConversionToInteger");

        trunc.end(as);
    }
    {
        var extend = as.defineOpcodeHandler(zig, "i64.extend_i32_s", .@"16");
        as.printInstrs(&.{
            "movsxd r13, dword ptr [{[vsp]f} - 0x10] # sign-extend",
            "mov qword ptr [{[vsp]f} - 0x10], r13",
        }, .{ .vsp = Gpr.vsp });
        extend.jmpToNextHandler(as);
        extend.end(as);
    }
    {
        var extend = as.defineOpcodeHandler(zig, "i64.extend_i32_u", .@"16");
        as.printInstrs(&.{
            "xor r13d, r13d",
            "mov dword ptr [{[vsp]f} - 0xC], r13d # zero-extend by placing zeroes in high 32-bits",
        }, .{ .vsp = Gpr.vsp });
        extend.jmpToNextHandler(as);
        extend.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f32.convert_i32_s", .@"16");
        as.printInstrs(&.{
            "cvtsi2ss xmm0, dword ptr [{[vsp]f} - 0x10]",
            "movss dword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        convert.jmpToNextHandler(as);
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f32.convert_i32_u", .@"16");
        as.printInstrs(&.{
            "mov r11d, dword ptr [{[vsp]f} - 0x10]",
            "cvtsi2ss xmm0, r11 # u32 is a valid i64",
            "movss dword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        convert.jmpToNextHandler(as);
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f32.convert_i64_s", .@"16");
        as.printInstrs(&.{
            "cvtsi2ss xmm0, qword ptr [{[vsp]f} - 0x10]",
            "movss dword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        convert.jmpToNextHandler(as);
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f32.convert_i64_u", .@"16");
        var done = as.label(&.{"done"});
        var negative = as.label(&.{"negative"});
        as.printInstrs(&.{
            "# Taken from LLVM output for Zig @floatFromInt",
            "mov r11, qword ptr [{[vsp]f} - 0x10]",
            "test r11, r11",
            "js {[negative]f}",
            "cvtsi2ss xmm0, r11",
        }, .{ .vsp = Gpr.vsp, .negative = negative });
        done.place(as);
        as.printInstrs(&.{"movss dword ptr [{[vsp]f} - 0x10], xmm0"}, .{ .vsp = Gpr.vsp });
        convert.jmpToNextHandler(as);

        negative.place(as);
        as.printInstrs(&.{
            "mov r13, r11",
            "shr r13",
            "and r11, 1",
            "or r11, r13",
            "cvtsi2ss xmm0, r11",
            "addss xmm0, xmm0",
            "jmp {[done]f}",
            "ud2",
        }, .{ .done = done });
        convert.end(as);
    }
    {
        var demote = as.defineOpcodeHandler(zig, "f32.demote_f64", .@"16");
        as.printInstrs(&.{
            "cvtsd2ss xmm0, qword ptr [{[vsp]f} - 0x10]",
            "movss dword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        demote.jmpToNextHandler(as);
        demote.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f64.convert_i32_s", .@"16");
        as.printInstrs(&.{
            "cvtsi2sd xmm0, dword ptr [{[vsp]f} - 0x10]",
            "movsd qword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        convert.jmpToNextHandler(as);
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f64.convert_i32_u", .@"16");
        as.printInstrs(&.{
            "mov r11d, dword ptr [{[vsp]f} - 0x10]",
            "cvtsi2sd xmm0, r11 # u32 as i64",
            "movsd qword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        convert.jmpToNextHandler(as);
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f64.convert_i64_s", .@"16");
        as.printInstrs(&.{
            "cvtsi2sd xmm0, qword ptr [{[vsp]f} - 0x10]",
            "movsd qword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        convert.jmpToNextHandler(as);
        convert.end(as);
    }
    {
        var convert = as.defineOpcodeHandler(zig, "f64.convert_i64_u", .@"16");
        as.write(
            \\.section .rodata
            \\.p2align 5
            \\
        );
        var const_dwords = as.label(&.{"const_dwords"});
        const_dwords.place(as);
        as.writeInstrs(&.{
            ".long 0x4330" ++ "0000",
            ".long 0x4530" ++ "0000",
            ".long 0",
            ".long 0",
        });
        var const_qwords = as.label(&.{"const_qwords"});
        const_qwords.place(as);
        as.writeInstrs(&.{
            ".quad 0x4330" ++ "0000" ++ "0000" ++ "0000",
            ".quad 0x4530" ++ "0000" ++ "0000" ++ "0000",
        });

        as.write(".text\n");
        as.printInstrs(&.{
            "# Based on what LLVM compilers for Zig's @floatFromInt",
            "movsd xmm0, qword ptr [{[vsp]f} - 0x10] # load integer to convert",
            "unpcklps xmm0, xmmword ptr [{[const_dwords]f}]",
            "subpd xmm0, xmmword ptr [{[const_qwords]f}]",
            "movapd xmm1, xmm0",
            "unpckhpd xmm1, xmm0",
            "addsd xmm1, xmm0",
            "movsd qword ptr [{[vsp]f} - 0x10], xmm1",
        }, .{
            .vsp = Gpr.vsp,
            .const_dwords = const_dwords,
            .const_qwords = const_qwords,
        });
        convert.jmpToNextHandler(as);
        convert.end(as);
    }
    {
        var demote = as.defineOpcodeHandler(zig, "f64.promote_f32", .@"16");
        as.printInstrs(&.{
            "cvtss2sd xmm0, dword ptr [{[vsp]f} - 0x10]",
            "movsd qword ptr [{[vsp]f} - 0x10], xmm0",
        }, .{ .vsp = Gpr.vsp });
        demote.jmpToNextHandler(as);
        demote.end(as);
    }
    for (&[_][]const u8{
        "i32.reinterpret_f32",
        "i64.reinterpret_f64",
        "f32.reinterpret_i32",
        "f64.reinterpret_i64",
    }) |name| {
        var reinterpret = as.defineOpcodeHandler(zig, name, .@"16");
        as.write("\t# no-op\n");
        reinterpret.jmpToNextHandler(as);
        reinterpret.end(as);
    }

    // Saturating conversions, based on the assembly generated by a call to LLVM's corresponding
    // `@llvm.fptosi.sat.*` and `@llvm.fptoui.sat.*` intrinsics:
    // - https://llvm.org/docs/LangRef.html#llvm-fptosi-sat-intrinsic
    // - https://llvm.org/docs/LangRef.html#llvm-fptoui-sat-intrinsic
    {
        var trunc = as.defineOpcodeHandler(zig, "i32.trunc_sat_f32_s", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptosi.sat.i32.f32` intrinsic",
            "movss xmm0, dword ptr [{[vsp]f} - 0x10] # load f32",
            "cvttss2si r11d, xmm0",
            "mov r13d, 0x4EFF" ++ "FFFF",
            "movd xmm1, r13d",
            "ucomiss xmm0, xmm1",
            "mov r13d, 0x7FFF" ++ "FFFF",
            "cmovbe r13d, r11d",
            "xor r11d, r11d",
            "ucomiss xmm0, xmm0",
            "cmovnp r11d, r13d # NaN detection in ucomiss, this ensures result is zero in that case?",
            "mov dword ptr [{[vsp]f} - 0x10], r11d # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
    {
        var trunc = as.defineOpcodeHandler(zig, "i32.trunc_sat_f32_u", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptoui.sat.i32.f32` intrinsic",
            "movss xmm0, dword ptr [{[vsp]f} - 0x10] # load f32",
            "cvttss2si r11, xmm0",
            "xor r13d, r13d",
            "xorps xmm1, xmm1",
            "ucomiss xmm0, xmm1",
            "cmovae r13d, r11d",
            "mov r14d, 0x4F7F" ++ "FFFF",
            "movd xmm2, r14d",
            "ucomiss xmm0, xmm2",
            "mov r11d, -1",
            "cmovbe r11d, r13d # If max u32 exceeded, this clamps it?",
            "mov dword ptr [{[vsp]f} - 0x10], r11d # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
    {
        var trunc = as.defineOpcodeHandler(zig, "i32.trunc_sat_f64_s", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptosi.sat.i32.f64` intrinsic",
            "movsd xmm0, qword ptr [{[vsp]f} - 0x10] # load f64",
            "xor r11d, r11d",
            "ucomisd xmm0, xmm0",
            "mov r13, 0xC1E0" ++ "0000" ++ "0000" ++ "0000 # minimum bound?",
            "movq xmm1, r13",
            "mov r14, 0x41DF" ++ "FFFF" ++ "FFC0" ++ "0000 # maximum bound?",
            "movq xmm2, r14",
            "maxsd xmm0, xmm1 # clamp to min bound?",
            "minsd xmm0, xmm2 # clamp to max bound?",
            "cvttsd2si r13d, xmm0",
            "cmovnp r11d, r13d # NaN detection in ucomisd? This ensures zero in that case?",
            "mov dword ptr [{[vsp]f} - 0x10], r11d # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
    {
        var trunc = as.defineOpcodeHandler(zig, "i32.trunc_sat_f64_u", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptoui.sat.i32.f64` intrinsic",
            "xorpd xmm0, xmm0",
            "maxsd xmm0, qword ptr [{[vsp]f} - 0x10] # load f64 and ensure non-negative",
            "mov r11, 0x41EF" ++ "FFFF" ++ "FFE0" ++ "0000 # maximum bound",
            "movq xmm1, r11",
            "minsd xmm1, xmm0 # ensure does not exceed maximum bound",
            "cvttsd2si r11, xmm1",
            "mov dword ptr [{[vsp]f} - 0x10], r11d # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
    {
        var trunc = as.defineOpcodeHandler(zig, "i64.trunc_sat_f32_s", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptosi.sat.i64.f32` intrinsic",
            "movss xmm0, dword ptr [{[vsp]f} - 0x10] # load f32",
            "cvttss2si r11, xmm0",
            "mov r13d, 0x5EFF" ++ "FFFF # could be a maximum bound?",
            "movd xmm1, r13d",
            "ucomiss xmm0, xmm1",
            "movabs r13, 0x7FFF" ++ "FFFF" ++ "FFFF" ++ "FFFF # most positive i64",
            "cmovbe r13, r11",
            "xor r11d, r11d",
            "ucomiss xmm0, xmm0 # detect NaN",
            "cmovnp r11, r13 # store calculated result if not NaN, zero otherwise?",
            "mov qword ptr [{[vsp]f} - 0x10], r11 # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
    {
        var trunc = as.defineOpcodeHandler(zig, "i64.trunc_sat_f32_u", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptoui.sat.i64.f32` intrinsic",
            "movss xmm0, dword ptr [{[vsp]f} - 0x10] # load f32",
            "cvttss2si r11, xmm0",
            "mov r13, r11",
            "sar r13, 63 # fill with sign bit",
            "movaps xmm1, xmm0",
            "mov r14d, 0x5F00" ++ "0000",
            "movd xmm2, r14d",
            "subss xmm1, xmm2",
            "cvttss2si r14, xmm1",
            "and r14, r13 # zero if r11 was positive?",
            "or r14, r11",
            "xor r11d, r11d",
            "xorps xmm1, xmm1",
            "ucomiss xmm0, xmm1",
            "cmovae r11, r14",
            "mov r15d, 0x5F7F" ++ "FFFF",
            "movd xmm2, r15d",
            "ucomiss xmm0, xmm2",
            "mov r13, -1",
            "cmovbe r13, r11",
            "mov qword ptr [{[vsp]f} - 0x10], r13 # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
    {
        var trunc = as.defineOpcodeHandler(zig, "i64.trunc_sat_f64_s", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptosi.sat.i64.f64` intrinsic",
            "movsd xmm0, qword ptr [{[vsp]f} - 0x10] # load f64",
            "cvttsd2si r11, xmm0",
            "movabs r13, 0x43DF" ++ "FFFF" ++ "FFFF" ++ "FFFF",
            "movq xmm1, r13",
            "ucomisd xmm0, xmm1",
            "movabs r13, 0x7FFF" ++ "FFFF" ++ "FFFF" ++ "FFFF # most positive i64",
            "cmovbe r13, r11",
            "xor r11d, r11d",
            "ucomisd xmm0, xmm0 # detect NaN",
            "cmovnp r11, r13 # store calculated result if not NaN, zero otherwise?",
            "mov qword ptr [{[vsp]f} - 0x10], r11 # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
    {
        var trunc = as.defineOpcodeHandler(zig, "i64.trunc_sat_f64_u", .@"16");
        as.printInstrs(&.{
            "# based on what LLVM generates for its `@llvm.fptoui.sat.i64.f64` intrinsic",
            "movsd xmm0, qword ptr [{[vsp]f} - 0x10] # load f64",
            "cvttsd2si r11, xmm0",
            "mov r13, r11",
            "sar r13, 63 # fill with sign bit",
            "movapd xmm1, xmm0",
            "movabs r14, 0x43E0" ++ "0000" ++ "0000" ++ "0000",
            "movq xmm2, r14",
            "subsd xmm1, xmm2",
            "cvttsd2si r14, xmm1",
            "and r14, r13 # all zeroes if r11 was positive",
            "or r14, r11",
            "xor r11d, r11d",
            "xorpd xmm1, xmm1",
            "ucomisd xmm0, xmm1",
            "cmovae r11, r14 # seems to detect negative f64?",
            "movabs r15, 0x43EF" ++ "FFFF" ++ "FFFF" ++ "FFFF",
            "movq xmm2, r15",
            "ucomisd xmm0, xmm2",
            "mov r13, -1",
            "cmovbe r13, r11",
            "mov qword ptr [{[vsp]f} - 0x10], r13 # store result",
        }, .{ .vsp = Gpr.vsp });
        trunc.jmpToNextHandler(as);
        trunc.end(as);
    }
}

fn defineReferenceOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var ref_null = as.defineOpcodeHandler(zig, "ref.null", .@"16");
        as.printInstrs(&.{
            "mov qword ptr [{[vsp]f}], 0",
            "inc {[vip]f} # skip ref type, should be LEB if GC support is added",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # vsp",
        }, .{ .vip = Gpr.vip, .vsp = Gpr.vsp });
        ref_null.jmpToNextHandler(as);
        ref_null.end(as);
    }
    {
        var is_null = as.defineOpcodeHandler(zig, "ref.is_null", .@"16");
        as.printInstrs(&.{
            "mov r13, qword ptr [{[vsp]f} - 0x10] # reference to check",
            "xor r14d, r14d",
            "test r13, r13",
            "setz r14b",
            "mov dword ptr [{[vsp]f} - 0x10], r14d # store result",
        }, .{ .vsp = Gpr.vsp });
        is_null.jmpToNextHandler(as);
        is_null.end(as);
    }
    {
        var ref_func = as.defineOpcodeHandler(zig, "ref.func", .@"16");
        var func_idx = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "func");

        const stack_saved_registers = [_]Gpr{ .locals, .mems, .interp, .eip };
        comptime std.debug.assert(
            (Gpr.system_v_callee_saved.len + stack_saved_registers.len) % 2 == 1,
        );

        for (stack_saved_registers) |saved| {
            // No CFI directives needed here right?
            as.printInstrs(&.{"push {f}"}, .{saved});
        }

        as.writeInstrs(&.{"push rax # garbage, ensures 16-byte alignment"});

        // Already saved
        comptime std.debug.assert(Gpr.system_v_callee_saved[4].tag == Gpr.stp.tag);
        comptime std.debug.assert(Gpr.system_v_callee_saved[3].tag == Gpr.disp.tag);
        const callee_saved_registers: [Gpr.system_v_callee_saved.len - 2]Gpr =
            .{ .vip, .fuel, .vsp };

        for (Gpr.system_v_callee_saved[0..3], callee_saved_registers) |dst, src| {
            // No CFI directives needed here right?
            as.printInstrs(&.{"mov {f}, {f}"}, .{ dst, src });
        }

        as.printInstrs(&.{
            "mov {[param_0]f}, r11 # func index",
            "# rsi is skipped",
            "# module already in rdx",
            "# System V calling convention",
            "call {[symbol_prefix]s}constructFuncRef",
            "# module still in rdx",
            "mov qword ptr [{[temp_vsp]f}], rax # vsp",
            "lea {[temp_vsp]f}, [{[temp_vsp]f} + 0x10] # vsp",
        }, .{
            .param_0 = SystemVParam{ .index = 0 },
            .symbol_prefix = as.symbol_prefix,
            .temp_vsp = Gpr.system_v_callee_saved[2],
        });
        comptime std.debug.assert(callee_saved_registers[2].tag == Gpr.vsp.tag);

        as.writeInstrs(&.{"pop rax # used to align stack"});

        for (0..stack_saved_registers.len) |i| {
            as.printInstrs(&.{"pop {f}"}, .{stack_saved_registers[stack_saved_registers.len - i - 1]});
        }

        for (Gpr.system_v_callee_saved[0..3], callee_saved_registers) |src, dst| {
            as.printInstrs(&.{"mov {f}, {f}"}, .{ dst, src });
        }

        ref_func.jmpToNextHandler(as);
        func_idx.writeSlowPath(as);
        ref_func.end(as);
    }
}

fn definePrefixOpcodeHandlers(
    as: *AsmWriter,
    zig: *ZigWriter,
    optimize: std.builtin.OptimizeMode,
) void {
    for (&[_][2][]const u8{.{ "0xFC", "fc_prefix_dispatch_table" }}) |info| {
        const opcode_name, const table_name = info;
        var op = as.startFunction(opcode_name, .@"32");
        AsmWriter.OpcodeHandler.writeStartingCfiDirectives(as);
        zig.defineOpcodeHandler(opcode_name);
        switch (optimize) {
            .Debug, .ReleaseSafe => as.printInstrs(&.{
                "lea {[invalid_ip]f}, [{[vip]f} - 1] # save IP in case of invalid opcode",
            }, .{ .invalid_ip = Gpr.prefix_opcode_base_ip, .vip = Gpr.vip }),
            .ReleaseFast, .ReleaseSmall => {},
        }
        var decode_opcode = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "opcode");
        as.printInstrs(
            &.{
                "jmp [{[symbol_prefix]s}{[table_name]s} + r13*8]",
                "ud2",
            },
            .{ .symbol_prefix = as.symbol_prefix, .table_name = table_name },
        );
        decode_opcode.writeSlowPath(as);
        op.end(as);
    }
}

fn defineBulkMemoryOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var memory_init = as.defineOpcodeHandler(zig, "memory.init", .fromByteUnits(128));
        as.printInstrs(&.{"mov r15, {f} # save IP to first byte after opcode"}, .{Gpr.vip});
        var data_idx = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "data");
        var mem_idx = DecodeUlebIdx.fastPath(as, .r13, .{ .r13, .r14 }, "mem");
        var clobbers = AsmWriter.PreservedRegisters.init(
            &.{ "vip", "fuel", "locals", "interp", "disp", "mems", "eip", "module" },
        );
        clobbers.preserve(as);
        var oob = as.label(&.{"oob"});
        var copy_trailing_bytes = as.label(&.{"copy_trailing_below_64"});
        as.printInstrs(&.{
            "mov r14, qword ptr [{[mems]f} + r13*8] # pointer to MemInst",
            "mov r9, qword ptr [{[module]f} + {[module_info_off]d}]" ++
                " # pointer to module info, clobbers interp",

            "mov edi, dword ptr [{[vsp]f} - 0x30] # dst offset, clobbers locals",
            "mov eax, dword ptr [{[vsp]f} - 0x10] # number of bytes to copy, clobbers vip",
            "mov r10d, dword ptr [{[vsp]f} - 0x20] # src offset, clobbers eip",
            "lea {[vsp]f}, [{[vsp]f} - 0x30] # vsp",

            "mov r12, qword ptr [r14 + {[size_field_off]d}] # dst memory size, clobbers dispatch",
            "lea r8, [rdi + rax] # dst end offset, clobbers mems",
            "cmp r8, r12",
            "ja {[oob]f}",

            "mov r12, qword ptr [r9 + {[info_datas_lens_off]d}]" ++
                " # ptr to data lens, clobbers dst mem size",
            "mov r12d, dword ptr [r12 + r11*4] # data len, clobbers ptr to data lens",

            "mov rdx, qword ptr [{[module]f} + {[module_datas_drop_mask_off]d}]" ++
                " # ptr to datas drop masks, clobbers module",
            "mov ecx, r11d # data index, clobbers fuel",
            "shr ecx, 5 # calculate index of drop word",
            "mov edx, dword ptr [rdx + rcx*4] # drop word ptr, clobbers datas drop masks ptr",
            "mov ecx, r11d # data index",
            "and ecx, 31 # bit index into data word",
            // "lea ecx, [31 - ecx]",
            // "shl edx, cl # move drop bit to bit 31",
            "shr edx, cl # move drop bit to bit 0",
            "shl edx, 31 # move drop bit to bit 31",
            "sar edx, 31 # all 0's is data segment was dropped, all 1's otherwise",
            "and r12d, edx # set data segment length to 0 if it was dropped",

            "mov rcx, r10 # src offset",
            "lea r8, [rcx + rax] # src end offset, clobbers dst end offset",
            "cmp r8, r12",
            "ja {[oob]f}",

            "mov r9, qword ptr [r9 + {[info_datas_ptrs_off]d}]" ++
                " # ptr to data byte ptrs, clobbers ptr to module info",
            "mov r9, qword ptr [r9 + r11*8] # ptr to data base, clobbers ptr to data byte ptrs",
            "add rcx, r9 # src data ptr, clobbers src offset",

            "mov r9, qword ptr [r14] # dst base pointer, clobbers ptr to data base",
            "add rdi, r9 # dst ptr, clobbers dst offset",

            "# differs from memory.copy since regions are guaranteed to not overlap",
            "# TODO: could test for large length to use rep stosb here",
            "cmp eax, 64",
            "jb {[copy_trailing_bytes]f}",
        }, .{
            .mems = Gpr.mems,
            .module = Gpr.module,
            .module_info_off = 8,
            .module_datas_drop_mask_off = 56,
            .info_datas_ptrs_off = 232, // Assumes offset of RawInner in Module.Inner is 0
            .info_datas_lens_off = 240, // Assumes offset of RawInner in Module.Inner is 0
            .size_field_off = 8,
            .vsp = Gpr.vsp,
            .oob = oob,
            .copy_trailing_bytes = copy_trailing_bytes,
        });

        as.write(".p2align 5\n");
        var hot_loop = as.label(&.{"hot_loop"});
        hot_loop.place(as);
        as.printInstrs(&.{
            "movups xmm0, xmmword ptr [rcx]",
            "movups xmmword ptr [rdi], xmm0",
            "movups xmm1, xmmword ptr [rcx + 0x10]",
            "movups xmmword ptr [rdi + 0x10], xmm1",
            "movups xmm2, xmmword ptr [rcx + 0x20]",
            "movups xmmword ptr [rdi + 0x20], xmm2",
            "movups xmm3, xmmword ptr [rcx + 0x30]",
            "movups xmmword ptr [rdi + 0x30], xmm3",
            "lea rcx, [rcx + 64] # src",
            "lea rdi, [rdi + 64] # dst",
            "sub eax, 64",
            "cmp eax, 64",
            "jae {[hot_loop]f}",
        }, .{ .hot_loop = hot_loop });

        as.write(".p2align 5\n");
        copy_trailing_bytes.place(as);
        var done = as.label(&.{"done"});
        as.printInstrs(&.{
            "test eax, eax",
            "jz {[done]f}",
            ".p2align 4",
        }, .{ .done = done });

        var copy_byte = as.label(&.{"copy_byte"});
        copy_byte.place(as);
        as.printInstrs(&.{
            "movzx r8, byte ptr [rcx]",
            "mov byte ptr [rdi], r8b",
            "inc rcx # src",
            "inc rdi # dst",
            "dec eax",
            "jnz {[copy_byte]f}",
        }, .{ .copy_byte = copy_byte });

        done.place(as);
        clobbers.restore(as);
        memory_init.jmpToNextHandler(as);

        data_idx.writeSlowPath(as);
        mem_idx.writeSlowPath(as);

        as.write(".p2align 5\n");
        oob.place(as);
        clobbers.restore(as);
        for (
            Gpr.system_v_parameters,
            &[6]Gpr{ .r15, .vsp, .eip, .stp, .r13, .interp },
            &[6][]const u8{ "vip", "vsp", "eip", "stp", "memory index", "interpreter" },
        ) |dst, src, comment| {
            if (dst != src)
                as.printInstrs(
                    &.{"mov {[dst]f}, {[src]f} # {[comment]s}"},
                    .{ .dst = dst, .src = src, .comment = comment },
                )
            else
                as.printInstrs(
                    &.{"# {[comment]s} stays in {[dst]f}"},
                    .{ .comment = comment, .dst = dst },
                );
        }
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapMemoryInitOutOfBounds",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });

        memory_init.end(as);
    }
    for (&[_]struct { []const u8, u8 }{
        .{ "data.drop", 56 },
        .{ "elem.drop", 64 },
    }) |info| {
        const name, const drop_mask_offset = info;
        const kind = name[0..4];
        var drop = as.defineOpcodeHandler(zig, name, .@"32");
        as.writeInstrs(&.{"mov r13, rcx # save fuel"});
        var idx = DecodeUlebIdx.fastPath(as, .rcx, .{ .r14, .r15 }, kind);
        as.printInstrs(&.{
            "mov r14, [{[module]f} + {[module_drop_mask_off]d}] # {[kind]s} drop masks ptr",
            "mov r15, rcx",
            "shr r15, 5 # calculate index of drop word",
            "lea r14, dword ptr [r14 + r15*4] # drop word ptr, clobbers {[kind]s}s drop masks ptr",
            "and rcx, 0x1F # calculate bit index into drop word, clobbers {[kind]s} idx",
            "mov r15d, 1",
            // "shlx r15d, r13b", // requires BMI2
            "shl r15d, cl # bit corresponding to the {[kind]s} to drop",
            "# could use ANDN if BMI1 is enabled",
            "not r15d # ensure only corresponding bit is set to zero",
            "and dword ptr [r14], r15d" ++
                " # set drop bit to zero, meaning {[kind]s} length is set to zero",
            "mov rcx, r13 # restore fuel",
        }, .{
            .module = Gpr.module,
            .module_drop_mask_off = drop_mask_offset,
            .kind = kind,
        });
        drop.jmpToNextHandler(as);
        idx.writeSlowPath(as);
        drop.end(as);
    }
    {
        var memmove = as.defineOpcodeHandler(zig, "memory.copy", .fromByteUnits(128));
        as.printInstrs(&.{
            "mov r15, {[vip]f} # save IP to first byte after opcode",
            "push {[stp]f} # STP clobbered when dst mem index is read",
        }, .{ .vip = Gpr.vip, .stp = Gpr.stp });

        var dst_mem_idx = DecodeUlebIdx.fastPath(as, .rbx, .{ .r13, .r14 }, "dst_mem");
        var src_mem_idx = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "src_mem");

        var clobbered_registers_buf: [8]Gpr =
            .{ .stp, .vip, .fuel, .locals, .mems, .eip, .disp, .interp };
        var clobbered_info_buf: [8][]const u8 = .{
            "stp (cloberred before indices were parsed)",
            "vip",
            "fuel",
            "locals",
            "memories",
            "eip",
            "dispatch",
            "interpreter",
        };
        var clobbers = AsmWriter.PreservedRegisters{
            .registers = clobbered_registers_buf[1..],
            .comments = clobbered_info_buf[1..],
        };
        clobbers.preserve(as); // STP is saved earlier
        clobbers.registers = &clobbered_registers_buf;
        clobbers.comments = &clobbered_info_buf;

        var dst_oob = as.label(&.{"src_oob"});
        var src_oob = as.label(&.{"dst_oob"});
        var copy_reverse = as.label(&.{"reverse"});
        as.printInstrs(&.{
            "# stp clobbered, rbx contains dst memory index",
            "mov r13, qword ptr [{[mems]f} + rbx*8] # pointer to dst MemInst",
            "mov r14, qword ptr [{[mems]f} + r11*8] # pointer to src MemInst",
            "mov r8, qword ptr [r13] # dst base pointer, clobbers mems",
            "mov r10, qword ptr [r13] # src base pointer, clobbers eip",

            "mov edi, dword ptr [{[vsp]f} - 0x30] # dst offset, clobbers locals",
            "mov eax, dword ptr [{[vsp]f} - 0x10] # number of bytes to copy, clobbers vip",
            "mov ecx, dword ptr [{[vsp]f} - 0x20] # src offset, clobbers fuel",
            "lea {[vsp]f}, [{[vsp]f} - 0x30] # vsp",

            "mov r12, qword ptr [r13 + {[size_field_off]d}] # dst memory size, clobbers dispatch",
            "lea r9, [rdi + rax] # dst end offset, clobbers interpreter",
            "cmp r9, r12",
            "ja {[dst_oob]f}",

            "mov r12, qword ptr [r14 + {[size_field_off]d}] # src memory size, clobbers dst size",
            "lea rbx, [rcx + rax] # src end offset, clobbers dst mem index",
            "cmp rbx, r12",
            "ja {[src_oob]f}",

            "lea rdi, [r8 + rdi] # dst start ptr, clobbers dst offset",
            "lea rcx, [r10 + rcx] # src start ptr, clobbers src offset",

            "# check for overlap:",
            "lea rbx, [rcx + rax] # src end ptr, clobbers src end offset",
            "mov r8, rbx # clobbers dst base pointer",
            "sub r8, rdi",
            "cmp r8, rax # reverse if dst start < src end and src end - dst start < bytes to copy",
            // TODO: Fix, logic might be wrong if src end == dst start
            "jl {[copy_reverse]f} # check for overlap",
        }, .{
            .mems = Gpr.mems,
            .vsp = Gpr.vsp,
            .size_field_off = 8,
            .dst_oob = dst_oob,
            .src_oob = src_oob,
            .copy_reverse = copy_reverse,
        });
        var done = as.label(&.{"done"});
        {
            var copy_trailing = as.label(&.{"copy_trailing"});
            as.printInstrs(&.{
                "# LLVM Zig backend emits memory.copy for lengths > 32",
                "# This assumes that lengths below that are unlikely",
                "# TODO: check for large length to use rep stosb",
                "cmp eax, 32",
                "jb {[copy_trailing]f}",
            }, .{ .copy_trailing = copy_trailing });

            var hot_loop = as.label(&.{"hot_loop"});
            hot_loop.place(as);
            as.write(".p2align 5\n");
            as.printInstrs(&.{
                "movups xmm0, xmmword ptr [rcx]",
                "movups xmmword ptr [rdi], xmm0",
                "movups xmm1, xmmword ptr [rcx + 16]",
                "movups xmmword ptr [rdi + 16], xmm1",
                "lea rcx, [rcx + 32] # advance src ptr",
                "lea rdi, [rdi + 32] # advance dst ptr",
                "sub eax, 32",
                "cmp eax, 32",
                "jae {[hot_loop]f}",
            }, .{ .hot_loop = hot_loop });

            copy_trailing.place(as);
            var copy_trailing_below_8 = as.label(&.{"copy_trailing_below_8"});
            as.printInstrs(&.{
                "cmp eax, 8",
                "jb {[copy_trailing_below_8]f}",
            }, .{ .copy_trailing_below_8 = copy_trailing_below_8 });
            var copy_trailing_qwords = as.label(&.{"copy_trailing_qwords"});
            as.write(".p2align 4\n");
            copy_trailing_qwords.place(as);
            as.printInstrs(&.{
                "mov rbx, qword ptr [rcx] # unaligned, clobbers src end ptr",
                "mov qword ptr [rdi], rbx # unaligned",
                "lea rcx, [rcx + 8] # advance src ptr",
                "lea rdi, [rdi + 8] # advance dst ptr",
                "sub eax, 8",
                "cmp eax, 8",
                "jae {[copy_trailing_qwords]f}",
            }, .{ .copy_trailing_qwords = copy_trailing_qwords });

            copy_trailing_below_8.place(as);
            as.printInstrs(&.{
                "test eax, eax",
                "jz {[done]f}",
                "xor ebx, ebx",
            }, .{ .done = done });
            as.write(".p2align 3\n");
            var copy_trailing_bytes = as.label(&.{"copy_trailing_bytes"});
            copy_trailing_bytes.place(as);
            as.printInstrs(&.{
                "mov bl, byte ptr [rcx]",
                "mov byte ptr [rdi], bl",
                "lea rcx, [rcx + 1] # advance src ptr",
                "lea rdi, [rdi + 1] # advance dst ptr",
                "dec eax",
                "jnz {[copy_trailing_bytes]f}",
            }, .{ .copy_trailing_bytes = copy_trailing_bytes });
        }
        {
            as.write(".p2align 4\n");
            done.place(as);
            clobbers.restore(as);
            memmove.jmpToNextHandler(as);
        }
        {
            copy_reverse.place(as);
            var copy_trailing = as.label(&.{"copy_trailing_reverse"});
            as.printInstrs(&.{
                "# src end ptr in rbx",
                "lea rdi, [rdi + rax] # dst end ptr, clobbers dst start pointer",
                "cmp eax, 32",
                "jb {[copy_trailing]f}",
            }, .{ .copy_trailing = copy_trailing });

            as.write(".p2align 5\n");
            var hot_loop = as.label(&.{"hot_loop_reverse"});
            hot_loop.place(as);
            as.printInstrs(&.{
                "movups xmm0, xmmword ptr [rbx - 16]",
                "movups xmmword ptr [rdi - 16], xmm0",
                "movups xmm1, xmmword ptr [rbx - 32]",
                "movups xmmword ptr [rdi - 32], xmm1",
                "lea rbx, [rbx - 32] # advance src ptr",
                "lea rdi, [rdi - 32] # advance dst ptr",
                "sub eax, 32",
                "cmp eax, 32",
                "jae {[hot_loop]f}",
            }, .{ .hot_loop = hot_loop });

            copy_trailing.place(as);
            as.write(".p2align 5\n");
            var copy_trailing_below_8 = as.label(&.{"copy_trailing_below_8_reverse"});
            as.printInstrs(&.{
                "cmp eax, 8",
                "jb {[copy_trailing_below_8]f}",
            }, .{ .copy_trailing_below_8 = copy_trailing_below_8 });
            var copy_trailing_qwords = as.label(&.{"copy_trailing_qwords_reverse"});
            copy_trailing_qwords.place(as);
            as.printInstrs(&.{
                "mov rcx, qword ptr [rbx - 8] # unaligned, clobbers src start ptr",
                "mov qword ptr [rdi - 8], rcx # unaligned",
                "lea rbx, [rbx - 8] # advance src ptr",
                "lea rdi, [rdi - 8] # advance dst ptr",
                "sub eax, 8",
                "cmp eax, 8",
                "jae {[copy_trailing_qwords]f}",
            }, .{ .copy_trailing_qwords = copy_trailing_qwords });

            copy_trailing_below_8.place(as);
            as.write(".p2align 4\n");
            as.printInstrs(&.{
                "test eax, eax",
                "jz {[done]f}",
                "xor ecx, ecx # clobbers",
            }, .{ .done = done });
            var copy_trailing_bytes = as.label(&.{"copy_trailing_bytes_reverse"});
            copy_trailing_bytes.place(as);
            as.printInstrs(&.{
                "mov cl, byte ptr [rbx - 1]",
                "mov byte ptr [rdi - 1], cl",
                "lea rbx, [rbx - 1] # advance src ptr",
                "lea rdi, [rdi - 1] # advance dst ptr",
                "dec eax",
                "jnz {[copy_trailing_bytes]f}",
                "jmp {[done]f}",
                "ud2",
            }, .{ .copy_trailing_bytes = copy_trailing_bytes, .done = done });
        }

        dst_mem_idx.writeSlowPath(as);
        src_mem_idx.writeSlowPath(as);

        {
            as.write(".p2align 5\n");
            dst_oob.place(as);
            as.writeInstrs(&.{"mov r11, rbx # dst memory index"});
            src_oob.place(as);
            as.write("\t# if src is oob, r11 contains src memory index\n");
            clobbers.restore(as);
            for (
                Gpr.system_v_parameters,
                &[6]Gpr{ .r15, .vsp, .eip, .stp, .r11, .interp },
                &[6][]const u8{ "vip", "vsp", "eip", "stp", "memory index", "interpreter" },
            ) |dst, src, comment| {
                if (dst != src)
                    as.printInstrs(
                        &.{"mov {[dst]f}, {[src]f} # {[comment]s}"},
                        .{ .dst = dst, .src = src, .comment = comment },
                    )
                else
                    as.printInstrs(
                        &.{"# {[comment]s} stays in {[dst]f}"},
                        .{ .comment = comment, .dst = dst },
                    );
            }
            as.popSystemVSavedRegisters();
            as.printInstrs(&.{
                "# rsp already refers to saved rbp",
                "pop rbp",
                ".cfi_def_cfa rsp, 8",
                "jmp {[prefix]s}trapMemoryCopyOutOfBounds",
                "ud2",
            }, .{ .prefix = as.symbol_prefix });
        }

        memmove.end(as);
    }
    {
        // LLVM uses `call memset@PLT`, but that means 5 interpreter registers need to be `pushed`
        // to the stack.
        var memset = as.defineOpcodeHandler(zig, "memory.fill", .@"64");
        as.printInstrs(&.{"mov r15, {f} # save IP to first byte after opcode"}, .{Gpr.vip});
        var oob = as.label(&.{"oob"});
        var mem_idx = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "memory");
        // With no proof whatsover, this assumes that calling `memset` via PLT would be slower than
        // a custom memset implementation.
        const clobbers = AsmWriter.PreservedRegisters.init(&.{ "vip", "fuel", "locals", "stp" });
        clobbers.preserve(as);
        var done = as.label(&.{"done"});
        var below_16 = as.label(&.{"below_16_bytes"});
        var between_16_and_32 = as.label(&.{"between_16_and_32_bytes"});
        var between_32_and_64 = as.label(&.{"between_32_and_64_bytes"});
        var set_64_trailing_bytes = as.label(&.{"set_64_trailing_bytes"});
        // TODO: See if AVX is enabled to use ymm registers
        as.printInstrs(&.{
            "mov r13, qword ptr [{[mems]f} + r11*8] # pointer to MemInst",
            "mov r14, qword ptr [r13] # base pointer",
            "mov ecx, dword ptr [{[vsp]f} - 0x10] # number of bytes to fill, clobbers fuel",
            "mov eax, dword ptr [{[vsp]f} - 0x20] # byte to replicate, clobbers vip",
            "mov edi, dword ptr [{[vsp]f} - 0x30] # offset to start at, clobbers locals",
            "lea {[vsp]f}, [{[vsp]f} - 0x30] # vsp",
            "mov rbx, qword ptr [r13 + {[size_field_off]d}] # memory size, clobbers stp",
            "lea r13, [rdi + rcx] # end offset, clobbers pointer to MemInst",
            "cmp r13, rbx",
            "ja {[oob]f} # exceeded memory bounds",
            "lea rdi, [r14 + rdi] # pointer to start at, clobbers offset to start at",
            "cmp ecx, 16 # assume most WASM compilers won't memory.fill for sizes below this",
            "# Zig LLVM backend emits `memory.fill` for sizes >= 32",
            "jb {[below_16]f}",
            "# vector stores beyond this point!",
            "mov r11, 0x0101010101010101 # clobbers memory index",
            "imul rax, r11 # expand byte to fill",
            "movq xmm0, rax",
            "pshufd xmm0, xmm0, 0x44 # 16-byte pattern to fill with",
            "cmp ecx, 32",
            "jbe {[between_16_and_32]f}",
            "cmp ecx, 64",
            "jbe {[between_32_and_64]f}",
            "# copy first 64 bytes",
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + 0x10], xmm0",
            "movups xmmword ptr [rdi + 0x20], xmm0",
            "movups xmmword ptr [rdi + 0x30], xmm0",
            "mov rbx, rdi # old destination pointer, clobbers memory size",
            "lea rdi, [rdi + 64]",
            "shr rdi, 6",
            "shl rdi, 6 # round rdi up to nearest multiple of 64",
            "mov rax, rdi # clobbers 8-byte pattern to fill",
            "sub rax, rbx # number of bytes to get to 64-byte alignment",
            "sub ecx, eax # update count",
            "# rdi is 64-byte aligned at this point",
            "cmp ecx, 64",
            "jb {[set_64_trailing_bytes]f}",
            // TODO: rep stosq if size > 1024
        }, .{
            .mems = Gpr.mems,
            .vsp = Gpr.vsp,
            .size_field_off = 8,
            .oob = oob,
            .below_16 = below_16,
            .between_16_and_32 = between_16_and_32,
            .between_32_and_64 = between_32_and_64,
            .set_64_trailing_bytes = set_64_trailing_bytes,
        });
        // https://www.microsoft.com/en-us/msrc/blog/2021/01/building-faster-amd64-memset-routines
        // ^ guesses that future `rep stos` would use AVX-512, requiring 64-byte alignment
        as.write(".p2align 4\n");
        var copy_64_aligned = as.label(&.{"copy_64_aligned"});
        copy_64_aligned.place(as);
        as.printInstrs(&.{
            "movaps xmmword ptr [rdi], xmm0",
            "movaps xmmword ptr [rdi + 0x10], xmm0",
            "movaps xmmword ptr [rdi + 0x20], xmm0",
            "movaps xmmword ptr [rdi + 0x30], xmm0",
            "lea rdi, [rdi + 64] # update destination pointer",
            "sub ecx, 64 # update count",
            "cmp ecx, 64",
            "jae {[copy_64_aligned]f}",
        }, .{ .copy_64_aligned = copy_64_aligned });
        set_64_trailing_bytes.place(as);
        as.writeInstrs(&.{
            "# fill remaining 0-63 bytes",
            "movups xmmword ptr [rdi + rcx - 0x40], xmm0",
            "movups xmmword ptr [rdi + rcx - 0x30], xmm0",
            "movups xmmword ptr [rdi + rcx - 0x20], xmm0",
            "movups xmmword ptr [rdi + rcx - 0x10], xmm0",
            "# no need to update counts, we are done",
        });
        done.place(as);
        clobbers.restore(as);
        memset.jmpToNextHandler(as);
        mem_idx.writeSlowPath(as);

        as.write(".p2align 4\n");
        below_16.place(as);
        as.printInstrs(&.{
            "test ecx, ecx",
            "jz {[done]f} # copying zero bytes?",
            "lea rcx, [r14 + r13 - 1] # clobbers # of bytes to copy",
        }, .{ .done = done });
        var loop_below_16 = as.label(&.{"below_16_loop"});
        loop_below_16.place(as);
        as.printInstrs(&.{
            "# fills from both ends, ensuring at most 2 stores per loop iteration",
            "mov byte ptr [rdi], al",
            "mov byte ptr [rcx], al",
            "inc rdi",
            "dec rcx",
            "cmp rdi, rcx",
            "jbe {[loop]f} # ensures middle byte is copied for odd lengths",
            "jmp {[done]f}",
            "ud2",
        }, .{ .loop = loop_below_16, .done = done });

        as.write(".p2align 4\n");
        between_32_and_64.place(as);
        as.printInstrs(&.{
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + 0x10], xmm0",
            "movups xmmword ptr [rdi + rcx - 0x20], xmm0",
            "movups xmmword ptr [rdi + rcx - 0x10], xmm0",
            "jmp {[done]f}",
            "ud2",
        }, .{ .done = done });

        as.write(".p2align 4\n");
        between_16_and_32.place(as);
        as.printInstrs(&.{
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + rcx - 0x10], xmm0",
            "jmp {[done]f}",
            "ud2",
        }, .{ .done = done });

        as.write(".p2align 4\n");
        oob.place(as);

        clobbers.restore(as);
        for (
            Gpr.system_v_parameters,
            &[6]Gpr{ .r15, .vsp, .eip, .stp, .r11, .interp },
            &[6][]const u8{ "vip", "vsp", "eip", "stp", "memory index", "interpreter" },
        ) |dst, src, comment| {
            if (dst != src)
                as.printInstrs(
                    &.{"mov {[dst]f}, {[src]f} # {[comment]s}"},
                    .{ .dst = dst, .src = src, .comment = comment },
                )
            else
                as.printInstrs(
                    &.{"# {[comment]s} stays in {[dst]f}"},
                    .{ .comment = comment, .dst = dst },
                );
        }
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapMemoryFillOutOfBounds",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        memset.end(as);
    }
    {
        var table_init = as.defineOpcodeHandler(zig, "table.init", .@"64");
        as.printInstrs(&.{
            "# better to implement in Zig instead of assembly\n",
            "mov r15, {[vip]f} # trap ip",
        }, .{ .vip = Gpr.vip });
        var elem_idx = DecodeUlebIdx.fastPath(as, .rdi, .{ .r13, .r14 }, "elem");
        var table_idx = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "table");
        as.printInstrs(&.{
            "# pack indices to ensure another register parameter can be passed",
            "shl rdi, 32 # elem index in high 32-bits",
            "or rdi, r11 # table index in low 32-bits",
            "# setup register parameters",
            "#0 elem/table indices in rdi, locals was clobbered",
            "#1 vsp is already in rsi",
            "#2 module is already in rdx",
            "#3 fuel is already in rcx",
            "mov r8, {[vip]f} #4 vip, memories was clobbered",
            "#5 interp is already in r9",
            "# setup stack parameters",
            "mov {[param_6]f}, {[stp]f} #6 EIP",
            "mov {[param_7]f}, r10 #7 EIP",
            "mov {[param_8]f}, r15 #8 trap IP",
        }, .{
            .vip = Gpr.vip,
            .stp = Gpr.stp,
            .param_6 = SystemVParam{ .index = 6 },
            .param_7 = SystemVParam{ .index = 7 },
            .param_8 = SystemVParam{ .index = 8 },
        });
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}tableInit",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        elem_idx.writeSlowPath(as);
        table_idx.writeSlowPath(as);
        table_init.end(as);
    }
    {
        var table_copy = as.defineOpcodeHandler(zig, "table.copy", .@"64");
        as.printInstrs(&.{
            "push {[disp]f} # prevent clobbering disp",
            "mov {[disp]f}, {[vip]f} # save IP to first byte after opcode, clobbers disp",
        }, .{ .vip = Gpr.vip, .disp = Gpr.disp });
        var dst_idx = DecodeUlebIdx.fastPath(as, .r11, .{ .r14, .r15 }, "dst");
        var src_idx = DecodeUlebIdx.fastPath(as, .r13, .{ .r14, .r15 }, "src");
        var clobbers = AsmWriter.PreservedRegisters.init(&.{
            "disp", // contains saved ip
            "module",
            "stp",
            "locals",
            "vip",
            "fuel",
            "mems",
            "interp",
        });
        // disp was already saved
        const restore_disp = clobbers;
        clobbers.registers = clobbers.registers[1..];
        clobbers.comments = clobbers.comments[1..];
        clobbers.preserve(as);
        clobbers = restore_disp;
        var src_oob = as.label(&.{"dst_oob"});
        var dst_oob = as.label(&.{"src_oob"});
        var copy_reverse = as.label(&.{"reverse"});
        as.printInstrs(&.{
            "mov rdx, qword ptr [{[module]f} + {[module_tables_off]d}]" ++
                " # ptr to table inst ptrs, clobbers module",
            "mov rbx, qword ptr [rdx + r13*8] # ptr to src table, clobbers STP",
            "mov rdx, qword ptr [rdx + r11*8] # ptr to dst table, clobbers ptr to table inst ptrs",

            "mov eax, dword ptr [{[vsp]f} - 0x10] # number of elements to copy, clobbers VIP",
            "mov ecx, dword ptr [{[vsp]f} - 0x20] # src offset, clobbers fuel",
            "mov edi, dword ptr [{[vsp]f} - 0x30] # dst offset, clobbers locals",
            "lea {[vsp]f}, [{[vsp]f} - 0x30] # VSP",

            "mov r8d, dword ptr [rbx + {[table_len_off]d}] # src table len, clobbers mems",
            "lea r9, [rcx + rax] # src end offset, clobbers interpreter",
            "cmp r9, r8",
            "ja {[src_oob]f}",

            "mov r8d, dword ptr [rdx + {[table_len_off]d}] # dst table len, clobbers src table len",
            "lea r13, [rdi + rax] # dst end offset, clobbers src table idx",
            "cmp r13, r8",
            "ja {[dst_oob]f}",

            "mov rbx, qword ptr [rbx] # src elems ptr, clobbers ptr to src tables",
            "mov rdx, qword ptr [rdx] # dst elems ptr, clobbers ptr to dst tables",
            "lea rcx, [rbx + rcx*8] # src ptr, clobbers src offset",

            "xor ebx, ebx # clobbers src elems ptr",
            "cmp edi, r9d # dst_start < src_end",
            "setb bl",
            "xor r13d, r13d # clobbers dst end offset",
            "sub r9d, edi # src_end - dst_start, clobbers src end offset",
            "cmp r9d, eax",
            "setb r13b",

            "lea rdi, [rdx + rdi*8] # dst ptr, clobbers dst offset",

            "# check for overlap:",
            "# if dst_start < src_end and src_end - dst_start < length then reverse",
            "test bl, r13b",
            "jnz {[copy_reverse]f}",
        }, .{
            .module = Gpr.module,
            .module_tables_off = 40,
            .table_len_off = 12,
            .vsp = Gpr.vsp,
            .src_oob = src_oob,
            .dst_oob = dst_oob,
            .copy_reverse = copy_reverse,
        });
        var done = as.label(&.{"label"});
        {
            var copy_trailing = as.label(&.{"copy_trailing"});
            as.printInstrs(&.{
                "cmp eax, 8",
                "jb {[copy_trailing]f}",
            }, .{ .copy_trailing = copy_trailing });

            as.write(".p2align 5\n");
            var copy_8_elems = as.label(&.{"copy_8_elems"});
            copy_8_elems.place(as);
            as.printInstrs(&.{
                "movups xmm0, xmmword ptr [rcx]",
                "movups xmmword ptr [rdi], xmm0",
                "movups xmm1, xmmword ptr [rcx + 0x10]",
                "movups xmmword ptr [rdi + 0x10], xmm1",
                "movups xmm2, xmmword ptr [rcx + 0x20]",
                "movups xmmword ptr [rdi + 0x20], xmm2",
                "movups xmm3, xmmword ptr [rcx + 0x30]",
                "movups xmmword ptr [rdi + 0x30], xmm3",
                "lea rcx, [rcx + 64] # advance src",
                "lea rdi, [rdi + 64] # advance dst",
                "sub eax, 8",
                "cmp eax, 8",
                "jae {[copy_8_elems]f}",
            }, .{ .copy_8_elems = copy_8_elems });

            as.write(".p2align 4\n");
            copy_trailing.place(as);
            as.printInstrs(&.{
                "test eax, eax",
                "jz {[done]f}",
            }, .{ .done = done });
            var copy_elem = as.label(&.{"copy_elem"});
            copy_elem.place(as);
            as.printInstrs(&.{
                "mov rbx, qword ptr [rcx] # clobbers",
                "mov qword ptr [rdi], rbx",
                "lea rcx, [rcx + 8] # advance src",
                "lea rdi, [rdi + 8] # advance dst",
                "dec eax",
                "jnz {[copy_elem]f}",
            }, .{ .copy_elem = copy_elem });
        }
        {
            done.place(as);
            clobbers.restore(as);
            table_copy.jmpToNextHandler(as);
        }
        {
            as.write(".p2align 5\n");
            copy_reverse.place(as);
            var copy_trailing = as.label(&.{"copy_reverse_trailing"});
            as.printInstrs(&.{
                "lea rcx, [rcx + rax*8] # src end ptr, clobbers src ptr",
                "lea rdi, [rdi + rax*8] # dst end ptr, clobbers dst ptr",
                "cmp eax, 8",
                "jb {[copy_trailing]f}",
            }, .{ .copy_trailing = copy_trailing });

            as.write(".p2align 5\n");
            var copy_8_elems = as.label(&.{"copy_reverse_8_elems"});
            copy_8_elems.place(as);
            as.printInstrs(&.{
                "movups xmm0, xmmword ptr [rcx - 0x10]",
                "movups xmmword ptr [rdi - 0x10], xmm0",
                "movups xmm1, xmmword ptr [rcx - 0x20]",
                "movups xmmword ptr [rdi - 0x20], xmm1",
                "movups xmm2, xmmword ptr [rcx - 0x30]",
                "movups xmmword ptr [rdi - 0x30], xmm2",
                "movups xmm3, xmmword ptr [rcx - 0x40]",
                "movups xmmword ptr [rdi - 0x40], xmm3",
                "sub rcx, 64 # advance src",
                "sub rdi, 64 # advance dst",
                "sub eax, 8",
                "cmp eax, 8",
                "jae {[copy_8_elems]f}",
            }, .{ .copy_8_elems = copy_8_elems });

            as.write(".p2align 4\n");
            copy_trailing.place(as);
            as.printInstrs(&.{
                "test eax, eax",
                "jz {[done]f}",
            }, .{ .done = done });
            var copy_elem = as.label(&.{"copy_reverse_elem"});
            copy_elem.place(as);
            as.printInstrs(&.{
                "mov rbx, qword ptr [rcx - 8] # clobbers ptr to src table elems",
                "mov qword ptr [rdi - 8], rbx",
                "sub rcx, 8 # advance src",
                "sub rdi, 8 # advance dst",
                "dec eax",
                "jnz {[copy_elem]f}",
                "jmp {[done]f}",
                "ud2",
            }, .{ .copy_elem = copy_elem, .done = done });
        }

        dst_idx.writeSlowPath(as);
        src_idx.writeSlowPath(as);

        {
            src_oob.place(as);
            as.writeInstrs(&.{"mov r11, r13 # move src table index"});
            dst_oob.place(as);
            as.printInstrs(
                &.{"mov r15, {[disp]f} # IP to first byte, saved in disp"},
                .{ .disp = Gpr.disp },
            );
            clobbers.restore(as);
            for (
                Gpr.system_v_parameters,
                &[6]Gpr{ .r15, .vsp, .eip, .stp, .r11, .interp },
                &[6][]const u8{ "first byte IP", "vsp", "eip", "stp", "table index", "interpreter" },
            ) |dst, src, comment| {
                if (dst != src)
                    as.printInstrs(
                        &.{"mov {[dst]f}, {[src]f} # {[comment]s}"},
                        .{ .dst = dst, .src = src, .comment = comment },
                    )
                else
                    as.printInstrs(
                        &.{"# {[comment]s} stays in {[dst]f}"},
                        .{ .comment = comment, .dst = dst },
                    );
            }
            as.popSystemVSavedRegisters();
            as.printInstrs(&.{
                "# rsp already refers to saved rbp",
                "pop rbp",
                ".cfi_def_cfa rsp, 8",
                "jmp {[prefix]s}trapTableCopyOutOfBounds",
                "ud2",
            }, .{ .prefix = as.symbol_prefix });
        }

        table_copy.end(as);
    }
    {
        var table_grow = as.defineOpcodeHandler(zig, "table.grow", .@"32");
        var table_idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "table");
        var fail = as.label(&.{"fail"});
        var within_capacity = as.label(&.{"within_capacity"});
        as.printInstrs(&.{
            "mov r13d, dword ptr [{[vsp]f} - 0x10] # delta",
            "mov r15, qword ptr [{[vsp]f} - 0x20] # element to fill with",
            "lea {[vsp]f}, [{[vsp]f} - 0x10] # update VSP",
            "mov r14, qword ptr [{[module]f} + {[module_tables_off]d}]" ++
                " # pointer to module table ptrs",
            "mov r11, qword ptr [r14 + r11*8] # pointer to TableInst, clobbers table index",
            "mov r14d, dword ptr [r11 + {[table_len_off]d}]" ++
                " # table len, clobbers ptr to module table ptrs",
            "add r13d, r14d # desired length, clobbers delta",
            "jc {[fail]f} # cmp below can't detect overflow",
            "cmp r13d, dword ptr [r11 + {[table_limit_off]d}] # check against limit",
            "ja {[fail]f}",
            "cmp r13d, dword ptr [r11 + {[table_cap_off]d}] # check against capacity",
            "jbe {[within_capacity]f}",
            "ud2 # TODO: Call into Zig",
        }, .{
            .module = Gpr.module,
            .module_tables_off = 40,
            .table_len_off = 12,
            .table_cap_off = 16,
            .table_limit_off = 20,
            .vsp = Gpr.vsp,
            .fail = fail,
            .within_capacity = within_capacity,
        });

        as.write(".p2align 4\n");
        within_capacity.place(as);
        var done = as.label(&.{"within_capacity_done"});
        var less_than_4_elems = as.label(&.{"less_than_4_elems"});
        as.printInstrs(&.{
            "mov dword ptr [r11 + {[table_len_off]d}], r13d # write new length",
            "mov r11, qword ptr [r11] # pointer to table elems, clobbers TableInst ptr",
            "lea r11, [r11 + r14*8] # start ptr, clobbers ptr to table elems",
            "mov dword ptr [{[vsp]f} - 0x10], r14d # put old length onto value stack",
            "sub r13d, r14d # delta, clobbers new length",
            "lea r14, [r11 + r13*8]" ++
                " # end ptr, one element past the last to write, clobbers table len",
            "# similar to what table.fill does",
            "cmp r13d, 4",
            "jb {[less_than_4_elems]f}",
            "movq xmm0, r15 # replicate element",
            "pshufd xmm0, xmm0, 0x44 # move low qword to high qword",
        }, .{
            .vsp = Gpr.vsp,
            .table_len_off = 12,
            .less_than_4_elems = less_than_4_elems,
        });
        as.write(".p2align 4\n");
        var copy_4_elems = as.label(&.{"copy_4_elems"});
        copy_4_elems.place(as);
        as.printInstrs(&.{
            "movups xmmword ptr [r11], xmm0",
            "movups xmmword ptr [r11 + 0x10], xmm0",
            "lea r11, [r11 + 32] # advance ptr",
            "sub r13d, 4",
            "cmp r13d, 4",
            "ja {[copy_4_elems]f}",
            "# write trailing 4 elements, possibly overlapping",
            "movups xmmword ptr [r14 - 0x10], xmm0",
            "movups xmmword ptr [r14 - 0x20], xmm0",
        }, .{ .copy_4_elems = copy_4_elems });
        done.place(as);
        table_grow.jmpToNextHandler(as);

        as.write(".p2align 4\n");
        less_than_4_elems.place(as);
        as.printInstrs(&.{
            "test r13d, r13d",
            "jz {[done]f}",
        }, .{ .done = done });
        var fill_1_elem = as.label(&.{"fill_1_elem"});
        fill_1_elem.place(as);
        as.printInstrs(&.{
            "mov qword ptr [r11], r15",
            "lea r11, [r11 + 8] # advance ptr",
            "dec r13d # count",
            "jz {[done]f}",
            "jmp {[loop]f}",
            "ud2",
        }, .{ .done = done, .loop = fill_1_elem });

        fail.place(as);
        as.printInstrs(&.{
            "mov dword ptr [{[vsp]f} - 0x10], -1",
            "jmp {[done]f}",
            "ud2",
        }, .{ .vsp = Gpr.vsp, .done = done });
        table_idx_decode.writeSlowPath(as);
        table_grow.end(as);
    }
    {
        var table_size = as.defineOpcodeHandler(zig, "table.size", .@"32");
        var table_idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "table");
        as.printInstrs(&.{
            "mov r13, qword ptr [{[module]f} + {[module_tables_off]d}]" ++
                " # pointer to module table ptrs",
            "mov r13, qword ptr [r13 + r11*8] # pointer to TableInst",
            "mov r13d, dword ptr [r13 + {[table_len_off]d}] # table len",
            "mov dword ptr [{[vsp]f}], r13d",
            "lea {[vsp]f}, [{[vsp]f} + 0x10] # pushed onto stack",
        }, .{
            .module = Gpr.module,
            .module_tables_off = 40,
            .table_len_off = 12,
            .vsp = Gpr.vsp,
        });
        table_size.jmpToNextHandler(as);
        table_idx_decode.writeSlowPath(as);
        table_size.end(as);
    }
    {
        var table_fill = as.defineOpcodeHandler(zig, "table.fill", .@"64");
        as.printInstrs(&.{"mov r15, {f} # save IP to first byte after opcode"}, .{Gpr.vip});
        var table_idx = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "table");
        const clobbers = AsmWriter.PreservedRegisters.init(&.{
            "vip",
            "fuel",
            "locals",
            "stp",
        });
        clobbers.preserve(as);
        var oob = as.label(&.{"oob"});
        var less_than_8_elems = as.label(&.{"less_than_8_elems"});
        as.printInstrs(&.{
            "mov rbx, qword ptr [{[module]f} + {[module_tables_off]d}]" ++
                " # ptr to table inst ptrs, clobbers STP",
            "mov rbx, qword ptr [rbx + r11*8]" ++
                " # ptr to table, clobbers ptr to table insts ptrs",

            "mov ecx, dword ptr [{[vsp]f} - 0x10] # number of elements to copy, clobbers fuel",
            "mov rax, qword ptr [{[vsp]f} - 0x20] # elem to replicate, clobbers vip",
            "mov edi, dword ptr [{[vsp]f} - 0x30] # offset to start at, clobbers locals",
            "lea {[vsp]f}, [{[vsp]f} - 0x30] # vsp",

            "mov r13d, dword ptr [rbx + {[table_len_off]d}] # table len",
            "lea r14, [edi + ecx] # end offset, clobbers interpreter",
            "cmp r14, r13",
            "ja {[oob]f}",

            "mov rbx, qword ptr [rbx] # table elems ptr, clobbers ptr to table",
            "lea rdi, [rbx + rdi*8] # ptr to write to, clobbers start offset",
            "lea rbx, [rbx + r14*8] # table end ptr, clobbers table elems ptr",

            "movq xmm0, rax # replicate element",
            "pshufd xmm0, xmm0, 0x44 # move low qword to high qword",

            "cmp ecx, 8",
            "jb {[less_than_8_elems]f}",
            "# Fill first 64-bytes, and align",
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + 0x10], xmm0",
            "movups xmmword ptr [rdi + 0x20], xmm0",
            "movups xmmword ptr [rdi + 0x30], xmm0",

            "mov r13, rdi # unrounded ptr to write to, clobbers table len",
            "lea rdi, [rdi + 64] # clobbers ptr to write to",
            "shr rdi, 6",
            "shl rdi, 6 # clears low 6 bits, contains rounded/aligned ptr to write to",
            "mov r14, rdi # clobbers end offset",
            "sub r14, r13 # how many elems were written to become aligned",
            "sub ecx, r14d # update count",
            "cmp ecx, 8",
            "jb {[less_than_8_elems]f}",
        }, .{
            .module = Gpr.module,
            .module_tables_off = 40,
            .table_len_off = 12,
            .vsp = Gpr.vsp,
            .oob = oob,
            .less_than_8_elems = less_than_8_elems,
        });
        var hot_loop = as.label(&.{"write_8_elems_aligned"});
        hot_loop.place(as);
        as.printInstrs(&.{
            "movaps xmmword ptr [rdi], xmm0",
            "movaps xmmword ptr [rdi + 0x10], xmm0",
            "movaps xmmword ptr [rdi + 0x20], xmm0",
            "movaps xmmword ptr [rdi + 0x30], xmm0",
            "lea rdi, [rdi + 64] # advance ptr",
            "sub ecx, 8",
            "cmp ecx, 8",
            "jae {[hot_loop]f}",
        }, .{ .hot_loop = hot_loop });

        less_than_8_elems.place(as);
        var done = as.label(&.{"done"});
        as.printInstrs(&.{
            "test ecx, ecx",
            "jz {[done]f}",
            "mov qword ptr [rdi], rax # write at least one element",
            "cmp ecx, 1",
            "je {[done]f} # if only one element was remaining, no need to update count & ptr",
            "# if more elements remaining, above write is duplicated",
        }, .{ .done = done });

        var write_2_elems = as.label(&.{"write_2_elems_unaligned"});
        write_2_elems.place(as);
        as.printInstrs(&.{
            "movups xmmword ptr [rdi], xmm0 # possibly unaligned if total # to copy is < 8",
            "lea rdi, [rdi + 16] # advance ptr",
            "dec ecx",
            "cmp ecx, 2",
            "ja {[loop]f}",
            "movups xmmword ptr [rbx - 0x10], xmm0 # write last 0-2 elements",
        }, .{ .loop = write_2_elems });

        done.place(as);
        clobbers.restore(as);
        table_fill.jmpToNextHandler(as);
        table_idx.writeSlowPath(as);

        oob.place(as);
        clobbers.restore(as);
        for (
            Gpr.system_v_parameters,
            &[6]Gpr{ .r15, .vsp, .eip, .stp, .r11, .interp },
            &[6][]const u8{ "VIP", "VSP", "EIP", "STP", "table index", "interpreter" },
        ) |dst, src, comment| {
            if (dst != src)
                as.printInstrs(
                    &.{"mov {[dst]f}, {[src]f} # {[comment]s}"},
                    .{ .dst = dst, .src = src, .comment = comment },
                )
            else
                as.printInstrs(&.{"# {[comment]s} stays in {[dst]f}"}, .{
                    .comment = comment,
                    .dst = dst,
                });
        }
        as.popSystemVSavedRegisters();
        as.printInstrs(&.{
            "# rsp already refers to saved rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            "jmp {[prefix]s}trapTableFillOutOfBounds",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });

        table_fill.end(as);
    }
}

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const AsmWriter = @import("AsmWriter.zig");
const SystemVParam = AsmWriter.SystemVParam;
const Gpr = AsmWriter.Gpr;
const ZigWriter = @import("ZigWriter");
