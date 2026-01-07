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
    defineControlOpcodeHandlers(&asm_writer, &zig_writer, optimize);
    defineCallOpcodeHandlers(&asm_writer, &zig_writer);
    defineParametericOpcodeHandlers(&asm_writer, &zig_writer);
    defineLocalOpcodeHandlers(&asm_writer, &zig_writer);
    defineGlobalOpcodeHandlers(&asm_writer, &zig_writer);
    defineMemoryLoadOpcodeHandlers(&asm_writer, &zig_writer);
    defineMemoryStoreOpcodeHandlers(&asm_writer, &zig_writer);
    defineMemoryManagementOpcodeHandlers(&asm_writer, &zig_writer);
    defineConstOpcodeHandlers(&asm_writer, &zig_writer);
    defineIntegerOpcodeHandlers(&asm_writer, &zig_writer, .i32);
    defineIntegerOpcodeHandlers(&asm_writer, &zig_writer, .i64);
    defineFloatOpcodeHandlers(&asm_writer, &zig_writer, .f32);
    defineFloatOpcodeHandlers(&asm_writer, &zig_writer, .f64);
    definePrefixOpcodeHandlers(&asm_writer, &zig_writer, optimize);

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
            "mov rbp, rsp",
            "# Move callee-saved registers into parameter stack area",
        });
        as.printInstrs(&.{
            "mov {[vip]f}, {[stack_0]f} # IP",
            "mov {[stack_0]f}, r15 # callee-saved",

            "mov r11, rbx # prevent clobbering RBX below",
            "mov {[stp]f}, {[stack_1]f} # STP, clobbers RBX",
            "mov {[stack_1]f}, r14 # callee-saved",

            "mov {[eip]f}, {[stack_2]f} # EIP",
            "mov {[stack_2]f}, r13 # callee-saved",

            "mov r15, {[stack_3]f} # opcode handler, clobbers r15 which was just saved",
            "mov {[stack_3]f}, r12 # callee-saved",

            "mov {[stack_4]f}, r11 # rbx is callee-saved",

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
            .stack_4 = SystemVParam{ .index = 10 },
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
        switch (optimize) {
            .Debug, .ReleaseSafe => as.printInstrs(&.{
                "mov {[param_0]f}, {[vip]f} # 1",
                "mov {[param_1]f}, {[eip]f} # 2",
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
        for (
            &[_]Gpr{ .vip, .vsp, .eip, .stp, .interp },
            &[_]u8{ 0, 2, 1, 3, 4 },
        ) |arg, idx| {
            as.printInstrs(&.{"mov {[param]f}, {[src]f} # argument #{[n]d}"}, .{
                .param = SystemVParam{ .index = idx },
                .src = arg,
                .n = idx + 1,
            });
        }
        as.writeInstrs(&.{"# perform a tail call"});
        // This will make the called function restore the registers
        // Seems to be no way to avoid doing this, even if a normal `call` is used here
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov rsp, rbp # TODO: is this mov unnecessary?",
            "pop rbp",
            "jmp {[symbol_prefix]s}interruptOutOfFuel",
            "ud2",
        }, .{ .symbol_prefix = as.symbol_prefix });
        oof.end(as);
    }
    switch (optimize) {
        .Debug, .ReleaseSafe => {
            var invalid = as.startFunction("invalidPrefixedOpcode", .@"16");
            for (0.., &[3]Gpr{ .vip, .eip, .prefix_opcode_base_ip }) |idx, param| {
                as.printInstrs(&.{"mov {[param]f}, {[src]f} #{[n]d}"}, .{
                    .param = SystemVParam{ .index = @intCast(idx) },
                    .src = param,
                    .n = idx + 1,
                });
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

    fn writeSlowPath(take: *TakeBranch, as: *AsmWriter, optimize: std.builtin.OptimizeMode) void {
        // TODO: See if AVX is enabled to use ymm registers
        as.write(".p2align 4\n");
        take.copy_results.place(as);
        as.printInstrs(&.{
            "add {[vsp]f}, 0x10 # one result was already copied",
            "lea r13, [r14 + 0x10] # pointer to results destination",
        }, .{ .vsp = Gpr.vsp });

        var loop_start = as.label(&.{"copy_results_loop"});
        loop_start.place(as);

        const unroll_count: usize = switch (optimize) {
            .Debug, .ReleaseSmall => 1,
            .ReleaseSafe, .ReleaseFast => 4,
        };
        for (0..unroll_count) |_| {
            as.printInstrs(&.{
                "movaps xmm0, xmmword ptr [{[vsp]f}]",
                "movaps xmmword ptr [r13], xmm0",
                "add {[vsp]f}, 0x10",
                "add r13, 0x10",
                "cmp r13, r15 # check if done",
                "je {[finish]f}",
            }, .{ .vsp = Gpr.vsp, .finish = take.finish });
        }

        as.printInstrs(&.{
            "jmp {[loop_start]f}",
            "ud2",
        }, .{ .loop_start = loop_start });
        take.* = undefined;
    }
};

fn defineControlOpcodeHandlers(
    as: *AsmWriter,
    zig: *ZigWriter,
    optimize: std.builtin.OptimizeMode,
) void {
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
            "sub {[vsp]f}, 0x10 # condition was popped",
            "test r13d, r13d",
            "jz {[false_branch]f}",
        }, .{
            .vsp = Gpr.vsp,
            .false_branch = false_branch,
        });
        var block_type = SkipUlebIdx.fastPath(as, .r11, "type");
        as.printInstrs(&.{"add {[stp]f}, 8 # increment STP"}, .{ .stp = Gpr.stp });
        @"if".jmpToNextHandler(as);

        false_branch.place(as);
        as.printInstrs(&.{
            "# no need to read the block type",
            "lea r15, [{[vip]f} - 1] # save ip to if byte",
        }, .{ .vip = Gpr.vip });
        var branch = TakeBranch.fastPath(as);
        @"if".jmpToNextHandler(as);
        branch.writeSlowPath(as, optimize);
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
        branch.writeSlowPath(as, optimize);
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
        branch.writeSlowPath(as, optimize);
        br.end(as);
    }
    {
        var br_if = as.defineOpcodeHandler(zig, "br_if", .@"32");
        var false_branch = as.label(&.{"false"});
        as.printInstrs(&.{
            "mov r13d, dword ptr [{[vsp]f} - 0x10] # load condition",
            "sub {[vsp]f}, 0x10 # pop condition",
            "test r13d, r13d",
            "jz {[false]f}",
            "lea r15, [{[vip]f} - 1] # save ip to br_if byte",
        }, .{ .vsp = Gpr.vsp, .vip = Gpr.vip, .false = false_branch });
        var branch = TakeBranch.fastPath(as);
        br_if.jmpToNextHandler(as);
        branch.writeSlowPath(as, optimize);

        as.write(".p2align 4\n");
        false_branch.place(as);
        var skip_label_idx = SkipUlebIdx.fastPath(as, .r11, "label");
        as.printInstrs(&.{"add {[stp]f}, 8 # increment stp"}, .{ .stp = Gpr.stp });
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
            "sub {[vsp]f}, 0x10 # VSP",
            "cmp r11d, r13d",
            "cmovb r13d, r11d # prevent exceeding label count",
            "shl r13d, 3 # side table entries are 8 bytes in size",
            "add {[stp]f}, r13",
        }, .{ .vsp = Gpr.vsp, .stp = Gpr.stp });
        var branch = TakeBranch.fastPath(as);
        br_table.jmpToNextHandler(as);
        branch.writeSlowPath(as, optimize);
        label_count.writeSlowPath(as);
        br_table.end(as);
    }
    {
        var @"return" = as.defineOpcodeHandler(zig, "return", .@"32");
        as.printInstrs(&.{
            "# no need to save every register, since this is returning",
            "mov {[param_0]f}, {[eip]f} # most parameters are already in the correct place",
        }, .{ .eip = Gpr.eip, .param_0 = SystemVParam{ .index = 0 } });
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov rsp, rbp # TODO: is this unnecessary",
            "pop rbp",
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
            "lea r15, [{[vip]f} - 1] # save ip to call byte",
        }, .{ .vip = Gpr.vip });
        var idx_decode = DecodeUlebIdx.fastPath(as, .r11, .{ .r13, .r14 }, "func");
        for (
            Gpr.system_v_parameters.len..,
            &[5]Gpr{ .vip, .stp, .eip, .r11, .r15 },
            &[5][]const u8{ "vip", "stp", "eip", "func_idx", "call_ip" },
        ) |i, src, comment| {
            as.printInstrs(
                &.{"mov {[dst]f}, {[src]f} # {[comment]s}"},
                .{ .dst = SystemVParam{ .index = @intCast(i) }, .src = src, .comment = comment },
            );
        }
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov rsp, rbp # TODO: is this unnecessary?",
            "pop rbp",
            "jmp {[prefix]s}invokeWithinWasm # call into Zig",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        idx_decode.writeSlowPath(as);
        call.end(as);
    }
    {
        var call_indirect = as.defineOpcodeHandler(zig, "call_indirect", .@"32");
        as.printInstrs(&.{
            "lea rdi, [{[vip]f} - 1] # save ip to call_indirect byte, clobbers locals",
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
            "ja {[oob]f}",
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
            &[3][]const u8{ "vip", "stp", "eip" },
        ) |i, src, comment| {
            as.printInstrs(&.{"mov {[dst]f}, {[src]f} # {[comment]s}"}, .{
                .dst = SystemVParam{ .index = @intCast(i) },
                .src = src,
                .comment = comment,
            });
        }
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov rsp, rbp # TODO: is this unnecessary?",
            "pop rbp",
            "jmp {[prefix]s}invokeWithinWasmIndirect",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        type_idx_decode.writeSlowPath(as);
        table_idx_decode.writeSlowPath(as);

        as.write(".p2align 4\n");
        oob.place(as);
        as.printInstrs(&.{
            "# rdi has trap_ip",
            "mov rdx, {[eip]f} # eip",
            "mov rcx, {[stp]f} # stp",
            "mov r8, r13 # table index",
        }, .{ .eip = Gpr.eip, .stp = Gpr.stp });
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov rsp, rbp # TODO: is this unnecessary?",
            "pop rbp",
            "jmp {[prefix]s}trapTableAccessOob",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });

        as.write(".p2align 4\n");
        null_elem.place(as);
        as.printInstrs(&.{
            "# rdi has trap_ip",
            "mov rdx, {[eip]f}",
            "mov rcx, {[stp]f}",
            "mov r8, r14 # elem index",
        }, .{ .eip = Gpr.eip, .stp = Gpr.stp });
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov rsp, rbp # TODO: is this unnecessary?",
            "pop rbp",
            "jmp {[prefix]s}trapIndirectCallToNull",
            "ud2",
        }, .{ .prefix = as.symbol_prefix });
        call_indirect.end(as);
    }
}

fn defineParametericOpcodeHandlers(as: *AsmWriter, zig: *ZigWriter) void {
    {
        var drop = as.defineOpcodeHandler(zig, "drop", .@"16");
        as.printInstrs(&.{"sub {[vsp]f}, 0x10 # vsp"}, .{ .vsp = Gpr.vsp });
        drop.jmpToNextHandler(as);
        drop.end(as);
    }
    // TODO: "select t" handler to fallthrough to "select" handler
    {
        var select = as.defineOpcodeHandler(zig, "select", .@"16");
        var true_label = as.label(&.{"true"});
        // select without type requires numeric or vector type, so this must
        // assume xmmword-sized values to be safe
        as.printInstrs(&.{
            "xor r14, r14",
            "mov r13d, dword ptr [{[vsp]f} - 0x10] # load condition",
            "test r13d, r13d",
            "jnz {[true]f}",
            "movaps xmm0, xmmword ptr [{[vsp]f} - 0x20] # move selected value to correct place",
            "movaps xmmword ptr [{[vsp]f} - 0x30], xmm0",
        }, .{ .vsp = Gpr.vsp, .true = true_label });
        true_label.place(as);
        as.printInstrs(&.{"sub {[vsp]f}, 0x20 # vsp"}, .{ .vsp = Gpr.vsp });
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
                "add {[vsp]f}, 0x10 # pop value that was stored",
            }, .{ .locals = Gpr.locals, .vsp = Gpr.vsp }),
            .@"local.set", .@"local.tee" => {
                as.printInstrs(&.{
                    "movaps xmm0, xmmword ptr [{[vsp]f} - 0x10] # load from value stack",
                }, .{ .vsp = Gpr.vsp });
                if (opcode_name == .@"local.set") {
                    as.printInstrs(&.{"sub {[vsp]f}, 0x10 # vsp"}, .{ .vsp = Gpr.vsp });
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
            "xor r14, r14",
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
            "add {[vsp]f}, 0x10 # vsp",
        }, .{ .vsp = Gpr.vsp });
        get.jmpToNextHandler(as);

        as.write(".p2align 4\n");
        load_8.place(as);
        as.printInstrs(&.{
            "mov r11, qword ptr [r15] # get value to load",
            "mov qword ptr [{[vsp]f}], r11",
            "add {[vsp]f}, 0x10 # vsp",
        }, .{ .vsp = Gpr.vsp });
        get.jmpToNextHandler(as);

        as.write(".p2align 5\n");
        load_16.place(as);
        as.printInstrs(&.{
            "movaps xmm0, xmmword ptr [r15] # get value to load",
            "movaps xmmword ptr [{[vsp]f}], xmm0",
            "add {[vsp]f}, 0x10 # vsp",
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
            "xor r14, r14",
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
            "sub {[vsp]f}, 0x10 # vsp",
        }, .{ .vsp = Gpr.vsp });
        set.jmpToNextHandler(as);

        as.write(".p2align 4\n");
        store_8.place(as);
        as.printInstrs(&.{
            "mov r11, qword ptr [{[vsp]f} - 0x10] # get value to store",
            "mov qword ptr [r15], r11",
            "sub {[vsp]f}, 0x10 # vsp",
        }, .{ .vsp = Gpr.vsp });
        set.jmpToNextHandler(as);

        as.write(".p2align 5\n");
        store_16.place(as);
        as.printInstrs(&.{
            "movaps xmm0, xmmword ptr [{[vsp]f} - 0x10] # get value to store",
            "movaps xmmword ptr [r15], xmm0",
            "sub {[vsp]f}, 0x10 # vsp",
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

    fn end(access: *LinearMemoryAccess, op: *AsmWriter.OpcodeHandler, as: *AsmWriter) void {
        op.jmpToNextHandler(as);
        access.align_skip.writeSlowPath(as);
        access.offset_decode.writeSlowPath(as);

        as.write(".p2align 4\n");
        access.oob.place(as);
        as.printInstrs(&.{
            "lea {[param_0]f}, [{[vip]f} - 1]",
            "# vsp in rsi",
            "mov {[param_2]f}, {[eip]f} # eip",
            "mov {[param_3]f}, {[stp]f} # stp",
            "mov {[param_4]f}, 0 # memidx",
            "# interp in r9",
            "mov r10d, r13d # address",
            "mov r11, r14 # *MemInst",
        }, .{
            .param_0 = SystemVParam{ .index = 0 },
            .vip = Gpr.vip,
            .param_2 = SystemVParam{ .index = 2 },
            .eip = Gpr.eip,
            .param_3 = SystemVParam{ .index = 3 },
            .stp = Gpr.stp,
            .param_4 = SystemVParam{ .index = 4 },
        });
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov {[param_6]f}, r10d # address",
            "mov {[param_7]f}, {[size]d} # size",
            "mov {[param_8]f}, r11 # *MemInst",
            "mov rsp, rbp # TODO: is this unnecessary?",
            "pop rbp",
            "jmp {[prefix]s}trapMemoryAccessOutOfBounds",
            "ud2",
        }, .{
            .param_6 = SystemVParam{ .index = 6, .size = .dword },
            .size = @intFromEnum(access.size),
            .param_7 = SystemVParam{ .index = 7, .size = .dword },
            .param_8 = SystemVParam{ .index = 8 },
            .prefix = as.symbol_prefix,
        });
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
            "sub {[vsp]f}, 0x20 # vsp",
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
    // memory.size
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
            "cmp r13, qword ptr [r11 + {[mem_limit_off]d}] # check against limit ",
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
            "#7 interp is already in r9",
            "mov r11, {[stp]f} # prevent clobbering STP",
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
        });
        as.restoreSystemVSavedRegisters();
        as.printInstrs(&.{
            "mov {[param_6]f}, r11 #7 stp",
            "mov rsp, rbp # TODO: is this unnecessary?",
            "pop rbp",
            "jmp {[prefix]s}memoryGrowReallocate",
            "ud2",
        }, .{
            .param_6 = SystemVParam{ .index = 6 },
            .prefix = as.symbol_prefix,
        });

        var to_next = as.label(&.{"next_opcode"});
        as.write(".p2align 4\n");
        within_capacity.place(as);
        as.printInstrs(&.{
            "# TODO: only fill with zeroes if allocator says it doesn't fill w/ zeroes",
            "# OS pages are zeroed",
            "# Assuming 65536 page size, could memset with rep stosb" ++
                " (apparently not as good on AMD)",
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
                std.fmt.bufPrint(&cont_label_name_buf, "byte_{d}", .{1 + i}) catch unreachable,
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
            "add {[vsp]f}, 0x10 # vsp",
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
            .final_shift = bit_size - (7 * continuation.len),
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
            "add {[vsp]f}, 0x10 # vsp",
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
            "add {[vsp]f}, 0x10 # vsp",
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

fn integerDivisionTrapJmp(as: *AsmWriter, handler: []const u8) void {
    as.printInstrs(&.{
        "# r12 is clobbered",
        "lea {[param_0]f}, [r14 - 1] # vip, param 1",
        "# VSP already in rsi, param 2",
        "mov {[param_2]f}, {[eip]f} # eip, param 3",
        "mov {[param_3]f}, {[stp]f} # stp, param 4",
    }, .{
        .eip = Gpr.eip,
        .stp = Gpr.stp,
        .param_0 = SystemVParam{ .index = 0 },
        .param_2 = SystemVParam{ .index = 2 },
        .param_3 = SystemVParam{ .index = 3 },
    });
    as.restoreSystemVSavedRegisters();
    as.printInstrs(&.{
        "mov rsp, rbp # TODO: is this unnecessary",
        "pop rbp",
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
            "sub {[vsp]f}, 0x10 # vsp",
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
            "sub {[vsp]f}, 0x10 # vsp",
        }, .{ .r13 = r13, .size = size, .vsp = Gpr.vsp });
        add.jmpToNextHandler(as);
        add.end(as);
    }
    {
        var sub = as.defineOpcodeHandler(zig, opcode_name.name(".sub"), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "sub {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f}",
            "sub {[vsp]f}, 0x10 # vsp",
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
            "sub {[vsp]f}, 0x10 # vsp",
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
            "sub {[vsp]f}, 0x10 # vsp",
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
                        "sub {[vsp]f}, 0x10 # vsp",
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
                .div => integerDivisionTrapJmp(as, "trapIntegerOverflow"),
            }
        }

        div_by_zero.place(as);
        integerDivisionTrapJmp(as, "trapIntegerDivisionByZero");

        op.end(as);
    }

    for (&[_][]const u8{ ".and", ".or", ".xor" }) |name| {
        var op = as.defineOpcodeHandler(zig, opcode_name.name(name), .@"64");
        as.printInstrs(&.{
            "mov {[r13]f}, {[size]t} ptr [{[vsp]f} - 0x10]",
            "{[instr]s} {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f}",
            "sub {[vsp]f}, 0x10 # VSP",
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
            "sub {[vsp]f}, 0x10 # VSP",
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
            "xor r13, r13",
            "{[instr]s}{[float_suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - 0x20] # load operand 1",
            "mov{[int_suffix]c} {[r13]f}, xmm0 # all 1's if true",
            "and {[r13]f}, 1",
            "mov {[size]t} ptr [{[vsp]f} - 0x20], {[r13]f} # write result",
            "sub {[vsp]f}, 0x10 # vsp",
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
            "xor r15, r15",
            "ucomis{[suffix]c} xmm0, {[size]t} ptr [{[vsp]f} - {[op_2]s}] # operand 1",
            "{[set_instr]s} r15b",
            "mov dword ptr [{[vsp]f} - 0x20], r15d # store result",
            "sub {[vsp]f}, 0x10 # vsp",
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
            "sub {[vsp]f}, 0x10 # vsp",
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
            "sub {[vsp]f}, 0x10 # vsp",
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
            "sub {[vsp]f}, 0x10 # vsp",
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
            "sub {[vsp]f}, 0x10 # vsp",
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

fn definePrefixOpcodeHandlers(
    as: *AsmWriter,
    zig: *ZigWriter,
    optimize: std.builtin.OptimizeMode,
) void {
    for (&[_][2][]const u8{.{ "0xFC", "fc_prefix_dispatch_table" }}) |info| {
        const opcode_name, const table_name = info;
        var op = as.startFunction(opcode_name, .@"32");
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

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const AsmWriter = @import("AsmWriter.zig");
const SystemVParam = AsmWriter.SystemVParam;
const Gpr = AsmWriter.Gpr;
const ZigWriter = @import("ZigWriter");
