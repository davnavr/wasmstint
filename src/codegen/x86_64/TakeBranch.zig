copy_results: AsmWriter.Label,
finish: AsmWriter.Label,

const TakeBranch = @This();

pub fn fastPath(as: *AsmWriter) TakeBranch {
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

pub fn writeSlowPath(take: *TakeBranch, as: *AsmWriter) void {
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

const AsmWriter = @import("AsmWriter.zig");
const Gpr = AsmWriter.Gpr;
