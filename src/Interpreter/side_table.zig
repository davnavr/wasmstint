/// `packed struct` to allow use in functions using the C calling convention.
pub const SideTable = packed struct(usize) {
    pub const Ptr = [*]const Module.Code.SideTableEntry;

    next: Ptr,

    pub fn init(stp: Ptr, stack: *const Stack) SideTable {
        const table = SideTable{ .next = stp };
        table.checkBounds(stack);
        return table;
    }

    pub fn checkBounds(self: SideTable, stack: *const Stack) void {
        const current_frame: *const Stack.Frame = stack.currentFrame().?;
        const code: *Module.Code.Inner = &current_frame.function.expanded().wasm.code().inner;
        const stp = @intFromPtr(self.next);
        std.debug.assert(@intFromPtr(code.side_table_ptr) <= stp);
        std.debug.assert(stp <= @intFromPtr(code.side_table_ptr + code.side_table_len));
    }

    pub fn increment(table: *SideTable, stack: *const Stack) void {
        table.next += 1;
        table.checkBounds(stack);
    }

    fn addPtrWithOffset(ptr: anytype, offset: isize) @TypeOf(ptr) {
        std.debug.assert(@typeInfo(@TypeOf(ptr)) == .pointer);
        const sum = if (offset < 0) ptr - @abs(offset) else ptr + @as(usize, @intCast(offset));
        // std.debug.print(" > {*} + {} = {*}\n", .{ ptr, offset, sum });
        return sum;
    }

    pub fn takeBranch(
        table: *SideTable,
        stack: *const Stack,
        stack_top: Stack.Top,
        base_ip: Instr.Ptr,
        instr: *Instr,
        branch: u32,
    ) Stack.Top {
        const current_frame: *const Stack.Frame = stack.currentFrame().?;
        const code = current_frame.function.expanded().wasm.code();
        const wasm_base_ptr = @intFromPtr(current_frame.function.expanded().wasm
            .module.header().module.inner.wasm.ptr);

        // std.debug.print("SIDE TABLE PTR = {*} + {}\n", .{ table.next, branch });
        const target: *const Module.Code.SideTableEntry = &table.next[branch];
        const target_idx: u32 = @intCast(target - code.inner.side_table_ptr);
        std.debug.assert(@intFromPtr(code.inner.side_table_ptr) <= @intFromPtr(target));

        if (builtin.mode == .Debug) {
            const side_table_end: [*]const Module.Code.SideTableEntry =
                code.inner.side_table_ptr + code.inner.side_table_len;

            if (@intFromPtr(target) > @intFromPtr(side_table_end)) {
                std.debug.panic( // oob past side table
                    "side table entry {X} (index {d}) is OOB past side table end at {X}..{X} " ++
                        "({} entries)",
                    .{
                        @intFromPtr(target),
                        target_idx,
                        @intFromPtr(code.inner.side_table_ptr),
                        @intFromPtr(side_table_end),
                        code.inner.side_table_len,
                    },
                );
            }

            const origin_ip = code.inner.instructions_start + target.origin;
            if (@intFromPtr(base_ip) != @intFromPtr(origin_ip)) {
                std.debug.panic(
                    "expected branch #{d} to originate from {X:0>6}, but got {X:0>6}",
                    .{
                        target_idx,
                        @intFromPtr(origin_ip) - wasm_base_ptr,
                        @intFromPtr(base_ip) - wasm_base_ptr,
                    },
                );
            }
        }

        // std.debug.print(
        //     " ? TGT BRANCH #{} (current is #{}): \u{394}ip={}, \u{394}stp={}, copy={}, pop={}\n",
        //     .{
        //         target_idx,
        //         (table.next - code.inner.side_table_ptr),
        //         target.delta_ip.done,
        //         target.delta_stp,
        //         target.copy_count,
        //         target.pop_count,
        //     },
        // );

        instr.next = addPtrWithOffset(base_ip, target.delta_ip.done);
        std.debug.assert(@intFromPtr(code.inner.instructions_end) == @intFromPtr(instr.end));
        std.debug.assert(@intFromPtr(code.inner.instructions_start) <= @intFromPtr(instr.next));

        // std.debug.print(
        //     " ? NEXT[{X:0>6}]: 0x{X} ({s})\n",
        //     .{
        //         @intFromPtr(instr.next) - wasm_base_ptr,
        //         instr.next[0],
        //         @tagName(@as(@import("../opcodes.zig").ByteOpcode, @enumFromInt(instr.next[0]))),
        //     },
        // );

        table.next = addPtrWithOffset(table.next + branch, target.delta_stp);
        table.checkBounds(stack);

        // std.debug.print(" ? STP=#{}\n", .{table.next - code.inner.side_table_ptr});

        // std.debug.print(" ? value stack height was {}\n", .{vals.items.len});

        const src = Stack.Values.init(stack_top, stack, target.copy_count, target.copy_count)
            .topSlice(target.copy_count);
        const dst = (stack_top.ptr - target.pop_count)[0..target.copy_count];
        @memmove(dst, src);

        const new_top = addPtrWithOffset(stack_top.ptr, @as(i16, target.copy_count) - target.pop_count);

        // std.debug.print(" ? value stack height is {}\n", .{});

        std.debug.assert(
            @intFromPtr(current_frame.valueStackBase()) <= @intFromPtr(new_top),
        );

        return Stack.Top{ .ptr = new_top };
    }
};

const std = @import("std");
const builtin = @import("builtin");
const Module = @import("../Module.zig");
const Stack = @import("Stack.zig");
const Instr = @import("Instr.zig");
