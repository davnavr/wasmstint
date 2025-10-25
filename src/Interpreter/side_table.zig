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

        // std.debug.print("SIDE TABLE PTR = {*} + {}\n", .{ table.next.ptr, branch });
        const target: *const Module.Code.SideTableEntry = &table.next[branch];
        std.debug.assert(@intFromPtr(code.inner.side_table_ptr) <= @intFromPtr(target));

        if (builtin.mode == .Debug) {
            const side_table_end: [*]const Module.Code.SideTableEntry =
                code.inner.side_table_ptr + code.inner.side_table_len;

            if (@intFromPtr(target) > @intFromPtr(side_table_end)) {
                std.debug.panic( // oob past side table
                    "side table entry {X} (index {}) is OOB past side table end at {X}..{X} " ++
                        "({} entries)",
                    .{
                        @intFromPtr(target),
                        target - code.inner.side_table_ptr,
                        @intFromPtr(code.inner.side_table_ptr),
                        @intFromPtr(side_table_end),
                        code.inner.side_table_len,
                    },
                );
            }

            const origin_ip = code.inner.instructions_start + target.origin;
            if (@intFromPtr(base_ip) != @intFromPtr(origin_ip)) {
                std.debug.panic(
                    "expected this branch to originate from {X:0>6}, but got {X:0>6}",
                    .{ @intFromPtr(origin_ip) - wasm_base_ptr, @intFromPtr(base_ip) - wasm_base_ptr },
                );
            }
        }

        // std.debug.print(
        //     " ? TGT BRANCH #{} (current is #{}): delta_ip={}, delta_stp={}, copy={}, pop={}\n",
        //     .{
        //         (@intFromPtr(target) - @intFromPtr(code.inner.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry),
        //         (@intFromPtr(s.*) - @intFromPtr(code.inner.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry),
        //         target.delta_ip.done,
        //         target.delta_stp,
        //         target.copy_count,
        //         target.pop_count,
        //     },
        // );

        instr.next = addPtrWithOffset(base_ip, target.delta_ip.done);
        std.debug.assert(@intFromPtr(code.inner.instructions_end) == @intFromPtr(instr.end));
        _ = instr.bytes();
        std.debug.assert(@intFromPtr(code.inner.instructions_start) <= @intFromPtr(instr.next));

        // std.debug.print(
        //     " ? NEXT[{X:0>6}]: 0x{X} ({s})\n",
        //     .{
        //         @intFromPtr(i.p) - wasm_base_ptr,
        //         i.p[0],
        //         @tagName(@as(opcodes.ByteOpcode, @enumFromInt(i.p[0]))),
        //     },
        // );

        table.next = addPtrWithOffset(table.next + branch, target.delta_stp);
        table.checkBounds(stack);

        // std.debug.print(
        //     " ? STP=#{}\n",
        //     .{(@intFromPtr(s.*) - @intFromPtr(code.inner.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry)},
        // );

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
