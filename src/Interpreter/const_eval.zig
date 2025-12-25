const ValStack = std.array_list.Aligned(Value, .fromByteUnits(@sizeOf(Value)));

fn binOp(
    val_stack: *ValStack,
    comptime ty: Value.Tag,
    comptime op: fn (ty.Type(), ty.Type()) (ty.Type()),
) void {
    const c_2 = @field(val_stack.pop().?, @tagName(ty));
    const c_1 = @field(val_stack.pop().?, @tagName(ty));
    val_stack.appendAssumeCapacity(@unionInit(Value, @tagName(ty), op(c_1, c_2)));
}

fn operations(comptime ty: Value.Tag) type {
    return struct {
        const T = ty.Type();

        fn add(i_1: T, i_2: T) T {
            return i_1 +% i_2;
        }

        fn sub(i_1: T, i_2: T) T {
            return i_1 -% i_2;
        }

        fn mul(i_1: T, i_2: T) T {
            return i_1 *% i_2;
        }
    };
}

/// Evaluates a constant expression.
///
/// Does not perform any fuel checking, callers must check the number of instructions/size of
/// the initializer expression.
///
/// Asserts that `val_stack_buf` is large enough to evaluate the expression.
pub fn calculate(
    expr: [:@intFromEnum(opcodes.ByteOpcode.end)]const u8,
    module: ModuleInst,
    comptime final_type: Value.Tag,
    val_stack_buf: []align(@sizeOf(Value)) Value,
) (final_type.Type()) {
    std.debug.assert(expr.len >= 1);
    std.debug.assert(expr.len <= std.math.maxInt(u32));

    @memset(val_stack_buf, undefined);
    var val_stack = ValStack.initBuffer(val_stack_buf);
    var instr = Instr.init(expr.ptr, @ptrCast(&expr[expr.len]));

    while (true) {
        const opcode = @as(opcodes.ByteOpcode, @enumFromInt(instr.readByte()));
        switch (opcode) {
            .@"i32.const" => val_stack.appendAssumeCapacity(.{ .i32 = instr.readIleb128(i32) }),
            .@"i64.const" => val_stack.appendAssumeCapacity(.{ .i64 = instr.readIleb128(i64) }),
            .@"f32.const" => val_stack.appendAssumeCapacity(.{
                .f32 = @bitCast(std.mem.readInt(u32, instr.readByteArray(4), .little)),
            }),
            .@"f64.const" => val_stack.appendAssumeCapacity(.{
                .f64 = @bitCast(std.mem.readInt(u64, instr.readByteArray(8), .little)),
            }),
            .@"global.get" => {
                const global_idx = instr.readIdx(Module.GlobalIdx);
                const global_addr = module.header().globalAddr(global_idx);
                std.debug.assert(
                    global_addr.global_type.val_type == @field(Module.ValType, @tagName(final_type)),
                );
                val_stack.appendAssumeCapacity(
                    @unionInit(
                        Value,
                        @tagName(final_type),
                        @as(*const (final_type.Type()), @ptrCast(@alignCast(global_addr.value))).*,
                    ),
                );
            },
            .@"ref.null" => {
                instr.skipValType();
                val_stack.appendAssumeCapacity(.{ .ptr = null });
            },
            .@"ref.func" => {
                const func_idx = instr.readIdx(Module.FuncIdx);
                val_stack.appendAssumeCapacity(
                    .{ .funcref = @bitCast(module.header().funcRef(func_idx)) },
                );
            },
            .end => {
                std.debug.assert(@intFromPtr(instr.next - 1) == @intFromPtr(instr.end));
                std.debug.assert(val_stack.items.len == 1);
                break;
            },
            // Extended constant proposal (https://github.com/WebAssembly/extended-const) support:
            .@"i32.add" => binOp(&val_stack, .i32, operations(.i32).add),
            .@"i32.sub" => binOp(&val_stack, .i32, operations(.i32).sub),
            .@"i32.mul" => binOp(&val_stack, .i32, operations(.i32).mul),
            .@"i64.add" => binOp(&val_stack, .i64, operations(.i64).add),
            .@"i64.sub" => binOp(&val_stack, .i64, operations(.i64).sub),
            .@"i64.mul" => binOp(&val_stack, .i64, operations(.i64).mul),
            .@"0xFD" => switch (@as(opcodes.FDPrefixOpcode, @enumFromInt(instr.readIdxRaw()))) {
                .@"v128.const" => {
                    const immediate = instr.readByteArray(16);
                    val_stack.appendAssumeCapacity(.{ .v128 = .{ .u8x16 = immediate.* } });
                },
                else => |bad| switch (builtin.mode) {
                    .Debug, .ReleaseSafe => std.debug.panic("non-constant SIMD opcode {t}", .{bad}),
                    .ReleaseFast, .ReleaseSmall => unreachable,
                },
            },
            else => switch (builtin.mode) {
                .Debug, .ReleaseSafe => std.debug.panic("non-constant opcode {t}", .{opcode}),
                .ReleaseFast, .ReleaseSmall => unreachable,
            },
        }
    }

    return @field(val_stack.items[0], @tagName(final_type));
}

const std = @import("std");
const builtin = @import("builtin");
const Module = @import("../Module.zig");
const Value = @import("value.zig").Value;
const Instr = @import("Instr.zig");
const ModuleInst = @import("../runtime/module_inst.zig").ModuleInst;
const opcodes = @import("../opcodes.zig");
