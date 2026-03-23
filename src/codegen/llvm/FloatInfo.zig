float_ty: Type,
int_ty: Type,
prefix: []const u8,
canonical_nan: Value,
/// Of type `int_ty`.
sign_bit: Value,
/// Of type `int_ty`.
magnitude_mask: Value,

const FloatInfo = @This();

pub fn init(b: *llvm.Builder) Oom![2]FloatInfo {
    return [2]FloatInfo{
        .{
            .float_ty = .float,
            .int_ty = .i32,
            .prefix = "f32",
            .canonical_nan = try b.floatValue(@bitCast(@as(u32, 0x7FC0_0000))),
            .sign_bit = try b.intValue(.i32, 0x8000_0000),
            .magnitude_mask = try b.intValue(.i32, 0x7FFF_FFFF),
        },
        .{
            .float_ty = .double,
            .int_ty = .i64,
            .prefix = "f64",
            .canonical_nan = try b.doubleValue(@bitCast(@as(u64, 0x7FF8_0000_0000_0000))),
            .sign_bit = try b.intValue(.i64, 0x8000_0000_0000_0000),
            .magnitude_mask = try b.intValue(.i64, 0x7FFF_FFFF_FFFF_FFFF),
        },
    };
}

pub fn floatBounds(b: *llvm.Builder, min: u32, max: u32) Oom!struct { Value, Value } {
    return .{ try b.floatValue(@bitCast(min)), try b.floatValue(@bitCast(max)) };
}

pub fn doubleBounds(b: *llvm.Builder, min: u64, max: u64) Oom!struct { Value, Value } {
    return .{ try b.doubleValue(@bitCast(min)), try b.doubleValue(@bitCast(max)) };
}

const std = @import("std");
const Oom = std.mem.Allocator.Error;
const llvm = std.zig.llvm;

const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
