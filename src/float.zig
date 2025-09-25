//! Special [floating-point values](https://webassembly.github.io/spec/core/syntax/values.html#floating-point).

const std = @import("std");

fn bitsWidth(comptime T: type) comptime_int {
    return switch (@typeInfo(T)) {
        .int => |int| int.bits,
        .float => |float| float.bits,
        else => unreachable,
    };
}

fn exponentWidth(comptime T: type) comptime_int {
    return switch (bitsWidth(T)) {
        32 => 8,
        64 => 11,
        else => unreachable,
    };
}

fn mantissaWidth(comptime T: type) comptime_int {
    return bitsWidth(T) - exponentWidth(T) - 1;
}

pub fn Bits(comptime T: type) type {
    return std.meta.Int(.unsigned, bitsWidth(T));
}

pub fn Exponent(comptime T: type) type {
    return std.meta.Int(.unsigned, exponentWidth(T));
}

pub fn Mantissa(comptime T: type) type {
    return std.meta.Int(.unsigned, mantissaWidth(T));
}

pub fn asBits(value: anytype) Bits(@TypeOf(value)) {
    return switch (@TypeOf(value)) {
        .int => value,
        .float => @bitCast(value),
        else => unreachable,
    };
}

fn construct(comptime T: type, sign: u1, exponent: Exponent(T), mantissa: Mantissa(T)) Bits(T) {
    return (@as(Bits(T), sign) << (bitsWidth(T) - 1)) |
        (@as(Bits(T), exponent) << mantissaWidth(T)) |
        @as(Bits(T), mantissa);
}

pub fn infOrNan(comptime T: type, sign: u1, mantissa: Mantissa(T)) Bits(T) {
    return construct(T, sign, std.math.maxInt(Exponent(T)), mantissa);
}

pub fn inf(comptime T: type, sign: u1) Bits(T) {
    return infOrNan(T, sign, 0);
}

pub fn canonicalNan(comptime T: type, sign: u1) Bits(T) {
    return infOrNan(T, sign, @as(Mantissa(T), 1) << (mantissaWidth(T) - 1));
}
