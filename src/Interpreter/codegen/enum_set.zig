/// Bug in `std.EnumSet` causes "error: evaluation exceeded 4967 backwards branches"
pub fn EnumSet(comptime E: type) type {
    return struct {
        const max_value: comptime_int = max: {
            var maximum: comptime_int = 0;
            for (@typeInfo(E).@"enum".fields) |field| {
                maximum = @max(maximum, field.value);
            }
            break :max maximum;
        };

        bits: std.StaticBitSet(max_value + 1),

        const Self = @This();

        pub fn count(set: Self) std.math.IntFittingRange(0, @typeInfo(E).@"enum".fields.len) {
            return @intCast(set.bits.count());
        }

        pub fn initEmpty() Self {
            return .{ .bits = .initEmpty() };
        }

        pub fn contains(set: Self, key: E) bool {
            return set.bits.isSet(@intFromEnum(key));
        }

        pub fn insert(set: *Self, key: E) void {
            set.bits.set(@intFromEnum(key));
        }
    };
}

const std = @import("std");
