//! Functions for calculating the sizes, in bytes, of things.

const std = @import("std");

pub fn averageOfFields(comptime T: type) usize {
    var sum: usize = 0;
    const fields = std.meta.fields(T);
    inline for (fields) |f| {
        sum += @sizeOf(f.type);
    }

    return sum / fields.len;
}
