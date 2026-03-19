pub fn expectNonNull(value: anytype) !std.meta.Child(@TypeOf(value)) {
    if (value) |non_null| {
        return non_null;
    } else {
        std.log.err("got null value of {s}", .{@typeName(std.meta.Child(@TypeOf(value)))});
        return error.NullValue;
    }
}

pub fn expectInterpreterState(
    state: Interpreter.State,
    comptime tag: @typeInfo(Interpreter.State).@"union".tag_type.?,
) !@FieldType(Interpreter.State, @tagName(tag)) {
    try testing.expectEqual(tag, @as(@typeInfo(Interpreter.State).@"union".tag_type.?, state));
    return @field(state, @tagName(tag));
}

const std = @import("std");
const testing = std.testing;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
