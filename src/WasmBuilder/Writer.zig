gpa: std.mem.Allocator,
buf: std.ArrayList(u8),

const Writer = @This();

pub fn init(allocator: std.mem.Allocator, capacity: usize) Oom!Writer {
    return .{ .gpa = allocator, .buf = try .initCapacity(allocator, capacity) };
}

pub fn initWithinScratch(scratch: *std.heap.ArenaAllocator, capacity: usize) Oom!Writer {
    _ = scratch.reset(.retain_capacity);
    return Writer.init(scratch.allocator(), capacity);
}

pub fn deinit(w: *Writer) void {
    w.buf.deinit(w.gpa);
    w.* = undefined;
}

pub const LebLen = enum(u4) {
    smallest,
    @"2",
    @"3",
    @"4",
    @"5",
    @"6",
    @"7",
    @"8",
    @"9",
    @"10",

    pub fn toByteUnits(len: LebLen) u4 {
        return @as(u4, @intFromEnum(len)) + 1;
    }

    pub fn forUnsigned(value: u32) LebLen {
        return if (value <= 0x7F)
            .smallest
        else if (value <= 0x3FFF)
            .@"2"
        else if (value <= 0x001F_FFFF)
            .@"3"
        else if (value <= 0x0FFF_FFFF)
            .@"4"
        else
            .@"5";
    }

    fn signedBound(comptime T: type, bound: @Int(.unsigned, @typeInfo(T).int.bits)) T {
        return @bitCast(bound);
    }

    pub fn forSigned(value: i64) LebLen {
        return if (signedBound(i7, 0x40) <= value and value <= 0x3F)
            .smallest
        else if (signedBound(i14, 0x2000) <= value and value <= 0x1FFF)
            .@"2"
        else if (signedBound(i21, 0x0010_0000) <= value and value <= 0x000F_FFFF)
            .@"3"
        else if (signedBound(i28, 0x0800_0000) <= value and value <= 0x07FF_FFFF)
            .@"4"
        else if (signedBound(i35, 0x0004_0000_0000) <= value and value <= 0x0003_FFFF_FFFF)
            .@"5"
        else if (signedBound(i42, 0x0200_0000_0000) <= value and value <= 0x01FF_FFFF_FFFF)
            .@"6"
        else if (signedBound(i49, 0x0001_0000_0000_0000) <= value and value <= 0xFFFF_FFFF_FFFF)
            .@"7"
        else if (signedBound(i56, 0x0080_0000_0000_0000) <= value and
            value <= 0x007F_FFFF_FFFF_FFFF)
            .@"8"
        else if (signedBound(i63, 0x4000_0000_0000_0000) <= value and
            value <= 0x3FFF_FFFF_FFFF_FFFF)
            .@"9"
        else
            .@"10";
    }

    pub fn forValue(value: anytype) LebLen {
        return switch (@typeInfo(@TypeOf(value)).int.signedness) {
            .signed => .forSigned(value),
            .unsigned => .forUnsigned(value),
        };
    }

    pub fn maximumForType(comptime T: type) LebLen {
        return switch (@typeInfo(T).int.signedness) {
            .signed => .forSigned(std.math.minInt(T)),
            .unsigned => .forUnsigned(std.math.maxInt(T)),
        };
    }

    pub fn maxOf(a: LebLen, b: LebLen) LebLen {
        return @enumFromInt(@max(@intFromEnum(a), @intFromEnum(b)));
    }

    pub fn minOf(a: LebLen, b: LebLen) LebLen {
        return @enumFromInt(@min(@intFromEnum(a), @intFromEnum(b)));
    }

    fn forValueWithMinimum(min: LebLen, value: anytype) LebLen {
        return .minOf(LebLen.maximumForType(@TypeOf(value)), .maxOf(min, forValue(value)));
    }
};

pub fn writeByte(w: *Writer, b: u8) Oom!void {
    try w.buf.append(w.gpa, b);
}

pub fn writeSlice(w: *Writer, bytes: []const u8) Oom!void {
    try w.buf.appendSlice(w.gpa, bytes);
}

fn encodeSignedLeb(bytes: []u8, value: anytype) void {
    comptime {
        std.debug.assert(@typeInfo(@TypeOf(value)).int.signedness == .signed);
    }
    std.debug.assert(bytes.len > 0);
    var current = value;
    for (0.., bytes) |i, *b| {
        const is_last = i == bytes.len - 1;
        const value_bits: u7 = @bitCast(@as(i7, @truncate(current)));
        b.* = @shlExact(@as(u8, @intFromBool(!is_last)), 7) | @as(u8, value_bits);
        current >>= 7;
    }
}

pub fn writeLeb(w: *Writer, comptime T: type, value: T, min_len: LebLen) Oom!void {
    const dst = try w.buf.addManyAsSlice(w.gpa, min_len.forValueWithMinimum(value).toByteUnits());
    switch (@typeInfo(T).int.signedness) {
        .unsigned => std.leb.writeUnsignedExtended(dst, value),
        .signed => encodeSignedLeb(dst, value),
    }
}

fn expectWritten(w: *const Writer, expected: []const u8) !void {
    try std.testing.expectEqualSlices(u8, expected, w.buf.items[w.buf.items.len - expected.len ..]);
}

test "unsigned LEB" {
    var w = try Writer.init(std.testing.allocator, 512);
    defer w.deinit();

    try w.writeLeb(u32, 0x11, .smallest);
    try expectWritten(&w, &.{0x11});

    try w.writeLeb(u32, 0x22, .@"2");
    try expectWritten(&w, &.{ 0xA2, 0x00 });

    try w.writeLeb(u32, 0x33, .@"3");
    try expectWritten(&w, &.{ 0xB3, 0x80, 0x00 });

    try w.writeLeb(u32, 0x14, .@"4");
    try expectWritten(&w, &.{ 0x94, 0x80, 0x80, 0x00 });

    try w.writeLeb(u32, 0x15, .@"5");
    try expectWritten(&w, &.{ 0x95, 0x80, 0x80, 0x80, 0x00 });

    // Bounds
    try w.writeLeb(u32, 0x80, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x01 });

    try w.writeLeb(u32, 0x3FFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0x7F });

    try w.writeLeb(u32, 0x4000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x01 });

    try w.writeLeb(u32, 0x001F_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0x7F });

    try w.writeLeb(u32, 0x0020_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x01 });

    try w.writeLeb(u32, 0x0FFF_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0x7F });

    try w.writeLeb(u32, 0x1000_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x01 });

    try w.writeLeb(u32, 0xFFFF_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0x0F });
}

test "signed LEB" {
    var w = try Writer.init(std.testing.allocator, 512);
    defer w.deinit();

    try w.writeLeb(i32, 0x11, .smallest);
    try expectWritten(&w, &.{0x11});

    try w.writeLeb(i32, -1, .smallest);
    try expectWritten(&w, &.{0x7F});

    try w.writeLeb(i32, -1, .@"2");
    try expectWritten(&w, &.{ 0xFF, 0x7F });

    try w.writeLeb(i32, -1, .@"3");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0x7F });

    try w.writeLeb(i32, -1, .@"4");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0x7F });

    try w.writeLeb(i32, -1, .@"5");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0x7F });

    try w.writeLeb(i64, -1, .@"6");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F });

    try w.writeLeb(i64, -1, .@"7");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F });

    try w.writeLeb(i64, -1, .@"8");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F });

    try w.writeLeb(i64, -1, .@"9");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F });

    try w.writeLeb(i64, -1, .@"10");
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F });

    // TODO: more tests for different minimum lengths

    // Bounds
    try w.writeLeb(i32, 0x3F, .smallest);
    try expectWritten(&w, &.{0x3F});

    try w.writeLeb(i32, -64, .smallest);
    try expectWritten(&w, &.{0x40});

    try w.writeLeb(i32, 0x40, .smallest);
    try expectWritten(&w, &.{ 0xC0, 0x00 });

    try w.writeLeb(i32, -65, .smallest);
    try expectWritten(&w, &.{ 0xBF, 0x7F });

    try w.writeLeb(i32, 0x1FFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0x3F });

    try w.writeLeb(i32, -8192, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x40 });

    try w.writeLeb(i32, 0x2000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0xC0, 0x00 });

    try w.writeLeb(i32, -8193, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xBF, 0x7F });

    try w.writeLeb(i32, 0x000F_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0x3F });

    try w.writeLeb(i32, -1_048_576, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x40 });

    try w.writeLeb(i32, 0x0010_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0xC0, 0x00 });

    try w.writeLeb(i32, -1_048_577, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xBF, 0x7F });

    try w.writeLeb(i32, 0x07FF_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0x3F });

    try w.writeLeb(i32, -134_217_728, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x40 });

    try w.writeLeb(i32, 0x0800_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0xC0, 0x00 });

    try w.writeLeb(i32, -134_217_729, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xBF, 0x7F });

    try w.writeLeb(i32, std.math.maxInt(i32), .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0x07 });

    try w.writeLeb(i32, std.math.minInt(i32), .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x78 });

    try w.writeLeb(i64, 0x0003_FFFF_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0x3F });

    try w.writeLeb(i64, -17_179_869_184, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x40 });

    try w.writeLeb(i64, 0x0004_0000_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0xC0, 0x00 });

    try w.writeLeb(i64, -17_179_869_185, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0x7F });

    try w.writeLeb(i64, 0x01FF_FFFF_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F });

    try w.writeLeb(i64, -2_199_023_255_552, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x40 });

    try w.writeLeb(i64, 0x0200_0000_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0xC0, 0x00 });

    try w.writeLeb(i64, -2_199_023_255_553, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0x7F });

    try w.writeLeb(i64, 0xFFFF_FFFF_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F });

    try w.writeLeb(i64, -281_474_976_710_656, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40 });

    try w.writeLeb(i64, 0x1_0000_0000_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xC0, 0x00 });

    try w.writeLeb(i64, -281_474_976_710_657, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0x7F });

    try w.writeLeb(i64, 0x007F_FFFF_FFFF_FFFF, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F });

    try w.writeLeb(i64, -36_028_797_018_963_968, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40 });

    try w.writeLeb(i64, 0x0080_0000_0000_0000, .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xC0, 0x00 });

    try w.writeLeb(i64, -36_028_797_018_963_969, .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0x7F });

    try w.writeLeb(i64, std.math.maxInt(i64), .smallest);
    try expectWritten(&w, &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 });

    try w.writeLeb(i64, std.math.minInt(i64), .smallest);
    try expectWritten(&w, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F });
}

pub fn writeByteVec(w: *Writer, bytes: []const u8, min_len: LebLen) Oom!void {
    try w.writeLeb(u32, @intCast(bytes.len), min_len);
    try w.writeSlice(bytes);
}

pub fn writeSection(w: *Writer, id: u8, contents: []const u8, min_len: LebLen) Oom!void {
    try w.buf.ensureUnusedCapacity(w.gpa, 2 + contents.len);
    w.buf.appendAssumeCapacity(id);
    try w.writeByteVec(contents, min_len);
}

const std = @import("std");
const Oom = std.mem.Allocator.Error;
