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

pub const LebLen = enum(u3) {
    smallest,
    @"2",
    @"3",
    @"4",
    @"5",

    pub fn toByteUnits(len: LebLen) u3 {
        return @as(u3, @intFromEnum(len)) + 1;
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

    fn forUnsignedWithMinimum(min: LebLen, value: u32) LebLen {
        return @enumFromInt(@max(@intFromEnum(min), @intFromEnum(LebLen.forUnsigned(value))));
    }
};

pub fn writeByte(w: *Writer, b: u8) Oom!void {
    try w.buf.append(w.gpa, b);
}

pub fn writeSlice(w: *Writer, bytes: []const u8) Oom!void {
    try w.buf.appendSlice(w.gpa, bytes);
}

pub fn writeUleb(w: *Writer, value: u32, min_len: LebLen) Oom!void {
    const dst = try w.buf.addManyAsSlice(w.gpa, min_len.forUnsignedWithMinimum(value).toByteUnits());
    std.leb.writeUnsignedExtended(dst, value);
}

// pub fn writeSleb(w: *Writer, value: i32, min_len: LebLen) Oom!void {
//     const dst = try w.buf.addManyAsSlice(w.gpa, min_len.forSignedWithMinimum(value).toByteUnits());
// }

test writeUleb {
    var w = try Writer.init(std.testing.allocator, 512);
    defer w.deinit();

    try w.writeUleb(0x11, .smallest);
    try std.testing.expectEqualSlices(u8, &.{0x11}, w.buf.items[w.buf.items.len - 1 ..]);

    try w.writeUleb(0x22, .@"2");
    try std.testing.expectEqualSlices(u8, &.{ 0xA2, 0x00 }, w.buf.items[w.buf.items.len - 2 ..]);

    try w.writeUleb(0x33, .@"3");
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xB3, 0x80, 0x00 },
        w.buf.items[w.buf.items.len - 3 ..],
    );

    try w.writeUleb(0x14, .@"4");
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x94, 0x80, 0x80, 0x00 },
        w.buf.items[w.buf.items.len - 4 ..],
    );

    try w.writeUleb(0x15, .@"5");
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x95, 0x80, 0x80, 0x80, 0x00 },
        w.buf.items[w.buf.items.len - 5 ..],
    );

    // Bounds
    try w.writeUleb(0x80, .smallest);
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, w.buf.items[w.buf.items.len - 2 ..]);

    try w.writeUleb(0x3FFF, .smallest);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xFF, 0x7F },
        w.buf.items[w.buf.items.len - 2 ..],
    );

    try w.writeUleb(0x4000, .smallest);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x80, 0x80, 0x01 },
        w.buf.items[w.buf.items.len - 3 ..],
    );

    try w.writeUleb(0x001F_FFFF, .smallest);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xFF, 0xFF, 0x7F },
        w.buf.items[w.buf.items.len - 3 ..],
    );

    try w.writeUleb(0x0020_0000, .smallest);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x80, 0x80, 0x80, 0x01 },
        w.buf.items[w.buf.items.len - 4 ..],
    );

    try w.writeUleb(0x0FFF_FFFF, .smallest);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xFF, 0xFF, 0xFF, 0x7F },
        w.buf.items[w.buf.items.len - 4 ..],
    );

    try w.writeUleb(0x1000_0000, .smallest);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x80, 0x80, 0x80, 0x80, 0x01 },
        w.buf.items[w.buf.items.len - 5 ..],
    );

    try w.writeUleb(0xFFFF_FFFF, .smallest);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0x0F },
        w.buf.items[w.buf.items.len - 5 ..],
    );
}

pub fn writeByteVec(w: *Writer, bytes: []const u8, min_len: LebLen) Oom!void {
    try w.writeUleb(@intCast(bytes.len), min_len);
    try w.writeSlice(bytes);
}

pub fn writeSection(w: *Writer, id: u8, contents: []const u8, min_len: LebLen) Oom!void {
    try w.buf.ensureUnusedCapacity(w.gpa, 2 + contents.len);
    w.buf.appendAssumeCapacity(id);
    try w.writeByteVec(contents, min_len);
}

const std = @import("std");
const Oom = std.mem.Allocator.Error;
