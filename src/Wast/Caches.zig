const std = @import("std");
const Name = @import("Name.zig");
const Ident = @import("Ident.zig");

ids: Ident.Cache,
names: Name.Cache,
allocator: std.mem.Allocator,

const Caches = @This();

pub fn init(allocator: std.mem.Allocator) Caches {
    return .{
        .ids = .empty,
        .names = .empty,
        .allocator = allocator,
    };
}

// pub fn reset
