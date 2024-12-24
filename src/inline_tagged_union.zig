const std = @import("std");

pub const PtrConstness = enum {
    @"const",
    mut,

    fn SinglePtr(comptime constness: PtrConstness, comptime T: type) type {
        return @Type(.{
            .pointer = .{
                .size = .One,
                .is_const = switch (constness) {
                    .@"const" => true,
                    .mut => false,
                },
                .is_volatile = false,
                .alignment = 0,
                .address_space = .generic,
                .child = T,
                .is_allowzero = false,
                .sentinel = null,
            },
        });
    }
};

pub fn InlineTaggedUnion(comptime T: type) type {
    return struct {
        pub const Tag = std.meta.FieldEnum(T);

        const fields = std.meta.fields(T);

        pub fn Tagged(comptime tag: Tag) type {
            return struct {
                const info = std.meta.fieldInfo(T, tag);

                tag: @Type(.{
                    .@"enum" = .{
                        .tag_type = @typeInfo(Tag).@"enum".tag_type,
                        .fields = &[1]std.builtin.Type.EnumField{
                            .{
                                .name = info.name,
                                .value = @intFromEnum(tag),
                            },
                        },
                        .decls = &[0]std.builtin.Type.Declaration{},
                        .is_exhaustive = true,
                    },
                }),
                value: info.type,
            };
        }

        pub fn Union(comptime constness: PtrConstness) type {
            var cases: [fields.len]std.builtin.Type.UnionField = undefined;
            for (fields, &cases) |*f, *c| {
                c.* = .{
                    .name = f.name ++ "",
                    .type = constness.SinglePtr(f.type),
                    .alignment = 0,
                };
            }

            return @Type(.{
                .@"union" = .{
                    .layout = .auto,
                    .tag_type = Tag,
                    .fields = &cases,
                    .decls = &[0]std.builtin.Type.Declaration{},
                },
            });
        }

        pub fn Ptr(comptime constness: PtrConstness) type {
            return struct {
                tag: constness.SinglePtr(Tag),

                const Self = @This();

                pub fn unpack(self: Self) Union(constness) {
                    switch (self.tag.*) {
                        inline else => |*tag| return @unionInit(
                            Union,
                            @tagName(tag.*),
                            @fieldParentPtr("tag", @constCast(tag)),
                        ),
                    }
                }

                pub fn init(u: Union(constness)) Self {
                    switch (u) {
                        inline else => |case| {
                            const parent: constness.SinglePtr(Tagged(@as(Tag, u))) = @fieldParentPtr("value", case);

                            comptime {
                                std.debug.assert(@sizeOf(Tag) == @sizeOf(@TypeOf(parent.tag)));
                                std.debug.assert(@alignOf(Tag) == @alignOf(@TypeOf(parent.tag)));
                            }

                            return Self{ .tag = @ptrCast(&parent.tag) };
                        },
                    }
                }
            };
        }

        pub fn allocate(
            allocator: std.mem.Allocator,
            comptime tag: Tag,
        ) error{OutOfMemory}!*Tagged(tag) {
            const ptr = try allocator.create(Tagged(tag));
            errdefer comptime unreachable;
            ptr.tag = @enumFromInt(@intFromEnum(tag));
            return ptr;
        }
    };
}
