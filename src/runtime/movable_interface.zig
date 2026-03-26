pub const Layout = extern struct {
    size: usize,
    /// Expressed as a power of two.
    ///
    /// Must be a valid `std.mem.Alignment`.
    alignment: usize,

    pub fn ofType(comptime T: type) Layout {
        return Layout{
            .size = @sizeOf(T),
            .alignment = @intFromEnum(std.mem.Alignment.fromByteUnits(@alignOf(T))),
        };
    }

    pub fn alignmentOf(layout: Layout) std.mem.Alignment {
        return @enumFromInt(layout.alignment);
    }

    pub fn allocate(layout: Layout, allocator: Allocator) Allocator.Error![]u8 {
        return try @import("allocators").allocBytes(allocator, layout.size, layout.alignmentOf());
    }
};

pub fn MovableInterface(comptime T: type) type {
    return extern struct {
        interface: T,

        pub const VTable = struct {
            /// - The `size` must be at least `@sizeOf(T)`.
            /// - The `alignment` must be at least `@alignOf(T)`.
            layout: Layout,
            /// Copies `src` into the given `dest` buffer, then returns a pointer to the newly
            /// moved interface.
            move: *const fn (
                /// Implementations are encouraged to set the contents of `src` to `undefined`.
                src: *T,
                /// Must have a length of `layout.size` with an alignment of
                /// `layout.alignment`
                dst: [*]u8,
            ) *T,

            pub fn forType(
                comptime S: type,
                /// `S` must contain a field of type `T`.
                comptime field_name: []const u8,
            ) VTable {
                const impl = struct {
                    fn move(src: *T, dst: [*]u8) *T {
                        const parent: *S = @fieldParentPtr(field_name, src);
                        const to: *S = @ptrCast(@alignCast(dst));
                        to.* = parent.*;
                        parent.* = undefined;
                        return &@field(to, field_name);
                    }
                };

                return VTable{ .layout = Layout.ofType(S), .move = impl.move };
            }
        };

        inline fn vtable(this: *T) *const VTable {
            return &this.vtable.moving;
        }

        pub fn move(src: *T, dst: []u8) *T {
            const table = vtable(src);
            std.debug.assert(table.layout.size == dst.len);
            std.debug.assert(@intFromPtr(dst.ptr) % table.layout.alignmentOf().toByteUnits() == 0);
            defer src.* = undefined;
            return table.move(src, dst.ptr);
        }
    };
}

const std = @import("std");
const Allocator = std.mem.Allocator;
