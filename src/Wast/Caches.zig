pub const Name = @import("Name.zig");
pub const Ident = @import("Ident.zig");

ids: Ident.Cache = .empty,
names: Name.Cache = .empty,
