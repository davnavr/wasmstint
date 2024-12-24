const ArenaAllocator = @import("std").heap.ArenaAllocator;

out: *ArenaAllocator,
/// An arena whose lifetime ends when parsing of the entire `Wast` script is finished.
parse: *ArenaAllocator,
scratch: *ArenaAllocator,
