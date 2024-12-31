const ArenaAllocator = @import("std").heap.ArenaAllocator;

out: *ArenaAllocator,
/// An arena whose lifetime ends when parsing of the entire `Wast` script is finished.
parse: *ArenaAllocator,
scratch: *ArenaAllocator,

// TODO: Make `scratch: ArenaAllocator` and then:
// pub fn newScratchAllocator(arenas: *const Arenas) struct { alloca: *ArenaAllocator, new: Arenas }
